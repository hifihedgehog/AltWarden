"""The Discord client: events, slash commands, buttons, and the timers."""
from __future__ import annotations

import asyncio
import io
import logging
import time
from types import SimpleNamespace

import discord
from discord import app_commands
from discord.ext import tasks

from .. import __version__, access, health, notices, settings as settings_module
from ..catalog import BUTTON, BY_ID, CHECK_IDS, INSTANT, WEB
from ..engine import bypass_options
from ..ports import DISCORD_BUSY, DiscordUnavailable
from ..service import NOT_SET_UP, Result, Service
from .gateway import FAILED, Gateway

log = logging.getLogger("altwarden.bot")

GREEN, RED, TEAL = notices.GREEN, notices.RED, notices.TEAL
BYPASS_HOURS = (1, 6, 12, 24, 48, 72, 168)
CATCH_UP_MARGIN = 120  # the last-online time is written once a minute, so look a little further back
CATCH_UP_RETRY_SECONDS = 300
BYPASS_NOTIFY = (("both", "DM and channel"), ("dm", "DM"), ("channel", "Channel"), ("none", "Don't notify"))
MODE_NAMES = {WEB: "Web page", BUTTON: "Button", INSTANT: "Instant"}
STILL_LOADING = "Discord is still loading this server. Try again in a moment."
HEALTH_ISSUES_SHOWN = 10
COMMAND_OVERRIDES_SECONDS = 60
OVERRIDES_READ_SECONDS = 2  # inside the three seconds Discord waits for an answer, so a slow read can still be refused out loud
SYNC_RETRY_SECONDS = 60
SYNC_RETRY_MOST_SECONDS = 3600
SHUTDOWN_SECONDS = 10
# What discord.py names a running event handler (client.py), slash command (app_commands/tree.py) and button or menu callback (ui/view.py).
HANDLER_TASKS = ("discord.py: ", "CommandTree-invoker", "discord-ui-view-dispatch-")


def intents() -> discord.Intents:
    """Only what the features use. Message text isn't read, so Message Content stays off."""
    wanted = discord.Intents.none()
    wanted.guilds = True
    wanted.members = True
    wanted.moderation = True
    wanted.guild_messages = True
    return wanted


class AltWardenBot(discord.Client):
    def __init__(self) -> None:
        super().__init__(intents=intents(), chunk_guilds_at_startup=False, max_messages=None,
                         allowed_mentions=discord.AllowedMentions.none())
        self.tree = app_commands.CommandTree(self)
        self.gateway = Gateway(self)
        self.service: Service | None = None
        self.synced = False
        self._sync_at = 0.0
        self._sync_wait = SYNC_RETRY_SECONDS
        self._stopping = False
        self._overrides: dict[str, tuple[float, dict]] = {}
        self._catch_up_task: asyncio.Task | None = None
        self.imports: dict[str, asyncio.Task] = {}  # the member import running on each server
        self._catch_up_again: float | None = None
        self._missed_since: float | None = None  # join events from here on won't arrive, and need looking for
        self._disconnected_at: float | None = None  # Discord may still replay these, if the session resumes
        self.on_ready_hook = None
        register_commands(self)

    async def setup_hook(self) -> None:
        # Read before the timers start, because they keep this time current.
        self._missed_since = await self.service.db.get_meta("last_online")
        self.minute_timer.start()
        self.hour_timer.start()

    async def on_ready(self) -> None:
        log.info("Connected as %s to %d servers", self.user, len(self.guilds))
        for guild in self.guilds:  # Servers that added the bot while it was offline, or came back.
            await self._add_server(str(guild.id))
        await self.service.db.mark_departed({str(guild.id) for guild in self.guilds})
        since, self._missed_since = self._missed_since, None
        if since is None:  # the very first start, with nothing to look for
            if not self._walking() and self._disconnected_at is None:
                await self.service.db.set_meta("last_online", time.time())
        elif self._walking():
            # Member lists are walked by ID, so a new gap means walking again once this one ends.
            self._catch_up_again = since if self._catch_up_again is None else min(since, self._catch_up_again)
        else:
            self._catch_up_task = asyncio.ensure_future(self._catch_up(since - CATCH_UP_MARGIN))
        await self._sync_commands()

    async def _sync_commands(self) -> None:
        """Send Discord the command list, once per start. It carries each command's default permissions, so a deploy that changes one takes effect here.

        A failure mustn't wait for the next new session, which can be weeks away, so the minute timer tries again, less often each time.
        """
        if self.synced or time.monotonic() < self._sync_at:
            return
        try:
            await self.tree.sync()
            self.synced = True
        except Exception:
            log.exception("Couldn't send Discord the command list. Trying again in %d seconds.", self._sync_wait)
            self._sync_at = time.monotonic() + self._sync_wait
            self._sync_wait = min(self._sync_wait * 2, SYNC_RETRY_MOST_SECONDS)

    async def on_raw_app_command_permissions_update(self, payload) -> None:
        """Discord says a command's permissions changed, so a revoked allow doesn't last out the minute.

        APPLICATION_COMMAND_PERMISSIONS_UPDATE in discord-api-docs (developers/events/gateway-events.mdx), and
        ConnectionState.parse_application_command_permissions_update in discord.py (discord/state.py).
        """
        self._overrides.pop(str(payload.guild.id), None)

    async def command_overrides(self, guild_id: str) -> dict | None:
        """Discord's own overrides for this server's commands, kept for a minute, or None if they couldn't be read in time."""
        kept = self._overrides.get(guild_id)
        if kept and time.monotonic() - kept[0] < COMMAND_OVERRIDES_SECONDS:
            return kept[1]
        try:
            data = await asyncio.wait_for(self.gateway.command_permissions(guild_id), OVERRIDES_READ_SECONDS)
        except asyncio.TimeoutError:
            log.warning("Reading command permissions in %s took too long", guild_id)
            return None
        if data is not None:
            self._overrides[guild_id] = (time.monotonic(), data)
        return data

    def _walking(self) -> bool:
        return self._catch_up_task is not None and not self._catch_up_task.done()

    async def on_disconnect(self) -> None:
        if self._disconnected_at is None:
            self._disconnected_at = time.time()

    async def on_connect(self) -> None:
        """READY arrived, so this is a new session, and what happened while disconnected won't be replayed."""
        if self._disconnected_at is not None:
            self._missed_since = self._disconnected_at if self._missed_since is None else min(self._missed_since, self._disconnected_at)
            self._disconnected_at = None

    async def on_resumed(self) -> None:
        self._disconnected_at = None  # Discord replays what a resumed session missed

    async def _catch_up(self, since: float) -> None:
        """Discord sends no join event for someone who joined while the bot was offline, so look for them.

        Member lists come a thousand at a time, and discord.py keeps to Discord's rate limit, so this
        runs in the background and takes a couple of minutes on a very large server. The last-online
        time only moves once this is done, so a restart or a failure partway through loses nothing.
        """
        waiting = list(self.guilds)
        while True:
            failed = []
            for guild in waiting:
                try:
                    await self._catch_up_in(guild, since)
                except Exception:
                    log.exception("Couldn't check for joins while offline in %s. Trying again in a few minutes.", guild.id)
                    failed.append(guild)
            if self._catch_up_again is not None:
                since = min(since, self._catch_up_again - CATCH_UP_MARGIN)
                self._catch_up_again = None
                waiting = list(self.guilds)
                continue
            # Only a server AltWarden is still in can be retried.
            waiting = [guild for guild in failed if self.get_guild(guild.id) is not None]
            if not waiting:
                break
            await asyncio.sleep(CATCH_UP_RETRY_SECONDS)
        if self._disconnected_at is None:  # if the gateway dropped meanwhile, the next ready looks again from that moment
            await self.service.db.set_meta("last_online", time.time())

    async def _catch_up_in(self, guild: discord.Guild, since: float) -> None:
        guild_id = str(guild.id)
        if not await self.service.is_set_up(guild_id):
            return
        found = 0
        async for member in guild.fetch_members(limit=None):
            joined = member.joined_at
            if member.bot or joined is None or joined.timestamp() < since:
                continue
            record = await self.service.db.member(guild_id, str(member.id))
            # The slack is for this machine's clock and Discord's disagreeing about a join already handled.
            if record is not None and (record["joined_at"] or 0) + CATCH_UP_MARGIN >= joined.timestamp():
                continue
            try:
                await self.service.on_join(self.gateway.info(member), catching_up=True)
                found += 1
            except Exception:
                log.exception("Couldn't handle a join while offline in %s", guild_id)  # one member mustn't cost everyone after them
        if found:
            log.info("Caught up on %d joins in %s", found, guild_id)

    def dispatch(self, event: str, /, *args, **kwargs) -> None:
        if not self._stopping:
            super().dispatch(event, *args, **kwargs)

    async def close(self) -> None:
        self.minute_timer.cancel()  # first, so the last-online time can't move past a walk that's being cut short
        self.hour_timer.cancel()
        if self._catch_up_task is not None:
            self._catch_up_task.cancel()
        for task in self.imports.values():  # nothing is marked until the whole list is read, so this one can simply run again
            task.cancel()
        # A join cut short here would leave a member half handled, so what's running gets to finish, on a connection that still works, and nothing new starts.
        self._stopping = True
        running = [task for task in asyncio.all_tasks() if task.get_name().startswith(HANDLER_TASKS) and task is not asyncio.current_task()]
        if running:
            await asyncio.wait(running, timeout=SHUTDOWN_SECONDS)
        await super().close()

    @tasks.loop(minutes=1)
    async def minute_timer(self) -> None:
        try:
            await self._sync_commands()
            # Held still while offline and during a catch-up, so what wasn't checked yet still gets checked after a restart.
            if self._missed_since is None and self._disconnected_at is None and not self._walking():
                await self.service.db.set_meta("last_online", time.time())
            await self.service.tick()
        except Exception:
            log.exception("Minute timer failed")

    @tasks.loop(hours=1)
    async def hour_timer(self) -> None:
        try:
            removed = await self.service.purge()
            if any(removed.values()):
                log.info("Removed expired records: %s", removed)
        except Exception:
            log.exception("Couldn't remove expired records")
        try:  # separately, so a failed purge can't leave the network lists aging as well
            if self.service.net.stale():
                changed = await self.service.net.refresh()
                log.info("Refreshed %d network lists", changed)
        except Exception:
            log.exception("Couldn't refresh the network lists")

    @minute_timer.before_loop
    @hour_timer.before_loop
    async def _wait(self) -> None:
        await self.wait_until_ready()

    # --- events -----------------------------------------------------------------------------

    async def on_guild_join(self, guild: discord.Guild) -> None:
        log.info("Joined %s", guild.id)
        await self._add_server(str(guild.id))

    async def _add_server(self, guild_id: str) -> None:
        """A server the bot is in has a row, and a server that came back keeps what it had."""
        if await self.service.db.guild(guild_id) is None:
            await self.service.edit_settings(guild_id, lambda current: current, section="rules", setup_done=False)
        await self.service.db.set_guild_field(guild_id, "left_at", None)

    async def on_guild_remove(self, guild: discord.Guild) -> None:
        """Records stay for a while, so a server that removed the bot by mistake loses nothing. Then they go."""
        log.info("Left %s", guild.id)
        await self.service.db.set_guild_field(str(guild.id), "left_at", time.time())

    async def on_member_join(self, member: discord.Member) -> None:
        self.gateway.forget_member(str(member.guild.id), str(member.id))  # a check made while they were out says they aren't here
        await self.service.on_join(self.gateway.info(member))

    async def on_member_update(self, _: discord.Member, after: discord.Member) -> None:
        """Roles and screening decide what a member may do. Discord.py fires this only for members in its cache, and those read from the cache."""
        self.gateway.forget_member(str(after.guild.id), str(after.id))
        if after.guild.me is not None and after.id == after.guild.me.id:
            self.gateway.forget_guild(str(after.guild.id))  # the server's view holds AltWarden's own permissions and top role

    async def on_guild_update(self, _: discord.Guild, after: discord.Guild) -> None:
        self.gateway.forget_guild(str(after.id))

    async def on_guild_role_create(self, role: discord.Role) -> None:
        self.gateway.forget_guild(str(role.guild.id))

    async def on_guild_role_delete(self, role: discord.Role) -> None:
        self.gateway.forget_guild(str(role.guild.id))

    async def on_guild_role_update(self, _: discord.Role, after: discord.Role) -> None:
        self.gateway.forget_guild(str(after.guild.id))

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        self.gateway.forget_guild(str(channel.guild.id))

    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        self.gateway.forget_guild(str(channel.guild.id))

    async def on_guild_channel_update(self, _: discord.abc.GuildChannel, after: discord.abc.GuildChannel) -> None:
        self.gateway.forget_guild(str(after.guild.id))

    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent) -> None:
        await self._post_deleted(payload.guild_id, payload.channel_id, payload.message_id)

    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent) -> None:
        for message_id in payload.message_ids:
            await self._post_deleted(payload.guild_id, payload.channel_id, message_id)

    async def _post_deleted(self, guild_id: int | None, channel_id: int, message_id: int) -> None:
        """If that was the Verify post, say so, because the health report looks for one. A post AltWarden replaces has a new ID by now."""
        if guild_id is not None:
            await self.service.db.run("UPDATE guilds SET verify_message_id = NULL WHERE guild_id = ? AND verify_message_id = ?",
                                      (str(guild_id), f"{channel_id}:{message_id}"))

    async def on_raw_member_remove(self, payload: discord.RawMemberRemoveEvent) -> None:
        """The raw event, because the plain one only fires for members in the cache, and most aren't."""
        guild_id, user_id = str(payload.guild_id), str(payload.user.id)
        self.gateway.forget_member(guild_id, user_id)
        await self.service.on_leave(guild_id, user_id)

    async def on_member_ban(self, guild: discord.Guild, user: discord.User) -> None:
        await self.service.on_ban(str(guild.id), str(user.id))

    async def on_member_unban(self, guild: discord.Guild, user: discord.User) -> None:
        await self.service.on_unban(str(guild.id), str(user.id))

    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author == self.user or message.is_system():
            return  # a pin notice or a join message isn't a post, and it would be blamed on whoever caused it
        settings = await self.service.get_settings(str(message.guild.id))
        if settings is None:
            return
        parent = getattr(message.channel, "parent_id", None)
        # Help threads live under the verification channel, so only a post there is looked up. The text itself is never read.
        if parent is not None and str(parent) == settings["core"]["channel"] and not message.author.bot and message.webhook_id is None:
            mentioned = tuple(str(role.id) for role in getattr(message, "role_mentions", ()))  # sent without Message Content
            await self.service.remind_in_help_thread(str(message.guild.id), str(message.channel.id), str(message.author.id), mentioned)
        if not settings["honeypot"]["enabled"]:
            return
        trap = settings["honeypot"]["channel"]
        if trap not in (str(message.channel.id), str(parent)):
            return
        roles = tuple(str(role.id) for role in getattr(message.author, "roles", ()))
        await self.service.honeypot_hit(str(message.guild.id), str(message.author.id), str(message.channel.id), str(message.id), role_ids=roles,
                                        is_webhook=message.webhook_id is not None, is_bot=message.author.bot, parent_id=str(parent) if parent else None)

    async def on_interaction(self, interaction: discord.Interaction) -> None:
        if interaction.type is not discord.InteractionType.component:
            return
        custom_id = (interaction.data or {}).get("custom_id", "")
        if not custom_id.startswith("aw:") or interaction.guild is None:
            return
        try:
            if await self.gateway.guild_loading(str(interaction.guild.id)):  # a member has no roles yet, so a verified one would read as new
                await reply(interaction, STILL_LOADING)
            elif custom_id == "aw:verify":
                await self._press_verify(interaction)
            elif custom_id == "aw:help":
                await self._press_help(interaction)
            elif custom_id == "aw:help:close":
                await self._press_close(interaction)
            elif custom_id.startswith("aw:appeal:"):
                await self._press_appeal(interaction, custom_id)
            elif custom_id.startswith("aw:staff:"):
                await self._press_staff(interaction, custom_id)
        except DiscordUnavailable:
            await reply(interaction, DISCORD_BUSY)
        except Exception:
            log.exception("Button %s failed", custom_id)
            await reply(interaction, "Something went wrong. Please try again.")

    async def _press_verify(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True, thinking=True)
        outcome = await self.service.press_verify(self.gateway.info(interaction.user))
        if isinstance(outcome, str):
            await interaction.followup.send(embed=discord.Embed(title="Your verification link", color=TEAL,
                                                                description="Press the button. The link is yours alone."),
                                            view=link_view("Verify", outcome), ephemeral=True)
            return
        await interaction.followup.send(embed=result_embed(outcome), ephemeral=True)

    async def _press_help(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True, thinking=True)
        _, text = await self.service.open_help(self.gateway.info(interaction.user))
        await interaction.followup.send(text, ephemeral=True)

    async def _press_close(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        actor = self.gateway.info(interaction.user)
        _, text = await self.service.close_help(str(interaction.guild.id), str(interaction.channel_id), actor)
        await interaction.followup.send(text, ephemeral=True)

    async def _press_appeal(self, interaction: discord.Interaction, custom_id: str) -> None:
        _, _, decision, appeal_id = custom_id.split(":")
        guild_id = str(interaction.guild.id)
        settings = await self.service.get_settings(guild_id)
        if settings is None:  # an old button, after /uninstall
            await reply(interaction, NOT_SET_UP)
            return
        actor = self.gateway.info(interaction.user)
        viewer = viewer_of(actor)
        if not access.allowed(settings_module.page_rule(settings, "appeals", "edit"), viewer):
            await reply(interaction, "You don't have access to appeals.")
            return
        await interaction.response.defer(ephemeral=True)
        if decision != "deny":  # approving gives the verified role, so it asks what giving it by hand would
            appeal = await self.service.db.one("SELECT user_id FROM appeals WHERE id = ? AND guild_id = ?", (int(appeal_id), guild_id))
            refusal = appeal and await self.service.staff_refusal(guild_id, actor, appeal["user_id"], "verify")
            if refusal:
                await interaction.followup.send(refusal, ephemeral=True)
                return
        outcome = await self.service.settle_appeal(guild_id, int(appeal_id), decision, str(interaction.user.id), interaction.user.name,
                                                   can_unban=viewer.is_admin or "ban_members" in viewer.permissions)
        await interaction.followup.send(outcome["problem"] or ("Done. They were told." if outcome["told"] else "Done. They weren't told, because Discord didn't deliver the DM."),
                                        ephemeral=True)

    async def _press_staff(self, interaction: discord.Interaction, custom_id: str) -> None:
        """Verify or Create bypass link on a help thread's first post. The member can see them too, so each asks what its command asks."""
        _, _, action, user_id = custom_id.split(":")
        target = SimpleNamespace(id=int(user_id), mention=f"<@{user_id}>", bot=False)  # only a person opens a help thread
        if action == "verify":
            await do_verify(self, interaction, target)
        elif action == "bypass":
            await do_bypass(self, interaction, target)

    # --- posting ----------------------------------------------------------------------------

    async def import_role_members(self, guild: discord.Guild, role_id: str, actor_id: str, actor_name: str) -> int:
        """Mark everyone holding a role as verified. Over REST, because discord.py doesn't notice when Discord rate limits a gateway request for the list, and would wait forever."""
        everyone = role_id == str(guild.id)
        members = [str(member.id) async for member in guild.fetch_members(limit=None) if not member.bot and (everyone or member.get_role(int(role_id)) is not None)]
        document = await self.service.get_settings(str(guild.id))
        return await self.service.import_members(str(guild.id), members, actor_id, actor_name, holding_role=role_id == document["core"]["verified_role"])

    def start_import(self, guild: discord.Guild, role_id: str, actor_id: str, actor_name: str, on_done=None) -> bool:
        """Run a member import in the background, one per server. False means one is already running.

        Reading a big server's list takes minutes, and a reply to a command can only be changed for 15 of them, so nothing waits on it.
        `on_done` gets the count, or None if the import failed.
        """
        guild_id = str(guild.id)
        if guild_id in self.imports:
            return False

        async def run() -> None:
            count = None
            try:
                count = await self.import_role_members(guild, role_id, actor_id, actor_name)
            except Exception:
                log.exception("Member import failed for %s", guild_id)
                await self.service.import_failed(guild_id)
            finally:
                self.imports.pop(guild_id, None)
            if on_done is not None:
                await on_done(count)
        self.imports[guild_id] = asyncio.ensure_future(run())
        return True

    async def post_message(self, guild_id: str, which: str) -> bool:
        """Post the verification or honeypot message, then remove the previous copy, wherever it was."""
        document = await self.service.get_settings(guild_id)
        guild = await self.gateway.guild(guild_id)
        row = await self.service.db.guild(guild_id)
        if document is None or guild is None or row is None:
            return False
        public_url = self.service.public_url
        if which == "verification":
            channel_id = document["core"]["channel"]
            icon = f"https://cdn.discordapp.com/icons/{guild.id}/{guild.icon}.png?size=256" if guild.icon else None
            notice = notices.verification_message(document["messages"]["verification"], guild_name=guild.name,
                                                  help_desk=document["core"]["help_desk"]["enabled"], icon_url=icon, public_url=public_url)
            field = "verify_message_id"
        else:
            if not document["honeypot"]["enabled"]:
                return False  # a warning about a trap that isn't set
            channel_id = document["honeypot"]["channel"]
            notice = notices.plain_message(document["messages"]["honeypot"], guild.name, public_url)
            field = "honeypot_message_id"
        if not channel_id:
            return False
        message_id = await self.gateway.send(channel_id, notice, guild_id=guild_id)
        if message_id is None:
            return False  # The old copy stays up, so a failed repost can't leave the server with no Verify button.
        await self._remove_post(row[field])
        await self.service.db.set_guild_field(guild_id, field, f"{channel_id}:{message_id}")
        if which == "honeypot":
            await self.gateway.pin(channel_id, message_id)
        return True

    async def _remove_post(self, where: str | None) -> None:
        channel_id, _, message_id = (where or "").partition(":")
        if message_id:
            await self.gateway.delete_message(channel_id, message_id)

    async def remove_posts(self, guild_id: str) -> None:
        row = await self.service.db.guild(guild_id)
        if row is not None:
            await self._remove_post(row["verify_message_id"])
            await self._remove_post(row["honeypot_message_id"])


def viewer_of(member) -> access.Viewer:
    return access.Viewer(member.user_id, frozenset(member.role_ids), member.permissions, member.is_owner)


async def refused_on_target(bot: AltWardenBot, interaction: discord.Interaction, target_id: int, action: str) -> bool:
    """Say why this person can't do this to this account, after the interaction is deferred, since the answer can take a call to Discord."""
    refusal = await bot.service.staff_refusal(str(interaction.guild_id), bot.gateway.info(interaction.user), str(target_id), action)
    if refusal:
        await reply(interaction, refusal)
    return bool(refusal)


def link_view(label: str, url: str) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(discord.ui.Button(label=label, url=url, style=discord.ButtonStyle.link))
    return view


def result_embed(result: Result) -> discord.Embed:
    color = GREEN if result.status in ("verified", "already") else RED
    return discord.Embed(title=result.title, description=result.discord_text(), color=color)


def health_embed(data: dict) -> discord.Embed:
    """Issues first, up to what stays readable, then the notices. A healthy server can still have a notice."""
    issues = data["issues"]
    parts = ["Everything AltWarden needs is in place."] if data["healthy"] else [f"**{issue['title']}**\n{issue['fix']}" for issue in issues[:HEALTH_ISSUES_SHOWN]]
    if len(issues) > HEALTH_ISSUES_SHOWN:
        parts.append(f"And {len(issues) - HEALTH_ISSUES_SHOWN} more on the Health page.")
    parts += [f"**{notice['title']}**\n{notice['fix']}" for notice in data["notices"]]
    return discord.Embed(title="Health check", description="\n".join(parts)[:4096], color=GREEN if data["healthy"] else RED)


async def reply(interaction: discord.Interaction, text: str) -> None:
    """Answer however the interaction allows. Its token dies after three seconds unanswered, and nothing can be done then."""
    try:
        if interaction.response.is_done():
            await interaction.followup.send(text, ephemeral=True)
        else:
            await interaction.response.send_message(text, ephemeral=True)
    except FAILED as exc:
        log.warning("Couldn't answer an interaction: %s", exc)


# The right-click commands follow the rule of the slash command they stand in for.
MENU_RULES = {"Verify": "verify-user", "Reset": "reset-user", "Create Bypass": "create-bypass", "Lookup": "lookup"}


def _channel_override(entries: list, places: tuple, all_channels: str) -> bool | None:
    for place in places:
        for entry in entries:
            if entry["type"] == "channel" and entry["id"] == place:
                return entry["allow"]
    return next((entry["allow"] for entry in entries if entry["type"] == "channel" and entry["id"] == all_channels), None)


def _member_override(entries: list, viewer: access.Viewer, guild_id: str) -> bool | None:
    """User, then the member's roles, where one allow among them is enough, then @everyone, whose ID is the server's. None means nothing here applies."""
    for entry in entries:
        if entry["type"] == "user" and entry["id"] == viewer.user_id:
            return entry["allow"]
    roles = [entry["allow"] for entry in entries if entry["type"] == "role" and entry["id"] in viewer.role_ids and entry["id"] != guild_id]
    if roles:
        return any(roles)
    return next((entry["allow"] for entry in entries if entry["type"] == "role" and entry["id"] == guild_id), None)


def discord_denies(data: dict, name: str, viewer: access.Viewer, places: tuple, guild_id: str) -> bool:
    """Whether Discord's own overrides say no to this person running this command here, walked the same way as `discord_allows`.

    Silence isn't a no. A command's entries for the member decide before the app's, as they do on Discord.
    """
    command = next((row["overrides"] for row in data["commands"] if row["name"] == name), [])
    all_channels = str(int(guild_id) - 1)
    for entries in (command, data["all"]):
        verdict = _channel_override(entries, places, all_channels)
        if verdict is not None:
            if not verdict:
                return True
            break
    verdict = _member_override(command, viewer, guild_id)
    if verdict is not None:
        return not verdict
    return _member_override(data["all"], viewer, guild_id) is False


def discord_allows(data: dict, name: str, viewer: access.Viewer, places: tuple, guild_id: str, required: list) -> bool:
    """Whether Discord's own overrides let this person run this command here, walked as Discord's flowchart of its client does.

    The channel is a gate: a command's entry for it, or for All Channels (the server's ID minus one), then the app's, and
    a deny ends it while an allow grants nothing by itself. Then a command's entries for the member decide outright. Failing
    those the app's apply, and an allow there still needs the command's default permissions. With no entry for the member
    this is no allow at all, because holding the default permissions alone is what the server's own rule already judged.
    """
    command = next((row["overrides"] for row in data["commands"] if row["name"] == name), [])
    all_channels = str(int(guild_id) - 1)
    for entries in (command, data["all"]):
        verdict = _channel_override(entries, places, all_channels)
        if verdict is not None:
            if not verdict:
                return False
            break
    verdict = _member_override(command, viewer, guild_id)
    if verdict is not None:
        return verdict
    return bool(_member_override(data["all"], viewer, guild_id)) and bool(required) and all(permission in viewer.permissions for permission in required)


async def allowed(bot: AltWardenBot, interaction: discord.Interaction, command: str, *, discord_name: str | None = None) -> bool:
    """Discord's list only decides who sees a command. This rule decides who can run it.

    A rule someone wrote on the Access page is final, because anyone with Manage Server and Manage Roles can add themselves on
    Discord's side, and a block there has to hold against them. While a command's rule is still its default, an allow on Discord's
    side counts too, since setting one is a decision staff made. A button has no command for Discord to check, so an explicit deny
    for the command it stands in for refuses the press, as Discord would refuse the command. Administrators and the owner are
    past all of this: application-commands.mdx says members with Administrator can use all commands. If Discord's side can't be
    read, the rule's answer stands.
    """
    if await bot.gateway.guild_loading(str(interaction.guild_id)):  # a member has no roles yet, so staff would read as nobody
        await reply(interaction, STILL_LOADING)
        return False
    document = await bot.service.get_settings(str(interaction.guild_id)) or settings_module.defaults()
    viewer = viewer_of(bot.gateway.info(interaction.user))
    channel = getattr(interaction, "channel", None)
    places = (str(interaction.channel_id), str(channel.parent_id)) if isinstance(channel, discord.Thread) else (str(interaction.channel_id),)
    guild_id = str(interaction.guild_id)
    # A right-click command has its own entries on Discord, under its own name. A button has no command, so it reads the one it stands in for.
    invoked = getattr(getattr(interaction, "command", None), "name", None)
    name = invoked or discord_name or command
    if access.allowed(settings_module.command_rule(document, command), viewer, places):
        if invoked or viewer.is_admin:
            return True
        overrides = await bot.command_overrides(guild_id)
        if overrides is None or not discord_denies(overrides, name, viewer, places, guild_id):
            return True
    elif settings_module.command_rule_untouched(document, command):
        overrides = await bot.command_overrides(guild_id)
        if overrides is not None and discord_allows(overrides, name, viewer, places, guild_id, settings_module.COMMAND_DEFAULTS.get(command, [])):
            return True
    await reply(interaction, "You don't have access to this command.")
    return False


async def do_verify(bot: AltWardenBot, interaction: discord.Interaction, user) -> None:
    if not await allowed(bot, interaction, "verify-user") or await ready(bot, interaction) is None:
        return
    if user.bot:
        await reply(interaction, "Bots don't verify.")
        return
    await interaction.response.defer(ephemeral=True)
    if await refused_on_target(bot, interaction, user.id, "verify"):
        return
    problem = await bot.service.manual_verify(str(interaction.guild_id), str(user.id), str(interaction.user.id), interaction.user.name)
    await interaction.followup.send(problem or f"{user.mention} is verified.", ephemeral=True)


async def do_bypass(bot: AltWardenBot, interaction: discord.Interaction, user, hours: int = 1, notify: str = "both") -> None:
    if not await allowed(bot, interaction, "create-bypass"):
        return
    if user.bot:
        await reply(interaction, "You can't create a link for a bot.")
        return
    guild_id = str(interaction.guild_id)
    document = await ready(bot, interaction)
    if document is None:
        return
    await interaction.response.defer(ephemeral=True)  # looking up the member can take longer than Discord waits
    member = await bot.gateway.member(guild_id, str(user.id))
    if member is None:
        await reply(interaction, "That person isn't in the server.")
        return
    if await refused_on_target(bot, interaction, user.id, "bypass"):
        return
    if document["core"]["verified_role"] in member.role_ids:
        await reply(interaction, "That member is already verified. Reset them first if they should verify again.")
        return
    options = bypass_options(document)
    if not options:
        await reply(interaction, "No checks are on, so there is nothing to skip.")
        return
    await interaction.followup.send(f"Choose what {user.mention}'s link skips.", view=BypassView(bot, user, options, hours, notify, getattr(interaction.command, "name", None)), ephemeral=True)


async def ready(bot: AltWardenBot, interaction: discord.Interaction) -> dict | None:
    """This server's settings, or None after telling the member that setup comes first."""
    guild_id = str(interaction.guild_id)
    if await bot.service.is_set_up(guild_id):
        return await bot.service.get_settings(guild_id)
    await reply(interaction, "This server isn't set up yet. Run /setup first.")
    return None


class StaffView(discord.ui.View):
    """A button pressed after the reply is deferred has nowhere to show a failure, unless it's told here."""

    async def on_error(self, interaction: discord.Interaction, error: Exception, _: discord.ui.Item) -> None:
        if isinstance(error, DiscordUnavailable):
            await reply(interaction, DISCORD_BUSY)
            return
        log.exception("A staff button failed", exc_info=error)
        await reply(interaction, "That didn't work. Please try again.")


class BypassView(StaffView):
    """Pick what one member's link skips, how they hear about it, and how long it lasts."""

    def __init__(self, bot: AltWardenBot, user: discord.abc.User, options: list[str], hours: int, notify: str, command_name: str | None = None):
        super().__init__(timeout=300)
        self.bot, self.user, self.hours, self.notify = bot, user, hours, notify
        self.command_name = command_name  # the slash command or the right-click one it was opened from, which have separate entries on Discord
        self.choice: list[str] = []
        self.checks = discord.ui.Select(placeholder="Checks to skip", min_values=1, max_values=min(25, len(options)), row=0,
                                        options=[discord.SelectOption(label=notices.check_name(check), value=check) for check in options[:25]])
        self.tell = discord.ui.Select(placeholder="How to tell them", row=1, options=[
            discord.SelectOption(label=label, value=value, default=value == notify) for value, label in BYPASS_NOTIFY])
        self.lasts = discord.ui.Select(placeholder="How long it lasts", row=2, options=[
            discord.SelectOption(label=f"{count} hour{'s' if count != 1 else ''}", value=str(count), default=count == hours)
            for count in sorted({*BYPASS_HOURS, hours})])
        self.checks.callback = self._pick
        self.tell.callback = self._pick
        self.lasts.callback = self._pick
        for menu in (self.checks, self.tell, self.lasts):
            self.add_item(menu)

    async def _pick(self, interaction: discord.Interaction) -> None:
        self.choice = list(self.checks.values) or self.choice
        self.notify = self.tell.values[0] if self.tell.values else self.notify
        self.hours = int(self.lasts.values[0]) if self.lasts.values else self.hours
        await interaction.response.defer()

    @discord.ui.button(label="Create link", style=discord.ButtonStyle.primary, row=3)
    async def create(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if not self.choice:
            await reply(interaction, "Pick at least one check first.")
            return
        # These menus stay open for minutes, so the right to do this is asked again at the press.
        if not await allowed(self.bot, interaction, "create-bypass", discord_name=self.command_name):
            return
        await interaction.response.defer(ephemeral=True)
        if await refused_on_target(self.bot, interaction, self.user.id, "bypass"):
            return
        url, told = await self.bot.service.create_bypass(
            str(interaction.guild_id), str(self.user.id), self.choice, self.hours, self.notify, str(interaction.user.id),
            interaction.user.name, str(interaction.channel_id))
        text = f"Link created for {self.user.mention}, good for {self.hours} hour{'s' if self.hours != 1 else ''}. "
        text += "They were told." if told else "They weren't told, so send it to them yourself."
        await interaction.followup.send(f"{text}\n{url}", ephemeral=True)  # Only staff see this reply, and it's the one place the link exists.
        self.stop()


class UninstallView(StaffView):
    def __init__(self, bot: AltWardenBot, actor_id: int):
        super().__init__(timeout=60)
        self.bot, self.actor_id = bot, actor_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.actor_id

    @discord.ui.button(label="Delete everything", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        if not await allowed(self.bot, interaction, "uninstall"):
            return
        await interaction.response.defer(ephemeral=True)
        guild_id = str(interaction.guild_id)
        await self.bot.service.note_uninstall(guild_id, str(interaction.user.id))
        await self.bot.remove_posts(guild_id)
        await self.bot.service.db.forget_guild(guild_id)
        self.bot.service.forget_cached(guild_id)
        await interaction.followup.send("AltWarden's settings and every record for this server are gone.", ephemeral=True)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await interaction.response.send_message("Nothing changed.", ephemeral=True)
        self.stop()


def register_commands(bot: AltWardenBot) -> None:
    tree = bot.tree

    @tree.command(name="setup", description="Set up verification with a verified role and a channel")
    @app_commands.guild_only()
    @app_commands.describe(role="The role members get after verifying", channel="The channel members verify in")
    async def setup(interaction: discord.Interaction, role: discord.Role, channel: discord.TextChannel) -> None:
        if not await allowed(bot, interaction, "setup"):
            return
        guild_id = str(interaction.guild_id)
        if await bot.service.is_set_up(guild_id):
            await reply(interaction, f"This server is already set up. Change it at {bot.service.public_url}/dashboard/{guild_id}")
            return
        if role.is_default() or role.managed:
            await reply(interaction, "Pick a regular role. @everyone and roles owned by other apps can't be given out.")
            return
        if role >= interaction.guild.me.top_role:
            await reply(interaction, f"Drag AltWarden's role above {role.mention} in Server Settings first.")
            return
        if not viewer_of(bot.gateway.info(interaction.user)).is_admin and role >= interaction.user.top_role:
            await reply(interaction, "Pick a role below your own highest role.")
            return
        await interaction.response.defer(ephemeral=True)

        def chosen(document: dict) -> dict:
            document["core"].update(verified_role=str(role.id), channel=str(channel.id))
            return document
        await bot.service.edit_settings(guild_id, chosen, section="rules", actor_id=str(interaction.user.id), actor_name=interaction.user.name, setup_done=True)
        if not await bot.post_message(guild_id, "verification"):
            await interaction.followup.send(f"Saved, but AltWarden couldn't post in {channel.mention}. Give it View Channel, Send Messages and Embed Links there, "
                                            "then run /post-message.", ephemeral=True)
            return
        preset = (await bot.service.get_settings(guild_id))["preset"].title()
        await interaction.followup.send(f"Done. Verification is on in {channel.mention}, using the {preset} rules.\n"
                                        f"Fine-tune it at {bot.service.public_url}/dashboard/{guild_id}", ephemeral=True)

    @tree.command(name="settings", description="Show how verification is set up here")
    @app_commands.guild_only()
    async def settings_command(interaction: discord.Interaction) -> None:
        if not await allowed(bot, interaction, "settings"):
            return
        document = await ready(bot, interaction)
        if document is None:
            return
        core = document["core"]
        lines = [f"**Mode:** {MODE_NAMES[core['mode']]}", f"**Rules:** {document['preset'].title()}",
                 f"**Verified role:** <@&{core['verified_role']}>" if core["verified_role"] else "**Verified role:** not set",
                 f"**Channel:** <#{core['channel']}>" if core["channel"] else "**Channel:** not set"]
        if core["unverified_enabled"] and core["unverified_role"]:
            lines.append(f"**Unverified role:** <@&{core['unverified_role']}>")
        # This reply is public, so it says what's on and never what each check does about it. A check the mode can't run isn't on.
        paused = settings_module.paused_checks(document)
        lines += [BY_ID[check_id].name for check_id in CHECK_IDS if document["checks"][check_id]["enabled"] and check_id not in paused]
        for name, on in (("Cooldown", core["cooldown"]["enabled"]), ("Auto kick", core["auto_kick"]["enabled"]),
                         ("Raid mode", document["raid"]["enabled"]), ("Honeypot", document["honeypot"]["enabled"])):
            if on:
                lines.append(name)
        await interaction.response.send_message(embed=discord.Embed(title="AltWarden settings", description="\n".join(lines), color=TEAL))

    @tree.command(name="post-message", description="Post a message again in its channel")
    @app_commands.guild_only()
    @app_commands.describe(message="Which message to post")
    @app_commands.choices(message=[app_commands.Choice(name="Verification message", value="verification"),
                                   app_commands.Choice(name="Honeypot warning", value="honeypot")])
    async def post_message(interaction: discord.Interaction, message: app_commands.Choice[str]) -> None:
        if not await allowed(bot, interaction, "post-message"):
            return
        document = await ready(bot, interaction)
        if document is None:
            return
        if message.value == "honeypot" and not document["honeypot"]["enabled"]:
            await reply(interaction, "The honeypot is off. Turn it on from the Rules page, and its warning goes up.")
            return
        await interaction.response.defer(ephemeral=True)
        outcome = await bot.service.staff_post(str(interaction.guild_id), message.value, bot.post_message, actor_id=str(interaction.user.id), actor_name=interaction.user.name)
        text = "Posted." if outcome == "posted" else "Couldn't post it. Pick a channel on the dashboard, then run /health."
        await interaction.followup.send(text, ephemeral=True)

    @tree.command(name="health", description="Find what would stop members from verifying")
    @app_commands.guild_only()
    async def health_command(interaction: discord.Interaction) -> None:
        if not await allowed(bot, interaction, "health"):
            return
        await interaction.response.defer(ephemeral=True)
        guild_id = str(interaction.guild_id)
        document = await bot.service.get_settings(guild_id) or settings_module.defaults()
        guild = await bot.gateway.guild(guild_id)
        if guild is None:
            await interaction.followup.send(STILL_LOADING, ephemeral=True)
            return
        await interaction.followup.send(embed=health_embed(await health.full_report(bot.service, guild_id, guild, document)), ephemeral=True)

    @tree.command(name="uninstall", description="Delete AltWarden's settings and every record for this server")
    @app_commands.guild_only()
    async def uninstall(interaction: discord.Interaction) -> None:
        if not await allowed(bot, interaction, "uninstall"):
            return
        document = await bot.service.get_settings(str(interaction.guild_id)) or settings_module.defaults()
        code = io.BytesIO(settings_module.export_code(document).encode())
        await interaction.response.send_message("This deletes all settings and every member record here, and can't be undone. "
                                                "The attached file holds your rules as a code. Paste it on the Rules page of a new setup to get them back. "
                                                "Roles, channels and messages aren't in it. Nothing changes if you don't answer within a minute.",
                                                file=discord.File(code, filename="altwarden-rules.txt", description="AltWarden rules code, for the Rules page"),
                                                view=UninstallView(bot, interaction.user.id), ephemeral=True)

    async def do_reset(interaction: discord.Interaction, user: discord.abc.User) -> None:
        if not await allowed(bot, interaction, "reset-user") or await ready(bot, interaction) is None:
            return
        await interaction.response.defer(ephemeral=True)
        if await refused_on_target(bot, interaction, user.id, "reset"):
            return
        result = await bot.service.reset_member(str(interaction.guild_id), str(user.id), str(interaction.user.id), interaction.user.name)
        text = f"Reset {user.mention}. " + ("They were told." if result.told else "They weren't told.")
        if result.kept_hashes:
            text += " Their hashes stay, because the account is banned."
        if result.problem:
            text += f" A role change failed: {result.problem}"
        await interaction.followup.send(text, ephemeral=True)

    async def do_lookup(interaction: discord.Interaction, user: discord.abc.User) -> None:
        if not await allowed(bot, interaction, "lookup"):
            return
        await interaction.response.defer(ephemeral=True)
        guild_id = str(interaction.guild_id)
        service = bot.service
        record = await service.db.member(guild_id, str(user.id))
        attempts = await service.db.all("SELECT at, outcome, check_id FROM attempts WHERE guild_id = ? AND user_id = ? AND outcome != 'started' ORDER BY at DESC LIMIT 8",
                                        (guild_id, str(user.id)))
        links = await service.db.all("SELECT main_id, alt_id, confidence FROM links WHERE guild_id = ? AND (main_id = ? OR alt_id = ?)", (guild_id, str(user.id), str(user.id)))
        lines = [f"**Status:** {record['status'] if record else 'no records'}"]
        lines += [f"<t:{int(row['at'])}:R> {row['outcome']}" + (f": {notices.check_name(row['check_id'])}" if row["check_id"] else "") for row in attempts]
        lines += [f"Linked: <@{row['main_id']}> main, <@{row['alt_id']}> alt ({row['confidence']})" for row in links[:12]]
        await reply(interaction, "\n".join(lines)[:1900])

    @tree.command(name="verify-user", description="Verify a member yourself")
    @app_commands.guild_only()
    @app_commands.describe(user="The member to verify, as a mention or a user ID")
    async def verify_user(interaction: discord.Interaction, user: discord.User) -> None:
        await do_verify(bot, interaction, user)

    @tree.command(name="reset-user", description="Clear a member's verification so they verify again")
    @app_commands.guild_only()
    @app_commands.describe(user="The member to reset, as a mention or a user ID. Works for people who left.")
    async def reset_user(interaction: discord.Interaction, user: discord.User) -> None:
        await do_reset(interaction, user)

    @tree.command(name="create-bypass", description="Make a link that skips the checks you choose for one member")
    @app_commands.guild_only()
    @app_commands.describe(user="The member the link is for", hours="How long the link lasts, 1 to 168 hours", notify="How the member hears about it")
    @app_commands.choices(notify=[app_commands.Choice(name="DM and channel", value="both"), app_commands.Choice(name="DM", value="dm"),
                                  app_commands.Choice(name="Channel", value="channel"), app_commands.Choice(name="Don't notify", value="none")])
    async def create_bypass(interaction: discord.Interaction, user: discord.User, hours: app_commands.Range[int, 1, 168] = 1,
                            notify: app_commands.Choice[str] | None = None) -> None:
        await do_bypass(bot, interaction, user, hours, notify.value if notify else "both")

    @tree.command(name="lookup", description="Show a member's verification history and links")
    @app_commands.guild_only()
    @app_commands.describe(user="The member to look up, as a mention or a user ID")
    async def lookup(interaction: discord.Interaction, user: discord.User) -> None:
        await do_lookup(interaction, user)

    @tree.command(name="trust-accounts", description="Mark two accounts as different people, so they stop matching")
    @app_commands.guild_only()
    @app_commands.describe(first="One of the accounts", second="The other account")
    async def trust_accounts(interaction: discord.Interaction, first: discord.User, second: discord.User) -> None:
        # After /uninstall there is no server record, and nothing would ever clean up what this writes.
        if not await allowed(bot, interaction, "trust-accounts") or await ready(bot, interaction) is None:
            return
        await interaction.response.defer(ephemeral=True)
        if await refused_on_target(bot, interaction, first.id, "trust") or await refused_on_target(bot, interaction, second.id, "trust"):
            return
        await bot.service.trust_accounts(str(interaction.guild_id), str(first.id), str(second.id), str(interaction.user.id), interaction.user.name)
        await reply(interaction, f"{first.mention} and {second.mention} won't be linked again.")

    @tree.command(name="import-members", description="Mark everyone with a role as verified, for switching from another bot")
    @app_commands.guild_only()
    @app_commands.describe(role="The role your members already hold")
    async def import_members(interaction: discord.Interaction, role: discord.Role) -> None:
        if not await allowed(bot, interaction, "import-members"):
            return
        if await ready(bot, interaction) is None:
            return

        async def done(count: int | None) -> None:
            text = "The import didn't finish. Run it again." if count is None else (
                f"Marked {count} member{'s' if count != 1 else ''} as verified. No roles were given. Anyone missing the verified role gets it by pressing Verify, with no checks.")
            try:
                await interaction.edit_original_response(content=text)
            except discord.HTTPException:
                log.info("The import's reply can't be changed any more. The log has its result.")
        await interaction.response.send_message("Importing everyone with that role. A big server takes a few minutes. This message updates when it's done, and the log says so too.", ephemeral=True)
        if not bot.start_import(interaction.guild, str(role.id), str(interaction.user.id), interaction.user.name, done):
            await interaction.edit_original_response(content="An import is already running on this server.")

    @tree.command(name="raid", description="Turn raid mode on or off")
    @app_commands.guild_only()
    @app_commands.describe(state="On, off, or see which it is now")
    @app_commands.choices(state=[app_commands.Choice(name="On", value="on"), app_commands.Choice(name="Off", value="off"),
                                 app_commands.Choice(name="Status", value="status")])
    async def raid(interaction: discord.Interaction, state: app_commands.Choice[str]) -> None:
        if not await allowed(bot, interaction, "raid"):
            return
        guild_id = str(interaction.guild_id)
        document = await ready(bot, interaction)
        if document is None:
            return
        if state.value == "status":
            active = await bot.service.raid_active(guild_id)
            await reply(interaction, "Raid mode is on." if active else "Raid mode is off.")
            return
        await interaction.response.defer(ephemeral=True)
        if state.value == "on":
            await bot.service.start_raid(guild_id, document, "Started by staff", actor_id=str(interaction.user.id), actor_name=interaction.user.name)
        else:
            await bot.service.stop_raid(guild_id, document, actor_id=str(interaction.user.id), actor_name=interaction.user.name)
        await interaction.followup.send(f"Raid mode is {state.value}.", ephemeral=True)

    @tree.command(name="my-data", description="See or delete what AltWarden holds about you")
    async def my_data(interaction: discord.Interaction) -> None:
        await interaction.response.send_message("You can see and delete your records here.",
                                                view=link_view("My data", f"{bot.service.public_url}/my-data"), ephemeral=True)

    @tree.command(name="help", description="Links to the dashboard and docs")
    async def help_command(interaction: discord.Interaction) -> None:
        url = bot.service.public_url
        await interaction.response.send_message(f"Dashboard: {url}/dashboard\nDocs: {url}/docs\nMember help: {url}/help\n"
                                                "Support and source code: https://github.com/hifihedgehog/AltWarden", ephemeral=True)

    @tree.command(name="ping", description="Show how quickly AltWarden responds")
    async def ping(interaction: discord.Interaction) -> None:
        started = time.perf_counter()
        await interaction.response.send_message("Measuring...", ephemeral=True)
        took = (time.perf_counter() - started) * 1000
        await interaction.edit_original_response(content=f"Gateway {bot.latency * 1000:.0f} ms, reply {took:.0f} ms. Version {__version__}.")

    @tree.context_menu(name="Verify")
    @app_commands.guild_only()
    async def menu_verify(interaction: discord.Interaction, user: discord.Member) -> None:
        await do_verify(bot, interaction, user)

    @tree.context_menu(name="Reset")
    @app_commands.guild_only()
    async def menu_reset(interaction: discord.Interaction, user: discord.Member) -> None:
        await do_reset(interaction, user)

    @tree.context_menu(name="Create Bypass")
    @app_commands.guild_only()
    async def menu_bypass(interaction: discord.Interaction, user: discord.Member) -> None:
        await do_bypass(bot, interaction, user)

    @tree.context_menu(name="Lookup")
    @app_commands.guild_only()
    async def menu_lookup(interaction: discord.Interaction, user: discord.Member) -> None:
        await do_lookup(interaction, user)

    @tree.error
    async def on_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        if isinstance(error, app_commands.CommandOnCooldown):
            await reply(interaction, f"Try again in {error.retry_after:.0f} seconds.")
            return
        if isinstance(getattr(error, "original", None), DiscordUnavailable):
            await reply(interaction, DISCORD_BUSY)
            return
        log.exception("Command failed", exc_info=error)
        await reply(interaction, "That command failed. Please try again.")

    # Discord keeps staff commands out of a member's list until the server changes that.
    for command in tree.get_commands():
        required = settings_module.COMMAND_DEFAULTS.get(MENU_RULES.get(command.name, command.name))
        if required:
            command.default_permissions = discord.Permissions(**dict.fromkeys(required, True))

