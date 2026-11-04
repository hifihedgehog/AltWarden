"""The Discord client: events, slash commands, buttons, and the timers."""
from __future__ import annotations

import asyncio
import logging
import time

import discord
from discord import app_commands
from discord.ext import tasks

from .. import __version__, access, health, notices, settings as settings_module
from ..catalog import BY_ID, CHECK_IDS
from ..engine import bypass_options
from ..service import Result, Service
from .gateway import FAILED, Gateway

log = logging.getLogger("altwarden.bot")

GREEN, RED, TEAL = notices.GREEN, notices.RED, notices.TEAL
BYPASS_HOURS = (1, 6, 12, 24, 48, 72, 168)
CATCH_UP_MARGIN = 120  # the last-online time is written once a minute, so look a little further back
CATCH_UP_RETRY_SECONDS = 300
BYPASS_NOTIFY = (("both", "DM and channel"), ("dm", "DM"), ("channel", "Channel"), ("none", "Don't notify"))


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
        self._catch_up_task: asyncio.Task | None = None
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
            if await self.service.db.guild(str(guild.id)) is None:
                await self.service.db.save_settings(str(guild.id), settings_module.defaults(), setup_done=False)
            await self.service.db.set_guild_field(str(guild.id), "left_at", None)
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
        if not self.synced:
            await self.tree.sync()
            self.synced = True

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

    async def close(self) -> None:
        self.minute_timer.cancel()  # first, so the last-online time can't move past a walk that's being cut short
        self.hour_timer.cancel()
        if self._catch_up_task is not None:
            self._catch_up_task.cancel()
        await super().close()

    @tasks.loop(minutes=1)
    async def minute_timer(self) -> None:
        try:
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
            if self.service.net.stale():
                changed = await self.service.net.refresh()
                log.info("Refreshed %d network lists", changed)
        except Exception:
            log.exception("Hour timer failed")

    @minute_timer.before_loop
    @hour_timer.before_loop
    async def _wait(self) -> None:
        await self.wait_until_ready()

    # --- events -----------------------------------------------------------------------------

    async def on_guild_join(self, guild: discord.Guild) -> None:
        log.info("Joined %s", guild.id)
        if await self.service.db.guild(str(guild.id)) is None:
            await self.service.db.save_settings(str(guild.id), settings_module.defaults(), setup_done=False)
        await self.service.db.set_guild_field(str(guild.id), "left_at", None)

    async def on_guild_remove(self, guild: discord.Guild) -> None:
        """Records stay for a while, so a server that removed the bot by mistake loses nothing. Then they go."""
        log.info("Left %s", guild.id)
        await self.service.db.set_guild_field(str(guild.id), "left_at", time.time())

    async def on_member_join(self, member: discord.Member) -> None:
        await self.service.on_join(self.gateway.info(member))

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
        if settings is None or not settings["honeypot"]["enabled"]:
            return
        trap = settings["honeypot"]["channel"]
        parent = getattr(message.channel, "parent_id", None)
        if trap not in (str(message.channel.id), str(parent)):
            return
        roles = tuple(str(role.id) for role in getattr(message.author, "roles", ()))
        await self.service.honeypot_hit(str(message.guild.id), str(message.author.id), message.author.name, str(message.channel.id),
                                        str(message.id), role_ids=roles, is_webhook=message.webhook_id is not None,
                                        parent_id=str(parent) if parent else None)

    async def on_interaction(self, interaction: discord.Interaction) -> None:
        if interaction.type is not discord.InteractionType.component:
            return
        custom_id = (interaction.data or {}).get("custom_id", "")
        if not custom_id.startswith("aw:") or interaction.guild is None:
            return
        try:
            if custom_id == "aw:verify":
                await self._press_verify(interaction)
            elif custom_id == "aw:help":
                await self._press_help(interaction)
            elif custom_id == "aw:help:close":
                await self._press_close(interaction)
            elif custom_id.startswith("aw:appeal:"):
                await self._press_appeal(interaction, custom_id)
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
        settings = await self.service.get_settings(str(interaction.guild.id))
        viewer = viewer_of(self.gateway.info(interaction.user))
        if not access.allowed(settings_module.page_rule(settings, "appeals", "edit"), viewer):
            await reply(interaction, "You don't have access to appeals.")
            return
        await interaction.response.defer(ephemeral=True)
        problem = await self.service.decide_appeal(str(interaction.guild.id), int(appeal_id), decision, str(interaction.user.id), interaction.user.name,
                                                   can_unban=viewer.is_admin or "ban_members" in viewer.permissions)
        await interaction.followup.send(problem or "Done.", ephemeral=True)

    # --- posting ----------------------------------------------------------------------------

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


def link_view(label: str, url: str) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(discord.ui.Button(label=label, url=url, style=discord.ButtonStyle.link))
    return view


def result_embed(result: Result) -> discord.Embed:
    color = GREEN if result.status in ("verified", "already") else RED
    return discord.Embed(title=result.title, description=result.discord_text(), color=color)


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


async def allowed(bot: AltWardenBot, interaction: discord.Interaction, command: str) -> bool:
    """Discord's list only decides who sees a command. This rule decides who can run it."""
    document = await bot.service.get_settings(str(interaction.guild_id)) or settings_module.defaults()
    viewer = viewer_of(bot.gateway.info(interaction.user))
    if access.allowed(settings_module.command_rule(document, command), viewer, str(interaction.channel_id)):
        return True
    await reply(interaction, "You don't have access to this command.")
    return False


async def ready(bot: AltWardenBot, interaction: discord.Interaction) -> dict | None:
    """This server's settings, or None after telling the member that setup comes first."""
    guild_id = str(interaction.guild_id)
    if await bot.service.is_set_up(guild_id):
        return await bot.service.get_settings(guild_id)
    await reply(interaction, "This server isn't set up yet. Run /setup first.")
    return None


class BypassView(discord.ui.View):
    """Pick what one member's link skips, how they hear about it, and how long it lasts."""

    def __init__(self, bot: AltWardenBot, user: discord.abc.User, options: list[str], hours: int, notify: str):
        super().__init__(timeout=300)
        self.bot, self.user, self.hours, self.notify = bot, user, hours, notify
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
        await interaction.response.defer(ephemeral=True)
        url, told = await self.bot.service.create_bypass(
            str(interaction.guild_id), str(self.user.id), self.choice, self.hours, self.notify, str(interaction.user.id),
            interaction.user.name, str(interaction.channel_id))
        text = f"Link created for {self.user.mention}, good for {self.hours} hour{'s' if self.hours != 1 else ''}. "
        text += "They were told." if told else "They weren't told, so send it to them yourself."
        await interaction.followup.send(f"{text}\n{url}", ephemeral=True)  # Only staff see this reply, and it's the one place the link exists.
        self.stop()


class UninstallView(discord.ui.View):
    def __init__(self, bot: AltWardenBot, actor_id: int):
        super().__init__(timeout=60)
        self.bot, self.actor_id = bot, actor_id

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.actor_id

    @discord.ui.button(label="Delete everything", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await interaction.response.defer(ephemeral=True)
        guild_id = str(interaction.guild_id)
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
        document = await bot.service.get_settings(guild_id) or settings_module.defaults()
        document = {**document, "core": {**document["core"], "verified_role": str(role.id), "channel": str(channel.id)}}
        await bot.service.save_settings(guild_id, document, actor_id=str(interaction.user.id), actor_name=interaction.user.name, setup_done=True)
        if not await bot.post_message(guild_id, "verification"):
            await interaction.followup.send(f"Saved, but AltWarden couldn't post in {channel.mention}. Give it View Channel, Send Messages and Embed Links there, "
                                            "then run /post-message.", ephemeral=True)
            return
        await interaction.followup.send(f"Done. Verification is on in {channel.mention}, using the Standard rules.\n"
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
        lines = [f"**Mode:** {core['mode']}", f"**Rules:** {document['preset'].title()}",
                 f"**Verified role:** <@&{core['verified_role']}>" if core["verified_role"] else "**Verified role:** not set",
                 f"**Channel:** <#{core['channel']}>" if core["channel"] else "**Channel:** not set"]
        for check_id in CHECK_IDS:
            check = document["checks"][check_id]
            if check["enabled"]:
                lines.append(f"{BY_ID[check_id].name}: {check['action']}")
        await interaction.response.send_message(embed=discord.Embed(title="AltWarden settings", description="\n".join(lines), color=TEAL))

    @tree.command(name="post-message", description="Post a message again in its channel")
    @app_commands.guild_only()
    @app_commands.describe(message="Which message to post")
    @app_commands.choices(message=[app_commands.Choice(name="Verification message", value="verification"),
                                   app_commands.Choice(name="Honeypot warning", value="honeypot")])
    async def post_message(interaction: discord.Interaction, message: app_commands.Choice[str]) -> None:
        if not await allowed(bot, interaction, "post-message") or await ready(bot, interaction) is None:
            return
        await interaction.response.defer(ephemeral=True)
        posted = await bot.post_message(str(interaction.guild_id), message.value)
        await interaction.followup.send("Posted." if posted else "Couldn't post it. Pick a channel on the dashboard, then run /health.", ephemeral=True)

    @tree.command(name="health", description="Find what would stop members from verifying")
    @app_commands.guild_only()
    @app_commands.checks.cooldown(1, 60, key=lambda i: (i.guild_id, i.user.id))
    async def health_command(interaction: discord.Interaction) -> None:
        if not await allowed(bot, interaction, "health"):
            return
        await interaction.response.defer(ephemeral=True)
        guild_id = str(interaction.guild_id)
        document = await bot.service.get_settings(guild_id) or settings_module.defaults()
        data = health.report(await bot.gateway.guild(guild_id), document)
        if data["healthy"]:
            text = "Everything AltWarden needs is in place."
        else:
            text = "\n".join(f"**{issue['title']}**\n{issue['fix']}" for issue in data["issues"][:10])
        if data["advice"]:
            text += f"\n\n{data['advice']}"
        await interaction.followup.send(embed=discord.Embed(title="Health check", description=text, color=GREEN if data["healthy"] else RED), ephemeral=True)

    @tree.command(name="uninstall", description="Delete AltWarden's settings and every record for this server")
    @app_commands.guild_only()
    async def uninstall(interaction: discord.Interaction) -> None:
        if not await allowed(bot, interaction, "uninstall"):
            return
        await interaction.response.send_message("This deletes all settings and every member record here, and can't be undone. "
                                                "To keep your rules, copy them from the Rules page first. Nothing changes if you don't answer within a minute.",
                                                view=UninstallView(bot, interaction.user.id), ephemeral=True)

    async def do_verify(interaction: discord.Interaction, user: discord.abc.User) -> None:
        if not await allowed(bot, interaction, "verify-user") or await ready(bot, interaction) is None:
            return
        if user.bot:
            await reply(interaction, "Bots don't verify.")
            return
        await interaction.response.defer(ephemeral=True)
        problem = await bot.service.manual_verify(str(interaction.guild_id), str(user.id), str(interaction.user.id), interaction.user.name)
        await interaction.followup.send(problem or f"{user.mention} is verified.", ephemeral=True)

    async def do_reset(interaction: discord.Interaction, user: discord.abc.User) -> None:
        if not await allowed(bot, interaction, "reset-user") or await ready(bot, interaction) is None:
            return
        await interaction.response.defer(ephemeral=True)
        told = await bot.service.reset_member(str(interaction.guild_id), str(user.id), str(interaction.user.id), interaction.user.name)
        await interaction.followup.send(f"Reset {user.mention}. " + ("They were told." if told else "They weren't told."), ephemeral=True)

    async def do_bypass(interaction: discord.Interaction, user: discord.abc.User, hours: int = 1, notify: str = "both") -> None:
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
        if document["core"]["verified_role"] in member.role_ids:
            await reply(interaction, "That member is already verified. Reset them first if they should verify again.")
            return
        options = bypass_options(document)
        if not options:
            await reply(interaction, "No checks are on, so there is nothing to skip.")
            return
        await interaction.followup.send(f"Choose what {user.mention}'s link skips.", view=BypassView(bot, user, options, hours, notify), ephemeral=True)

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
        await do_verify(interaction, user)

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
        await do_bypass(interaction, user, hours, notify.value if notify else "both")

    @tree.command(name="lookup", description="Show a member's verification history and links")
    @app_commands.guild_only()
    @app_commands.describe(user="The member to look up, as a mention or a user ID")
    async def lookup(interaction: discord.Interaction, user: discord.User) -> None:
        await do_lookup(interaction, user)

    @tree.command(name="trust-accounts", description="Mark two accounts as different people, so they stop matching")
    @app_commands.guild_only()
    @app_commands.describe(first="One of the accounts", second="The other account")
    async def trust_accounts(interaction: discord.Interaction, first: discord.User, second: discord.User) -> None:
        if not await allowed(bot, interaction, "trust-accounts"):
            return
        await interaction.response.defer(ephemeral=True)
        guild_id = str(interaction.guild_id)
        await bot.service.db.trust_pair(guild_id, str(first.id), str(second.id), str(interaction.user.id))
        await bot.service.db.add_audit(guild_id, "trust", actor_id=str(interaction.user.id), actor_name=interaction.user.name,
                                       detail={"first": str(first.id), "second": str(second.id)})
        await reply(interaction, f"{first.mention} and {second.mention} won't be linked again.")

    @tree.command(name="import-members", description="Mark everyone with a role as verified, for switching from another bot")
    @app_commands.guild_only()
    @app_commands.describe(role="The role your members already hold")
    async def import_members(interaction: discord.Interaction, role: discord.Role) -> None:
        if not await allowed(bot, interaction, "import-members") or await ready(bot, interaction) is None:
            return
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        # Over REST, because discord.py doesn't notice when Discord rate limits a gateway request for the list, and would wait forever.
        members = [str(member.id) async for member in guild.fetch_members(limit=None) if not member.bot and (role.is_default() or member.get_role(role.id) is not None)]
        count = await bot.service.import_members(str(guild.id), members, str(interaction.user.id), interaction.user.name)
        await interaction.followup.send(f"Marked {count} members as verified. They won't be asked to verify.", ephemeral=True)

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
            await bot.service.start_raid(guild_id, document, "Started by staff", actor_id=str(interaction.user.id))
        else:
            await bot.service.stop_raid(guild_id, document, actor_id=str(interaction.user.id))
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
        await do_verify(interaction, user)

    @tree.context_menu(name="Reset")
    @app_commands.guild_only()
    async def menu_reset(interaction: discord.Interaction, user: discord.Member) -> None:
        await do_reset(interaction, user)

    @tree.context_menu(name="Create Bypass")
    @app_commands.guild_only()
    async def menu_bypass(interaction: discord.Interaction, user: discord.Member) -> None:
        await do_bypass(interaction, user)

    @tree.context_menu(name="Lookup")
    @app_commands.guild_only()
    async def menu_lookup(interaction: discord.Interaction, user: discord.Member) -> None:
        await do_lookup(interaction, user)

    @tree.error
    async def on_error(interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        if isinstance(error, app_commands.CommandOnCooldown):
            await reply(interaction, f"Try again in {error.retry_after:.0f} seconds.")
            return
        log.exception("Command failed", exc_info=error)
        await reply(interaction, "That command failed. Please try again.")

    # Discord keeps staff commands out of a member's list until the server changes that.
    for command in tree.get_commands():
        required = settings_module.COMMAND_DEFAULTS.get(MENU_RULES.get(command.name, command.name))
        if required:
            command.default_permissions = discord.Permissions(**dict.fromkeys(required, True))

