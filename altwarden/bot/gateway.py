"""DiscordPort on top of discord.py. Every call turns a Discord failure into a plain result, or into DiscordUnavailable where "no" and "couldn't say" lead to different actions."""
from __future__ import annotations

import asyncio
import base64
import logging
import time
from datetime import timedelta

import aiohttp
import discord
from discord.http import Route

from ..ports import DISCORD_BUSY, MEMBER_GONE, ROLE_TOO_LOW, Button, DiscordUnavailable, GuildView, MemberInfo, Notice

log = logging.getLogger("altwarden.gateway")

# discord.py raises its own errors for what Discord says, and lets connection errors through.
FAILED = (discord.HTTPException, aiohttp.ClientError, OSError, asyncio.TimeoutError)
COMMAND_LIST_SECONDS = 3600
GUILD_CACHE_SECONDS = 30
MEMBER_CACHE_SECONDS = 30
STYLES = {"primary": discord.ButtonStyle.primary, "secondary": discord.ButtonStyle.secondary,
          "success": discord.ButtonStyle.success, "danger": discord.ButtonStyle.danger, "link": discord.ButtonStyle.link}
COMMAND_PERMISSION_NAMES = {1: "role", 2: "user", 3: "channel"}
CHANNEL_TYPES = {discord.ChannelType.text: "text", discord.ChannelType.news: "news", discord.ChannelType.forum: "forum",
                 discord.ChannelType.voice: "voice", discord.ChannelType.stage_voice: "stage"}
# Discord's codes for "Cannot send messages to this user" and for an unknown role, from its opcodes and status codes topic.
CLOSED_DMS = 50007
UNKNOWN_ROLE = 10011


def style_problem(style: dict, member: dict) -> str | None:
    """Discord can answer 200 and drop a name style, so compare what it sent back with what was asked for."""
    if "display_name_styles" not in member or style["display_name_font_id"] is None:
        return None
    applied = member["display_name_styles"] or {}
    if applied.get("font_id") == style["display_name_font_id"] and applied.get("effect_id") == style["display_name_effect_id"]:
        return None
    return "Discord accepted the name style but didn't apply it. The rest was saved."


def permission_names(permissions: discord.Permissions) -> frozenset:
    """The permissions held, by Discord's names. discord.py lists View Channel under its old name, read_messages."""
    names = {name for name, value in permissions if value}
    if "read_messages" in names:
        names.add("view_channel")
    return frozenset(names)


def to_view(buttons: list[Button]) -> discord.ui.View | None:
    if not buttons:
        return None
    view = discord.ui.View(timeout=None)
    for button in buttons:
        emoji = discord.PartialEmoji.from_str(button.emoji) if button.emoji else None
        view.add_item(discord.ui.Button(label=button.label, url=button.url, custom_id=None if button.url else button.custom_id,
                                        style=STYLES.get(button.style, discord.ButtonStyle.secondary), emoji=emoji))
    return view


def to_kwargs(notice: Notice) -> dict:
    kwargs: dict = {
        "content": notice.content or None,
        "embeds": [discord.Embed.from_dict(embed) for embed in notice.embeds],
        "allowed_mentions": discord.AllowedMentions(everyone=False, replied_user=False,
                                                    roles=[discord.Object(int(role)) for role in notice.mention_roles],
                                                    users=[discord.Object(int(user)) for user in notice.mention_users]),
    }
    view = to_view(notice.buttons)
    if view is not None:
        kwargs["view"] = view
    return kwargs


class Gateway:
    def __init__(self, client: discord.Client):
        self.client = client
        self._guilds: dict[str, tuple[float, GuildView]] = {}
        self._members: dict[tuple[str, str], tuple[float, MemberInfo | None]] = {}
        self._commands: tuple[float, dict[str, str]] = (0.0, {})

    def _guild(self, guild_id: str) -> discord.Guild | None:
        return self.client.get_guild(int(guild_id))

    async def _resolve(self, guild_id: str, user_id: str, *, fresh: bool = False) -> discord.Member | None:
        guild = self._guild(guild_id)
        if guild is None:
            return None
        member = None if fresh else guild.get_member(int(user_id))
        if member is not None:
            return member
        try:
            return await guild.fetch_member(int(user_id))
        except discord.NotFound:
            return None
        except FAILED as exc:
            raise DiscordUnavailable(str(exc)) from exc

    def forget_member(self, guild_id: str, user_id: str) -> None:
        self._members.pop((guild_id, user_id), None)

    def forget_guild(self, guild_id: str) -> None:
        """A role or channel changed, which can change the server's view and what any member is allowed to do."""
        self._guilds.pop(guild_id, None)
        for key in [key for key in self._members if key[0] == guild_id]:
            del self._members[key]

    def info(self, member: discord.Member) -> MemberInfo:
        return MemberInfo(str(member.guild.id), str(member.id), member.name, member.avatar.key if member.avatar else None, member.bot,
                          tuple(str(role.id) for role in member.roles), permission_names(member.guild_permissions),
                          member.guild.owner_id == member.id, member.pending)

    async def member(self, guild_id: str, user_id: str, *, fresh: bool = False) -> MemberInfo | None:
        """Who this is in that server, or None if they aren't in it. Raises DiscordUnavailable if Discord can't say.

        discord.py's copy comes first, because the gateway keeps it current. An answer fetched earlier spares a
        call for those outside that copy. `fresh` asks Discord itself, for a decision that shouldn't rest on either.
        """
        guild = self._guild(guild_id)
        if guild is None or guild.unavailable:
            # Discord hasn't handed the server over, so its members have no roles yet. Nothing from this moment is worth keeping.
            if guild is not None or not self.client.is_ready():
                raise DiscordUnavailable("still loading")
            return None
        key = (guild_id, user_id)
        if not fresh:
            live = guild.get_member(int(user_id))
            if live is not None:
                return self.info(live)
            cached = self._members.get(key)
            if cached and time.monotonic() - cached[0] < MEMBER_CACHE_SECONDS:
                return cached[1]
        member = await self._resolve(guild_id, user_id, fresh=fresh)
        info = self.info(member) if member else None
        self._members[key] = (time.monotonic(), info)
        if len(self._members) > 20000:
            self._members.clear()
        return info

    async def guild(self, guild_id: str) -> GuildView | None:
        cached = self._guilds.get(guild_id)
        if cached and time.monotonic() - cached[0] < GUILD_CACHE_SECONDS:
            return cached[1]
        guild = self._guild(guild_id)
        if guild is None or guild.unavailable or guild.me is None:
            return None
        me = guild.me
        view = GuildView(
            id=str(guild.id), name=guild.name, icon=guild.icon.key if guild.icon else None, owner_id=str(guild.owner_id),
            member_count=guild.member_count or 0,
            roles=[{"id": str(role.id), "name": role.name, "color": role.color.value, "position": role.position,
                    "managed": role.managed, "mentionable": role.mentionable} for role in reversed(guild.roles)],
            channels=[{"id": str(channel.id), "name": channel.name, "type": CHANNEL_TYPES.get(channel.type, "other"),
                       "category": channel.category.name if channel.category else None, "position": channel.position}
                      for channel in guild.channels if channel.type in CHANNEL_TYPES],
            bot_permissions=permission_names(me.guild_permissions), bot_top_role=me.top_role.position,
            channel_permissions={str(channel.id): permission_names(channel.permissions_for(me)) for channel in guild.channels},
            bot_top_role_id=str(me.top_role.id),
            public_channels=[str(channel.id) for channel in guild.channels
                             if channel.type in CHANNEL_TYPES and channel.permissions_for(guild.default_role).view_channel],
        )
        self._guilds[guild_id] = (time.monotonic(), view)
        return view

    def guild_ids(self) -> list[str]:
        """Every server the bot is in, the newest arrival first."""
        def arrived(guild: discord.Guild) -> float:
            me = guild.me
            return me.joined_at.timestamp() if me is not None and me.joined_at else 0
        return [str(guild.id) for guild in sorted(self.client.guilds, key=arrived, reverse=True)]

    async def guild_loading(self, guild_id: str) -> bool:
        """Discord hasn't handed this server over yet: the bot is starting, or the server is in an outage."""
        guild = self._guild(guild_id)
        return not self.client.is_ready() or (guild is not None and guild.unavailable)

    async def add_role(self, guild_id: str, user_id: str, role_id: str, reason: str) -> str | None:
        return await self._role(guild_id, user_id, role_id, reason, add=True)

    async def remove_role(self, guild_id: str, user_id: str, role_id: str, reason: str) -> str | None:
        return await self._role(guild_id, user_id, role_id, reason, add=False)

    async def _role(self, guild_id: str, user_id: str, role_id: str, reason: str, *, add: bool) -> str | None:
        guild = self._guild(guild_id)
        if guild is None:
            return "AltWarden isn't in that server." if self.client.is_ready() else DISCORD_BUSY
        if guild.unavailable:  # it has no roles yet, which mustn't read as the role having been deleted
            return DISCORD_BUSY
        role = guild.get_role(int(role_id or 0))
        if role is None:
            return "That role no longer exists."
        try:
            member = await self._resolve(guild_id, user_id)
        except DiscordUnavailable:
            return DISCORD_BUSY
        if member is None:
            return MEMBER_GONE
        if guild.me is not None and role >= guild.me.top_role:
            return ROLE_TOO_LOW
        try:
            if add:
                await member.add_roles(role, reason=reason)
            else:
                await member.remove_roles(role, reason=reason)
        except discord.Forbidden:
            return "AltWarden needs Manage Roles, and its role must sit above the role it gives."
        except discord.NotFound as exc:  # they left, or someone deleted the role, since the checks above
            return "That role no longer exists." if exc.code == UNKNOWN_ROLE else MEMBER_GONE
        except discord.HTTPException as exc:
            return f"Discord refused the role change ({exc.status})."
        except FAILED:
            return DISCORD_BUSY
        self.forget_member(guild_id, user_id)
        return None

    async def kick(self, guild_id: str, user_id: str, reason: str) -> bool:
        guild = self._guild(guild_id)
        try:
            await guild.kick(discord.Object(int(user_id)), reason=reason)
            self.forget_member(guild_id, user_id)
            return True
        except discord.NotFound:
            self.forget_member(guild_id, user_id)
            return True  # they already left, which is the outcome that was wanted
        except (*FAILED, AttributeError) as exc:
            log.warning("Kick failed in %s: %s", guild_id, exc)
            return False

    async def ban(self, guild_id: str, user_id: str, reason: str, delete_seconds: int = 0) -> bool:
        guild = self._guild(guild_id)
        try:
            await guild.ban(discord.Object(int(user_id)), reason=reason, delete_message_seconds=delete_seconds)
            self.forget_member(guild_id, user_id)
            return True
        except (*FAILED, AttributeError) as exc:
            log.warning("Ban failed in %s: %s", guild_id, exc)
            return False

    async def unban(self, guild_id: str, user_id: str, reason: str) -> bool:
        guild = self._guild(guild_id)
        try:
            await guild.unban(discord.Object(int(user_id)), reason=reason)
            return True
        except discord.NotFound:
            return True  # there's no ban to lift, which is the outcome that was wanted
        except (*FAILED, AttributeError):
            return False

    async def timeout(self, guild_id: str, user_id: str, minutes: int, reason: str) -> bool:
        try:
            member = await self._resolve(guild_id, user_id)
            if member is None:
                return False
            await member.timeout(timedelta(minutes=minutes), reason=reason)
            return True
        except (*FAILED, DiscordUnavailable):
            return False

    async def clear_timeout(self, guild_id: str, user_id: str, reason: str) -> bool:
        try:
            member = await self._resolve(guild_id, user_id)
            if member is None:
                return False
            await member.timeout(None, reason=reason)
            return True
        except (*FAILED, DiscordUnavailable):
            return False

    async def is_banned(self, guild_id: str, user_id: str) -> bool:
        """Whether Discord has this ban. Raises DiscordUnavailable if it can't say, because a "no" clears AltWarden's own ban record."""
        guild = self._guild(guild_id)
        if guild is None:
            raise DiscordUnavailable("that server isn't loaded")
        try:
            await guild.fetch_ban(discord.Object(int(user_id)))
            return True
        except discord.NotFound:
            return False
        except FAILED as exc:  # a 403 means AltWarden has no Ban Members, which says nothing about the ban
            raise DiscordUnavailable(str(exc)) from exc

    async def dm(self, user_id: str, notice: Notice) -> bool | None:
        """True delivered, False their DMs are closed, None any other failure, which a member can't fix by opening them."""
        try:
            user = self.client.get_user(int(user_id)) or await self.client.fetch_user(int(user_id))
            await user.send(**to_kwargs(notice))
            return True
        except discord.HTTPException as exc:
            return False if exc.code == CLOSED_DMS else None
        except FAILED:
            return None

    def _channel(self, channel_id: str):
        return self.client.get_channel(int(channel_id))

    async def send(self, channel_id: str, notice: Notice, *, guild_id: str | None = None) -> str | None:
        """Post in a channel. With guild_id, only if the channel is in that server, because the lookup covers every server."""
        channel = self._channel(channel_id)
        if channel is None:
            return None
        if guild_id is not None and str(getattr(channel, "guild", None) and channel.guild.id) != guild_id:
            log.warning("Refused to post in a channel outside server %s", guild_id)
            return None
        try:
            message = await channel.send(delete_after=notice.delete_after, **to_kwargs(notice))
            return str(message.id)
        except (*FAILED, AttributeError) as exc:  # a forum or category channel has no send
            log.warning("Couldn't post in %s: %s", channel_id, exc)
            return None

    async def delete_message(self, channel_id: str, message_id: str) -> bool:
        channel = self._channel(channel_id)
        if channel is None:
            return False
        try:
            await channel.get_partial_message(int(message_id)).delete()
            return True
        except discord.NotFound:
            return True  # someone else deleted it first, which is the outcome that was wanted
        except (*FAILED, AttributeError):
            return False

    async def edit_message(self, channel_id: str, message_id: str, notice: Notice) -> bool:
        channel = self._channel(channel_id)
        if channel is None:
            return False
        kwargs = to_kwargs(notice)
        kwargs.setdefault("view", None)
        try:
            await channel.get_partial_message(int(message_id)).edit(**kwargs)
            return True
        except (*FAILED, AttributeError):
            return False

    async def pin(self, channel_id: str, message_id: str) -> bool:
        channel = self._channel(channel_id)
        if channel is None:
            return False
        try:
            await channel.get_partial_message(int(message_id)).pin()
            return True
        except (*FAILED, AttributeError):
            return False

    async def open_help_thread(self, channel_id: str, name: str, user_id: str, role_id: str | None, notice: Notice, *, guild_id: str | None = None) -> str | None:
        channel = self._channel(channel_id)
        if not isinstance(channel, discord.TextChannel) or (guild_id is not None and str(channel.guild.id) != guild_id):
            return None
        thread = None
        try:
            thread = await channel.create_thread(name=name[:90] or "Help", type=discord.ChannelType.private_thread, invitable=False,
                                                 auto_archive_duration=10080, reason="Help desk")
            await thread.add_user(discord.Object(int(user_id)))
            ping = f"<@{user_id}>" + (f" <@&{role_id}>" if role_id else "")
            notice.content = f"{ping}\n{notice.content}".strip()[:2000]
            notice.mention_users = [user_id]
            notice.mention_roles = [role_id] if role_id else []
            message = await thread.send(**to_kwargs(notice))
            try:
                await message.pin()
            except FAILED:
                pass
            return str(thread.id)
        except FAILED as exc:
            log.warning("Couldn't open a help thread: %s", exc)
            if thread is not None:  # or each press of the button would leave another empty thread behind
                try:
                    await thread.delete(reason="Help desk: the first post failed")
                except FAILED as second:
                    log.warning("Couldn't delete an empty help thread: %s", second)
            return None

    async def _thread(self, thread_id: str):
        """The thread, or None if it's gone. Archived threads aren't in the cache, so a miss goes to Discord first. Raises DiscordUnavailable if it can't say."""
        thread = self.client.get_channel(int(thread_id))
        if thread is None:
            try:
                thread = await self.client.fetch_channel(int(thread_id))
            except (discord.NotFound, discord.Forbidden):
                return None
            except FAILED as exc:
                raise DiscordUnavailable(str(exc)) from exc
        return thread

    async def reopen_thread(self, thread_id: str, user_id: str | None = None) -> bool:
        """Make sure a member's thread can be used, with them in it, since leaving the server may have taken them out.

        False means it's gone, or locked so the member couldn't post in it. A failure that says neither raises
        DiscordUnavailable, so a blip can't cost the member the thread they have.
        """
        thread = await self._thread(thread_id)
        if thread is None or thread.locked:
            return False
        try:
            if thread.archived:
                await thread.edit(archived=False)
            if user_id:  # after unarchiving, because adding someone needs the thread open
                await thread.add_user(discord.Object(int(user_id)))
            return True
        except (discord.NotFound, discord.Forbidden):
            return False
        except FAILED as exc:
            raise DiscordUnavailable(str(exc)) from exc

    async def close_thread(self, thread_id: str) -> bool:
        try:
            thread = await self._thread(thread_id)
        except DiscordUnavailable:
            return False
        if thread is None:
            return False
        try:
            if thread.archived:
                if thread.locked:
                    return True  # already closed
                await thread.edit(archived=False)  # Discord refuses an edit to an archived thread unless the edit unarchives it
            await thread.edit(archived=True, locked=True)
            return True
        except FAILED:
            return False

    async def apply_profile(self, guild_id: str, profile: dict, style: dict | None = None) -> str | None:
        """Per-server profile through Discord's Modify Current Member endpoint.

        Only changed fields go out, because sending a name at all needs Change Nickname. A name style
        goes in its own request. Its fields aren't in Discord's public reference, so a refusal there
        mustn't cost the rest of the save.
        """
        route = Route("PATCH", "/guilds/{guild_id}/members/@me", guild_id=guild_id)
        body = dict(profile)
        if isinstance(body.get("avatar"), bytes):
            body["avatar"] = "data:image/png;base64," + base64.b64encode(body["avatar"]).decode()
        if body:
            try:
                await self.client.http.request(route, json=body)
            except discord.Forbidden:
                return "AltWarden needs Change Nickname for a custom name."
            except discord.HTTPException as exc:
                return f"Discord refused the change ({exc.status})."
            except FAILED:
                return "Discord didn't answer, so the profile wasn't changed. Save again in a moment."
        self._guilds.pop(guild_id, None)
        if style is None:
            return None
        try:
            return style_problem(style, await self.client.http.request(route, json=style))
        except discord.Forbidden:
            return "AltWarden needs Change Nickname for a name style."
        except discord.HTTPException as exc:
            return f"Discord refused the name style ({exc.status}). The rest was saved."
        except FAILED:
            return "Discord didn't answer, so the name style wasn't changed. The rest was saved."

    async def _command_ids(self, application_id: int) -> dict[str, str]:
        """Every command's name and ID. They only change when the bot starts, so an hour's cache is plenty."""
        fetched, names = self._commands
        if not names or time.monotonic() - fetched > COMMAND_LIST_SECONDS:
            rows = await self.client.http.get_global_commands(application_id)
            names = {row["name"]: str(row["id"]) for row in rows}
            self._commands = (time.monotonic(), names)
        return names

    async def command_permissions(self, guild_id: str) -> dict | None:
        """Discord's own overrides for each command in this server, the ones Server Settings, Integrations edits."""
        application_id = self.client.application_id
        if application_id is None or self._guild(guild_id) is None:
            return None
        try:
            names = await self._command_ids(application_id)
            rows = await self.client.http.get_guild_application_command_permissions(application_id, int(guild_id))
        except FAILED as exc:
            log.warning("Couldn't read command permissions in %s: %s", guild_id, exc)
            return None
        found = {str(row["id"]): row["permissions"] for row in rows}

        def overrides(command_id: str) -> list[dict]:
            return [{"type": COMMAND_PERMISSION_NAMES[entry["type"]], "id": str(entry["id"]), "allow": bool(entry["permission"])}
                    for entry in found.get(command_id, []) if entry["type"] in COMMAND_PERMISSION_NAMES]
        return {"application": str(application_id), "all": overrides(str(application_id)),
                "commands": [{"name": name, "id": command_id, "overrides": overrides(command_id)} for name, command_id in sorted(names.items())]}
