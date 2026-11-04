"""The boundary between AltWarden's logic and Discord.

The service layer calls this interface and never touches discord.py, so every rule can be tested
without a live connection. `bot/gateway.py` is the real implementation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

# add_role returns this text when the role sits above the bot, so members can get the matching help.
ROLE_TOO_LOW = "AltWarden's role sits below that role. Drag it higher in Server Settings."
# And this one when the member has left, which is different news from a broken role.
MEMBER_GONE = "That member isn't in the server."


class DiscordUnavailable(Exception):
    """Discord couldn't answer, which says nothing about whether a member is there."""


@dataclass
class MemberInfo:
    guild_id: str
    user_id: str
    username: str = ""
    avatar: str | None = None
    is_bot: bool = False
    role_ids: tuple = ()
    permissions: frozenset = frozenset()
    is_owner: bool = False


@dataclass
class Button:
    label: str
    url: str | None = None
    custom_id: str | None = None
    style: str = "secondary"
    emoji: str | None = None


@dataclass
class Notice:
    """A message in Discord's terms, kept free of any library types."""

    content: str = ""
    embeds: list = field(default_factory=list)
    buttons: list = field(default_factory=list)
    mention_roles: list = field(default_factory=list)
    mention_users: list = field(default_factory=list)
    delete_after: float | None = None


@dataclass
class GuildView:
    """What the dashboard and health report need to know about a server."""

    id: str
    name: str = ""
    icon: str | None = None
    owner_id: str | None = None
    member_count: int = 0
    roles: list = field(default_factory=list)      # {id, name, color, position, managed, mentionable}
    channels: list = field(default_factory=list)   # {id, name, type, category, position}
    bot_permissions: frozenset = frozenset()
    bot_top_role: int = 0
    channel_permissions: dict = field(default_factory=dict)


class DiscordPort(Protocol):
    async def member(self, guild_id: str, user_id: str) -> MemberInfo | None: ...
    async def guild(self, guild_id: str) -> GuildView | None: ...
    async def guild_loading(self, guild_id: str) -> bool: ...
    async def add_role(self, guild_id: str, user_id: str, role_id: str, reason: str) -> str | None: ...
    async def remove_role(self, guild_id: str, user_id: str, role_id: str, reason: str) -> str | None: ...
    async def kick(self, guild_id: str, user_id: str, reason: str) -> bool: ...
    async def ban(self, guild_id: str, user_id: str, reason: str, delete_seconds: int = 0) -> bool: ...
    async def unban(self, guild_id: str, user_id: str, reason: str) -> bool: ...
    async def timeout(self, guild_id: str, user_id: str, minutes: int, reason: str) -> bool: ...
    async def is_banned(self, guild_id: str, user_id: str) -> bool: ...
    async def dm(self, user_id: str, notice: Notice) -> bool: ...
    async def send(self, channel_id: str, notice: Notice, *, guild_id: str | None = None) -> str | None: ...
    async def delete_message(self, channel_id: str, message_id: str) -> bool: ...
    async def edit_message(self, channel_id: str, message_id: str, notice: Notice) -> bool: ...
    async def pin(self, channel_id: str, message_id: str) -> bool: ...
    async def open_help_thread(self, channel_id: str, name: str, user_id: str, role_id: str | None, notice: Notice, *, guild_id: str | None = None) -> str | None: ...
    async def reopen_thread(self, thread_id: str) -> bool: ...
    async def close_thread(self, thread_id: str) -> bool: ...
    async def apply_profile(self, guild_id: str, profile: dict, style: dict | None = None) -> str | None: ...
    async def command_permissions(self, guild_id: str) -> dict | None: ...
