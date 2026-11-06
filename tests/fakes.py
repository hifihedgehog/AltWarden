"""A fake Discord for tests: records what the service asked for and answers like the real API."""
from __future__ import annotations

import asyncio

from aiohttp import web

from altwarden.ports import DiscordUnavailable, GuildView, MemberInfo, Notice

GUILD = "970000000000000001"
VERIFIED_ROLE = "970000000000000002"
UNVERIFIED_ROLE = "970000000000000003"
CHANNEL = "970000000000000004"
LOG_CHANNEL = "970000000000000005"
DB_KEY = "ab" * 32  # what Keyring.database_key would give, for test databases only
OLD_USER = "175928847299117063"   # a 2016 account
OTHER_USER = "175928847299117064"
STAFF = "175928847299117065"


class FakePort:
    def __init__(self) -> None:
        self.members: dict[tuple[str, str], MemberInfo] = {}
        self.calls: list[tuple] = []
        self.dms: list[tuple[str, Notice]] = []
        self.sent: list[tuple[str, Notice]] = []
        self.banned: set = set()
        self.dm_open = True          # False is closed DMs, the one failure a member can fix
        self.dm_fails = False        # any other failure, where dm answers None
        self.role_problem: str | None = None
        self.role_refusals: dict[str, str] = {}  # one role's problem, for adds and removes
        self.kick_works = True
        self.ban_works = True
        self.unban_works = True
        self.timeout_works = True
        self.close_works = True
        self.discord_down = False
        self.next_message = 1000
        self.threads: list[Notice] = []
        self.loading = False
        self.absent = False
        self.thread_open = True
        self.delete_works = True
        self.channel_posts_work = True
        self.extra_roles: list = []
        self.extra_channels: list = []
        self.profile_problem = None
        self.discord_commands = {"application": "123", "all": [], "commands": [
            {"name": "verify-user", "id": "900000000000000001", "overrides": []},
            {"name": "Verify", "id": "900000000000000002", "overrides": [{"type": "role", "id": VERIFIED_ROLE, "allow": False}]}]}

    def add_member(self, user_id: str, *, username: str = "someone", avatar: str | None = "abc", roles: tuple = (), perms: tuple = (),
                   owner: bool = False, bot: bool = False, pending: bool = False) -> MemberInfo:
        info = MemberInfo(GUILD, user_id, username, avatar, bot, roles, frozenset(perms), owner, pending)
        self.members[(GUILD, user_id)] = info
        return info

    def did(self, name: str) -> list[tuple]:
        return [call for call in self.calls if call[0] == name]

    def forget_member(self, guild_id, user_id):
        pass

    def forget_guild(self, guild_id):
        pass

    async def member(self, guild_id, user_id, *, fresh=False):
        if fresh:
            self.calls.append(("fresh_member", user_id))
        if self.discord_down:
            raise DiscordUnavailable("down")
        return self.members.get((guild_id, user_id))

    def guild_ids(self):
        return [] if self.absent else [GUILD]

    async def guild_loading(self, guild_id):
        return self.loading

    async def guild(self, guild_id):
        if guild_id != GUILD or self.absent:
            return None
        return GuildView(id=GUILD, name="Test Server", icon=None, owner_id=STAFF, member_count=10,
                         roles=[{"id": VERIFIED_ROLE, "name": "Verified", "color": 0, "position": 2, "managed": False, "mentionable": False},
                                {"id": UNVERIFIED_ROLE, "name": "Unverified", "color": 0, "position": 1, "managed": False, "mentionable": False},
                                *self.extra_roles],
                         channels=[{"id": CHANNEL, "name": "verify", "type": "text", "category": None, "position": 0},
                                   {"id": LOG_CHANNEL, "name": "logs", "type": "text", "category": None, "position": 1},
                                   *self.extra_channels],
                         bot_permissions=frozenset({"manage_roles", "kick_members", "ban_members"}), bot_top_role=5,
                         channel_permissions={CHANNEL: frozenset({"view_channel", "send_messages", "embed_links"}),
                                              LOG_CHANNEL: frozenset({"view_channel", "send_messages", "embed_links"})})

    async def add_role(self, guild_id, user_id, role_id, reason):
        self.calls.append(("add_role", user_id, role_id))
        if self.role_problem or role_id in self.role_refusals:
            return self.role_problem or self.role_refusals[role_id]
        member = self.members.get((guild_id, user_id))
        if member is not None:
            member.role_ids = tuple(dict.fromkeys(member.role_ids + (role_id,)))
        return None

    async def remove_role(self, guild_id, user_id, role_id, reason):
        self.calls.append(("remove_role", user_id, role_id))
        if role_id in self.role_refusals:
            return self.role_refusals[role_id]
        member = self.members.get((guild_id, user_id))
        if member is not None:
            member.role_ids = tuple(role for role in member.role_ids if role != role_id)
        return None

    async def kick(self, guild_id, user_id, reason):
        self.calls.append(("kick", user_id, reason))
        return self.kick_works

    async def ban(self, guild_id, user_id, reason, delete_seconds=0):
        self.calls.append(("ban", user_id, reason, delete_seconds))
        if not self.ban_works:
            return False
        self.banned.add(user_id)
        return True

    async def unban(self, guild_id, user_id, reason):
        self.calls.append(("unban", user_id))
        if not self.unban_works:
            return False
        self.banned.discard(user_id)
        return True

    async def timeout(self, guild_id, user_id, minutes, reason):
        self.calls.append(("timeout", user_id, minutes))
        return self.timeout_works

    async def clear_timeout(self, guild_id, user_id, reason):
        self.calls.append(("clear_timeout", user_id))
        return self.timeout_works

    async def is_banned(self, guild_id, user_id):
        if self.discord_down:
            raise DiscordUnavailable("down")
        return user_id in self.banned

    async def dm(self, user_id, notice):
        self.dms.append((user_id, notice))
        return None if self.dm_fails else self.dm_open

    async def send(self, channel_id, notice, *, guild_id=None):
        self.sent.append((channel_id, notice))
        if not self.channel_posts_work:
            return None
        self.next_message += 1
        return str(self.next_message)

    async def delete_message(self, channel_id, message_id):
        self.calls.append(("delete_message", channel_id, message_id))
        return self.delete_works

    async def edit_message(self, channel_id, message_id, notice):
        self.calls.append(("edit_message", channel_id, message_id))
        return True

    async def pin(self, channel_id, message_id):
        return True

    async def open_help_thread(self, channel_id, name, user_id, role_id, notice, *, guild_id=None):
        self.calls.append(("open_help_thread", user_id))
        self.threads.append(notice)
        return "970000000000000099"

    async def reopen_thread(self, thread_id, user_id=None):
        self.calls.append(("reopen_thread", thread_id))
        return self.thread_open

    async def close_thread(self, thread_id):
        self.calls.append(("close_thread", thread_id))
        return self.close_works

    async def apply_profile(self, guild_id, profile, style=None):
        self.calls.append(("apply_profile", profile, style))
        return self.profile_problem

    async def command_permissions(self, guild_id):
        return self.discord_commands


class FakeDiscordApi:
    """Stands in for discord.com's OAuth2 endpoints in the web tests."""

    def __init__(self) -> None:
        self.user = {"id": OLD_USER, "username": "someone", "avatar": "abc", "mfa_enabled": True, "verified": True, "email": "someone@example.org"}
        self.guilds: list = []
        self.revoked: list = []
        self.exchanged: list = []
        self.fail_exchange = False
        self.command_writes: list = []
        self.command_write_status = 200
        self.authorizations: list = []
        self.hanging: set = set()      # endpoints that don't answer in time: token, me, guilds, write
        self.revoke_hangs = 0          # how many revoke calls hang before one answers
        self.revoke_status = 200
        self.revoke_calls = 0
        self.token_body: str | None = None  # a 200 whose body isn't what Discord documents
        self.me_body: str | None = None

    async def maybe_hang(self, endpoint):
        if endpoint in self.hanging:
            await asyncio.sleep(2)

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_put("/applications/{app}/guilds/{guild}/commands/{command}/permissions", self.write_command)
        app.router.add_post("/oauth2/token", self.token)
        app.router.add_post("/oauth2/token/revoke", self.revoke)
        app.router.add_get("/users/@me", self.me)
        app.router.add_get("/users/@me/guilds", self.my_guilds)
        return app

    async def token(self, request):
        form = await request.post()
        self.exchanged.append(dict(form))
        await self.maybe_hang("token")
        if self.token_body is not None:
            return web.Response(text=self.token_body, content_type="application/json")
        if self.fail_exchange:
            return web.json_response({"error": "invalid_grant"}, status=400)
        return web.json_response({"access_token": "fake-access", "refresh_token": "fake-refresh", "token_type": "Bearer", "expires_in": 604800, "scope": "identify"})

    async def write_command(self, request):
        self.authorizations.append(request.headers.get("Authorization"))
        if self.command_writes:  # the first write lands, and the next one can hang
            await self.maybe_hang("write")
        if self.command_write_status == 429:
            self.command_write_status = 200
            return web.json_response({"retry_after": 0.01}, status=429)
        if self.command_write_status != 200:
            return web.json_response({"message": "Missing Permissions"}, status=self.command_write_status)
        self.command_writes.append((request.match_info["guild"], request.match_info["command"], await request.json()))
        return web.json_response({})

    async def revoke(self, request):
        form = await request.post()
        self.revoke_calls += 1
        if self.revoke_hangs > 0:
            self.revoke_hangs -= 1
            await asyncio.sleep(2)
        if self.revoke_status != 200:
            return web.json_response({"error": "try later"}, status=self.revoke_status)
        self.revoked.append(form["token"])
        return web.json_response({})

    async def me(self, request):
        await self.maybe_hang("me")
        if self.me_body is not None:
            return web.Response(text=self.me_body, content_type="application/json")
        return web.json_response(self.user)

    async def my_guilds(self, request):
        await self.maybe_hang("guilds")
        return web.json_response(self.guilds)
