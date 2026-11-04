"""A fake Discord for tests: records what the service asked for and answers like the real API."""
from __future__ import annotations

from aiohttp import web

from altwarden.ports import GuildView, MemberInfo, Notice

GUILD = "970000000000000001"
VERIFIED_ROLE = "970000000000000002"
UNVERIFIED_ROLE = "970000000000000003"
CHANNEL = "970000000000000004"
LOG_CHANNEL = "970000000000000005"
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
        self.dm_open = True
        self.role_problem: str | None = None
        self.kick_works = True
        self.next_message = 1000
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
                   owner: bool = False, bot: bool = False) -> MemberInfo:
        info = MemberInfo(GUILD, user_id, username, avatar, bot, roles, frozenset(perms), owner)
        self.members[(GUILD, user_id)] = info
        return info

    def did(self, name: str) -> list[tuple]:
        return [call for call in self.calls if call[0] == name]

    async def member(self, guild_id, user_id):
        return self.members.get((guild_id, user_id))

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
        if self.role_problem:
            return self.role_problem
        member = self.members.get((guild_id, user_id))
        if member is not None:
            member.role_ids = tuple(dict.fromkeys(member.role_ids + (role_id,)))
        return None

    async def remove_role(self, guild_id, user_id, role_id, reason):
        self.calls.append(("remove_role", user_id, role_id))
        member = self.members.get((guild_id, user_id))
        if member is not None:
            member.role_ids = tuple(role for role in member.role_ids if role != role_id)
        return None

    async def kick(self, guild_id, user_id, reason):
        self.calls.append(("kick", user_id, reason))
        return self.kick_works

    async def ban(self, guild_id, user_id, reason, delete_seconds=0):
        self.calls.append(("ban", user_id, reason, delete_seconds))
        self.banned.add(user_id)
        return True

    async def unban(self, guild_id, user_id, reason):
        self.calls.append(("unban", user_id))
        self.banned.discard(user_id)
        return True

    async def timeout(self, guild_id, user_id, minutes, reason):
        self.calls.append(("timeout", user_id, minutes))
        return True

    async def is_banned(self, guild_id, user_id):
        return user_id in self.banned

    async def dm(self, user_id, notice):
        self.dms.append((user_id, notice))
        return self.dm_open

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
        return "970000000000000099"

    async def reopen_thread(self, thread_id):
        self.calls.append(("reopen_thread", thread_id))
        return self.thread_open

    async def close_thread(self, thread_id):
        self.calls.append(("close_thread", thread_id))
        return True

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
        if self.fail_exchange:
            return web.json_response({"error": "invalid_grant"}, status=400)
        return web.json_response({"access_token": "fake-access", "refresh_token": "fake-refresh", "token_type": "Bearer", "expires_in": 604800, "scope": "identify"})

    async def write_command(self, request):
        self.authorizations.append(request.headers.get("Authorization"))
        if self.command_write_status == 429:
            self.command_write_status = 200
            return web.json_response({"retry_after": 0.01}, status=429)
        if self.command_write_status != 200:
            return web.json_response({"message": "Missing Permissions"}, status=self.command_write_status)
        self.command_writes.append((request.match_info["guild"], request.match_info["command"], await request.json()))
        return web.json_response({})

    async def revoke(self, request):
        form = await request.post()
        self.revoked.append(form["token"])
        return web.json_response({})

    async def me(self, request):
        return web.json_response(self.user)

    async def my_guilds(self, request):
        return web.json_response(self.guilds)
