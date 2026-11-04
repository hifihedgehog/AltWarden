"""The real gateway code on real discord.py objects, with only the HTTP call replaced.

Every assertion is on what would go to Discord: the method, the route and the JSON body, as listed
in Discord's API reference. This is as close to a live server as a test can get without a token.
"""
import asyncio
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aiohttp
import discord
from discord.http import Route

from altwarden.bot.client import AltWardenBot
from altwarden.ports import ROLE_TOO_LOW, Button, Notice

GUILD = 970000000000000001
BOT = 970000000000000010
OWNER = 970000000000000011
MEMBER = 970000000000000012
ROLE_LOW = 970000000000000020
ROLE_BOT = 970000000000000021
ROLE_HIGH = 970000000000000022
CHANNEL = 970000000000000030
THREAD = 970000000000000031


def user(user_id, name="someone", bot=False):
    return {"id": str(user_id), "username": name, "discriminator": "0", "avatar": "abc", "global_name": None, "bot": bot}


def member(user_id, roles=(), name="someone", bot=False):
    return {"user": user(user_id, name, bot), "roles": [str(role) for role in roles], "joined_at": "2025-01-01T00:00:00+00:00",
            "deaf": False, "mute": False, "flags": 0}


def role(role_id, name, position, permissions=0, managed=False):
    return {"id": str(role_id), "name": name, "color": 0, "hoist": False, "position": position, "permissions": str(permissions),
            "managed": managed, "mentionable": False, "flags": 0}


GUILD_PAYLOAD = {
    "id": str(GUILD), "name": "Test Server", "icon": None, "owner_id": str(OWNER), "member_count": 3, "unavailable": False,
    "roles": [role(GUILD, "@everyone", 0, 1024 | 2048), role(ROLE_LOW, "Verified", 1), role(ROLE_BOT, "AltWarden", 2, 1 << 28, managed=True), role(ROLE_HIGH, "Admins", 3)],
    "channels": [{"id": str(CHANNEL), "type": 0, "name": "verify", "position": 0, "permission_overwrites": [], "parent_id": None, "guild_id": str(GUILD)}],
    "threads": [], "members": [member(BOT, [ROLE_BOT], "altwarden", True), member(OWNER, [], "owner"), member(MEMBER, [], "member")],
    "emojis": [], "stickers": [], "features": [], "premium_tier": 0, "preferred_locale": "en-US", "mfa_level": 0, "verification_level": 0, "nsfw_level": 0,
    "explicit_content_filter": 0, "default_message_notifications": 0, "system_channel_flags": 0, "afk_timeout": 0, "voice_states": [], "presences": [],
}


def message(channel_id, message_id=555):
    return {"id": str(message_id), "channel_id": str(channel_id), "author": user(BOT, "altwarden", True), "content": "", "timestamp": "2026-11-04T00:00:00+00:00",
            "edited_timestamp": None, "tts": False, "mention_everyone": False, "mentions": [], "mention_roles": [], "attachments": [], "embeds": [], "pinned": False,
            "type": 0, "flags": 0}


def thread(thread_id=THREAD, archived=False):
    return {"id": str(thread_id), "type": 12, "guild_id": str(GUILD), "name": "member", "parent_id": str(CHANNEL), "owner_id": str(BOT), "message_count": 0, "member_count": 1,
            "rate_limit_per_user": 0, "thread_metadata": {"archived": archived, "auto_archive_duration": 10080, "archive_timestamp": "2026-11-04T00:00:00+00:00", "locked": False, "invitable": False}}


class Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bot = AltWardenBot()
        await self.bot._async_setup_hook()
        state = self.bot._connection
        state.user = discord.ClientUser(state=state, data=user(BOT, "altwarden", True))
        state.application_id = 123
        state._add_guild_from_data(GUILD_PAYLOAD)
        self.requests = []
        self.answers = {}
        self.bot.http.request = self.fake_request
        self.gateway = self.bot.gateway

    async def asyncTearDown(self):
        await self.bot.http.close()

    async def fake_request(self, route: Route, **kwargs):
        self.requests.append((route.method, route.path.format(**route.__dict__.get("metadata", {}) or {}) if False else route.url.split("/api/v10")[-1], kwargs))
        answer = self.answers.get((route.method, route.url.split("/api/v10")[-1]))
        if isinstance(answer, Exception):
            raise answer
        return answer

    def last(self):
        return self.requests[-1]

    def forbidden(self):
        return discord.Forbidden(SimpleNamespace(status=403, reason="Forbidden"), {"code": 50013, "message": "Missing Permissions"})

    def not_found(self):
        return discord.NotFound(SimpleNamespace(status=404, reason="Not Found"), {"code": 10008, "message": "Unknown"})


class PermissionNames(unittest.TestCase):
    def test_every_permission_the_code_asks_about_reads_back_from_discord_py(self):
        from altwarden import health, settings
        from altwarden.bot.gateway import permission_names
        for name, bit in health.BITS.items():
            self.assertIn(name, permission_names(discord.Permissions(bit)), name)
        everything = permission_names(discord.Permissions.all())
        for name in settings.PERMISSION_NAMES:
            self.assertIn(name, everything, name)


class Reading(Base):
    async def test_guild_view_has_what_the_dashboard_needs(self):
        view = await self.gateway.guild(str(GUILD))
        self.assertEqual((view.id, view.name, view.owner_id, view.member_count), (str(GUILD), "Test Server", str(OWNER), 3))
        self.assertEqual([item["name"] for item in view.roles], ["Admins", "AltWarden", "Verified", "@everyone"])
        self.assertTrue(next(item for item in view.roles if item["name"] == "AltWarden")["managed"])
        self.assertEqual(view.channels[0]["type"], "text")
        self.assertEqual(view.bot_top_role, 2)
        self.assertIn("manage_roles", view.bot_permissions)
        self.assertIn("view_channel", view.channel_permissions[str(CHANNEL)])

    async def test_a_server_it_isnt_in_is_nobody(self):
        self.assertIsNone(await self.gateway.guild("970000000000000099"))

    async def test_an_unavailable_server_reads_as_loading(self):
        self.bot._ready.set()
        self.assertFalse(await self.gateway.guild_loading(str(GUILD)))
        self.bot.get_guild(GUILD).unavailable = True
        self.assertTrue(await self.gateway.guild_loading(str(GUILD)))
        self.assertIsNone(await self.gateway.guild(str(GUILD)))

    async def test_before_ready_everything_is_loading(self):
        self.assertTrue(await self.gateway.guild_loading(str(GUILD)))

    async def test_member_info(self):
        info = await self.gateway.member(str(GUILD), str(OWNER))
        self.assertTrue(info.is_owner)
        self.assertEqual(info.username, "owner")
        self.assertIn("administrator", info.permissions, "discord.py gives a server's owner every permission")
        other = await self.gateway.member(str(GUILD), str(MEMBER))
        self.assertFalse(other.is_owner)
        self.assertIn("send_messages", other.permissions)
        self.assertNotIn("manage_roles", other.permissions)

    async def test_a_member_it_hasnt_seen_is_fetched(self):
        stranger = 970000000000000013
        self.answers[("GET", f"/guilds/{GUILD}/members/{stranger}")] = member(stranger, [], "stranger")
        info = await self.gateway.member(str(GUILD), str(stranger))
        self.assertEqual(info.username, "stranger")

    async def test_someone_who_left_is_none(self):
        stranger = 970000000000000014
        self.answers[("GET", f"/guilds/{GUILD}/members/{stranger}")] = self.not_found()
        self.assertIsNone(await self.gateway.member(str(GUILD), str(stranger)))


class Roles(Base):
    async def test_giving_a_role(self):
        self.assertIsNone(await self.gateway.add_role(str(GUILD), str(MEMBER), str(ROLE_LOW), "Passed verification"))
        method, path, kwargs = self.last()
        self.assertEqual((method, path), ("PUT", f"/guilds/{GUILD}/members/{MEMBER}/roles/{ROLE_LOW}"))
        self.assertEqual(kwargs.get("reason"), "Passed verification")

    async def test_taking_a_role(self):
        self.assertIsNone(await self.gateway.remove_role(str(GUILD), str(MEMBER), str(ROLE_LOW), "Reset"))
        self.assertEqual(self.last()[:2], ("DELETE", f"/guilds/{GUILD}/members/{MEMBER}/roles/{ROLE_LOW}"))

    async def test_a_role_above_the_bot_is_named_without_asking_discord(self):
        self.assertEqual(await self.gateway.add_role(str(GUILD), str(MEMBER), str(ROLE_HIGH), "x"), ROLE_TOO_LOW)
        self.assertEqual(self.requests, [])

    async def test_a_deleted_role(self):
        self.assertIn("no longer exists", await self.gateway.add_role(str(GUILD), str(MEMBER), "970000000000000098", "x"))

    async def test_a_refusal_is_explained(self):
        self.answers[("PUT", f"/guilds/{GUILD}/members/{MEMBER}/roles/{ROLE_LOW}")] = self.forbidden()
        self.assertIn("Manage Roles", await self.gateway.add_role(str(GUILD), str(MEMBER), str(ROLE_LOW), "x"))


class Moderation(Base):
    async def test_kick(self):
        self.assertTrue(await self.gateway.kick(str(GUILD), str(MEMBER), "why"))
        method, path, kwargs = self.last()
        self.assertEqual((method, path, kwargs.get("reason")), ("DELETE", f"/guilds/{GUILD}/members/{MEMBER}", "why"))

    async def test_ban_with_message_cleanup(self):
        self.assertTrue(await self.gateway.ban(str(GUILD), str(MEMBER), "why", delete_seconds=3600))
        method, path, kwargs = self.last()
        self.assertEqual((method, path), ("PUT", f"/guilds/{GUILD}/bans/{MEMBER}"))
        self.assertEqual(kwargs["params"], {"delete_message_seconds": 3600})

    async def test_unban(self):
        self.assertTrue(await self.gateway.unban(str(GUILD), str(MEMBER), "why"))
        self.assertEqual(self.last()[:2], ("DELETE", f"/guilds/{GUILD}/bans/{MEMBER}"))

    async def test_timeout(self):
        self.answers[("PATCH", f"/guilds/{GUILD}/members/{MEMBER}")] = member(MEMBER)
        self.assertTrue(await self.gateway.timeout(str(GUILD), str(MEMBER), 60, "why"))
        self.assertIn("communication_disabled_until", self.last()[2]["json"])

    async def test_a_refused_kick_is_false(self):
        self.answers[("DELETE", f"/guilds/{GUILD}/members/{MEMBER}")] = self.forbidden()
        self.assertFalse(await self.gateway.kick(str(GUILD), str(MEMBER), "why"))

    async def test_is_banned(self):
        self.answers[("GET", f"/guilds/{GUILD}/bans/{MEMBER}")] = {"reason": None, "user": user(MEMBER)}
        self.assertTrue(await self.gateway.is_banned(str(GUILD), str(MEMBER)))
        self.answers[("GET", f"/guilds/{GUILD}/bans/{MEMBER}")] = self.not_found()
        self.assertFalse(await self.gateway.is_banned(str(GUILD), str(MEMBER)))


class Messages(Base):
    def posted(self):
        method, path, kwargs = self.last()
        self.assertEqual(method, "POST")
        return path, kwargs

    async def test_a_message_with_a_ping_and_a_button(self):
        self.answers[("POST", f"/channels/{CHANNEL}/messages")] = message(CHANNEL)
        notice = Notice(content=f"<@&{ROLE_LOW}>", embeds=[{"title": "T", "description": "D", "color": 5}], buttons=[Button("Verify", custom_id="aw:verify", style="success", emoji="✅")],
                        mention_roles=[str(ROLE_LOW)])
        self.assertEqual(await self.gateway.send(str(CHANNEL), notice), "555")
        path, kwargs = self.posted()
        self.assertEqual(path, f"/channels/{CHANNEL}/messages")
        import json
        body = json.loads(kwargs["form"][0]["value"]) if "form" in kwargs else kwargs["json"]
        self.assertEqual(body["embeds"][0]["title"], "T")
        self.assertEqual(body["allowed_mentions"]["roles"], [ROLE_LOW])
        self.assertEqual(body["allowed_mentions"]["parse"], [])
        button = body["components"][0]["components"][0]
        self.assertEqual((button["custom_id"], button["style"], button["label"]), ("aw:verify", 3, "Verify"))
        self.assertEqual(button["emoji"]["name"], "✅")

    async def test_a_link_button_has_no_custom_id(self):
        self.answers[("POST", f"/channels/{CHANNEL}/messages")] = message(CHANNEL)
        await self.gateway.send(str(CHANNEL), Notice(embeds=[{"description": "D"}], buttons=[Button("Verify", url="https://x.test/v/abc", style="link")]))
        import json
        _, kwargs = self.posted()
        body = json.loads(kwargs["form"][0]["value"]) if "form" in kwargs else kwargs["json"]
        button = body["components"][0]["components"][0]
        self.assertEqual((button["style"], button["url"]), (5, "https://x.test/v/abc"))
        self.assertNotIn("custom_id", button)

    async def test_a_custom_emoji_keeps_its_id(self):
        self.answers[("POST", f"/channels/{CHANNEL}/messages")] = message(CHANNEL)
        await self.gateway.send(str(CHANNEL), Notice(embeds=[{"description": "D"}], buttons=[Button("Go", custom_id="aw:help", emoji="<:shield:123456789012345678>")]))
        import json
        _, kwargs = self.posted()
        body = json.loads(kwargs["form"][0]["value"]) if "form" in kwargs else kwargs["json"]
        self.assertEqual(body["components"][0]["components"][0]["emoji"]["id"], 123456789012345678)

    async def test_a_dm_opens_a_channel_first(self):
        self.answers[("POST", "/users/@me/channels")] = {"id": "970000000000000040", "type": 1, "recipients": [user(MEMBER)]}
        self.answers[("POST", "/channels/970000000000000040/messages")] = message(970000000000000040)
        self.assertTrue(await self.gateway.dm(str(MEMBER), Notice(content="hello")))
        self.assertEqual([request[:2] for request in self.requests][-2:], [("POST", "/users/@me/channels"), ("POST", "/channels/970000000000000040/messages")])

    async def test_closed_dms_are_false(self):
        self.answers[("POST", "/users/@me/channels")] = {"id": "970000000000000040", "type": 1, "recipients": [user(MEMBER)]}
        self.answers[("POST", "/channels/970000000000000040/messages")] = self.forbidden()
        self.assertFalse(await self.gateway.dm(str(MEMBER), Notice(content="hello")))

    async def test_delete_and_pin(self):
        self.assertTrue(await self.gateway.delete_message(str(CHANNEL), "555"))
        self.assertEqual(self.last()[:2], ("DELETE", f"/channels/{CHANNEL}/messages/555"))
        self.assertTrue(await self.gateway.pin(str(CHANNEL), "555"))
        self.assertEqual(self.last()[:2], ("PUT", f"/channels/{CHANNEL}/messages/pins/555"))

    async def test_a_channel_that_doesnt_exist(self):
        self.assertIsNone(await self.gateway.send("970000000000000097", Notice(content="x")))
        self.assertFalse(await self.gateway.delete_message("970000000000000097", "1"))

    async def test_edit_removes_the_buttons(self):
        self.answers[("PATCH", f"/channels/{CHANNEL}/messages/555")] = message(CHANNEL)
        self.assertTrue(await self.gateway.edit_message(str(CHANNEL), "555", Notice(embeds=[{"description": "Decided"}])))
        import json
        kwargs = self.last()[2]
        body = json.loads(kwargs["form"][0]["value"]) if "form" in kwargs else kwargs["json"]
        self.assertEqual(body["components"], [])


class Threads(Base):
    def prepare(self):
        self.answers[("POST", f"/channels/{CHANNEL}/threads")] = thread()
        self.answers[("POST", f"/channels/{THREAD}/messages")] = message(THREAD)

    async def test_a_private_thread_with_the_member_and_a_role_ping(self):
        self.prepare()
        notice = Notice(content="hello", embeds=[{"description": "Tell us"}])
        result = await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), str(ROLE_LOW), notice)
        self.assertEqual(result, str(THREAD))
        calls = {request[:2]: request[2] for request in self.requests}
        created = calls[("POST", f"/channels/{CHANNEL}/threads")]["json"]
        self.assertEqual((created["type"], created["invitable"], created["auto_archive_duration"]), (12, False, 10080))
        self.assertIn(("PUT", f"/channels/{THREAD}/thread-members/{MEMBER}"), calls)
        self.assertIn(("PUT", f"/channels/{THREAD}/messages/pins/555"), calls)
        self.assertTrue(notice.content.startswith(f"<@{MEMBER}> <@&{ROLE_LOW}>"))

    async def test_a_long_message_still_fits_after_the_ping(self):
        self.prepare()
        notice = Notice(content="x" * 2000)
        await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), None, notice)
        self.assertLessEqual(len(notice.content), 2000)

    async def test_a_failed_pin_doesnt_lose_the_thread(self):
        self.prepare()
        self.answers[("PUT", f"/channels/{THREAD}/messages/pins/555")] = self.forbidden()
        self.assertEqual(await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), None, Notice(content="x")), str(THREAD))

    async def test_a_missing_permission_is_none(self):
        self.answers[("POST", f"/channels/{CHANNEL}/threads")] = self.forbidden()
        self.assertIsNone(await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), None, Notice(content="x")))

    async def test_closing_locks_and_archives(self):
        self.answers[("GET", f"/channels/{THREAD}")] = thread()
        self.answers[("PATCH", f"/channels/{THREAD}")] = thread(archived=True)
        self.assertTrue(await self.gateway.close_thread(str(THREAD)))
        body = self.last()[2]["json"]
        self.assertEqual((body["archived"], body["locked"]), (True, True))

    async def test_pressing_help_on_an_archived_thread_unarchives_it(self):
        self.answers[("GET", f"/channels/{THREAD}")] = thread(archived=True)
        self.answers[("PATCH", f"/channels/{THREAD}")] = thread()
        self.assertTrue(await self.gateway.reopen_thread(str(THREAD)))
        self.assertEqual(self.last()[2]["json"]["archived"], False)

    async def test_a_deleted_thread_is_false(self):
        self.answers[("GET", f"/channels/{THREAD}")] = self.not_found()
        self.assertFalse(await self.gateway.reopen_thread(str(THREAD)))
        self.assertFalse(await self.gateway.close_thread(str(THREAD)))


class Profile(Base):
    route = ("PATCH", f"/guilds/{GUILD}/members/@me")

    async def test_only_the_changed_fields_go_out(self):
        self.answers[self.route] = {}
        self.assertIsNone(await self.gateway.apply_profile(str(GUILD), {"bio": "Hello"}))
        self.assertEqual(self.last()[2]["json"], {"bio": "Hello"})

    async def test_a_picture_becomes_a_data_uri(self):
        self.answers[self.route] = {}
        await self.gateway.apply_profile(str(GUILD), {"avatar": b"\x89PNG"})
        self.assertEqual(self.last()[2]["json"]["avatar"], "data:image/png;base64,iVBORw==")

    async def test_a_cleared_picture_stays_null(self):
        self.answers[self.route] = {}
        await self.gateway.apply_profile(str(GUILD), {"avatar": None})
        self.assertIsNone(self.last()[2]["json"]["avatar"])

    async def test_a_style_goes_in_its_own_request(self):
        self.answers[self.route] = {"display_name_styles": {"font_id": 12, "effect_id": 2, "colors": [1, 2]}}
        style = {"display_name_font_id": 12, "display_name_effect_id": 2, "display_name_colors": [1, 2]}
        self.assertIsNone(await self.gateway.apply_profile(str(GUILD), {"nick": "Warden"}, style))
        self.assertEqual([request[2]["json"] for request in self.requests], [{"nick": "Warden"}, style])

    async def test_a_style_refusal_keeps_the_rest(self):
        outcomes = [{}, discord.HTTPException(SimpleNamespace(status=400, reason="Bad Request"), {"code": 50035, "message": "Invalid Form Body"})]

        async def answer(route, **kwargs):
            self.requests.append((route.method, route.url, kwargs))
            result = outcomes.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
        self.bot.http.request = answer
        problem = await self.gateway.apply_profile(str(GUILD), {"nick": "Warden"}, {"display_name_font_id": 12, "display_name_effect_id": 1, "display_name_colors": [1]})
        self.assertIn("refused the name style (400)", problem)
        self.assertIn("rest was saved", problem)

    async def test_a_nickname_without_the_permission(self):
        self.answers[self.route] = self.forbidden()
        self.assertIn("Change Nickname", await self.gateway.apply_profile(str(GUILD), {"nick": "Warden"}))


class CommandPermissions(Base):
    def prepare(self):
        self.answers[("GET", "/applications/123/commands")] = [{"id": "901", "name": "verify-user", "type": 1}, {"id": "902", "name": "Verify", "type": 2}]
        self.answers[("GET", f"/applications/123/guilds/{GUILD}/commands/permissions")] = [
            {"id": "901", "application_id": "123", "guild_id": str(GUILD), "permissions": [{"id": str(ROLE_LOW), "type": 1, "permission": True}]},
            {"id": "123", "application_id": "123", "guild_id": str(GUILD), "permissions": [{"id": str(GUILD), "type": 1, "permission": False}]},
        ]

    async def test_reading_them_with_the_bot_token(self):
        self.prepare()
        data = await self.gateway.command_permissions(str(GUILD))
        self.assertEqual(data["application"], "123")
        self.assertEqual(data["all"], [{"type": "role", "id": str(GUILD), "allow": False}])
        rows = {row["name"]: row for row in data["commands"]}
        self.assertEqual(rows["verify-user"]["overrides"], [{"type": "role", "id": str(ROLE_LOW), "allow": True}])
        self.assertEqual(rows["Verify"]["overrides"], [])

    async def test_the_command_list_is_cached(self):
        self.prepare()
        await self.gateway.command_permissions(str(GUILD))
        await self.gateway.command_permissions(str(GUILD))
        self.assertEqual(sum(request[1] == "/applications/123/commands" for request in self.requests), 1)

    async def test_no_answer_is_none(self):
        self.prepare()
        self.answers[("GET", f"/applications/123/guilds/{GUILD}/commands/permissions")] = self.forbidden()
        self.assertIsNone(await self.gateway.command_permissions(str(GUILD)))


class Buttons(Base):
    """A press on a posted button, through the bot's real handler."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.service = SimpleNamespace()
        self.bot.service = self.service
        self.said = []

    def press(self, custom_id, user_id=MEMBER):
        guild = self.bot.get_guild(GUILD)
        interaction = SimpleNamespace(type=discord.InteractionType.component, data={"custom_id": custom_id}, guild=guild, user=guild.get_member(user_id), channel_id=THREAD, guild_id=GUILD)

        async def defer(**kwargs):
            pass

        async def send(*args, **kwargs):
            self.said.append((args, kwargs))
        interaction.response = SimpleNamespace(defer=defer, is_done=lambda: True, send_message=send)
        interaction.followup = SimpleNamespace(send=send)
        return interaction

    async def test_other_bots_buttons_are_left_alone(self):
        await self.bot.on_interaction(self.press("someone-else:thing"))
        self.assertEqual(self.said, [])

    async def test_verify_in_web_mode_gives_a_private_link(self):
        async def press_verify(member_info):
            self.seen = member_info
            return "https://x.test/v/abc"
        self.service.press_verify = press_verify
        await self.bot.on_interaction(self.press("aw:verify"))
        kwargs = self.said[0][1]
        self.assertTrue(kwargs["ephemeral"])
        self.assertEqual(kwargs["view"].children[0].url, "https://x.test/v/abc")
        self.assertEqual(self.seen.user_id, str(MEMBER))

    async def test_a_crash_tells_the_member_instead_of_timing_out(self):
        async def press_verify(member_info):
            raise RuntimeError("boom")
        self.service.press_verify = press_verify
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.bot.on_interaction(self.press("aw:verify"))
        self.assertIn("Something went wrong", self.said[0][0][0])

    async def test_appeals_need_the_access_rule(self):
        from altwarden import settings

        async def get_settings(guild_id):
            return settings.defaults()
        self.service.get_settings = get_settings
        await self.bot.on_interaction(self.press("aw:appeal:approve:7"))
        self.assertIn("don't have access", self.said[0][0][0])


if __name__ == "__main__":
    unittest.main()
