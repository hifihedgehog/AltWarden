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

from altwarden.bot.client import CATCH_UP_MARGIN, AltWardenBot
import unittest.mock
from unittest.mock import AsyncMock

from altwarden.ports import ROLE_TOO_LOW, Button, DiscordUnavailable, Notice

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


class OtherServers(Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        other = dict(GUILD_PAYLOAD, id="970000000000000099", name="Someone else's server",
                     channels=[{"id": "970000000000000098", "type": 0, "name": "general", "position": 0, "permission_overwrites": [], "parent_id": None, "guild_id": "970000000000000099"}])
        self.bot._connection._add_guild_from_data(other)

    async def test_a_channel_in_another_server_is_refused(self):
        self.assertIsNone(await self.gateway.send("970000000000000098", Notice(content="hi"), guild_id=str(GUILD)))
        self.assertEqual(self.requests, [])

    async def test_a_channel_in_this_server_is_fine(self):
        self.answers[("POST", f"/channels/{CHANNEL}/messages")] = message(CHANNEL)
        self.assertEqual(await self.gateway.send(str(CHANNEL), Notice(content="hi"), guild_id=str(GUILD)), "555")

    async def test_a_help_thread_stays_in_its_server(self):
        self.assertIsNone(await self.gateway.open_help_thread("970000000000000098", "x", str(MEMBER), Notice(content="hi"), guild_id=str(GUILD)))
        self.assertEqual(self.requests, [])


class WhenDiscordFails(Base):
    async def test_a_dropped_connection_comes_back_as_a_plain_result(self):
        async def dropped(route, **kwargs):
            raise aiohttp.ServerDisconnectedError()
        self.bot.http.request = dropped
        self.bot._connection._users.clear()
        guild = str(GUILD)
        self.assertFalse(await self.gateway.kick(guild, str(MEMBER), "x"))
        self.assertFalse(await self.gateway.ban(guild, str(MEMBER), "x"))
        self.assertFalse(await self.gateway.unban(guild, str(MEMBER), "x"))
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.is_banned(guild, str(MEMBER))
        self.assertIsNone(await self.gateway.dm(str(MEMBER), Notice(content="hi")))
        self.assertIsNone(await self.gateway.send(str(CHANNEL), Notice(content="hi")))
        self.assertFalse(await self.gateway.delete_message(str(CHANNEL), "1"))
        self.assertFalse(await self.gateway.edit_message(str(CHANNEL), "1", Notice(content="hi")))
        self.assertFalse(await self.gateway.pin(str(CHANNEL), "1"))
        self.assertIsNone(await self.gateway.open_help_thread(str(CHANNEL), "x", str(MEMBER), Notice(content="hi")))
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.reopen_thread("970000000000000077")
        self.assertFalse(await self.gateway.close_thread("970000000000000077"))
        self.assertIsNotNone(await self.gateway.add_role(guild, str(MEMBER), str(ROLE_LOW), "x"))
        self.assertIsNotNone(await self.gateway.apply_profile(guild, {"nick": "x"}))
        self.assertIsNone(await self.gateway.command_permissions(guild))

    async def uncached(self):
        self.bot.get_guild(GUILD)._remove_member(self.bot.get_guild(GUILD).get_member(MEMBER))
        self.gateway.forget_member(str(GUILD), str(MEMBER))

    async def test_gone_and_unreachable_arent_the_same(self):
        await self.uncached()
        self.answers[("GET", f"/guilds/{GUILD}/members/{MEMBER}")] = self.not_found()
        self.assertIsNone(await self.gateway.member(str(GUILD), str(MEMBER)))
        self.gateway.forget_member(str(GUILD), str(MEMBER))
        self.answers[("GET", f"/guilds/{GUILD}/members/{MEMBER}")] = discord.DiscordServerError(SimpleNamespace(status=503, reason="Unavailable"), "down")
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.member(str(GUILD), str(MEMBER))

    async def test_an_unreachable_answer_isnt_remembered(self):
        await self.uncached()
        self.answers[("GET", f"/guilds/{GUILD}/members/{MEMBER}")] = discord.DiscordServerError(SimpleNamespace(status=503, reason="Unavailable"), "down")
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.member(str(GUILD), str(MEMBER))
        self.answers[("GET", f"/guilds/{GUILD}/members/{MEMBER}")] = member(MEMBER)
        self.assertIsNotNone(await self.gateway.member(str(GUILD), str(MEMBER)))

    async def test_a_locked_thread_counts_as_gone(self):
        locked = thread()
        locked["thread_metadata"]["locked"] = True
        self.answers[("GET", f"/channels/{THREAD}")] = locked
        self.assertFalse(await self.gateway.reopen_thread(str(THREAD)))
        self.assertFalse([call for call in self.requests if call[0] == "PATCH"])


class EventsAndCatchUp(Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.bot.service = SimpleNamespace(
            on_leave=AsyncMock(), on_join=AsyncMock(), is_set_up=AsyncMock(return_value=True),
            db=SimpleNamespace(member=AsyncMock(return_value=None), set_meta=AsyncMock(), get_meta=AsyncMock(return_value=None)))

    async def test_a_member_outside_the_cache_leaving_still_counts(self):
        guild = self.bot.get_guild(GUILD)
        guild._remove_member(guild.get_member(MEMBER))
        self.bot._connection.parse_guild_member_remove({"guild_id": str(GUILD), "user": user(MEMBER)})
        await asyncio.sleep(0.05)
        self.bot.service.on_leave.assert_awaited_once_with(str(GUILD), str(MEMBER))

    async def test_a_cached_member_leaving_counts_once(self):
        self.bot._connection.parse_guild_member_remove({"guild_id": str(GUILD), "user": user(MEMBER)})
        await asyncio.sleep(0.05)
        self.bot.service.on_leave.assert_awaited_once_with(str(GUILD), str(MEMBER))

    def member_page(self, joined):
        row = member(MEMBER)
        row["joined_at"] = joined
        return row

    async def test_someone_who_joined_while_offline_is_handled(self):
        self.answers[("GET", f"/guilds/{GUILD}/members?limit=1000")] = [self.member_page("2026-11-04T12:00:00+00:00")]
        pages = iter([[self.member_page("2026-11-04T12:00:00+00:00")], []])

        async def listing(route, **kwargs):
            self.requests.append((route.method, route.url, kwargs))
            return next(pages)
        self.bot.http.request = listing
        since = discord.utils.parse_time("2026-11-04T11:00:00+00:00").timestamp()
        await self.bot._catch_up(since)
        self.bot.service.on_join.assert_awaited_once()
        self.assertEqual(self.bot.service.on_join.await_args.kwargs, {"catching_up": True})

    async def test_someone_who_joined_before_the_gap_is_left_alone(self):
        pages = iter([[self.member_page("2026-11-04T10:00:00+00:00")], []])

        async def listing(route, **kwargs):
            return next(pages)
        self.bot.http.request = listing
        await self.bot._catch_up(discord.utils.parse_time("2026-11-04T11:00:00+00:00").timestamp())
        self.bot.service.on_join.assert_not_awaited()

    async def test_the_last_online_time_moves_only_when_the_walk_finishes(self):
        pages = iter([[]])

        async def listing(route, **kwargs):
            return next(pages)
        self.bot.http.request = listing
        await self.bot._catch_up(0.0)
        self.bot.service.db.set_meta.assert_awaited_once()

    async def test_a_walk_ending_while_the_gateway_is_down_leaves_the_time_alone(self):
        pages = iter([[]])

        async def listing(route, **kwargs):
            return next(pages)
        self.bot.http.request = listing
        await self.bot.on_disconnect()
        await self.bot._catch_up(0.0)
        self.bot.service.db.set_meta.assert_not_awaited()

    async def test_any_error_in_a_walk_is_retried_rather_than_given_up(self):
        calls = []

        async def listing(route, **kwargs):
            calls.append(route.url)
            if len(calls) <= 3:
                raise RuntimeError("a bug, not a network error")
            return []
        self.bot.http.request = listing
        with unittest.mock.patch("altwarden.bot.client.CATCH_UP_RETRY_SECONDS", 0), self.assertLogs("altwarden.bot", "ERROR"):
            await self.bot._catch_up(0.0)
        self.assertEqual(len(calls), 4)
        self.bot.service.db.set_meta.assert_awaited_once()

    async def test_a_gap_during_a_walk_walks_again(self):
        pages = iter([[], []])
        seen = []

        async def listing(route, **kwargs):
            seen.append(route.url)
            if len(seen) == 1:
                self.bot._catch_up_again = 50.0
            return next(pages)
        self.bot.http.request = listing
        await self.bot._catch_up(100.0)
        self.assertEqual(len(seen), 2)
        self.assertIsNone(self.bot._catch_up_again)

    async def test_a_failed_walk_tries_again(self):
        calls = []

        async def listing(route, **kwargs):
            calls.append(route.url)
            if len(calls) == 1:
                raise aiohttp.ServerDisconnectedError()
            return []
        self.bot.http.request = listing
        with unittest.mock.patch("altwarden.bot.client.CATCH_UP_RETRY_SECONDS", 0):
            await self.bot._catch_up(0.0)
        self.assertEqual(len(calls), 2)
        self.bot.service.db.set_meta.assert_awaited_once()

    async def test_one_members_failure_doesnt_stop_the_walk(self):
        other = member(OWNER)
        other["joined_at"] = "2026-11-04T12:00:00+00:00"
        pages = iter([[self.member_page("2026-11-04T12:00:00+00:00"), other], []])

        async def listing(route, **kwargs):
            return next(pages)
        self.bot.http.request = listing
        self.bot.service.on_join = AsyncMock(side_effect=[RuntimeError("boom"), None])
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.bot._catch_up(discord.utils.parse_time("2026-11-04T11:00:00+00:00").timestamp())
        self.assertEqual(self.bot.service.on_join.await_count, 2)

    async def test_the_time_is_read_before_the_timers_can_change_it(self):
        self.bot.service.db.get_meta = AsyncMock(return_value=123.0)
        self.bot.service.tick = AsyncMock()
        await self.bot.setup_hook()
        self.bot.minute_timer.cancel()
        self.bot.hour_timer.cancel()
        self.assertEqual(self.bot._missed_since, 123.0)

    async def test_a_gateway_outage_counts_as_offline(self):
        await self.bot.on_disconnect()
        first = self.bot._disconnected_at
        self.assertIsNotNone(first)
        await self.bot.on_disconnect()
        self.assertEqual(self.bot._disconnected_at, first, "the earliest moment counts")
        await self.bot.on_resumed()
        self.assertIsNone(self.bot._disconnected_at, "Discord replays what a resume missed")

    async def test_a_resume_doesnt_forget_the_downtime_before_this_start(self):
        self.bot._missed_since = 123.0
        await self.bot.on_disconnect()
        await self.bot.on_resumed()
        self.assertEqual(self.bot._missed_since, 123.0)

    async def test_someone_already_handled_is_left_alone(self):
        self.bot.service.db.member = AsyncMock(return_value={"joined_at": discord.utils.parse_time("2026-11-04T12:30:00+00:00").timestamp()})
        pages = iter([[self.member_page("2026-11-04T12:00:00+00:00")], []])

        async def listing(route, **kwargs):
            return next(pages)
        self.bot.http.request = listing
        await self.bot._catch_up(discord.utils.parse_time("2026-11-04T11:00:00+00:00").timestamp())
        self.bot.service.on_join.assert_not_awaited()


class ConnectionEvents(Base):
    """Real READY and RESUMED parsing in discord.py, with only HTTP and the database replaced."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.writes = []
        self.walks = []
        self.on_guild_read = None

        async def set_meta(key, value):
            self.writes.append(value)

        async def guild_row(guild_id):
            if self.on_guild_read:
                hook, self.on_guild_read = self.on_guild_read, None
                hook()
                await asyncio.sleep(0)
            return {"id": guild_id}

        self.bot.service = SimpleNamespace(
            on_join=AsyncMock(), on_leave=AsyncMock(), is_set_up=AsyncMock(return_value=True), tick=AsyncMock(),
            db=SimpleNamespace(member=AsyncMock(return_value=None), set_meta=set_meta, get_meta=AsyncMock(return_value=None), guild=guild_row,
                               set_guild_field=AsyncMock(), mark_departed=AsyncMock(), save_settings=AsyncMock()))
        self.bot.tree.sync = AsyncMock()
        real = self.bot._catch_up

        async def walk(since):
            self.walks.append(since)
            await real(since)
        self.bot._catch_up = walk

        async def listing(route, **kwargs):
            return []
        self.bot.http.request = listing
        self.bot._connection.guild_ready_timeout = 0.05

    def drop(self):
        self.bot.dispatch("disconnect")

    def ready(self):
        state = self.bot._connection
        state.parse_ready({"user": user(BOT, "altwarden", True), "session_id": "s", "resume_gateway_url": "wss://gateway.invalid",
                           "guilds": [{"id": str(GUILD), "unavailable": True}], "application": {"id": "123", "flags": 0}})
        state.parse_guild_create(GUILD_PAYLOAD)

    def checked(self, moment):
        return any(since <= moment - CATCH_UP_MARGIN for since in self.walks)

    async def test_a_drop_then_a_new_session_looks_from_the_drop(self):
        self.drop()
        await asyncio.sleep(0)
        gap = self.bot._disconnected_at
        self.ready()
        await asyncio.sleep(0.25)
        self.assertTrue(self.checked(gap))

    async def test_a_resume_right_after_a_new_session_keeps_the_first_gap(self):
        self.drop()
        await asyncio.sleep(0)
        gap = self.bot._disconnected_at
        self.ready()  # a new session, so nothing before it will be replayed
        await asyncio.sleep(0.01)  # inside the library's wait for its servers, before on_ready
        self.assertFalse(self.bot.is_ready())
        self.drop()
        await asyncio.sleep(0)
        self.bot._connection.parse_resumed({})
        await asyncio.sleep(0.25)
        self.assertTrue(self.checked(gap))

    async def test_a_drop_during_on_ready_stays_unchecked_until_the_next_session(self):
        self.bot._missed_since = 1000.0
        self.on_guild_read = self.drop
        self.ready()
        await asyncio.sleep(0.25)
        self.assertIsNotNone(self.bot._disconnected_at, "on_ready leaves the new drop alone")
        gap = self.bot._disconnected_at
        written = len(self.writes)
        await self.bot.minute_timer.coro(self.bot)
        self.assertEqual(len(self.writes), written, "the time can't move during the outage")
        self.ready()
        await asyncio.sleep(0.25)
        self.assertTrue(self.checked(gap))

    async def test_a_plain_resume_looks_for_nothing(self):
        self.drop()
        await asyncio.sleep(0)
        self.bot._connection.parse_resumed({})
        await asyncio.sleep(0.05)
        self.assertEqual(self.walks, [])
        self.assertIsNone(self.bot._disconnected_at)

    async def test_the_very_first_start_looks_for_nothing(self):
        self.ready()
        await asyncio.sleep(0.25)
        self.assertEqual(self.walks, [])
        self.assertEqual(len(self.writes), 1)


class Unbans(Base):
    async def test_no_ban_members_means_it_cant_say(self):
        self.answers[("GET", f"/guilds/{GUILD}/bans/{MEMBER}")] = self.forbidden()
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.is_banned(str(GUILD), str(MEMBER))

    async def test_no_ban_to_lift_counts_as_lifted(self):
        self.answers[("DELETE", f"/guilds/{GUILD}/bans/{MEMBER}")] = self.not_found()
        self.assertTrue(await self.gateway.unban(str(GUILD), str(MEMBER), "x"))

    async def test_a_refusal_doesnt(self):
        self.answers[("DELETE", f"/guilds/{GUILD}/bans/{MEMBER}")] = self.forbidden()
        self.assertFalse(await self.gateway.unban(str(GUILD), str(MEMBER), "x"))


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

    async def test_a_private_thread_pings_only_the_member(self):
        self.prepare()
        notice = Notice(content="hello", embeds=[{"description": "Tell us"}])
        result = await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), notice)
        self.assertEqual(result, str(THREAD))
        calls = {request[:2]: request[2] for request in self.requests}
        created = calls[("POST", f"/channels/{CHANNEL}/threads")]["json"]
        self.assertEqual((created["type"], created["invitable"], created["auto_archive_duration"]), (12, False, 10080))
        self.assertIn(("PUT", f"/channels/{THREAD}/thread-members/{MEMBER}"), calls)
        self.assertIn(("PUT", f"/channels/{THREAD}/messages/pins/555"), calls)
        self.assertEqual(notice.content, f"<@{MEMBER}>\nhello")
        self.assertEqual((notice.mention_users, notice.mention_roles), ([str(MEMBER)], []))

    async def test_a_long_message_still_fits_after_the_ping(self):
        self.prepare()
        notice = Notice(content="x" * 2000)
        await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), notice)
        self.assertLessEqual(len(notice.content), 2000)

    async def test_a_failed_pin_doesnt_lose_the_thread(self):
        self.prepare()
        self.answers[("PUT", f"/channels/{THREAD}/messages/pins/555")] = self.forbidden()
        self.assertEqual(await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), Notice(content="x")), str(THREAD))

    async def test_a_missing_permission_is_none(self):
        self.answers[("POST", f"/channels/{CHANNEL}/threads")] = self.forbidden()
        self.assertIsNone(await self.gateway.open_help_thread(str(CHANNEL), "member", str(MEMBER), Notice(content="x")))

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
        self.bot._ready.set()
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
