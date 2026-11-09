"""The bot's side of Discord: what a failure means, what a command checks, and what a server's health report says."""
import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aiohttp
import discord

import fakes
from altwarden import __main__ as entry_module
from altwarden import access, health, netintel, settings
from altwarden.bot import client
from altwarden.bot.client import BypassView, allowed, discord_allows, health_embed
from altwarden.crypto import new_master_key
from altwarden.netintel import NetIntel
from altwarden.notices import GREEN
from altwarden.ports import DISCORD_BUSY, MEMBER_GONE, DiscordUnavailable, GuildView, MemberInfo, Notice
from test_client import STAFF_ROLE, Client, Rank, fake_interaction, said
from test_startup import StubBot, free_port
from test_gateway import Base as GatewayBase
from test_gateway import CHANNEL, GUILD, MEMBER, ROLE_BOT, ROLE_LOW, THREAD, member, message, thread

DM_CHANNEL = 970000000000000040
STRANGER = 970000000000000013
FORUM = 970000000000000032
GUILD_ID = fakes.GUILD


def error(kind, status, code):
    return kind(SimpleNamespace(status=status, reason="x"), {"code": code, "message": "x"})


class Gateway(GatewayBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.guild = self.bot.get_guild(GUILD)
        self.bot._ready.set()
        self.bot.service = SimpleNamespace(on_join=AsyncMock(), on_leave=AsyncMock())

    def member_route(self, user_id=STRANGER):
        return ("GET", f"/guilds/{GUILD}/members/{user_id}")

    def real_member(self, user_id=STRANGER, roles=()):
        return discord.Member(data=member(user_id, roles), guild=self.guild, state=self.bot._connection)

    def fetches(self, user_id=STRANGER):
        return sum(request[:2] == self.member_route(user_id) for request in self.requests)


class WhoIsInTheServer(Gateway):
    async def test_someone_who_rejoins_isnt_still_read_as_gone(self):
        self.answers[self.member_route()] = self.not_found()
        self.assertIsNone(await self.gateway.member(str(GUILD), str(STRANGER)))
        self.answers[self.member_route()] = member(STRANGER)
        await self.bot.on_member_join(self.real_member())
        self.assertIsNotNone(await self.gateway.member(str(GUILD), str(STRANGER)))

    async def test_a_role_change_reaches_the_next_read(self):
        self.answers[self.member_route()] = member(STRANGER)
        self.assertNotIn(str(ROLE_LOW), (await self.gateway.member(str(GUILD), str(STRANGER))).role_ids)
        self.answers[self.member_route()] = member(STRANGER, [ROLE_LOW])
        before = self.real_member()
        await self.bot.on_member_update(before, self.real_member(roles=[ROLE_LOW]))
        self.assertIn(str(ROLE_LOW), (await self.gateway.member(str(GUILD), str(STRANGER))).role_ids)

    async def test_a_role_change_on_a_member_outside_the_cache_reaches_the_next_read(self):
        """Discord.py only adds such a member to its cache, and fires no event, so the live copy has to win over a remembered answer."""
        self.answers[self.member_route()] = member(STRANGER)
        await self.gateway.member(str(GUILD), str(STRANGER))
        self.bot._connection.parse_guild_member_update({"guild_id": str(GUILD), **member(STRANGER, [ROLE_LOW])})
        self.assertIn(str(ROLE_LOW), (await self.gateway.member(str(GUILD), str(STRANGER))).role_ids)

    async def test_a_remembered_answer_saves_a_call(self):
        self.answers[self.member_route()] = member(STRANGER)
        await self.gateway.member(str(GUILD), str(STRANGER))
        await self.gateway.member(str(GUILD), str(STRANGER))
        self.assertEqual(self.fetches(), 1)

    async def test_a_fresh_read_asks_discord_past_both_copies(self):
        self.answers[self.member_route(MEMBER)] = member(MEMBER, [ROLE_LOW])
        self.assertNotIn(str(ROLE_LOW), (await self.gateway.member(str(GUILD), str(MEMBER))).role_ids, "the gateway's copy has no such role")
        self.assertIn(str(ROLE_LOW), (await self.gateway.member(str(GUILD), str(MEMBER), fresh=True)).role_ids)
        self.assertEqual(self.fetches(MEMBER), 1)

    async def test_a_fresh_read_that_finds_nobody_says_so(self):
        self.answers[self.member_route(MEMBER)] = self.not_found()
        self.assertIsNone(await self.gateway.member(str(GUILD), str(MEMBER), fresh=True))

    async def test_a_fresh_read_with_discord_down_says_it_couldnt_tell(self):
        self.answers[self.member_route(MEMBER)] = error(discord.DiscordServerError, 503, 0)
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.member(str(GUILD), str(MEMBER), fresh=True)

    async def test_a_changed_role_forgets_what_members_could_do(self):
        self.answers[self.member_route()] = member(STRANGER)
        await self.gateway.member(str(GUILD), str(STRANGER))
        role = self.guild.get_role(ROLE_LOW)
        await self.bot.on_guild_role_update(role, role)
        await self.gateway.member(str(GUILD), str(STRANGER))
        self.assertEqual(self.fetches(), 2)

    async def test_a_screening_member_reads_as_pending(self):
        pending = {**member(STRANGER), "pending": True}
        self.answers[self.member_route()] = pending
        self.assertTrue((await self.gateway.member(str(GUILD), str(STRANGER))).pending)
        self.assertFalse((await self.gateway.member(str(GUILD), str(MEMBER))).pending)


class WhileAServerLoads(Gateway):
    async def test_a_loading_server_cant_say_who_is_in_it(self):
        self.guild.unavailable = True
        self.answers[self.member_route()] = member(STRANGER)
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.member(str(GUILD), str(STRANGER))
        self.assertEqual(self.gateway._members, {})

    async def test_nothing_is_remembered_before_discord_hands_servers_over(self):
        self.bot._ready.clear()
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.member("970000000000000099", str(STRANGER))
        self.assertEqual(self.gateway._members, {})

    async def test_a_server_the_bot_isnt_in_has_nobody_and_nothing_is_remembered(self):
        self.assertIsNone(await self.gateway.member("970000000000000099", str(STRANGER)))
        self.assertEqual(self.gateway._members, {})

    async def test_a_role_doesnt_read_as_deleted_while_a_server_loads(self):
        self.guild.unavailable = True
        self.assertEqual(await self.gateway.add_role(str(GUILD), str(MEMBER), str(ROLE_LOW), "x"), DISCORD_BUSY)

    async def test_no_server_yet_before_ready_isnt_read_as_left(self):
        self.bot._ready.clear()
        self.assertEqual(await self.gateway.add_role("970000000000000099", str(MEMBER), str(ROLE_LOW), "x"), DISCORD_BUSY)

    async def test_a_server_the_bot_isnt_in_still_says_so(self):
        self.assertEqual(await self.gateway.add_role("970000000000000099", str(MEMBER), str(ROLE_LOW), "x"), "AltWarden isn't in that server.")


class RolesAndRemovals(Gateway):
    def role_route(self):
        return ("PUT", f"/guilds/{GUILD}/members/{MEMBER}/roles/{ROLE_LOW}")

    async def test_a_member_who_left_during_the_role_change_is_gone_not_a_role_problem(self):
        self.answers[self.role_route()] = error(discord.NotFound, 404, 10007)
        self.assertEqual(await self.gateway.add_role(str(GUILD), str(MEMBER), str(ROLE_LOW), "x"), MEMBER_GONE)

    async def test_a_role_deleted_during_the_change_is_a_role_problem(self):
        self.answers[self.role_route()] = error(discord.NotFound, 404, 10011)
        self.assertEqual(await self.gateway.add_role(str(GUILD), str(MEMBER), str(ROLE_LOW), "x"), "That role no longer exists.")

    async def test_kicking_someone_who_already_left_counts_as_done(self):
        self.answers[("DELETE", f"/guilds/{GUILD}/members/{MEMBER}")] = error(discord.NotFound, 404, 10007)
        self.assertTrue(await self.gateway.kick(str(GUILD), str(MEMBER), "x"))

    async def test_a_refused_kick_still_fails(self):
        self.answers[("DELETE", f"/guilds/{GUILD}/members/{MEMBER}")] = self.forbidden()
        self.assertFalse(await self.gateway.kick(str(GUILD), str(MEMBER), "x"))

    async def test_no_permission_to_see_a_ban_isnt_read_as_no_ban(self):
        self.answers[("GET", f"/guilds/{GUILD}/bans/{MEMBER}")] = self.forbidden()
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.is_banned(str(GUILD), str(MEMBER))

    async def test_a_server_not_loaded_cant_say_there_is_no_ban(self):
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.is_banned("970000000000000099", str(MEMBER))

    async def test_a_recorded_ban_stays_when_the_bot_loses_ban_members(self):
        """A ban row is what catches an account's next one, and a 403 says nothing about whether the ban was lifted."""
        from altwarden.service import Service
        service = Service.__new__(Service)
        service.port = self.gateway
        self.answers[("GET", f"/guilds/{GUILD}/bans/{MEMBER}")] = self.forbidden()
        self.assertIsNone(await service._discord_ban(str(GUILD), str(MEMBER)))


class DirectMessages(Gateway):
    def prepare(self, answer):
        self.answers[("POST", "/users/@me/channels")] = {"id": str(DM_CHANNEL), "type": 1, "recipients": []}
        self.answers[("POST", f"/channels/{DM_CHANNEL}/messages")] = answer

    async def test_delivered_is_true(self):
        self.prepare(message(DM_CHANNEL))
        self.assertIs(await self.gateway.dm(str(MEMBER), Notice(content="x")), True)

    async def test_closed_dms_are_false(self):
        self.prepare(error(discord.Forbidden, 403, 50007))
        self.assertIs(await self.gateway.dm(str(MEMBER), Notice(content="x")), False)

    async def test_any_other_failure_is_none(self):
        for answer in (error(discord.DiscordServerError, 500, 0), error(discord.Forbidden, 403, 50278), error(discord.HTTPException, 400, 40003),
                       aiohttp.ServerDisconnectedError()):
            self.prepare(answer)
            self.assertIsNone(await self.gateway.dm(str(MEMBER), Notice(content="x")), answer)

    async def test_a_user_who_cant_be_found_is_none(self):
        self.bot._connection._users.clear()
        self.answers[("GET", f"/users/{MEMBER}")] = self.not_found()
        self.assertIsNone(await self.gateway.dm(str(MEMBER), Notice(content="x")))


class PostsInChannels(Gateway):
    def forum(self):
        forum = discord.ForumChannel(state=self.bot._connection, guild=self.guild, data={
            "id": str(FORUM), "type": 15, "name": "forum", "position": 1, "permission_overwrites": [], "parent_id": None, "guild_id": str(GUILD), "nsfw": False})
        self.guild._add_channel(forum)

    async def test_a_message_someone_else_deleted_counts_as_deleted(self):
        self.answers[("DELETE", f"/channels/{CHANNEL}/messages/555")] = self.not_found()
        self.assertTrue(await self.gateway.delete_message(str(CHANNEL), "555"))

    async def test_a_refused_delete_still_fails(self):
        self.answers[("DELETE", f"/channels/{CHANNEL}/messages/555")] = self.forbidden()
        self.assertFalse(await self.gateway.delete_message(str(CHANNEL), "555"))

    async def test_a_forum_channel_is_a_plain_failure_everywhere(self):
        self.forum()
        self.assertIsNone(await self.gateway.send(str(FORUM), Notice(content="x")))
        self.assertFalse(await self.gateway.delete_message(str(FORUM), "1"))
        self.assertFalse(await self.gateway.edit_message(str(FORUM), "1", Notice(content="x")))
        self.assertFalse(await self.gateway.pin(str(FORUM), "1"))


class HelpThreads(Gateway):
    def opening(self):
        self.answers[("POST", f"/channels/{CHANNEL}/threads")] = thread()
        self.answers[("POST", f"/channels/{THREAD}/messages")] = message(THREAD)

    def calls(self, method):
        return [request for request in self.requests if request[0] == method]

    async def test_a_first_post_that_fails_takes_its_thread_with_it(self):
        self.opening()
        self.answers[("POST", f"/channels/{THREAD}/messages")] = error(discord.HTTPException, 400, 50035)
        self.assertIsNone(await self.gateway.open_help_thread(str(CHANNEL), "x", str(MEMBER), Notice(content="hi")))
        self.assertIn(("DELETE", f"/channels/{THREAD}"), [request[:2] for request in self.requests])

    async def test_a_member_who_cant_be_added_takes_the_thread_with_them(self):
        self.opening()
        self.answers[("PUT", f"/channels/{THREAD}/thread-members/{MEMBER}")] = self.forbidden()
        self.assertIsNone(await self.gateway.open_help_thread(str(CHANNEL), "x", str(MEMBER), Notice(content="hi")))
        self.assertIn(("DELETE", f"/channels/{THREAD}"), [request[:2] for request in self.requests])

    async def test_a_thread_that_cant_be_deleted_either_is_still_a_plain_failure(self):
        self.opening()
        self.answers[("POST", f"/channels/{THREAD}/messages")] = error(discord.HTTPException, 400, 50035)
        self.answers[("DELETE", f"/channels/{THREAD}")] = self.forbidden()
        self.assertIsNone(await self.gateway.open_help_thread(str(CHANNEL), "x", str(MEMBER), Notice(content="hi")))

    async def test_a_thread_that_opens_stays(self):
        self.opening()
        self.assertEqual(await self.gateway.open_help_thread(str(CHANNEL), "x", str(MEMBER), Notice(content="hi")), str(THREAD))
        self.assertNotIn(("DELETE", f"/channels/{THREAD}"), [request[:2] for request in self.requests])

    async def test_closing_an_archived_thread_unarchives_it_first(self):
        """channel.mdx: an edit needs the thread unarchived, or being unarchived by that request."""
        self.answers[("GET", f"/channels/{THREAD}")] = thread(archived=True)
        self.answers[("PATCH", f"/channels/{THREAD}")] = thread()
        self.assertTrue(await self.gateway.close_thread(str(THREAD)))
        bodies = [request[2]["json"] for request in self.calls("PATCH")]
        self.assertEqual(bodies[0]["archived"], False)
        self.assertEqual((bodies[1]["archived"], bodies[1]["locked"]), (True, True))
        self.assertEqual(len(bodies), 2)

    async def test_closing_an_open_thread_takes_one_edit(self):
        self.answers[("GET", f"/channels/{THREAD}")] = thread()
        self.answers[("PATCH", f"/channels/{THREAD}")] = thread(archived=True)
        self.assertTrue(await self.gateway.close_thread(str(THREAD)))
        self.assertEqual(len(self.calls("PATCH")), 1)

    async def test_a_thread_already_closed_is_closed(self):
        done = thread(archived=True)
        done["thread_metadata"]["locked"] = True
        self.answers[("GET", f"/channels/{THREAD}")] = done
        self.assertTrue(await self.gateway.close_thread(str(THREAD)))
        self.assertEqual(self.calls("PATCH"), [])

    async def test_a_blip_isnt_read_as_a_deleted_thread(self):
        self.answers[("GET", f"/channels/{THREAD}")] = error(discord.DiscordServerError, 500, 0)
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.reopen_thread(str(THREAD))
        self.assertFalse(await self.gateway.close_thread(str(THREAD)), "closing reports a plain failure, and its caller keeps the link")

    async def test_a_blip_while_reopening_isnt_read_as_gone(self):
        self.answers[("GET", f"/channels/{THREAD}")] = thread(archived=True)
        self.answers[("PATCH", f"/channels/{THREAD}")] = error(discord.DiscordServerError, 500, 0)
        with self.assertRaises(DiscordUnavailable):
            await self.gateway.reopen_thread(str(THREAD))

    async def test_a_refused_reopen_is_false(self):
        self.answers[("GET", f"/channels/{THREAD}")] = thread(archived=True)
        self.answers[("PATCH", f"/channels/{THREAD}")] = self.forbidden()
        self.assertFalse(await self.gateway.reopen_thread(str(THREAD)))

    async def test_reopening_for_a_member_adds_them_back(self):
        self.answers[("GET", f"/channels/{THREAD}")] = thread()
        self.assertTrue(await self.gateway.reopen_thread(str(THREAD), str(MEMBER)))
        self.assertIn(("PUT", f"/channels/{THREAD}/thread-members/{MEMBER}"), [request[:2] for request in self.requests])

    async def test_they_are_added_after_the_thread_is_unarchived(self):
        self.answers[("GET", f"/channels/{THREAD}")] = thread(archived=True)
        self.answers[("PATCH", f"/channels/{THREAD}")] = thread()
        await self.gateway.reopen_thread(str(THREAD), str(MEMBER))
        order = [request[:2] for request in self.requests if request[0] in ("PATCH", "PUT")]
        self.assertEqual(order, [("PATCH", f"/channels/{THREAD}"), ("PUT", f"/channels/{THREAD}/thread-members/{MEMBER}")])


class TheServerView(Gateway):
    async def test_a_role_change_shows_on_the_next_read(self):
        before = await self.gateway.guild(str(GUILD))
        self.guild.get_role(ROLE_LOW).name = "Renamed"
        self.assertEqual(await self.gateway.guild(str(GUILD)), before, "without an event the view stays for its half minute")
        role = self.guild.get_role(ROLE_LOW)
        await self.bot.on_guild_role_update(role, role)
        names = [item["name"] for item in (await self.gateway.guild(str(GUILD))).roles]
        self.assertIn("Renamed", names)

    async def test_each_kind_of_change_drops_the_view(self):
        role = self.guild.get_role(ROLE_LOW)
        channel = self.guild.get_channel(CHANNEL)
        for fire in (lambda: self.bot.on_guild_role_create(role), lambda: self.bot.on_guild_role_delete(role),
                     lambda: self.bot.on_guild_channel_create(channel), lambda: self.bot.on_guild_channel_delete(channel),
                     lambda: self.bot.on_guild_channel_update(channel, channel), lambda: self.bot.on_guild_update(self.guild, self.guild)):
            await self.gateway.guild(str(GUILD))
            self.assertIn(str(GUILD), self.gateway._guilds)
            await fire()
            self.assertNotIn(str(GUILD), self.gateway._guilds)

    async def test_the_bots_own_new_role_shows(self):
        await self.gateway.guild(str(GUILD))
        me = self.guild.me
        await self.bot.on_member_update(me, me)
        self.assertNotIn(str(GUILD), self.gateway._guilds)

    async def test_another_members_change_keeps_the_view(self):
        await self.gateway.guild(str(GUILD))
        other = self.guild.get_member(MEMBER)
        await self.bot.on_member_update(other, other)
        self.assertIn(str(GUILD), self.gateway._guilds)

    def private_channel(self, channel_id, name="staff"):
        channel = discord.TextChannel(state=self.bot._connection, guild=self.guild, data={
            "id": str(channel_id), "type": 0, "name": name, "position": 2, "parent_id": None, "guild_id": str(GUILD), "nsfw": False,
            "permission_overwrites": [{"id": str(GUILD), "type": 0, "allow": "0", "deny": str(1 << 10)}]})
        self.guild._add_channel(channel)

    async def test_it_lists_the_channels_everyone_can_read(self):
        self.private_channel(970000000000000033)
        view = await self.gateway.guild(str(GUILD))
        self.assertEqual(view.public_channels, [str(CHANNEL)])

    async def test_it_knows_which_role_is_the_bots_top_one(self):
        view = await self.gateway.guild(str(GUILD))
        self.assertEqual(view.bot_top_role_id, str(ROLE_BOT))


LOW, MIDDLE, TOP = "970000000000000061", "970000000000000062", "970000000000000063"


def server(*permissions, roles=(), channels=(), channel_permissions=None, public=(), top=5, top_id=""):
    all_roles = [{"id": fakes.VERIFIED_ROLE, "name": "Verified", "color": 0, "position": 2, "managed": False, "mentionable": True},
                 {"id": fakes.GUILD, "name": "@everyone", "color": 0, "position": 0, "managed": False, "mentionable": False}, *roles]
    all_channels = [{"id": fakes.CHANNEL, "name": "verify", "type": "text", "category": None, "position": 0},
                    {"id": fakes.LOG_CHANNEL, "name": "logs", "type": "text", "category": None, "position": 1}, *channels]
    held = frozenset({"view_channel", "send_messages", "embed_links"})
    return GuildView(id=fakes.GUILD, name="Test", roles=all_roles, channels=all_channels, bot_permissions=frozenset(permissions or ("administrator",)), bot_top_role=top,
                     bot_top_role_id=top_id, channel_permissions=channel_permissions or {fakes.CHANNEL: held, fakes.LOG_CHANNEL: held}, public_channels=list(public))


def rules(**changes):
    """A set-up server whose logs reach staff, so a test starts from a healthy report."""
    document = settings.defaults()
    document["core"].update(verified_role=fakes.VERIFIED_ROLE, channel=fakes.CHANNEL)
    document["core"]["logs"] = {"enabled": True, "modules": {"general": fakes.LOG_CHANNEL}}
    for key, value in changes.items():
        document[key] = {**document[key], **value}
    return settings.normalize(document)


def titles(report):
    return [issue["title"] for issue in report["issues"]]


class RaidAlerts(unittest.TestCase):
    NOBODY = "Raid mode can't tell staff"

    def test_a_raid_with_the_logs_off_tells_nobody(self):
        document = rules()
        document["core"]["logs"]["enabled"] = False
        report = health.report(server(), document)
        self.assertIn(self.NOBODY, titles(report))
        self.assertFalse(report["healthy"])

    def test_a_raid_with_neither_of_its_channels_set_tells_nobody(self):
        document = rules()
        document["core"]["logs"]["modules"] = {"honeypot": fakes.LOG_CHANNEL}
        self.assertIn(self.NOBODY, titles(health.report(server(), document)))

    def test_the_raid_channel_or_the_general_channel_is_enough(self):
        for module in ("raid", "general"):
            document = rules()
            document["core"]["logs"]["modules"] = {module: fakes.LOG_CHANNEL}
            self.assertNotIn(self.NOBODY, titles(health.report(server(), document)), module)

    def test_raid_mode_off_has_nobody_to_tell(self):
        document = rules(raid={"enabled": False})
        document["core"]["logs"]["enabled"] = False
        self.assertNotIn(self.NOBODY, titles(health.report(server(), document)))

    def test_it_isnt_listed_as_a_feature_warning(self):
        document = rules()
        document["core"]["logs"]["enabled"] = False
        self.assertEqual(health.feature_warnings(server(), document), {})


class AppealsAndRaidRoles(unittest.TestCase):
    def test_an_appeals_channel_thats_gone_is_an_issue(self):
        report = health.report(server(), rules(appeals={"channel": "970000000000000050"}))
        self.assertIn("Appeals channel is missing", titles(report))

    def test_an_appeals_channel_the_bot_cant_post_in_is_an_issue(self):
        held = frozenset({"view_channel", "send_messages", "embed_links"})
        appeals = {"id": "970000000000000050", "name": "appeals", "type": "text", "category": None, "position": 3}
        report = health.report(server(channels=[appeals], channel_permissions={fakes.CHANNEL: held, fakes.LOG_CHANNEL: held, appeals["id"]: frozenset()}),
                               rules(appeals={"channel": appeals["id"]}))
        self.assertIn("AltWarden can't work in #appeals", titles(report))

    def test_appeals_off_needs_no_channel(self):
        self.assertTrue(health.report(server(), rules(appeals={"enabled": False, "channel": "970000000000000050"}))["healthy"])

    def test_no_appeals_channel_chosen_isnt_an_issue(self):
        self.assertTrue(health.report(server(), rules())["healthy"])

    def test_an_appeals_role_thats_gone_is_an_issue(self):
        self.assertIn("Appeals role is missing", titles(health.report(server(), rules(appeals={"role": "970000000000000050"}))))
        self.assertTrue(health.report(server(), rules(appeals={"enabled": False, "role": "970000000000000050"}))["healthy"])

    def test_a_raid_alert_role_thats_gone_is_an_issue(self):
        self.assertIn("Raid alert role is missing", titles(health.report(server(), rules(raid={"alert_role": "970000000000000050"}))))
        self.assertTrue(health.report(server(), rules(raid={"enabled": False, "alert_role": "970000000000000050"}))["healthy"])

    def test_a_raid_alert_role_that_cant_be_pinged_is_an_issue(self):
        role = {"id": LOW, "name": "Mods", "color": 0, "position": 1, "managed": False, "mentionable": False}
        report = health.report(server("manage_roles", "kick_members", "ban_members", roles=[role]), rules(raid={"alert_role": LOW}))
        self.assertIn("Mods can't be pinged", titles(report))

    def test_appeals_need_ban_members(self):
        self.assertIn("Appeals", health.needed_permissions(rules())["ban_members"])
        self.assertNotIn("Appeals", health.needed_permissions(rules(appeals={"enabled": False}))["ban_members"])


class RaidPermissions(unittest.TestCase):
    def strict_off(self):
        """Nothing here bans or kicks on an ordinary day, so only a raid can need those permissions."""
        document = rules(appeals={"enabled": False})
        for check in document["checks"].values():
            check["enabled"] = False
        return document

    def test_a_raid_can_need_ban_members(self):
        needs = health.needed_permissions(self.strict_off())
        self.assertEqual(needs["ban_members"], ["Raid mode"], "a raid turns Alt accounts on, and a banned account's alt stays at Ban")
        self.assertEqual(needs["kick_members"], ["Raid mode"])

    def test_a_raid_that_never_bans_doesnt_ask_for_it(self):
        document = self.strict_off()
        document["checks"]["alt_account"].update(banned_alt_action="kick")
        self.assertNotIn("ban_members", health.needed_permissions(document))

    def test_raid_mode_off_asks_for_nothing(self):
        document = self.strict_off()
        document["raid"]["enabled"] = False
        needs = health.needed_permissions(document)
        self.assertNotIn("ban_members", needs)
        self.assertNotIn("kick_members", needs)

    def test_a_check_that_bans_anyway_is_still_named(self):
        document = self.strict_off()
        document["checks"]["vpn"].update(enabled=True, action="ban")
        self.assertIn("VPN and proxy", health.needed_permissions(document)["ban_members"])


class EqualPositions(unittest.TestCase):
    """permissions.mdx: roles with the same position are sorted by ID. discord/role.py: the higher ID sorts lower."""

    def report(self, role_id, bot_role_id):
        document = rules()
        document["core"]["verified_role"] = role_id
        role = {"id": role_id, "name": "Level", "color": 0, "position": 5, "managed": False, "mentionable": True}
        return health.report(server(roles=[role], top=5, top_id=bot_role_id), document)

    def test_a_tied_role_with_the_higher_id_sits_below_the_bot(self):
        self.assertNotIn("AltWarden's role is below Level", titles(self.report(MIDDLE, LOW)))

    def test_a_tied_role_with_the_lower_id_sits_above_the_bot(self):
        self.assertIn("AltWarden's role is below Level", titles(self.report(LOW, MIDDLE)))

    def test_a_role_higher_or_lower_ignores_ids(self):
        document = rules()
        document["core"]["verified_role"] = MIDDLE
        high = {"id": MIDDLE, "name": "High", "color": 0, "position": 6, "managed": False, "mentionable": True}
        self.assertIn("AltWarden's role is below High", titles(health.report(server(roles=[high], top=5, top_id=LOW), document)))
        low = {**high, "position": 4}
        self.assertNotIn("AltWarden's role is below High", titles(health.report(server(roles=[low], top=5, top_id=TOP), document)))

    def test_saving_a_tied_role_uses_the_same_order(self):
        viewer = access.Viewer(fakes.STAFF, frozenset(), frozenset({"administrator"}), False)
        role = {"id": LOW, "name": "Level", "color": 0, "position": 5, "managed": False, "mentionable": True}
        document = rules()
        document["core"]["verified_role"] = LOW
        refused = health.role_refusals(server(roles=[role], top=5, top_id=MIDDLE), None, document, viewer)
        self.assertIn("drag AltWarden's role above Level", refused[0]["text"])
        role = {**role, "id": TOP}
        document["core"]["verified_role"] = TOP
        self.assertEqual(health.role_refusals(server(roles=[role], top=5, top_id=MIDDLE), None, document, viewer), [])


class TheVerifyPost(unittest.TestCase):
    TITLE = "The verification message isn't posted"

    def test_no_post_is_an_issue(self):
        report = health.report(server(), rules(), verify_post=None)
        self.assertIn(self.TITLE, titles(report))
        self.assertFalse(report["healthy"])

    def test_a_post_on_record_is_fine(self):
        self.assertNotIn(self.TITLE, titles(health.report(server(), rules(), verify_post=f"{fakes.CHANNEL}:5")))

    def test_a_caller_that_didnt_look_isnt_told_it_is_missing(self):
        self.assertNotIn(self.TITLE, titles(health.report(server(), rules())))


class ChosenChannels(unittest.TestCase):
    def test_a_forum_or_voice_channel_cant_be_chosen(self):
        for kind in ("forum", "voice", "stage"):
            channel = {"id": "970000000000000050", "name": "x", "type": kind, "category": None, "position": 3}
            document = rules(appeals={"channel": "970000000000000050"})
            refused = health.channel_refusals(server(channels=[channel]), None, document)
            self.assertEqual(refused[0]["item"], "appeals", kind)

    def test_a_text_or_news_channel_can(self):
        for kind in ("text", "news"):
            channel = {"id": "970000000000000050", "name": "x", "type": kind, "category": None, "position": 3}
            self.assertEqual(health.channel_refusals(server(channels=[channel]), None, rules(appeals={"channel": "970000000000000050"})), [], kind)


class ChosenRoles(unittest.TestCase):
    viewer = access.Viewer(fakes.STAFF, frozenset({TOP}), frozenset({"manage_guild"}), False)

    def refused(self, document, before=None):
        top = {"id": TOP, "name": "Top", "color": 0, "position": 4, "managed": False, "mentionable": False}
        return health.role_refusals(server(roles=[top]), before, document, self.viewer)

    def every_way(self, role_id):
        alerts = rules()
        alerts["core"]["alerts"] = {"enabled": True, "role": None, "off": [], "roles": {"raid": role_id}}
        desk = rules()
        desk["core"]["help_desk"].update(enabled=True, support_role=role_id)
        return {"alert": alerts, "raid": rules(raid={"alert_role": role_id}), "appeals": rules(appeals={"role": role_id}), "support": desk,
                "whitelist": rules(honeypot={"whitelist_roles": [role_id]})}

    def test_a_role_from_elsewhere_is_refused_in_each_place(self):
        for name, document in self.every_way("970000000000000050").items():
            self.assertIn("no longer exists", self.refused(document)[0]["text"], name)

    def test_everyone_is_refused_in_each_place(self):
        for name, document in self.every_way(fakes.GUILD).items():
            self.assertIn("@everyone", self.refused(document)[0]["text"], name)

    def test_a_real_role_passes_in_each_place(self):
        for name, document in self.every_way(fakes.VERIFIED_ROLE).items():
            self.assertEqual(self.refused(document), [], name)

    def test_a_role_above_the_person_saving_can_still_be_pinged(self):
        """Only a role AltWarden hands out could raise someone's own rank."""
        self.assertEqual(self.refused(rules(raid={"alert_role": TOP})), [])

    def test_a_role_that_was_already_set_is_left_alone(self):
        document = rules(raid={"alert_role": "970000000000000050"})
        self.assertEqual(self.refused(document, before=document), [])


class Notices(unittest.TestCase):
    OPEN = "@everyone can read channels beyond the verification channel"
    COUNTRY = "A country rule is on and the VPN check is off"

    def extra(self, count):
        return [{"id": str(970000000000000100 + index), "name": f"open-{index}", "type": "text", "category": None, "position": 5} for index in range(count)]

    def titled(self, report):
        return [notice["title"] for notice in report["notices"]]

    def test_channels_everyone_can_read_are_a_notice_and_the_server_stays_healthy(self):
        channels = self.extra(1)
        report = health.report(server(channels=channels, public=[channels[0]["id"]]), rules())
        self.assertIn(self.OPEN, self.titled(report))
        self.assertIn("#open-0", json.dumps(report["notices"]))
        self.assertTrue(report["healthy"])

    def test_the_verification_channel_doesnt_count(self):
        self.assertNotIn(self.OPEN, self.titled(health.report(server(public=[fakes.CHANNEL]), rules())))

    def test_the_honeypot_doesnt_count_because_it_is_meant_to_be_seen(self):
        document = rules(honeypot={"enabled": True, "channel": fakes.LOG_CHANNEL})
        self.assertNotIn(self.OPEN, self.titled(health.report(server(public=[fakes.LOG_CHANNEL]), document)))
        document = rules(honeypot={"enabled": False, "channel": fakes.LOG_CHANNEL})
        self.assertIn(self.OPEN, self.titled(health.report(server(public=[fakes.LOG_CHANNEL]), document)))

    def test_a_long_list_is_capped_and_says_how_many_more(self):
        channels = self.extra(14)
        report = health.report(server(channels=channels, public=[channel["id"] for channel in channels]), rules())
        text = json.dumps(report["notices"])
        self.assertIn("#open-9", text)
        self.assertNotIn("#open-10", text)
        self.assertIn("4 more", text)

    def test_a_country_rule_without_the_vpn_check_is_a_notice(self):
        document = rules()
        document["checks"]["geogate"].update(enabled=True, countries=["US"])
        document["checks"]["vpn"]["enabled"] = False
        report = health.report(server(), document)
        self.assertIn(self.COUNTRY, self.titled(report))
        self.assertTrue(report["healthy"])

    def test_with_the_vpn_check_on_there_is_nothing_to_say(self):
        document = rules()
        document["checks"]["geogate"].update(enabled=True, countries=["US"])
        document["checks"]["vpn"]["enabled"] = True
        self.assertNotIn(self.COUNTRY, self.titled(health.report(server(), document)))

    def test_no_country_rule_has_nothing_to_say(self):
        document = rules()
        document["checks"]["geogate"]["enabled"] = False
        document["checks"]["vpn"]["enabled"] = False
        self.assertNotIn(self.COUNTRY, self.titled(health.report(server(), document)))


class WhatTheServiceKnows(unittest.IsolatedAsyncioTestCase):
    def service(self, *, row=None, refused=None, lists=()):
        async def guild(_):
            return row
        return SimpleNamespace(db=SimpleNamespace(guild=guild), lookup_refused=lambda _: refused, net=SimpleNamespace(list_status=lambda: list(lists), ready=True))

    def fine(self, name="tor"):
        return {"name": name, "age_days": 1.0, "rows": 100}

    async def report(self, service, *, alert_role=fakes.VERIFIED_ROLE):
        document = rules()
        document["core"]["alerts"]["role"] = alert_role
        return await health.full_report(service, fakes.GUILD, server(), document)

    async def test_alerts_with_no_role_are_a_notice(self):
        self.assertIn("Alerts have no role to ping", self.titled(await self.report(self.service(lists=[self.fine()]), alert_role=None)))

    def titled(self, report):
        return [notice["title"] for notice in report["notices"]]

    async def test_it_carries_the_lookup_latch_and_the_lists(self):
        refused = {"at": 5.0, "message": "out of queries"}
        report = await self.report(self.service(refused=refused, lists=[self.fine()]))
        self.assertEqual(report["lookup_refused"], refused)
        self.assertEqual(report["lists"], [self.fine()])

    async def test_a_refused_lookup_is_a_notice_with_its_message(self):
        report = await self.report(self.service(refused={"at": 5.0, "message": "out of queries"}))
        self.assertIn("The outside VPN lookup isn't answering", self.titled(report))
        self.assertIn("out of queries", json.dumps(report["notices"]))
        self.assertTrue(report["healthy"])

    async def test_no_refusal_has_nothing_to_say(self):
        report = await self.report(self.service(lists=[self.fine()]))
        self.assertIsNone(report["lookup_refused"])
        self.assertEqual(report["notices"], [])

    async def test_a_list_that_has_gone_stale_is_a_notice(self):
        report = await self.report(self.service(lists=[self.fine("firehol"), {"name": "tor", "age_days": 30.0, "rows": 5}]))
        self.assertIn("tor", json.dumps(report["notices"]))
        self.assertNotIn("firehol", json.dumps(report["notices"]))

    async def test_a_list_within_its_refresh_time_is_fine(self):
        report = await self.report(self.service(lists=[{"name": "tor", "age_days": netintel.REFRESH_SECONDS / 86400, "rows": 5}]))
        self.assertEqual(report["notices"], [])

    async def test_a_list_never_downloaded_or_read_empty_is_a_notice(self):
        for row in ({"name": "torlist", "age_days": None, "rows": 0}, {"name": "torlist", "age_days": 1.0, "rows": 0}):
            self.assertIn("torlist", json.dumps((await self.report(self.service(lists=[row])))["notices"]), row)

    async def test_it_looks_for_the_verify_post_on_a_server_thats_set_up(self):
        report = await self.report(self.service(row={"setup_done": 1, "verify_message_id": None}))
        self.assertIn("The verification message isn't posted", titles(report))
        report = await self.report(self.service(row={"setup_done": 1, "verify_message_id": "1:2"}))
        self.assertNotIn("The verification message isn't posted", titles(report))

    async def test_a_server_not_set_up_yet_has_no_post_to_look_for(self):
        report = await self.report(self.service(row={"setup_done": 0, "verify_message_id": None}))
        self.assertNotIn("The verification message isn't posted", titles(report))


class DeletedPosts(Gateway):
    """The bot hears when its Verify post goes, so the report can say so."""

    def rows(self):
        self.written = []

        async def run(sql, values=()):
            self.written.append((sql, values))
            return 1
        self.bot.service.db = SimpleNamespace(run=run)

    async def test_a_deleted_message_is_matched_against_the_post(self):
        self.rows()
        await self.bot.on_raw_message_delete(SimpleNamespace(guild_id=GUILD, channel_id=CHANNEL, message_id=555))
        sql, values = self.written[0]
        self.assertIn("verify_message_id = NULL", sql)
        self.assertEqual(values, (str(GUILD), f"{CHANNEL}:555"))

    async def test_a_purge_is_matched_too(self):
        self.rows()
        await self.bot.on_raw_bulk_message_delete(SimpleNamespace(guild_id=GUILD, channel_id=CHANNEL, message_ids={555, 556}))
        self.assertEqual(sorted(values[1] for _, values in self.written), [f"{CHANNEL}:555", f"{CHANNEL}:556"])

    async def test_a_dm_has_no_post(self):
        self.rows()
        await self.bot.on_raw_message_delete(SimpleNamespace(guild_id=None, channel_id=CHANNEL, message_id=555))
        await self.bot.on_raw_bulk_message_delete(SimpleNamespace(guild_id=None, channel_id=CHANNEL, message_ids={555}))
        self.assertEqual(self.written, [])


class Commands(Client):
    def target(self, user_id=fakes.OLD_USER, *, bot=False):
        return SimpleNamespace(id=int(user_id), mention=f"<@{user_id}>", bot=bot, name="someone")

    def embed_text(self, interaction):
        return interaction.said[0][1]["embed"].description


class AgainstATarget(Commands):
    async def test_verify_refuses_someone_at_your_level(self):
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        interaction = fake_interaction()
        await self.command("verify-user")(interaction, self.target())
        self.assertIn("at or above yours", said(interaction))
        self.assertFalse(self.port.did("add_role"))

    async def test_verify_refuses_a_role_above_your_own(self):
        interaction = fake_interaction()
        interaction.user.role_ids = (fakes.UNVERIFIED_ROLE,)
        await self.command("verify-user")(interaction, self.target())
        self.assertIn("verified role sits at or above", said(interaction))
        self.assertFalse(self.port.did("add_role"))

    async def test_the_right_click_commands_refuse_the_same(self):
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        for name in ("Verify", "Reset", "Create Bypass"):
            interaction = fake_interaction()
            await self.bot.tree.get_command(name, type=discord.AppCommandType.user).callback(interaction, self.target())
            self.assertIn("at or above yours", said(interaction), name)

    async def test_reset_refuses_someone_at_your_level_and_changes_nothing(self):
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        await self.db.touch_member(GUILD_ID, fakes.OLD_USER)
        await self.db.mark_verified(GUILD_ID, fakes.OLD_USER, "staff")
        interaction = fake_interaction()
        await self.command("reset-user")(interaction, self.target())
        self.assertIn("at or above yours", said(interaction))
        self.assertEqual((await self.db.member(GUILD_ID, fakes.OLD_USER))["status"], "verified")

    async def test_a_banned_accounts_records_take_ban_members(self):
        self.port.banned.add(fakes.OLD_USER)
        interaction = fake_interaction()
        await self.command("reset-user")(interaction, self.target())
        self.assertIn("takes Ban Members", said(interaction))

    async def test_a_bypass_refuses_someone_at_your_level(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        interaction = fake_interaction()
        await self.command("create-bypass")(interaction, self.target())
        self.assertIn("at or above yours", said(interaction))
        self.assertNotIn("view", interaction.said[0][1])

    async def test_trusting_checks_both_accounts(self):
        self.port.add_member(fakes.OTHER_USER, roles=(STAFF_ROLE,))
        for first, second in ((fakes.OLD_USER, fakes.OTHER_USER), (fakes.OTHER_USER, fakes.OLD_USER)):
            interaction = fake_interaction()
            await self.command("trust-accounts")(interaction, self.target(first), self.target(second))
            self.assertIn("at or above yours", said(interaction))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM trusted_pairs"), 0)

    async def test_an_administrator_passes(self):
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        interaction = fake_interaction(perms=("administrator",))
        await self.command("verify-user")(interaction, self.target())
        self.assertIn("is verified", said(interaction))

    async def test_discord_not_answering_is_said_plainly(self):
        self.port.discord_down = True
        interaction = fake_interaction()
        await self.command("verify-user")(interaction, self.target())
        self.assertIn(DISCORD_BUSY, said(interaction))


class Replies(Commands):
    def members(self, *ids):
        async def walk(limit=None):
            for user_id in ids:
                yield SimpleNamespace(id=int(user_id), bot=False, get_role=lambda _: True)
        return walk

    async def test_an_import_says_no_roles_were_given_and_how_they_get_one(self):
        interaction = fake_interaction()
        interaction.guild.id = int(GUILD_ID)
        interaction.guild.fetch_members = self.members(fakes.OLD_USER, fakes.OTHER_USER)
        await self.command("import-members")(interaction, SimpleNamespace(id=5, is_default=lambda: False))
        await asyncio.gather(*self.bot.imports.values())
        self.assertIn("Marked 2 members as verified", said(interaction))
        self.assertIn("No roles were given", said(interaction))
        self.assertIn("pressing Verify", said(interaction))
        self.assertNotIn("won't be asked", said(interaction))

    async def test_an_import_of_one_is_singular(self):
        interaction = fake_interaction()
        interaction.guild.id = int(GUILD_ID)
        interaction.guild.fetch_members = self.members(fakes.OTHER_USER)
        await self.command("import-members")(interaction, SimpleNamespace(id=5, is_default=lambda: False))
        await asyncio.gather(*self.bot.imports.values())
        self.assertIn("Marked 1 member as verified", said(interaction))

    async def test_a_reset_names_a_role_it_couldnt_take(self):
        self.port.role_refusals[fakes.VERIFIED_ROLE] = "That role no longer exists."
        interaction = fake_interaction()
        await self.command("reset-user")(interaction, self.target())
        self.assertIn("A role change failed: That role no longer exists.", said(interaction))

    async def test_a_reset_says_when_a_banned_accounts_hashes_stay(self):
        self.port.banned.add(fakes.OLD_USER)
        interaction = fake_interaction(perms=("manage_roles", "ban_members"))
        await self.command("reset-user")(interaction, self.target())
        self.assertIn("hashes stay", said(interaction))

    async def test_a_plain_reset_says_neither(self):
        interaction = fake_interaction()
        await self.command("reset-user")(interaction, self.target())
        self.assertNotIn("hashes stay", said(interaction))
        self.assertNotIn("role change failed", said(interaction))


class AfterUninstall(Commands):
    async def test_trusting_after_uninstall_leaves_nothing_behind(self):
        await self.db.forget_guild(GUILD_ID)
        self.service.forget_cached(GUILD_ID)
        interaction = fake_interaction()
        await self.command("trust-accounts")(interaction, self.target(), self.target(fakes.OTHER_USER))
        self.assertIn("isn't set up", said(interaction))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM trusted_pairs"), 0)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM audit"), 0)


class WhoDidIt(Commands):
    async def test_trusting_reaches_the_staff_log(self):
        interaction = fake_interaction()
        await self.command("trust-accounts")(interaction, self.target(), self.target(fakes.OTHER_USER))
        self.assertIn("Accounts trusted", json.dumps([notice.embeds for _, notice in self.port.sent]))
        row = await self.db.one("SELECT actor_name FROM audit WHERE kind = 'trust'")
        self.assertEqual(row["actor_name"], "staff")

    async def test_raid_records_name_who_ran_it(self):
        for state, kind in (("on", "raid_start"), ("off", "raid_stop")):
            interaction = fake_interaction(perms=("manage_guild", "kick_members"))
            await self.command("raid")(interaction, SimpleNamespace(value=state))
            row = await self.db.one("SELECT actor_id, actor_name FROM audit WHERE kind = ?", (kind,))
            self.assertEqual((row["actor_id"], row["actor_name"]), (fakes.STAFF, "staff"), state)


class SettingsReply(Commands):
    async def reply(self):
        interaction = fake_interaction()
        await self.command("settings")(interaction)
        return interaction

    async def test_it_stays_public(self):
        self.assertFalse((await self.reply()).said[0][1].get("ephemeral", False))

    async def test_it_names_checks_and_never_what_they_do(self):
        await self.change(vpn={"enabled": True, "action": "kick"}, account_age={"enabled": True, "action": "ban"})
        text = self.embed_text(await self.reply())
        self.assertIn("VPN and proxy", text)
        self.assertIn("Account age", text)
        for word in ("deny", "kick", "ban", "watch"):
            self.assertNotIn(word, text.lower().replace("auto kick", ""), word)

    async def test_a_check_this_mode_cant_run_isnt_listed(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        document = await self.service.get_settings(GUILD_ID)
        document = {**document, "core": {**document["core"], "mode": "button"}}
        await self.service.save_settings(GUILD_ID, document)
        text = self.embed_text(await self.reply())
        self.assertNotIn("VPN and proxy", text)
        self.assertIn("Button", text)

    async def test_it_lists_what_else_is_on(self):
        document = await self.service.get_settings(GUILD_ID)
        document = {**document, "core": {**document["core"], "cooldown": {"enabled": True, "seconds": 60}, "auto_kick": {"enabled": True, "minutes": 10}},
                    "honeypot": {**document["honeypot"], "enabled": True, "channel": fakes.LOG_CHANNEL}, "raid": {**document["raid"], "enabled": True}}
        await self.service.save_settings(GUILD_ID, document)
        text = self.embed_text(await self.reply())
        for name in ("Cooldown", "Auto kick", "Honeypot", "Raid mode"):
            self.assertIn(name, text)
        self.assertNotIn(fakes.LOG_CHANNEL, text.replace(f"<#{fakes.CHANNEL}>", ""), "the trap's channel stays unnamed")

    async def test_what_is_off_isnt_listed(self):
        document = await self.service.get_settings(GUILD_ID)
        document = {**document, "raid": {**document["raid"], "enabled": False}}
        await self.service.save_settings(GUILD_ID, document)
        text = self.embed_text(await self.reply())
        for name in ("Cooldown", "Auto kick", "Honeypot", "Raid mode"):
            self.assertNotIn(name, text)


class SetupCommand(Commands):
    async def run_setup(self, interaction):
        self.bot.post_message = AsyncMock(return_value=True)
        await self.command("setup")(interaction, Rank(2), SimpleNamespace(id=int(fakes.CHANNEL), mention=f"<#{fakes.CHANNEL}>"))

    async def test_its_reply_names_the_rules_actually_in_force(self):
        await self.forget_setup()
        document = settings.apply_preset(await self.service.get_settings(GUILD_ID), "strict")
        await self.service.save_settings(GUILD_ID, document)
        interaction = fake_interaction(perms=("administrator",))
        await self.run_setup(interaction)
        self.assertIn("using the Strict rules", said(interaction))

    async def test_it_saves_through_the_settings_lock(self):
        await self.forget_setup()
        real = self.service.edit_settings
        self.service.edit_settings = AsyncMock(side_effect=real)
        await self.run_setup(fake_interaction(perms=("administrator",)))
        self.assertEqual(self.service.edit_settings.await_args.kwargs["section"], "rules")
        stored_meanwhile = settings.apply_preset(settings.defaults(), "strict")
        built = self.service.edit_settings.await_args.args[1](stored_meanwhile)
        self.assertEqual(built["preset"], "strict", "it changes what's stored at that moment, not what it read earlier")
        self.assertEqual(built["core"]["channel"], fakes.CHANNEL)
        self.assertTrue(await self.service.is_set_up(GUILD_ID))
        self.assertEqual((await self.service.get_settings(GUILD_ID))["core"]["channel"], fakes.CHANNEL)

    async def test_a_server_that_appears_gets_its_row_through_the_settings_lock(self):
        await self.db.run("DELETE FROM guilds")
        self.service.forget_cached(GUILD_ID)
        real = self.service.edit_settings
        self.service.edit_settings = AsyncMock(side_effect=real)
        await self.bot.on_guild_join(SimpleNamespace(id=int(GUILD_ID)))
        self.service.edit_settings.assert_awaited_once()
        self.assertFalse(await self.service.is_set_up(GUILD_ID))
        self.assertEqual((await self.service.get_settings(GUILD_ID))["preset"], "standard")

    async def test_a_server_that_came_online_keeps_what_it_has(self):
        await self.service.save_settings(GUILD_ID, settings.apply_preset(await self.service.get_settings(GUILD_ID), "strict"))
        await self.bot.on_guild_join(SimpleNamespace(id=int(GUILD_ID)))
        self.assertEqual((await self.service.get_settings(GUILD_ID))["preset"], "strict")
        self.assertTrue(await self.service.is_set_up(GUILD_ID))


class TrapPosts(Commands):
    def post(self, *, bot=False, webhook_id=None):
        return SimpleNamespace(guild=SimpleNamespace(id=int(GUILD_ID)), id=7, webhook_id=webhook_id, is_system=lambda: False,
                               author=SimpleNamespace(id=int(fakes.OTHER_USER), name="spam", roles=(), bot=bot),
                               channel=SimpleNamespace(id=int(fakes.LOG_CHANNEL), parent_id=None))

    async def asyncSetUp(self):
        await super().asyncSetUp()
        document = await self.service.get_settings(GUILD_ID)
        await self.service.save_settings(GUILD_ID, {**document, "honeypot": {**document["honeypot"], "enabled": True, "channel": fakes.LOG_CHANNEL, "action": "ban"}})

    async def test_a_bots_post_goes_and_the_bot_stays(self):
        await self.bot.on_message(self.post(bot=True))
        self.assertTrue(self.port.did("delete_message"))
        self.assertFalse(self.port.did("ban"))

    async def test_a_members_post_gets_the_action(self):
        await self.bot.on_message(self.post())
        self.assertTrue(self.port.did("ban"))


class HealthCommand(Commands):
    async def reply(self):
        interaction = fake_interaction()
        await self.command("health")(interaction)
        return interaction

    async def test_a_server_still_loading_gets_a_plain_answer(self):
        self.port.absent = True
        interaction = await self.reply()
        self.assertIn("still loading", said(interaction))

    def many_issues(self, count):
        document = {"healthy": False, "issues": [{"title": f"Problem {index}", "fix": "Fix it."} for index in range(count)], "notices": []}
        return document

    def test_past_ten_issues_it_says_how_many_more(self):
        text = health_embed(self.many_issues(12)).description
        self.assertIn("Problem 9", text)
        self.assertNotIn("Problem 10", text)
        self.assertIn("And 2 more on the Health page", text)

    def test_ten_issues_are_all_there_is(self):
        self.assertNotIn("more on the Health page", health_embed(self.many_issues(10)).description)

    def test_it_stays_inside_discords_limit(self):
        data = {"healthy": True, "issues": [], "notices": [{"title": "x" * 900, "fix": "y" * 900} for _ in range(5)]}
        self.assertLessEqual(len(health_embed(data).description), 4096)

    async def test_a_healthy_server_still_hears_a_notice(self):
        data = {"healthy": True, "issues": [], "notices": [{"title": "Worth knowing", "fix": "Do this."}]}
        embed = health_embed(data)
        self.assertIn("Everything AltWarden needs is in place", embed.description)
        self.assertIn("Worth knowing", embed.description)
        self.assertEqual(embed.color.value, GREEN)

    async def test_it_reads_what_the_service_knows(self):
        await self.db.set_guild_field(GUILD_ID, "verify_message_id", None)
        self.assertIn("The verification message isn't posted", self.embed_text(await self.reply()))

    async def test_a_lookup_refusal_shows(self):
        await self.db.set_guild_field(GUILD_ID, "verify_message_id", f"{fakes.CHANNEL}:1")
        self.service._lookup_failures[GUILD_ID] = {"at": 1.0, "message": "out of queries"}
        self.assertIn("out of queries", self.embed_text(await self.reply()))


class PostMessageCommand(Commands):
    async def test_the_trap_warning_stays_down_while_the_trap_is_off(self):
        document = await self.service.get_settings(GUILD_ID)
        await self.service.save_settings(GUILD_ID, {**document, "honeypot": {**document["honeypot"], "enabled": False, "channel": fakes.LOG_CHANNEL}})
        self.port.sent.clear()
        interaction = fake_interaction()
        await self.command("post-message")(interaction, SimpleNamespace(value="honeypot"))
        self.assertIn("honeypot is off", said(interaction))
        self.assertEqual(self.port.sent, [])

    async def test_posting_directly_refuses_too(self):
        document = await self.service.get_settings(GUILD_ID)
        await self.service.save_settings(GUILD_ID, {**document, "honeypot": {**document["honeypot"], "enabled": False, "channel": fakes.LOG_CHANNEL}})
        self.port.sent.clear()
        self.assertFalse(await self.bot.post_message(GUILD_ID, "honeypot"))
        self.assertEqual(self.port.sent, [])

    async def test_with_the_trap_on_it_posts(self):
        document = await self.service.get_settings(GUILD_ID)
        await self.service.save_settings(GUILD_ID, {**document, "honeypot": {**document["honeypot"], "enabled": True, "channel": fakes.LOG_CHANNEL}})
        self.assertTrue(await self.bot.post_message(GUILD_ID, "honeypot"))


class Uninstall(Commands):
    ADMIN = {"perms": ("administrator",)}

    async def open(self):
        interaction = fake_interaction(**self.ADMIN)
        await self.command("uninstall")(interaction)
        return interaction

    async def test_its_confirmation_carries_the_rules_code(self):
        await self.service.save_settings(GUILD_ID, settings.apply_preset(await self.service.get_settings(GUILD_ID), "strict"))
        kwargs = (await self.open()).said[0][1]
        self.assertTrue(kwargs["ephemeral"])
        code = kwargs["file"].fp.read().decode()
        restored = settings.import_code(settings.defaults(), code)
        self.assertEqual(restored["preset"], "strict")
        self.assertEqual(kwargs["file"].filename, "altwarden-rules.txt")
        self.assertIn("rules", kwargs["file"].description.lower())

    async def test_its_message_says_what_the_file_is(self):
        text = said(await self.open())
        self.assertIn("attached file", text)
        self.assertIn("Rules page", text)

    async def test_staff_hear_about_it_before_the_records_go(self):
        guild_row_when_posted = []
        real = self.port.send

        async def send(channel_id, notice, *, guild_id=None):
            guild_row_when_posted.append(await self.db.guild(GUILD_ID) is not None)
            return await real(channel_id, notice, guild_id=guild_id)
        self.port.send = send
        view = (await self.open()).said[0][1]["view"]
        await view.confirm.callback(fake_interaction(**self.ADMIN))
        self.assertEqual(guild_row_when_posted, [True])
        self.assertIn("/uninstall", json.dumps([notice.embeds for _, notice in self.port.sent]))
        self.assertIsNone(await self.db.guild(GUILD_ID))

    async def test_someone_who_lost_the_right_cant_finish_it(self):
        view = (await self.open()).said[0][1]["view"]
        interaction = fake_interaction(perms=())
        await view.confirm.callback(interaction)
        self.assertIn("don't have access", said(interaction))
        self.assertIsNotNone(await self.db.guild(GUILD_ID))

    async def test_a_failure_in_the_button_is_answered(self):
        view = (await self.open()).said[0][1]["view"]
        interaction = fake_interaction(**self.ADMIN)
        with self.assertLogs("altwarden.bot", "ERROR"):
            await view.on_error(interaction, RuntimeError("boom"), view.confirm)
        self.assertIn("didn't work", said(interaction))


class BypassButton(Commands):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.change(vpn={"enabled": True, "action": "deny"})

    def view(self):
        view = BypassView(self.bot, self.target(), ["vpn"], 1, "dm")
        view.choice = ["vpn"]
        return view

    async def test_someone_who_lost_the_right_cant_make_the_link(self):
        interaction = fake_interaction(perms=())
        await self.view().create.callback(interaction)
        self.assertIn("don't have access", said(interaction))
        self.assertNotIn("/v/", said(interaction))

    async def test_a_target_who_moved_up_is_refused_at_the_press(self):
        view = self.view()
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        interaction = fake_interaction()
        await view.create.callback(interaction)
        self.assertIn("at or above yours", said(interaction))
        self.assertNotIn("/v/", said(interaction))

    async def test_a_failure_in_the_button_is_answered(self):
        view = self.view()
        interaction = fake_interaction()
        with self.assertLogs("altwarden.bot", "ERROR"):
            await view.on_error(interaction, RuntimeError("boom"), view.create)
        self.assertIn("didn't work", said(interaction))

    async def test_discord_not_answering_in_the_button_is_said_plainly(self):
        view = self.view()
        interaction = fake_interaction()
        await view.on_error(interaction, DiscordUnavailable("x"), view.create)
        self.assertIn(DISCORD_BUSY, said(interaction))


class CommandErrors(Commands):
    async def test_discord_not_answering_is_said_plainly(self):
        interaction = fake_interaction()
        error = discord.app_commands.CommandInvokeError(self.bot.tree.get_command("reset-user"), DiscordUnavailable("x"))
        await self.bot.tree.on_error(interaction, error)
        self.assertIn(DISCORD_BUSY, said(interaction))

    async def test_anything_else_is_logged(self):
        interaction = fake_interaction()
        error = discord.app_commands.CommandInvokeError(self.bot.tree.get_command("reset-user"), RuntimeError("x"))
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.bot.tree.on_error(interaction, error)
        self.assertIn("That command failed", said(interaction))


class Buttons(Commands):
    def press(self, custom_id, **kwargs):
        interaction = fake_interaction(**kwargs)
        interaction.type = discord.InteractionType.component
        interaction.data = {"custom_id": custom_id}
        interaction.guild = SimpleNamespace(id=int(GUILD_ID))
        interaction.command = None
        return interaction

    async def fire(self, custom_id, **kwargs):
        interaction = self.press(custom_id, **kwargs)
        await self.bot.on_interaction(interaction)
        return interaction

    async def uninstalled(self):
        await self.db.forget_guild(GUILD_ID)
        self.service.forget_cached(GUILD_ID)

    async def test_old_buttons_after_uninstall_get_a_plain_answer(self):
        await self.uninstalled()
        for custom_id, expected in (("aw:appeal:approve:7", "isn't set up"), ("aw:help", "isn't set up"), ("aw:help:close", "isn't set up"),
                                    (f"aw:staff:verify:{fakes.OLD_USER}", "isn't set up")):
            interaction = await self.fire(custom_id, perms=("administrator",))
            self.assertIn(expected, said(interaction), custom_id)

    async def test_a_verify_button_works_for_staff(self):
        interaction = await self.fire(f"aw:staff:verify:{fakes.OLD_USER}")
        self.assertIn("is verified", said(interaction))
        self.assertEqual((await self.db.member(GUILD_ID, fakes.OLD_USER))["method"], "staff")

    async def test_a_verify_button_needs_the_rule(self):
        interaction = await self.fire(f"aw:staff:verify:{fakes.OLD_USER}", perms=())
        self.assertIn("don't have access", said(interaction))
        self.assertFalse(self.port.did("add_role"))

    async def test_a_verify_button_stops_at_the_target(self):
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        interaction = await self.fire(f"aw:staff:verify:{fakes.OLD_USER}")
        self.assertIn("at or above yours", said(interaction))
        self.assertFalse(self.port.did("add_role"))

    async def test_a_bypass_button_opens_the_choices(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        interaction = await self.fire(f"aw:staff:bypass:{fakes.OLD_USER}")
        self.assertIsInstance(interaction.said[0][1]["view"], BypassView)
        self.assertEqual(interaction.said[0][1]["view"].user.id, int(fakes.OLD_USER))

    async def test_a_bypass_button_needs_the_rule(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        interaction = await self.fire(f"aw:staff:bypass:{fakes.OLD_USER}", perms=())
        self.assertIn("don't have access", said(interaction))

    async def test_a_bypass_button_stops_at_the_target(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.port.add_member(fakes.OLD_USER, roles=(STAFF_ROLE,))
        interaction = await self.fire(f"aw:staff:bypass:{fakes.OLD_USER}")
        self.assertIn("at or above yours", said(interaction))

    async def test_a_loading_server_is_said_plainly(self):
        self.port.loading = True
        interaction = await self.fire("aw:verify")
        self.assertIn("still loading", said(interaction))
        self.assertFalse(await self.db.member(GUILD_ID, str(interaction.user.id)))

    async def test_a_loading_server_stops_commands_too(self):
        self.port.loading = True
        interaction = fake_interaction()
        await self.command("verify-user")(interaction, self.target())
        self.assertIn("still loading", said(interaction))
        self.assertFalse(self.port.did("add_role"))

    async def test_discord_not_answering_is_said_plainly(self):
        self.service.open_help = AsyncMock(side_effect=DiscordUnavailable("x"))
        interaction = await self.fire("aw:help")
        self.assertIn(DISCORD_BUSY, said(interaction))

    async def test_an_appeal_says_whether_the_member_was_told(self):
        appeal = await self.insert_appeal()
        interaction = await self.fire(f"aw:appeal:approve:{appeal}", perms=("manage_guild", "manage_roles", "ban_members", "kick_members"))
        self.assertIn("They were told", said(interaction))

    async def test_an_appeal_says_when_the_member_wasnt_told(self):
        self.port.dm_open = False
        appeal = await self.insert_appeal()
        interaction = await self.fire(f"aw:appeal:deny:{appeal}", perms=("manage_guild", "manage_roles", "ban_members", "kick_members"))
        self.assertIn("weren't told", said(interaction))

    async def test_approving_an_appeal_needs_a_rank_above_the_role_it_gives(self):
        appeal = await self.insert_appeal()
        interaction = self.press(f"aw:appeal:approve:{appeal}", perms=("manage_guild", "manage_roles", "ban_members", "kick_members"))
        interaction.user.role_ids = (fakes.UNVERIFIED_ROLE,)
        await self.bot.on_interaction(interaction)
        self.assertIn("verified role sits at or above", said(interaction))
        self.assertEqual((await self.db.one("SELECT status FROM appeals WHERE id = ?", (appeal,)))["status"], "open")

    async def test_turning_an_appeal_down_gives_nothing_so_it_needs_no_rank(self):
        appeal = await self.insert_appeal()
        interaction = self.press(f"aw:appeal:deny:{appeal}", perms=("manage_guild", "manage_roles", "ban_members", "kick_members"))
        interaction.user.role_ids = (fakes.UNVERIFIED_ROLE,)
        await self.bot.on_interaction(interaction)
        self.assertEqual((await self.db.one("SELECT status FROM appeals WHERE id = ?", (appeal,)))["status"], "denied")

    async def insert_appeal(self):
        await self.db.touch_member(GUILD_ID, fakes.OLD_USER)
        await self.db.run("INSERT INTO appeals (guild_id, user_id, text, status, created_at) VALUES (?, ?, 'x', 'open', 1)", (GUILD_ID, fakes.OLD_USER))
        return (await self.db.one("SELECT id FROM appeals WHERE guild_id = ?", (GUILD_ID,)))["id"]


class ServiceReads(Commands):
    async def due(self):
        document = await self.service.get_settings(GUILD_ID)
        await self.service.save_settings(GUILD_ID, {**document, "core": {**document["core"], "auto_kick": {"enabled": True, "minutes": 10}}})
        await self.db.touch_member(GUILD_ID, fakes.OLD_USER)

    def watched(self):
        real = self.port.member
        self.port.member = AsyncMock(side_effect=real)
        return self.port.member

    async def test_an_auto_kick_asks_discord_itself(self):
        await self.due()
        await self.db.update_member(GUILD_ID, fakes.OLD_USER, kick_at=time.time() - 1)
        watch = self.watched()
        await self.service.tick()
        self.assertTrue(watch.await_args.kwargs.get("fresh"))
        self.assertTrue(self.port.did("kick"))

    async def test_a_kick_reminder_asks_discord_itself(self):
        await self.due()
        await self.db.update_member(GUILD_ID, fakes.OLD_USER, kick_warn_at=time.time() - 1, kick_at=time.time() + 600)
        watch = self.watched()
        await self.service.tick()
        self.assertTrue(watch.await_args.kwargs.get("fresh"))

    async def test_a_reopened_thread_gets_its_member_back(self):
        document = await self.service.get_settings(GUILD_ID)
        await self.service.save_settings(GUILD_ID, {**document, "core": {**document["core"], "help_desk": {**document["core"]["help_desk"], "enabled": True, "support_role": fakes.VERIFIED_ROLE}}})
        await self.db.touch_member(GUILD_ID, fakes.OLD_USER)
        await self.db.update_member(GUILD_ID, fakes.OLD_USER, help_thread_id="55")
        self.port.reopen_thread = AsyncMock(return_value=True)
        await self.service.open_help(MemberInfo(GUILD_ID, fakes.OLD_USER, "someone"))
        self.port.reopen_thread.assert_awaited_once_with("55", fakes.OLD_USER)

    async def test_a_blip_keeps_the_members_thread(self):
        document = await self.service.get_settings(GUILD_ID)
        await self.service.save_settings(GUILD_ID, {**document, "core": {**document["core"], "help_desk": {**document["core"]["help_desk"], "enabled": True, "support_role": fakes.VERIFIED_ROLE}}})
        await self.db.touch_member(GUILD_ID, fakes.OLD_USER)
        await self.db.update_member(GUILD_ID, fakes.OLD_USER, help_thread_id="55")
        self.port.reopen_thread = AsyncMock(side_effect=DiscordUnavailable("x"))
        with self.assertRaises(DiscordUnavailable):
            await self.service.open_help(MemberInfo(GUILD_ID, fakes.OLD_USER, "someone"))
        self.assertEqual((await self.db.member(GUILD_ID, fakes.OLD_USER))["help_thread_id"], "55")
        self.assertFalse(self.port.did("open_help_thread"))


def overrides(command=(), app=(), name="verify-user"):
    return {"application": "123", "all": list(app), "commands": [{"name": name, "id": "901", "overrides": list(command)}]}


def entry(kind, entry_id, allow=True):
    return {"type": kind, "id": entry_id, "allow": allow}


class DiscordsOwnOrder(unittest.TestCase):
    """Discord's flowchart of how its client decides, images/new-permissions-flowchart.svg in discord-api-docs."""

    GUILD = "500"
    ALL_CHANNELS = "499"
    PLACE = ("70",)

    def viewer(self, *roles, permissions=()):
        return access.Viewer("10", frozenset({self.GUILD, *roles}), frozenset(permissions))

    def ask(self, data, viewer=None, places=None, required=("manage_roles",)):
        return discord_allows(data, "verify-user", viewer or self.viewer(), places or self.PLACE, self.GUILD, list(required))

    def test_no_override_at_all_isnt_an_allow(self):
        self.assertFalse(self.ask(overrides()))

    def test_no_override_isnt_an_allow_even_holding_the_default_permissions(self):
        self.assertFalse(self.ask(overrides(), self.viewer(permissions=("manage_roles",))))

    def test_a_user_allow_on_the_command_is_enough(self):
        self.assertTrue(self.ask(overrides([entry("user", "10")])))

    def test_a_user_deny_on_the_command_ends_it(self):
        self.assertFalse(self.ask(overrides([entry("user", "10", False), entry("role", "20"), entry("role", self.GUILD)]), self.viewer("20")))

    def test_a_user_allow_beats_a_role_deny(self):
        self.assertTrue(self.ask(overrides([entry("user", "10"), entry("role", "20", False)]), self.viewer("20")))

    def test_someone_elses_user_entry_doesnt_count(self):
        self.assertFalse(self.ask(overrides([entry("user", "11")])))

    def test_a_role_allow_on_the_command_is_enough(self):
        self.assertTrue(self.ask(overrides([entry("role", "20")]), self.viewer("20")))

    def test_one_allowed_role_among_denied_ones_is_enough(self):
        self.assertTrue(self.ask(overrides([entry("role", "20", False), entry("role", "21")]), self.viewer("20", "21")))

    def test_only_denied_roles_end_it(self):
        self.assertFalse(self.ask(overrides([entry("role", "20", False), entry("role", self.GUILD)]), self.viewer("20")))

    def test_a_role_the_member_doesnt_hold_doesnt_count(self):
        self.assertFalse(self.ask(overrides([entry("role", "21")]), self.viewer("20")))

    def test_everyone_allow_on_the_command_is_enough(self):
        self.assertTrue(self.ask(overrides([entry("role", self.GUILD)])))

    def test_everyone_deny_on_the_command_ends_it(self):
        self.assertFalse(self.ask(overrides([entry("role", self.GUILD, False)], [entry("user", "10")]), self.viewer(permissions=("manage_roles",))))

    def test_a_role_entry_on_the_command_comes_before_everyone(self):
        self.assertFalse(self.ask(overrides([entry("role", "20", False), entry("role", self.GUILD)]), self.viewer("20")))
        self.assertTrue(self.ask(overrides([entry("role", "20"), entry("role", self.GUILD, False)]), self.viewer("20")))

    def test_a_command_entry_decides_before_the_apps(self):
        self.assertTrue(self.ask(overrides([entry("user", "10")], [entry("user", "10", False)])))

    def test_an_app_allow_still_needs_the_default_permissions(self):
        """change-log.mdx: an app-level grant stays restricted to default_member_permissions."""
        for app in ([entry("user", "10")], [entry("role", "20")], [entry("role", self.GUILD)]):
            self.assertFalse(self.ask(overrides([], app), self.viewer("20")), app)
            self.assertTrue(self.ask(overrides([], app), self.viewer("20", permissions=("manage_roles",))), app)

    def test_an_app_deny_ends_it(self):
        for app in ([entry("user", "10", False)], [entry("role", "20", False)], [entry("role", self.GUILD, False)]):
            self.assertFalse(self.ask(overrides([], app), self.viewer("20", permissions=("manage_roles",))), app)

    def test_an_app_level_order_is_user_then_role_then_everyone(self):
        held = self.viewer("20", permissions=("manage_roles",))
        self.assertTrue(self.ask(overrides([], [entry("user", "10"), entry("role", "20", False)]), held))
        self.assertFalse(self.ask(overrides([], [entry("role", "20", False), entry("role", self.GUILD)]), held))

    def test_a_command_deny_in_this_channel_ends_it(self):
        self.assertFalse(self.ask(overrides([entry("user", "10"), entry("channel", "70", False)])))

    def test_a_command_allow_in_this_channel_grants_nothing_by_itself(self):
        self.assertFalse(self.ask(overrides([entry("channel", "70")])))

    def test_a_channel_entry_on_the_command_comes_before_all_channels(self):
        self.assertTrue(self.ask(overrides([entry("user", "10"), entry("channel", "70"), entry("channel", self.ALL_CHANNELS, False)])))
        self.assertFalse(self.ask(overrides([entry("user", "10"), entry("channel", "70", False), entry("channel", self.ALL_CHANNELS)])))

    def test_all_channels_off_on_the_command_ends_it(self):
        self.assertFalse(self.ask(overrides([entry("user", "10"), entry("channel", self.ALL_CHANNELS, False)])))

    def test_an_other_channels_entry_doesnt_count(self):
        self.assertTrue(self.ask(overrides([entry("user", "10"), entry("channel", "71", False)])))

    def test_the_apps_channel_rule_applies_when_the_command_has_none(self):
        self.assertFalse(self.ask(overrides([entry("user", "10")], [entry("channel", "70", False)])))
        self.assertFalse(self.ask(overrides([entry("user", "10")], [entry("channel", self.ALL_CHANNELS, False)])))
        self.assertTrue(self.ask(overrides([entry("user", "10")], [entry("channel", "70"), entry("channel", self.ALL_CHANNELS, False)])))

    def test_a_command_allow_in_this_channel_passes_an_app_channel_deny(self):
        self.assertTrue(self.ask(overrides([entry("user", "10"), entry("channel", "70")], [entry("channel", "70", False)])))

    def test_a_channels_entry_covers_its_threads(self):
        """application-commands.mdx: command permissions for a channel apply to the threads it contains."""
        self.assertFalse(self.ask(overrides([entry("user", "10"), entry("channel", "70", False)]), places=("80", "70")))

    def test_each_command_has_its_own_entries(self):
        data = overrides([entry("user", "10")], name="reset-user")
        self.assertFalse(self.ask(data))

    def test_the_server_id_as_a_held_role_is_everyone_not_a_role(self):
        """discord.py lists @everyone among a member's roles, so it mustn't count as a role they hold."""
        self.assertFalse(self.ask(overrides([entry("role", self.GUILD, False), entry("role", "21")])))


class ThreadsAndChannelRules(unittest.TestCase):
    def rule(self, *entries):
        return {"overrides": list(entries), "required": []}

    def test_a_block_on_a_channel_covers_its_threads(self):
        self.assertFalse(access.channel_allowed(self.rule(entry("channel", "70", False)), ("80", "70")))

    def test_an_allow_list_covers_threads_in_a_listed_channel(self):
        self.assertTrue(access.channel_allowed(self.rule(entry("channel", "70")), ("80", "70")))

    def test_an_allow_list_refuses_threads_elsewhere(self):
        self.assertFalse(access.channel_allowed(self.rule(entry("channel", "71")), ("80", "70")))

    def test_a_block_elsewhere_leaves_a_thread_alone(self):
        self.assertTrue(access.channel_allowed(self.rule(entry("channel", "71", False)), ("80", "70")))

    def test_a_rule_on_the_thread_itself_comes_first(self):
        self.assertTrue(access.channel_allowed(self.rule(entry("channel", "70", False), entry("channel", "80")), ("80", "70")))

    def test_a_plain_channel_id_still_works(self):
        self.assertFalse(access.channel_allowed(self.rule(entry("channel", "70", False)), "70"))
        self.assertTrue(access.channel_allowed(self.rule(entry("channel", "70")), "70"))
        self.assertTrue(access.channel_allowed(self.rule(entry("channel", "70")), None))

    def test_the_rule_as_a_whole_reads_the_parent_too(self):
        viewer = access.Viewer("10", frozenset(), frozenset({"manage_roles"}))
        rule = {"overrides": [entry("channel", "70", False)], "required": ["manage_roles"]}
        self.assertFalse(access.allowed(rule, viewer, ("80", "70")))
        self.assertTrue(access.allowed(rule, viewer, ("80", "71")))


class CommandsAndDiscordsOverrides(Commands):
    ROLE = "970000000000000071"

    def member_with_role(self, interaction):
        interaction.user.role_ids = (self.ROLE,)
        return interaction

    def set_overrides(self, command=(), app=(), name="verify-user"):
        self.port.discord_commands = {"application": "123", "all": list(app), "commands": [{"name": name, "id": "901", "overrides": list(command)}]}
        self.port.command_permissions = AsyncMock(side_effect=lambda _: self.port.discord_commands)

    def named(self, interaction, name="verify-user"):
        interaction.command = SimpleNamespace(name=name)
        return interaction

    async def test_a_discord_allow_lets_someone_past_the_rule(self):
        self.set_overrides([entry("role", self.ROLE)])
        interaction = self.member_with_role(self.named(fake_interaction(perms=())))
        self.assertTrue(await allowed(self.bot, interaction, "verify-user"))

    async def test_without_one_the_rule_stands(self):
        self.set_overrides([entry("role", "970000000000000072")])
        interaction = self.member_with_role(self.named(fake_interaction(perms=())))
        self.assertFalse(await allowed(self.bot, interaction, "verify-user"))
        self.assertIn("don't have access", said(interaction))

    async def test_someone_the_rule_lets_in_costs_no_call(self):
        self.set_overrides()
        self.assertTrue(await allowed(self.bot, self.named(fake_interaction()), "verify-user"))
        self.port.command_permissions.assert_not_awaited()

    async def test_a_failed_read_refuses(self):
        self.port.command_permissions = AsyncMock(return_value=None)
        interaction = self.named(fake_interaction(perms=()))
        self.assertFalse(await allowed(self.bot, interaction, "verify-user"))
        self.assertIn("don't have access", said(interaction))

    async def test_a_failed_read_isnt_remembered(self):
        self.port.command_permissions = AsyncMock(return_value=None)
        await allowed(self.bot, self.named(fake_interaction(perms=())), "verify-user")
        await allowed(self.bot, self.named(fake_interaction(perms=())), "verify-user")
        self.assertEqual(self.port.command_permissions.await_count, 2)

    async def test_a_read_that_takes_too_long_refuses_in_time_to_say_so(self):
        async def slow(_):
            await asyncio.sleep(60)
        self.port.command_permissions = slow
        with patch.object(client, "OVERRIDES_READ_SECONDS", 0.01):
            interaction = self.named(fake_interaction(perms=()))
            self.assertFalse(await asyncio.wait_for(allowed(self.bot, interaction, "verify-user"), 2))
        self.assertIn("don't have access", said(interaction))

    async def test_the_read_is_kept_for_a_minute(self):
        self.set_overrides([entry("role", self.ROLE)])
        await allowed(self.bot, self.member_with_role(self.named(fake_interaction(perms=()))), "verify-user")
        await allowed(self.bot, self.member_with_role(self.named(fake_interaction(perms=()))), "verify-user")
        self.assertEqual(self.port.command_permissions.await_count, 1)

    async def test_after_a_minute_it_reads_again_so_a_removed_allow_ends(self):
        self.set_overrides([entry("role", self.ROLE)])
        start = time.monotonic()
        with patch.object(client.time, "monotonic", return_value=start):
            self.assertTrue(await allowed(self.bot, self.member_with_role(self.named(fake_interaction(perms=()))), "verify-user"))
        self.set_overrides([])
        with patch.object(client.time, "monotonic", return_value=start + 59):
            self.port.command_permissions = AsyncMock(return_value=None)
            self.assertTrue(await allowed(self.bot, self.member_with_role(self.named(fake_interaction(perms=()))), "verify-user"))
        self.set_overrides([])
        with patch.object(client.time, "monotonic", return_value=start + 61):
            self.assertFalse(await allowed(self.bot, self.member_with_role(self.named(fake_interaction(perms=()))), "verify-user"))

    async def test_each_server_has_its_own_read(self):
        self.set_overrides([entry("role", self.ROLE)])
        await allowed(self.bot, self.member_with_role(self.named(fake_interaction(perms=()))), "verify-user")
        other = self.member_with_role(self.named(fake_interaction(perms=())))
        other.guild_id = 970000000000000098
        await allowed(self.bot, other, "verify-user")
        self.assertEqual(self.port.command_permissions.await_count, 2)

    async def test_a_right_click_command_reads_its_own_entries(self):
        self.set_overrides([entry("role", self.ROLE)], name="Verify")
        interaction = self.member_with_role(self.named(fake_interaction(perms=()), "Verify"))
        self.assertTrue(await allowed(self.bot, interaction, "verify-user"))
        interaction = self.member_with_role(self.named(fake_interaction(perms=()), "verify-user"))
        self.assertFalse(await allowed(self.bot, interaction, "verify-user"))

    async def test_a_button_reads_the_entries_of_its_command(self):
        self.set_overrides([entry("role", self.ROLE)])
        interaction = self.member_with_role(fake_interaction(perms=()))
        interaction.command = None
        self.assertTrue(await allowed(self.bot, interaction, "verify-user"))

    async def test_a_rule_someone_wrote_is_final_against_an_app_allow(self):
        # A Discord allow counts only while the rule is its default, or anyone who can add themselves on Discord's side walks past a block here.
        self.set_overrides([], [entry("role", self.ROLE)])
        document = await self.service.get_settings(GUILD_ID)
        rule = {"overrides": [entry("everyone", "0", False)], "required": ["manage_guild"]}
        await self.service.save_settings(GUILD_ID, {**document, "permissions": {**document["permissions"], "commands": {"verify-user": rule}}})
        for perms in (("manage_roles",), ("manage_guild",)):
            self.assertFalse(await allowed(self.bot, self.member_with_role(self.named(fake_interaction(perms=perms))), "verify-user"), perms)

    async def test_a_channel_deny_on_discord_stops_a_discord_allow(self):
        self.set_overrides([entry("role", self.ROLE), entry("channel", fakes.CHANNEL, False)])
        interaction = self.member_with_role(self.named(fake_interaction(perms=())))
        self.assertFalse(await allowed(self.bot, interaction, "verify-user"))

    async def test_inside_a_thread_the_parent_channels_entry_applies(self):
        self.set_overrides([entry("role", self.ROLE), entry("channel", fakes.LOG_CHANNEL, False)])
        interaction = self.member_with_role(self.named(fake_interaction(perms=())))
        interaction.channel = MagicMock(spec=discord.Thread, parent_id=int(fakes.LOG_CHANNEL))
        self.assertFalse(await allowed(self.bot, interaction, "verify-user"))

    async def test_inside_a_thread_this_servers_channel_rule_reads_the_parent(self):
        document = await self.service.get_settings(GUILD_ID)
        rule = {"overrides": [entry("channel", fakes.LOG_CHANNEL)], "required": ["manage_roles"]}
        await self.service.save_settings(GUILD_ID, {**document, "permissions": {**document["permissions"], "commands": {"verify-user": rule}}})
        interaction = self.named(fake_interaction())
        interaction.channel = MagicMock(spec=discord.Thread, parent_id=int(fakes.LOG_CHANNEL))
        self.assertTrue(await allowed(self.bot, interaction, "verify-user"))
        interaction = self.named(fake_interaction())
        self.assertFalse(await allowed(self.bot, interaction, "verify-user"), "this one isn't in a thread, and its channel isn't listed")


class Lifecycle(GatewayBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.service = SimpleNamespace(db=SimpleNamespace(get_meta=AsyncMock(), set_meta=AsyncMock()), tick=AsyncMock(), purge=AsyncMock(return_value={}),
                                       net=SimpleNamespace(stale=lambda: False, refresh=AsyncMock(return_value=1)), _background=set())
        self.bot.service = self.service

    async def minute(self):
        await self.bot.minute_timer.coro(self.bot)

    async def hour(self):
        await self.bot.hour_timer.coro(self.bot)

    async def test_a_failed_sync_tries_again_from_the_timer(self):
        self.bot.tree.sync = AsyncMock(side_effect=[error(discord.HTTPException, 500, 0), []])
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.bot._sync_commands()
        self.assertFalse(self.bot.synced)
        self.bot._sync_at = 0
        await self.minute()
        self.assertTrue(self.bot.synced)
        self.assertEqual(self.bot.tree.sync.await_count, 2)

    async def test_a_sync_that_worked_isnt_repeated(self):
        self.bot.tree.sync = AsyncMock(return_value=[])
        await self.bot._sync_commands()
        await self.minute()
        self.assertEqual(self.bot.tree.sync.await_count, 1)

    async def test_a_sync_that_keeps_failing_waits_longer_each_time_up_to_an_hour(self):
        self.bot.tree.sync = AsyncMock(side_effect=error(discord.HTTPException, 500, 0))
        waits = []
        with self.assertLogs("altwarden.bot", "ERROR"):
            for _ in range(9):
                before = time.monotonic()
                self.bot._sync_at = 0
                await self.bot._sync_commands()
                waits.append(round(self.bot._sync_at - before, -1))
        self.assertEqual(waits[:3], [60, 120, 240])
        self.assertEqual(waits[-1], 3600)

    async def test_a_sync_not_due_isnt_tried(self):
        self.bot.tree.sync = AsyncMock(side_effect=error(discord.HTTPException, 500, 0))
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.bot._sync_commands()
        await self.bot._sync_commands()
        self.assertEqual(self.bot.tree.sync.await_count, 1)

    async def test_a_failed_sync_doesnt_stop_the_ready_event(self):
        self.bot.tree.sync = AsyncMock(side_effect=error(discord.HTTPException, 500, 0))
        self.service.db.guild = AsyncMock(return_value={"id": 1})
        self.service.db.set_guild_field = AsyncMock()
        self.service.db.mark_departed = AsyncMock()
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.bot.on_ready()
        self.assertFalse(self.bot.synced)

    async def test_the_sync_on_start_tells_discord_each_commands_default_permissions(self):
        """Every process start syncs once, so a deploy reaches Discord without anyone running anything."""
        self.answers[("PUT", "/applications/123/commands")] = []
        self.assertFalse(self.bot.synced)
        await self.bot._sync_commands()
        sent = {row["name"]: row["default_member_permissions"] for row in self.last()[2]["json"]}
        self.assertEqual(self.last()[:2], ("PUT", "/applications/123/commands"))
        self.assertEqual(sent["uninstall"], 1 << 3)
        self.assertEqual(sent["raid"], (1 << 5) | (1 << 1))
        self.assertTrue(self.bot.synced)

    async def test_a_failed_purge_still_refreshes_the_lists(self):
        self.service.purge = AsyncMock(side_effect=RuntimeError("boom"))
        self.service.net.stale = lambda: True
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.hour()
        self.service.net.refresh.assert_awaited_once()

    async def test_a_failed_refresh_is_logged(self):
        self.service.net.stale = lambda: True
        self.service.net.refresh = AsyncMock(side_effect=RuntimeError("boom"))
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.hour()
        self.service.purge.assert_awaited_once()


class ShuttingDown(GatewayBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.finished = []
        self.bot.loop = asyncio.get_running_loop()

    async def handler(self, gate, name):
        await gate.wait()
        self.finished.append(name)

    async def test_a_running_handler_finishes_before_the_connection_closes(self):
        gate = asyncio.Event()
        self.bot.on_member_join = lambda: self.handler(gate, "join")
        self.bot.dispatch("member_join")
        await asyncio.sleep(0)
        order = []
        real = self.bot.http.close

        async def closing():
            order.append(list(self.finished))
            await real()
        self.bot.http.close = closing
        closer = asyncio.ensure_future(self.bot.close())
        await asyncio.sleep(0.05)
        self.assertFalse(closer.done(), "it waits for the handler")
        gate.set()
        await closer
        self.assertEqual(order, [["join"]])

    async def test_an_event_after_the_stop_starts_nothing(self):
        await self.bot.close()
        self.bot.on_member_join = AsyncMock()
        self.bot.dispatch("member_join")
        await asyncio.sleep(0)
        self.bot.on_member_join.assert_not_called()

    async def test_a_handler_that_never_ends_cant_hold_the_stop_up(self):
        self.bot.on_member_join = lambda: self.handler(asyncio.Event(), "never")
        self.bot.dispatch("member_join")
        await asyncio.sleep(0)
        with patch.object(client, "SHUTDOWN_SECONDS", 0.01):
            await asyncio.wait_for(self.bot.close(), 2)
        for task in asyncio.all_tasks():
            if task.get_name().startswith("discord.py: "):
                task.cancel()


class Startup(unittest.IsolatedAsyncioTestCase):
    """The real startup path, with the stand-in from test_startup."""

    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.args = argparse.Namespace(public_url="https://altwarden.test", host="127.0.0.1", port=free_port(), data=self.folder.name)
        self.patches = [patch.dict(os.environ, {"DISCORD_TOKEN": "token", "DISCORD_CLIENT_SECRET": "secret", "MASTER_KEY": new_master_key()}),
                        patch("altwarden.bot.client.AltWardenBot", StubBot), patch.object(NetIntel, "refresh", AsyncMock(return_value=0))]
        for item in self.patches:
            item.start()

    async def asyncTearDown(self):
        for item in reversed(self.patches):
            item.stop()
        await asyncio.sleep(0.05)
        self.folder.cleanup()

    async def serving(self):
        async with aiohttp.ClientSession() as session:
            for _ in range(100):
                try:
                    async with session.get(f"http://127.0.0.1:{self.args.port}/healthz"):
                        return
                except aiohttp.ClientError:
                    await asyncio.sleep(0.05)
        self.fail("The site never came up")

    async def test_stored_secrets_are_sealed_before_anything_runs(self):
        order = []
        real = entry_module.Service.seal_stored_secrets

        async def sealing(service):
            order.append(list(StubBot.made.calls))
            return await real(service)
        with patch.object(entry_module.Service, "seal_stored_secrets", sealing):
            task = asyncio.ensure_future(entry_module.run(self.args))
            await self.serving()
            StubBot.made.finish.set()
            await asyncio.wait_for(task, 10)
        self.assertEqual(order, [[]], "before the bot logs in or anything serves")

    async def test_the_web_app_can_ask_discord_about_the_application_again(self):
        apps = []
        real = entry_module.build_app

        def build(*args, **kwargs):
            app = real(*args, **kwargs)
            apps.append(app)
            return app
        with patch.object(entry_module, "build_app", build):
            task = asyncio.ensure_future(entry_module.run(self.args))
            await self.serving()
            self.assertEqual((await apps[0]["application_info"]()).id, 123)
            StubBot.made.finish.set()
            await asyncio.wait_for(task, 10)

    async def test_shutting_down_closes_in_the_order_things_depend_on(self):
        order = []
        real_bot_close = StubBot.close
        real_session_close = aiohttp.ClientSession.close
        real_db_close = entry_module.Database.close

        async def bot_close(bot):
            order.append("bot")
            await real_bot_close(bot)

        async def session_close(session):
            if not session.closed:
                order.append("session")
            await real_session_close(session)

        async def db_close(database):
            order.append("database")
            await real_db_close(database)
        with patch.object(StubBot, "close", bot_close), patch.object(entry_module.aiohttp.ClientSession, "close", session_close), patch.object(entry_module.Database, "close", db_close):
            task = asyncio.ensure_future(entry_module.run(self.args))
            await self.serving()
            order.clear()
            StubBot.made.finish.set()
            await asyncio.wait_for(task, 10)
        self.assertEqual(order, ["bot", "session", "session", "database"])

    async def test_a_webhook_on_its_way_out_finishes_before_its_session_closes(self):
        services = []
        real_service = entry_module.Service

        def service(*args, **kwargs):
            made = real_service(*args, **kwargs)
            services.append(made)
            return made
        order = []
        real_session_close = aiohttp.ClientSession.close

        async def session_close(session):
            if not session.closed:
                order.append("session")
            await real_session_close(session)

        async def webhook():
            await asyncio.sleep(0.05)
            order.append("webhook")
        with patch.object(entry_module, "Service", service), patch.object(entry_module.aiohttp.ClientSession, "close", session_close):
            task = asyncio.ensure_future(entry_module.run(self.args))
            await self.serving()
            order.clear()
            sending = asyncio.ensure_future(webhook())
            services[0]._background.add(sending)
            StubBot.made.finish.set()
            await asyncio.wait_for(task, 10)
        self.assertEqual(order[0], "webhook")

    async def test_a_webhook_that_hangs_cant_hold_the_stop_up(self):
        services = []
        real_service = entry_module.Service

        def service(*args, **kwargs):
            made = real_service(*args, **kwargs)
            services.append(made)
            return made
        with patch.object(entry_module, "Service", service), patch.object(entry_module, "SHUTDOWN_SECONDS", 0.01):
            task = asyncio.ensure_future(entry_module.run(self.args))
            await self.serving()
            hanging = asyncio.ensure_future(asyncio.sleep(60))
            services[0]._background.add(hanging)
            StubBot.made.finish.set()
            await asyncio.wait_for(task, 10)
        hanging.cancel()


class ExitCodes(unittest.TestCase):
    """Exit 78 is the one the service unit won't restart, because no restart fixes these two."""

    def main(self, failure):
        async def run(_):
            raise failure
        env = {"DISCORD_TOKEN": "token", "DISCORD_CLIENT_SECRET": "secret", "MASTER_KEY": "key"}
        with patch.object(sys, "argv", ["altwarden", "--public-url", "https://x.test"]), patch.dict(os.environ, env), patch.object(entry_module, "load_dotenv"), \
                patch.object(entry_module, "run", run):
            entry_module.main()

    def test_a_rejected_token_stops_for_good(self):
        with self.assertRaises(SystemExit) as caught, self.assertLogs("altwarden", "CRITICAL") as logs:
            self.main(discord.LoginFailure("Improper token"))
        self.assertEqual(caught.exception.code, 78)
        self.assertIn("token", " ".join(logs.output))

    def test_a_refused_intent_stops_for_good(self):
        with self.assertRaises(SystemExit) as caught, self.assertLogs("altwarden", "CRITICAL") as logs:
            self.main(discord.PrivilegedIntentsRequired(None))
        self.assertEqual(caught.exception.code, 78)
        self.assertIn("Server Members", " ".join(logs.output))

    def test_anything_else_stays_a_failure_systemd_retries(self):
        with self.assertRaises(RuntimeError):
            self.main(RuntimeError("gateway said no"))

    def test_the_service_unit_holds_the_other_half(self):
        folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for name in ("altwarden.service", os.path.join("deploy", "altwarden.service")):
            path = os.path.join(folder, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as unit:
                    self.assertIn("RestartPreventExitStatus=78", unit.read(), name)


if __name__ == "__main__":
    unittest.main()
