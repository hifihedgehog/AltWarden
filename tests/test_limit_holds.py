"""Lookups, imports, alerts, and the small promises that pages and commands make."""
import asyncio
import json
import os
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import discord

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_web_guards
import test_bot_commands
import test_limits_and_links as limits
from altwarden import altmatch, catalog, engine, health, notices, service as service_module, settings
from altwarden.bot import client as client_module
from altwarden.netintel import NetInfo
from altwarden.ports import DISCORD_BUSY, GuildView, MemberInfo
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, UNVERIFIED_ROLE, VERIFIED_ROLE
from test_client import fake_interaction
from test_member_states import LIMIT_ROLE

STATIC = Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static"


class LookupCharges(limits.Limited):
    async def lookups(self, answer):
        await self.edit(lambda document: (document["core"].update(external_vpn_lookup=True), document["checks"]["vpn"].update(enabled=True), document["checks"]["max_attempts"].update(enabled=False)))
        self.service.proxycheck = AsyncMock(return_value=answer)

    async def ask(self, user, ip):
        net = NetInfo(known=True)
        return await self.service._outside_lookup(GUILD, user, ip, net, await self.service.get_settings(GUILD), frozenset()), net

    async def test_a_service_thats_down_costs_the_member_nothing(self):
        await self.lookups(None)
        for _ in range(service_module.LOOKUP_DAILY_LIMIT + 3):
            note, net = await self.ask(OLD_USER, "8.8.8.8")
        self.assertEqual(note, "unavailable")
        self.assertFalse(net.vpn, "a retry from one home connection isn't a VPN")

    async def test_answers_still_count_toward_the_day(self):
        await self.lookups({})
        for number in range(service_module.LOOKUP_DAILY_LIMIT):
            await self.ask(OLD_USER, f"8.8.{number}.8")
        note, net = await self.ask(OLD_USER, "9.9.9.9")
        self.assertEqual(note, "over_limit")
        self.assertTrue(net.vpn)


class ImportedRoles(limits.Limited):
    def press(self):
        return self.service.press_verify(self.port.members[(GUILD, OLD_USER)])

    async def test_an_import_by_the_verified_role_doesnt_hand_back_a_role_staff_took(self):
        await self.service.import_members(GUILD, [OLD_USER], STAFF, "staff", holding_role=True)
        self.assertIsInstance(await self.press(), str, "staff took the role, so this member verifies again")
        self.assertEqual(self.port.did("add_role"), [])

    async def test_an_import_by_another_role_gives_the_role_once(self):
        await self.service.import_members(GUILD, [OLD_USER], STAFF, "staff")
        result = await self.press()
        self.assertEqual(result.status, "already")
        self.assertIn(("add_role", OLD_USER, VERIFIED_ROLE), self.port.calls)
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        self.assertIsInstance(await self.press(), str, "taking the role now asks for a recheck, like anyone else")

    async def test_a_join_holding_the_role_is_no_import_to_finish(self):
        self.port.members[(GUILD, OLD_USER)].role_ids = (VERIFIED_ROLE,)
        await self.service.on_join(self.port.members[(GUILD, OLD_USER)])
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        self.assertIsInstance(await self.press(), str)


class ResetDuringABlip(limits.Limited):
    async def test_the_stamp_stays_until_the_role_really_comes_off(self):
        await self.button_mode(attempts=2, reset_minutes=60, role=LIMIT_ROLE)
        await self.fail_on_button(2)
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=time.time() - 3601)
        real = self.port.remove_role
        self.port.remove_role = AsyncMock(return_value=DISCORD_BUSY)
        await self.service.tick()
        self.assertIsNotNone((await self.row())["limit_reached_at"], "the next minute has to be able to try again")
        self.port.remove_role = real
        await self.service.tick()
        row = await self.row()
        self.assertEqual((row["limit_reached_at"], row["fails"]), (None, 0))
        self.assertIn(("remove_role", OLD_USER, LIMIT_ROLE), self.port.calls)

    async def test_any_other_refusal_doesnt_hold_attempts_back(self):
        await self.button_mode(attempts=2, reset_minutes=60, role=LIMIT_ROLE)
        await self.fail_on_button(2)
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=time.time() - 3601)
        self.port.remove_role = AsyncMock(return_value="AltWarden needs Manage Roles, and its role must sit above the role it gives.")
        await self.service.tick()
        self.assertIsNone((await self.row())["limit_reached_at"])


class BannedLinkFloor(unittest.TestCase):
    def link(self, *methods, weak=(), score=65):
        return altmatch.Link("1", score, altmatch.confidence_for(score), list(methods), banned=True, weak=list(weak))

    def test_a_fingerprint_and_a_device_count_for_a_banned_account(self):
        self.assertEqual(len(altmatch.counting([self.link("fingerprint", "device")], "likely")), 1)

    def test_a_phone_model_at_one_address_doesnt(self):
        self.assertEqual(altmatch.counting([self.link("fingerprint", "ip", "device", weak=["fingerprint"])], "likely"), [])

    def test_a_weak_connection_with_a_good_fingerprint_still_does(self):
        self.assertEqual(len(altmatch.counting([self.link("fingerprint", "device", "ip", weak=["ip"], score=75)], "likely")), 1)


class BanLookups(limits.Limited):
    async def asked_for(self, *links, floor="confirmed"):
        alt = {**(await self.service.get_settings(GUILD))["checks"]["alt_account"], "min_confidence": floor}
        before = len(self.port.calls)
        self.port.is_banned = AsyncMock(return_value=False)
        with patch.object(altmatch, "find_links", AsyncMock(return_value=list(links))):
            await self.service._alt_links(GUILD, OLD_USER, {}, {}, alt, weak_fingerprint=False, weak_ip=False)
        self.assertEqual(len(self.port.calls), before)
        return self.port.is_banned.await_count

    async def test_links_only_a_ban_would_make_count_get_a_few_calls(self):
        links = [altmatch.Link(str(170000000000000000 + number), 65, "possible", ["fingerprint", "device"], verified=True) for number in range(10)]
        self.assertEqual(await self.asked_for(*links), service_module.BELOW_FLOOR_BAN_LOOKUPS)

    async def test_links_that_already_count_are_all_asked_about(self):
        links = [altmatch.Link(str(170000000000000000 + number), 80, "likely", ["fingerprint", "ip"], verified=True) for number in range(10)]
        self.assertEqual(await self.asked_for(*links, floor="likely"), 10)


class CooldownPastALimit(unittest.TestCase):
    def decide(self, **member):
        document = settings.defaults()
        document["core"]["cooldown"].update(enabled=True, seconds=600)
        document["checks"]["max_attempts"].update(enabled=True, action=member.pop("action", "deny"), attempts=2, reset_minutes=0)
        now = time.time()
        return engine.run_checks(engine.Attempt(document, "button", engine.Account(OLD_USER, "x", "abc"), {"last_fail_at": now, **member}, now=now))

    def test_past_a_stamped_limit_there_is_no_wait_to_promise(self):
        decision = self.decide(fails=2, limit_reached_at=time.time())
        self.assertEqual(decision.cooldown_left, 0)
        self.assertEqual(decision.primary.check_id, "max_attempts")

    def test_short_of_the_limit_the_cooldown_stands(self):
        self.assertGreater(self.decide(fails=1).cooldown_left, 0)

    def test_a_limit_that_removes_people_keeps_the_cooldown(self):
        self.assertGreater(self.decide(fails=2, limit_reached_at=time.time(), action="kick").cooldown_left, 0)


class HealthNotice(limits.HealthWithNoLists):
    test_every_member_being_stopped_is_an_issue = None

    async def test_lists_not_loaded_with_members_let_through_is_a_notice_for_both_surfaces(self):
        await self.no_lists(fail_open=True)
        guild = await self.service.port.guild(GUILD)
        report = await health.full_report(self.service, GUILD, guild, await self.service.get_settings(GUILD))
        self.assertIn("The network lists haven't loaded yet", [notice["title"] for notice in report["notices"]])
        self.assertTrue(report["healthy"], report["issues"])


class Checkpoints(limits.Limited):
    async def test_one_starting_during_another_puts_the_real_timeout_back(self):
        before = await self.db.scalar("PRAGMA busy_timeout")
        self.assertGreater(before, 0)
        real = self.db.scalar
        first_done = asyncio.Event()
        second = []

        async def scalar(sql, *args):
            if sql == "PRAGMA busy_timeout = 0" and second:
                await first_done.wait()  # by now it has read the zero, if nothing kept it waiting, and it finishes last
            answer = await real(sql, *args)
            if sql == "PRAGMA busy_timeout = 0" and not second:
                second.append(asyncio.create_task(self.db.checkpoint()))
                await asyncio.sleep(0.05)
            return answer
        with patch.object(self.db, "scalar", scalar):
            await self.db.checkpoint()
            first_done.set()
            await second[0]
        self.assertEqual(await real("PRAGMA busy_timeout"), before)


class InstantModeButton(limits.Limited):
    async def set_up(self, **member):
        await self.edit(lambda document: (document["core"].update(mode="instant"), document["checks"]["max_attempts"].update(enabled=True, action="deny", attempts=2, reset_minutes=0)))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, **member)

    async def test_past_a_limit_it_doesnt_say_to_rejoin(self):
        await self.set_up(fails=2, limit_reached_at=time.time())
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual((result.status, result.reason), ("failed", "max_attempts"))
        self.assertNotIn("rejoin", result.message.lower())
        self.assertEqual(len(self.port.dms), 0)

    async def test_otherwise_it_does(self):
        await self.set_up(fails=1)
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(result.title, "Rejoin to verify")


class WhatALimitKeeps(limits.Limited):
    async def old_row(self, *, limit_on):
        await self.edit(lambda document: document["checks"]["max_attempts"].update(enabled=limit_on, action="deny", attempts=2, reset_minutes=0))
        await self.db.touch_member(GUILD, OLD_USER, username="someone", avatar="abc")
        old = time.time() - 800 * 86400
        await self.db.update_member(GUILD, OLD_USER, fails=2, limit_reached_at=old, last_fail_at=old, joined_at=old, kick_at=None, kick_warn_at=None)

    async def test_the_row_stays_with_no_name_while_the_limit_is_on(self):
        await self.old_row(limit_on=True)
        await self.service.purge()
        row = await self.row()
        self.assertEqual((row["username"], row["avatar"], row["fails"]), ("", None, 2))

    async def test_the_row_goes_with_the_limit_off(self):
        await self.old_row(limit_on=False)
        await self.service.purge()
        self.assertIsNone(await self.row())


class RejoiningAtALimit(limits.Limited):
    async def test_leaving_doesnt_shed_the_limit_role(self):
        await self.button_mode(attempts=2, reset_minutes=0, role=LIMIT_ROLE)
        await self.fail_on_button(2)
        self.port.calls.clear()
        await self.service.on_join(self.port.members[(GUILD, OLD_USER)], catching_up=True)
        self.assertIn(("add_role", OLD_USER, LIMIT_ROLE), self.port.calls)

    async def test_nobody_else_gets_it(self):
        await self.button_mode(attempts=2, reset_minutes=0, role=LIMIT_ROLE)
        self.port.calls.clear()
        await self.service.on_join(self.port.members[(GUILD, OLD_USER)], catching_up=True)
        self.assertNotIn(("add_role", OLD_USER, LIMIT_ROLE), self.port.calls)


class Words(unittest.TestCase):
    def card_fields(self, check, **options):
        card = notices.appeal_card(1, OLD_USER, "someone", check, "this wasn't me", **options)
        return [field["name"] for field in card.embeds[0]["fields"]]

    def test_a_limit_reached_on_a_link_still_explains_the_buttons(self):
        self.assertIn("Which button", self.card_fields("max_attempts", linked=True))
        self.assertIn("Which button", self.card_fields("alt_account"))
        self.assertNotIn("Which button", self.card_fields("max_attempts"))

    def instant_text(self, show_reason):
        notice = notices.failed_notice("A server", "max_attempts", "used up", "deny", "https://x", None, show_reason, instant=True)
        return notice.embeds[0]["description"]

    def test_with_reasons_hidden_the_rejoin_line_doesnt_give_the_limit_away(self):
        self.assertIn("rejoin", self.instant_text(False))
        self.assertNotIn("rejoin", self.instant_text(True))

    def test_every_help_page_is_listed_with_how_to_verify_first(self):
        text = (STATIC / "js" / "help.js").read_text(encoding="utf-8")
        self.assertIn('const PAGES = {\n  "how-to-verify":', text.replace("\r\n", "\n"))

    def test_a_members_row_shows_every_kind_of_result(self):
        self.assertNotIn("slice(0, 4)", (STATIC / "dash" / "members.js").read_text(encoding="utf-8"))

    def test_no_file_uses_syntax_older_pythons_refuse(self):
        # A backslash inside an f-string's braces only compiles from Python 3.12, and the project supports 3.11.
        import ast
        import re
        for path in (Path(__file__).resolve().parent.parent / "altwarden").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            ast.parse(text)
            for match in re.finditer(r"""\bf(['"])(?:(?!\1).)*\{[^}'"\n]*\\[^}\n]*\}""", text):
                self.fail(f"{path.name}: {match.group(0)[:80]}")


class TheMenuAndItsName(unittest.IsolatedAsyncioTestCase):
    """A bypass opened from the right-click command answers to that command's entries on Discord."""

    ME = "175928847299117065"

    async def ask(self, **options):
        info = MemberInfo(GUILD, self.ME, "mod", None, False, (GUILD,), frozenset(), False, False)

        async def loading(_):
            return False

        async def get_settings(_):
            return settings.defaults()

        async def overrides(_):
            return {"application": "1", "all": [], "commands": [{"name": "Create Bypass", "id": "900000000000000001", "overrides": [{"type": "user", "id": self.ME, "allow": True}]}]}

        async def send(*_, **__):
            return None
        bot = SimpleNamespace(gateway=SimpleNamespace(guild_loading=loading, info=lambda _: info), service=SimpleNamespace(get_settings=get_settings), command_overrides=overrides)
        interaction = SimpleNamespace(guild_id=int(GUILD), channel_id=1, channel=None, user=info, command=None, response=SimpleNamespace(is_done=lambda: False, send_message=send))
        return await client_module.allowed(bot, interaction, "create-bypass", **options)

    async def test_the_press_reads_the_entries_the_menu_was_opened_under(self):
        self.assertTrue(await self.ask(discord_name="Create Bypass"))

    async def test_without_that_name_it_reads_the_slash_commands(self):
        self.assertFalse(await self.ask())


class SettingsAndBypass(test_bot_commands.Commands):
    async def settings_text(self):
        interaction = fake_interaction()
        await self.command("settings")(interaction)
        return self.embed_text(interaction)

    async def core(self, **change):
        document = await self.service.get_settings(GUILD)
        await self.service.save_settings(GUILD, {**document, "core": {**document["core"], **change}})

    async def test_the_unverified_role_is_named_when_its_on(self):
        await self.core(unverified_enabled=True, unverified_role=UNVERIFIED_ROLE)
        self.assertIn(f"**Unverified role:** <@&{UNVERIFIED_ROLE}>", await self.settings_text())

    async def test_and_not_when_its_off(self):
        await self.core(unverified_enabled=False, unverified_role=UNVERIFIED_ROLE)
        self.assertNotIn("Unverified role", await self.settings_text())

    async def test_the_menu_remembers_the_command_it_was_opened_from(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.port.add_member(OLD_USER)
        interaction = fake_interaction()
        interaction.command = SimpleNamespace(name="Create Bypass")
        await client_module.do_bypass(self.bot, interaction, self.target())
        self.assertEqual(interaction.said[-1][1]["view"].command_name, "Create Bypass")

    async def test_the_press_asks_under_that_name(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        view = client_module.BypassView(self.bot, self.target(), ["vpn"], 1, "dm", "Create Bypass")
        view.choice = ["vpn"]
        names = []
        real = client_module.allowed

        async def spy(bot, interaction, command, *, discord_name=None):
            names.append((command, discord_name))
            return await real(bot, interaction, command, discord_name=discord_name)
        with patch.object(client_module, "allowed", spy):
            await view.create.callback(fake_interaction())
        self.assertEqual(names, [("create-bypass", "Create Bypass")])


class ImportCommand(test_bot_commands.Commands):
    def everyone(self):
        async def walk(limit=None):
            yield SimpleNamespace(id=int(OLD_USER), bot=False, get_role=lambda _: True)
        return walk

    async def import_by(self, role_id):
        interaction = fake_interaction()
        interaction.guild.id = int(GUILD)
        interaction.guild.fetch_members = self.everyone()
        await self.command("import-members")(interaction, SimpleNamespace(id=int(role_id), is_default=lambda: False))
        await asyncio.gather(*self.bot.imports.values())
        return await self.db.scalar("SELECT method FROM members WHERE guild_id = ? AND user_id = ?", (GUILD, OLD_USER))

    async def test_by_the_verified_role_they_already_hold_it(self):
        self.assertEqual(await self.import_by(VERIFIED_ROLE), "imported")

    async def test_by_another_role_they_dont_yet(self):
        self.assertEqual(await self.import_by(UNVERIFIED_ROLE), service_module.IMPORTED_WITHOUT_ROLE)


class AppealCard(limits.Limited):
    async def card_after(self, *, linked):
        await self.edit(lambda document: document["appeals"].update(enabled=True, channel=LOG_CHANNEL))
        await self.button_mode(attempts=2, reset_minutes=0)
        await self.fail_on_button(2)
        if linked:
            await self.db.run("INSERT INTO links (guild_id, alt_id, main_id, confidence, score, methods, at) VALUES (?, ?, ?, 'likely', 80, '[]', ?)", (GUILD, OLD_USER, OTHER_USER, time.time()))
        self.assertIsNone(await self.service.submit_appeal(GUILD, OLD_USER, "someone", "this wasn't me at all"))
        return json.dumps(self.port.sent[-1][1].embeds)

    async def test_a_limit_on_a_linked_member_shows_which_button(self):
        self.assertIn("Which button", await self.card_after(linked=True))

    async def test_a_limit_with_no_link_doesnt(self):
        self.assertNotIn("Which button", await self.card_after(linked=False))


class ServerAddedAfterSignIn(test_web_guards.Base):
    async def listed(self):
        data = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        return [guild["id"] for guild in data["guilds"]]

    async def signed_in_before_it_joined(self, **options):
        self.port.absent = True
        await self.log_in(**options)
        self.port.absent = False

    async def test_it_shows_without_signing_in_again(self):
        await self.signed_in_before_it_joined()
        self.assertEqual(await self.listed(), [GUILD])

    async def test_someone_who_isnt_in_it_doesnt_see_it(self):
        await self.signed_in_before_it_joined()
        self.port.members.clear()
        self.assertEqual(await self.listed(), [])

    async def test_someone_without_access_doesnt_see_it(self):
        await self.signed_in_before_it_joined(perms=(), owner=False)
        self.assertEqual(await self.listed(), [])

    async def test_discord_not_answering_keeps_it_hidden(self):
        await self.signed_in_before_it_joined()
        self.port.discord_down = True
        self.assertEqual(await self.listed(), [])

    async def test_a_server_from_sign_in_stays_through_a_bad_moment(self):
        await self.log_in()
        self.port.discord_down = True
        self.assertEqual(await self.listed(), [GUILD])

    async def test_the_lookups_are_capped(self):
        await self.log_in()
        self.port.guild_ids = lambda: [str(980000000000000000 + number) for number in range(100)]
        asked = []
        real = self.port.guild

        async def counting(guild_id):
            asked.append(guild_id)
            return await real(guild_id)
        self.port.guild = counting
        await self.listed()
        late = {guild_id for guild_id in asked if guild_id != GUILD}
        self.assertEqual(len(late), 25)


class ImportFromTheDashboard(test_web_guards.Base):
    async def start(self, role=VERIFIED_ROLE):
        response = await self.client.post(f"/api/guilds/{GUILD}/import-members", json={"role": role}, headers=self.headers)
        return response.status, await response.json()

    async def test_it_starts_and_passes_the_role_and_who_asked(self):
        await self.log_in()
        hook = self.app["import_role"] = MagicMock(return_value=True)
        self.assertEqual((await self.start())[0], 200)
        self.assertEqual(hook.call_args.args[:2], (GUILD, VERIFIED_ROLE))

    async def test_it_needs_the_commands_permissions(self):
        await self.log_in(perms=("manage_guild",), owner=False)
        self.app["import_role"] = MagicMock(return_value=True)
        self.assertEqual((await self.start())[0], 403)
        self.app["import_role"].assert_not_called()

    async def test_a_role_from_elsewhere_is_refused(self):
        await self.log_in()
        self.app["import_role"] = MagicMock(return_value=True)
        self.assertEqual((await self.start("980000000000000001"))[0], 400)
        self.app["import_role"].assert_not_called()

    async def test_one_already_running_is_said_plainly(self):
        await self.log_in()
        self.app["import_role"] = MagicMock(return_value=False)
        status, body = await self.start()
        self.assertEqual((status, body["error"]), (409, "An import is already running on this server."))

    async def test_the_guild_view_says_who_can(self):
        await self.log_in()
        self.assertTrue((await (await self.client.get(f"/api/guilds/{GUILD}", headers=self.session_cookie)).json())["can_import"])


class ImportInTheBackground(test_bot_commands.Commands):
    def role(self):
        return SimpleNamespace(id=5, is_default=lambda: False)

    def interaction(self, walk):
        interaction = fake_interaction()
        interaction.guild.id = int(GUILD)
        interaction.guild.fetch_members = walk
        return interaction

    def members(self):
        async def walk(limit=None):
            yield SimpleNamespace(id=int(OLD_USER), bot=False, get_role=lambda _: True)
        return walk

    async def settled(self):
        await asyncio.gather(*self.bot.imports.values())

    async def test_the_answer_comes_before_the_list_is_read(self):
        release = asyncio.Event()

        async def walk(limit=None):
            await release.wait()
            yield SimpleNamespace(id=int(OLD_USER), bot=False, get_role=lambda _: True)
        interaction = self.interaction(walk)
        await self.command("import-members")(interaction, self.role())
        self.assertIn("Importing everyone", interaction.said[-1][0])
        self.assertTrue(interaction.said[-1][1]["ephemeral"])
        release.set()
        await self.settled()
        self.assertIn("Marked 1 member as verified", interaction.said[-1][0])
        self.assertEqual(self.bot.imports, {})

    async def test_a_second_one_is_told_the_first_is_running(self):
        release = asyncio.Event()

        async def walk(limit=None):
            await release.wait()
            yield SimpleNamespace(id=int(OLD_USER), bot=False, get_role=lambda _: True)
        first = self.interaction(walk)
        await self.command("import-members")(first, self.role())
        second = self.interaction(self.members())
        await self.command("import-members")(second, self.role())
        self.assertEqual(second.said[-1][0], "An import is already running on this server.")
        release.set()
        await self.settled()
        self.assertTrue(self.bot.start_import(self.interaction(self.members()).guild, "5", STAFF, "staff"))
        await self.settled()

    async def test_a_failure_tells_staff_and_lets_it_run_again(self):
        async def walk(limit=None):
            raise RuntimeError("no")
            yield
        self.service.import_failed = AsyncMock()
        interaction = self.interaction(walk)
        with self.assertLogs("altwarden.bot", "ERROR"):
            await self.command("import-members")(interaction, self.role())
            await self.settled()
        self.service.import_failed.assert_awaited_once_with(GUILD)
        self.assertEqual(interaction.said[-1][0], "The import didn't finish. Run it again.")
        self.assertEqual(self.bot.imports, {})

    async def test_a_reply_past_its_15_minutes_changes_nothing(self):
        interaction = self.interaction(self.members())
        interaction.edit_original_response = AsyncMock(side_effect=discord.HTTPException(MagicMock(status=401, reason="expired"), "expired"))
        await self.command("import-members")(interaction, self.role())
        await self.settled()
        self.assertEqual(await self.db.scalar("SELECT status FROM members WHERE guild_id = ? AND user_id = ?", (GUILD, OLD_USER)), "verified")


ALERT_ROLE_ID = "970000000000000901"
OTHER_ROLE_ID = "970000000000000902"


class OneAlertRole(limits.Limited):
    async def set_up_logs(self, **alerts):
        def change(document):
            document["core"]["logs"].update(enabled=True, modules={name: LOG_CHANNEL for name in catalog.LOG_MODULES})
            document["core"]["alerts"].update(alerts)
        await self.edit(change)

    async def pings(self, *modules, **options):
        rules = await self.service.get_settings(GUILD)
        self.port.sent.clear()
        await self.service._log(GUILD, rules, list(modules), {"title": "x"}, **options)
        return self.port.sent[-1][1].mention_roles

    async def test_alerts_start_on_with_nothing_to_choose_but_the_role(self):
        alerts = settings.defaults()["core"]["alerts"]
        self.assertEqual(alerts, {"enabled": True, "role": None, "off": [], "roles": {}})

    async def test_the_role_covers_what_stops_someone(self):
        await self.set_up_logs(role=ALERT_ROLE_ID)
        for module in (*catalog.CHECK_IDS, "honeypot"):
            self.assertEqual(await self.pings(module), [ALERT_ROLE_ID], module)

    async def test_routine_logs_stay_quiet(self):
        await self.set_up_logs(role=ALERT_ROLE_ID)
        for module in ("success", "general", "settings", "auto_kick", "help_desk"):
            self.assertEqual(await self.pings(module), [], module)

    async def test_no_role_pings_nobody(self):
        await self.set_up_logs()
        self.assertEqual(await self.pings("alt_account"), [])

    async def test_one_can_be_turned_off(self):
        await self.set_up_logs(role=ALERT_ROLE_ID, off=["vpn"])
        self.assertEqual(await self.pings("vpn"), [])
        self.assertEqual(await self.pings("alt_account"), [ALERT_ROLE_ID])

    async def test_one_can_have_its_own_role_and_a_routine_one_can_join(self):
        await self.set_up_logs(role=ALERT_ROLE_ID, roles={"vpn": OTHER_ROLE_ID, "success": OTHER_ROLE_ID})
        self.assertEqual(await self.pings("vpn"), [OTHER_ROLE_ID])
        self.assertEqual(await self.pings("success"), [OTHER_ROLE_ID])

    async def test_the_switch_stops_every_ping(self):
        await self.set_up_logs(role=ALERT_ROLE_ID, enabled=False)
        self.assertEqual(await self.pings("alt_account"), [])

    async def test_a_raid_pings_the_main_role_unless_it_has_its_own(self):
        await self.set_up_logs(role=ALERT_ROLE_ID)
        self.assertEqual(await self.pings("raid", "general"), [ALERT_ROLE_ID])
        self.assertEqual(await self.pings("raid", "general", alert_role=OTHER_ROLE_ID), [OTHER_ROLE_ID])

    async def test_an_appeal_pings_the_main_role_unless_it_has_its_own(self):
        await self.button_mode(attempts=2, reset_minutes=0)
        await self.set_up_logs(role=ALERT_ROLE_ID)
        await self.edit(lambda document: document["appeals"].update(enabled=True, channel=LOG_CHANNEL))
        await self.fail_on_button(2)
        self.port.sent.clear()
        self.assertIsNone(await self.service.submit_appeal(GUILD, OLD_USER, "someone", "this wasn't me at all"))
        self.assertEqual(self.port.sent[-1][1].mention_roles, [ALERT_ROLE_ID])

    async def test_an_appeals_own_role_wins(self):
        await self.button_mode(attempts=2, reset_minutes=0)
        await self.set_up_logs(role=ALERT_ROLE_ID)
        await self.edit(lambda document: document["appeals"].update(enabled=True, channel=LOG_CHANNEL, role=OTHER_ROLE_ID))
        await self.fail_on_button(2)
        self.port.sent.clear()
        self.assertIsNone(await self.service.submit_appeal(GUILD, OLD_USER, "someone", "this wasn't me at all"))
        self.assertEqual(self.port.sent[-1][1].mention_roles, [OTHER_ROLE_ID])


class AlertsSavedBefore(unittest.TestCase):
    def alerts(self, saved):
        document = settings.defaults()
        document["core"]["alerts"] = saved
        return settings.normalize(document)["core"]["alerts"]

    def test_one_role_on_many_rows_becomes_the_main_role(self):
        saved = {"enabled": True, "roles": {"vpn": ALERT_ROLE_ID, "alt_account": ALERT_ROLE_ID}}
        alerts = self.alerts(saved)
        self.assertEqual((alerts["role"], alerts["roles"]), (ALERT_ROLE_ID, {}))
        self.assertNotIn("vpn", alerts["off"])
        self.assertIn("avatar", alerts["off"], "what pinged nobody before still pings nobody")

    def test_a_different_role_on_one_row_stays_on_that_row(self):
        alerts = self.alerts({"enabled": True, "roles": {"vpn": ALERT_ROLE_ID, "mfa": ALERT_ROLE_ID, "avatar": OTHER_ROLE_ID}})
        self.assertEqual((alerts["role"], alerts["roles"]), (ALERT_ROLE_ID, {"avatar": OTHER_ROLE_ID}))

    def test_no_roles_at_all_leaves_everything_ready_for_one(self):
        self.assertEqual(self.alerts({"enabled": True, "roles": {}}), {"enabled": True, "role": None, "off": [], "roles": {}})

    def test_saving_again_changes_nothing(self):
        once = self.alerts({"enabled": True, "roles": {"vpn": ALERT_ROLE_ID, "avatar": OTHER_ROLE_ID, "mfa": ALERT_ROLE_ID}})
        self.assertEqual(self.alerts(once), once)

    def test_the_role_stays_behind_in_an_export(self):
        document = settings.defaults()
        document["core"]["alerts"].update(role=ALERT_ROLE_ID, off=["vpn"])
        merged = settings.import_code(settings.defaults(), settings.export_code(document))
        self.assertIsNone(merged["core"]["alerts"]["role"])
        self.assertEqual(merged["core"]["alerts"]["off"], ["vpn"])


class SetupWithLogsAndAlerts(test_web_guards.Base):
    async def set_up(self, **extra):
        await self.db.run("UPDATE guilds SET setup_done = 0")
        return await self.send("POST", "/setup", {"verified_role": VERIFIED_ROLE, "channel": CHANNEL, **extra})

    async def test_both_are_optional(self):
        await self.log_in()
        before = (await self.service.get_settings(GUILD))["core"]
        status, _ = await self.set_up()
        self.assertEqual(status, 200)
        after = (await self.service.get_settings(GUILD))["core"]
        self.assertEqual((after["logs"], after["alerts"]), (before["logs"], before["alerts"]))

    async def test_one_channel_takes_every_log_and_the_role_takes_the_alerts(self):
        await self.log_in()
        status, _ = await self.set_up(log_channel=LOG_CHANNEL, alert_role=UNVERIFIED_ROLE)
        self.assertEqual(status, 200)
        core = (await self.service.get_settings(GUILD))["core"]
        self.assertTrue(core["logs"]["enabled"])
        self.assertEqual(set(core["logs"]["modules"].values()), {LOG_CHANNEL})
        self.assertEqual(len(core["logs"]["modules"]), len(catalog.LOG_MODULES))
        self.assertEqual(core["alerts"]["role"], UNVERIFIED_ROLE)

    async def test_a_channel_from_elsewhere_is_refused(self):
        await self.log_in()
        status, _ = await self.set_up(log_channel="980000000000000001")
        self.assertEqual(status, 400)


class NoLimitOnHealth(test_bot_commands.Commands):
    def test_health_can_be_run_as_often_as_staff_like(self):
        self.assertEqual(self.bot.tree.get_command("health").checks, [])


class NoLimitOnStaff(test_web_guards.Base):
    async def test_posting_answers_every_time(self):
        await self.log_in()
        self.app["post_message"] = AsyncMock(return_value=True)
        answers = [(await self.send("POST", "/post-message", {"message": "verification"}))[0] for _ in range(12)]
        self.assertEqual(answers, [200] * 12)

    async def test_analytics_answers_every_time(self):
        await self.log_in()
        answers = [(await self.get("/analytics"))[0] for _ in range(40)]
        self.assertEqual(answers, [200] * 40)

    async def test_the_preview_answers_every_time(self):
        await self.log_in()
        document = (await self.get("/settings"))[1]["settings"]
        answers = [(await self.send("POST", "/settings/preview", {"settings": document}))[0] for _ in range(12)]
        self.assertEqual(answers, [200] * 12)


class HistoryRows(test_web_guards.Base):
    async def test_a_members_history_leaves_out_starts_and_keeps_a_thousand(self):
        await self.log_in()
        self.port.add_member(OLD_USER)
        await self.db.touch_member(GUILD, OLD_USER)
        now = time.time()
        await self.db.run_many("INSERT INTO attempts (guild_id, user_id, at, outcome, detail) VALUES (?, ?, ?, ?, '{}')",
                               [(GUILD, OLD_USER, now - number, "started" if number % 2 else "failed") for number in range(2400)])
        status, data = await self.get(f"/members/{OLD_USER}")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["attempts"]), 1000)
        self.assertEqual({row["outcome"] for row in data["attempts"]}, {"failed"})


class AFamilyWithNoLists(limits.Limited):
    async def attempt(self, *, fail_open, net):
        await self.edit(lambda document: document["core"].update(fail_open=fail_open))
        self.service.net.lists.entries = 1  # other lists loaded, so this isn't the no-lists-at-all case
        self.service.net.lookup = lambda ip: net
        token = await self.signed_in(OLD_USER)
        return await self.submit_directly(token, device=None)

    async def test_with_fail_open_off_it_waits_like_no_lists_at_all(self):
        result = await self.attempt(fail_open=False, net=NetInfo(known=False))
        self.assertEqual((result.status, result.reason, result.retry), ("problem", "connection_check", True))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)
        self.assertEqual(await self.db.scalar("SELECT state FROM sessions"), "signed_in")

    async def test_with_fail_open_on_it_goes_ahead(self):
        self.assertEqual((await self.attempt(fail_open=True, net=NetInfo(known=False))).status, "verified")

    async def test_a_reserved_address_isnt_this_case(self):
        result = await self.attempt(fail_open=False, net=NetInfo(known=False, reserved=True))
        self.assertNotEqual(result.reason, "connection_check")


class HoneypotThreads(unittest.TestCase):
    def test_a_private_thread_under_the_trap_needs_manage_threads(self):
        document = settings.defaults()
        document["core"].update(verified_role=VERIFIED_ROLE, channel=LOG_CHANNEL)
        document["honeypot"] = {"enabled": True, "channel": LOG_CHANNEL, "action": "log"}
        document = settings.normalize(document)

        def view(*held):
            return GuildView(id=GUILD, channels=[{"id": LOG_CHANNEL, "name": "trap", "type": "text", "category": None, "position": 0}], bot_permissions=frozenset({"manage_roles"}), bot_top_role=5,
                             channel_permissions={LOG_CHANNEL: frozenset({"view_channel", "send_messages", "embed_links", *held})})
        missing = json.dumps(health.report(view("manage_messages", "pin_messages"), document)["issues"])
        self.assertIn("Manage Threads", missing)
        present = json.dumps(health.report(view("manage_messages", "pin_messages", "manage_threads"), document)["issues"])
        self.assertNotIn("Manage Threads", present)


if __name__ == "__main__":
    unittest.main()
