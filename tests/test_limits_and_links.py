"""Limits with no way back, evidence locks held too long, and rules that have to hold together."""
import array
import asyncio
import itertools
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import altmatch, catalog, crypto, engine, health, notices, service as service_module, settings
from altwarden.netintel import NetInfo, NetIntel, RangeTable, load_lists
from altwarden.ports import MemberInfo
from altwarden.bot import client as client_module
from altwarden.web import app as app_module
from altwarden.web.app import FLOW_COOKIE, VERIFY_FLOW_COOKIE
from fakes import CHANNEL, GUILD, OLD_USER, OTHER_USER, STAFF, UNVERIFIED_ROLE, VERIFIED_ROLE
from test_member_states import ALERT_ROLE, LIMIT_ROLE, THIRD_USER, Base, Gate, Prepared
from test_web_guards import Base as WebBase
from test_client import Client, fake_interaction
from test_detection import clean_report

ELSEWHERE = "198.51.100.7"
HOME = "203.0.113.9"
PUBLIC = "8.8.8.8"  # the other two are reserved for documentation, so a match on them counts as weak


class Limited(Prepared):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.edit(lambda document: document["core"]["cooldown"].update(enabled=False))

    async def row(self, user=OLD_USER):
        return await self.db.member(GUILD, user)

    async def button_mode(self, **limit):
        def change(document):
            document["core"]["mode"] = "button"
            document["checks"]["avatar"].update(enabled=True, action="deny")
            document["checks"]["max_attempts"].update(limit)
        await self.edit(change)

    async def noise(self):
        """Everything a quiet try must leave alone."""
        return len(self.port.dms), len(self.port.sent), await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE guild_id = ?", (GUILD,))

    async def fail_on_button(self, times, user=OLD_USER):
        member = self.port.members[(GUILD, user)]
        member.avatar = None
        result = None
        for _ in range(times):
            result = await self.service.press_verify(member)
        return result


class TheQuietPath(Limited):
    async def test_a_limit_turned_on_after_the_failures_comes_back_on_time(self):
        await self.button_mode(enabled=False, attempts=5, reset_minutes=60)
        await self.fail_on_button(5)
        await self.edit(lambda document: document["checks"]["max_attempts"].update(enabled=True))
        before = time.time()
        result = await self.fail_on_button(1)
        row = await self.row()
        self.assertEqual((result.status, result.reason), ("failed", "max_attempts"))
        self.assertGreaterEqual(row["limit_reached_at"], before)
        self.assertAlmostEqual(result.retry_on, row["limit_reached_at"] + 3600, delta=2)
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=time.time() - 3601)
        await self.service.tick()
        row = await self.row()
        self.assertEqual((row["fails"], row["limit_reached_at"]), (0, None))

    async def test_lowering_the_limit_under_a_members_count_stamps_on_the_next_try(self):
        await self.button_mode(attempts=5, reset_minutes=60)
        await self.fail_on_button(3)
        await self.edit(lambda document: document["checks"]["max_attempts"].update(attempts=3))
        self.assertIsNone((await self.row())["limit_reached_at"])
        await self.fail_on_button(1)
        self.assertIsNotNone((await self.row())["limit_reached_at"])

    async def test_the_first_try_past_the_limit_speaks_and_the_next_is_quiet(self):
        await self.button_mode(attempts=2, reset_minutes=60)
        await self.fail_on_button(2)
        await self.db.update_member(GUILD, OLD_USER, fails=4, limit_reached_at=None)
        before = await self.noise()
        await self.fail_on_button(1)
        after_first = await self.noise()
        self.assertGreater(after_first[0], before[0], "the try that stamps is told like any other")
        await self.fail_on_button(1)
        self.assertEqual(await self.noise(), after_first)

    async def test_a_try_past_a_stamped_limit_doesnt_restart_its_clock(self):
        await self.button_mode(attempts=2, reset_minutes=60)
        await self.fail_on_button(2)
        stamped = time.time() - 600
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=stamped)
        result = await self.fail_on_button(1)
        self.assertEqual((await self.row())["limit_reached_at"], stamped)
        self.assertAlmostEqual(result.retry_on, stamped + 3600, delta=1)

    async def test_a_link_that_skips_the_limit_never_stamps_it(self):
        await self.edit(lambda document: document["checks"]["avatar"].update(enabled=True, action="deny"))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=9)
        document = await self.service.get_settings(GUILD)
        url, _ = await self.service.new_link(GUILD, OLD_USER, document, bypass=["max_attempts"], hours=1)
        token = url.rsplit("/", 1)[1]
        await self.sign_in(token)
        await self.db.run("UPDATE sessions SET account = json_set(account, '$.avatar', NULL)")
        result = await self.submit_directly(token, device=None)
        self.assertEqual(result.reason, "avatar")
        self.assertIsNone((await self.row())["limit_reached_at"])

    async def test_a_web_try_past_an_unstamped_limit_stamps_and_the_next_stores_nothing(self):
        await self.edit(lambda document: document["checks"]["max_attempts"].update(attempts=2, reset_minutes=60))
        token = await self.signed_in(OLD_USER)
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=2)
        result = await self.submit_directly(token, device=None)
        self.assertEqual(result.reason, "max_attempts")
        self.assertIsNotNone((await self.row())["limit_reached_at"])
        await self.db.run("DELETE FROM identifiers")
        before = await self.noise()
        result = await self.submit_directly(token, device=None)
        self.assertEqual(result.reason, "max_attempts")
        self.assertEqual(await self.noise(), before)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)


class AppealingPastALimit(Limited):
    async def appeal(self):
        return await self.service.submit_appeal(GUILD, OLD_USER, "someone", "this wasn't me at all")

    async def decide(self):
        row = await self.db.one("SELECT id FROM appeals WHERE guild_id = ? AND status = 'open'", (GUILD,))
        await self.service.settle_appeal(GUILD, row["id"], "deny", STAFF, "staff")

    async def test_a_quiet_try_counts_as_a_new_failed_attempt_for_an_appeal(self):
        await self.edit(lambda document: document["appeals"].update(enabled=True))
        await self.button_mode(attempts=2, reset_minutes=0)
        await self.fail_on_button(2)
        self.assertIsNone(await self.appeal())
        await self.decide()
        await asyncio.sleep(0.01)
        self.assertIn("appeal again tomorrow", await self.appeal())
        before = await self.noise()
        await self.fail_on_button(1)
        self.assertEqual(await self.noise(), before, "the try itself stays quiet")
        self.assertIn("appeal again tomorrow", await self.appeal(), "a try can't bring a new ping at once")
        await self.db.run("UPDATE appeals SET decided_at = ?", (time.time() - service_module.REAPPEAL_SECONDS - 60,))
        await self.db.update_member(GUILD, OLD_USER, last_fail_at=time.time() - service_module.REAPPEAL_SECONDS - 90)
        await self.db.run("UPDATE attempts SET at = ?", (time.time() - service_module.REAPPEAL_SECONDS - 90,))
        self.assertIn("A new failed attempt can be appealed", await self.appeal(), "a day on, it still takes a new try")
        await self.fail_on_button(1)
        self.assertIsNone(await self.appeal(), "the sentence the member was shown holds")
        self.assertEqual((await self.db.one("SELECT check_id FROM appeals WHERE status = 'open'"))["check_id"], "max_attempts")

    async def test_a_quiet_try_a_week_on_still_opens_an_appeal(self):
        await self.edit(lambda document: document["appeals"].update(enabled=True))
        await self.button_mode(attempts=2, reset_minutes=0)
        await self.fail_on_button(2)
        await self.db.run("UPDATE attempts SET at = ?", (time.time() - 8 * 86400,))
        await self.db.update_member(GUILD, OLD_USER, last_fail_at=time.time() - 8 * 86400)
        self.assertIsNotNone(await self.appeal())
        await self.fail_on_button(1)
        self.assertIsNone(await self.appeal())

    async def test_a_failure_time_with_no_limit_reached_opens_nothing(self):
        await self.edit(lambda document: document["appeals"].update(enabled=True))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, last_fail_at=time.time())
        self.assertIsNotNone(await self.appeal())


class InstantMode(Limited):
    async def instant(self, **limit):
        def change(document):
            document["core"]["mode"] = "instant"
            document["checks"]["avatar"].update(enabled=True, action="deny")
            document["checks"]["max_attempts"].update(limit)
        await self.edit(change)
        self.port.members[(GUILD, OLD_USER)].avatar = None

    async def join(self):
        await self.service.on_join(self.port.members[(GUILD, OLD_USER)])

    async def test_reaching_the_limit_doesnt_say_a_rejoin_helps(self):
        await self.instant(attempts=2, reset_minutes=0)
        await self.join()
        self.assertIn("Leave the server and rejoin to try again.", self.dm_text()[-1])
        await self.join()
        self.assertIn("You have used all your verification attempts", self.dm_text()[-1])
        self.assertNotIn("rejoin", self.dm_text()[-1])

    async def test_each_rejoin_past_the_limit_gets_one_dm_and_nothing_else(self):
        await self.instant(attempts=2, reset_minutes=0)
        await self.join()
        await self.join()
        for _ in range(2):
            count, posts, rows = await self.noise()
            await self.join()
            self.assertEqual(await self.noise(), (count + 1, posts, rows))
            self.assertIn("You have used all your verification attempts", self.dm_text()[-1])
            self.assertNotIn("rejoin", self.dm_text()[-1])

    async def test_a_held_lock_sends_no_cooldown_dm(self):
        await self.instant(attempts=5, reset_minutes=0)
        async with self.service._lock(GUILD, OLD_USER):
            await self.service._check_on_join(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(self.port.dms, [])

    async def test_a_real_cooldown_still_says_so(self):
        await self.edit(lambda document: document["core"]["cooldown"].update(enabled=True, seconds=300))
        await self.instant(attempts=5, reset_minutes=0)
        await self.join()
        await self.join()
        self.assertIn("You're on cooldown", self.dm_text()[-1])

    async def test_a_live_bypass_link_is_honored_on_a_rejoin(self):
        await self.instant(attempts=5, reset_minutes=0)
        await self.edit(lambda document: document["checks"]["avatar"].update(action="kick"))
        await self.service.create_bypass(GUILD, OLD_USER, ["avatar"], 24, "dm", STAFF)
        self.port.dms.clear()
        await self.join()
        self.assertEqual(self.port.did("kick"), [])
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE outcome = 'failed'"), 0)
        self.assertEqual(len(self.port.dms), 1)

    async def test_no_unverified_role_on_a_rejoin_with_a_bypass(self):
        await self.instant(attempts=5, reset_minutes=0)
        await self.edit(lambda document: document["core"].update(unverified_enabled=True, unverified_role=UNVERIFIED_ROLE))
        await self.service.create_bypass(GUILD, OLD_USER, ["avatar"], 24, "dm", STAFF)
        await self.join()
        self.assertNotIn(("add_role", OLD_USER, UNVERIFIED_ROLE), self.port.calls)

    async def test_with_no_live_link_a_rejoin_is_checked(self):
        await self.instant(attempts=5, reset_minutes=0)
        await self.join()
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE outcome = 'failed'"), 1)


class HoldingALimitForAnUnprovenLink(Limited):
    """A fingerprint and a device can be planted, so a link below confirmed can't reach a kick through the attempt limit."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.turn_on_alts()
        await self.edit(lambda document: document["checks"]["max_attempts"].update(enabled=True, action="kick", attempts=2, reset_minutes=0, role=LIMIT_ROLE))
        first = await self.signed_in(OTHER_USER)
        self.assertEqual((await self.submit_directly(first, device=None)).status, "verified")
        self.token = await self.signed_in(OLD_USER)

    async def retry(self):
        result = await self.submit_directly(self.token, device=None)
        return result.status, result.reason, result.action

    def on_a_vpn(self):
        return patch.object(self.service.net, "lookup", lambda ip: NetInfo(vpn=True, known=True))

    async def test_the_attempt_reaching_the_limit_stays_a_deny(self):
        self.assertEqual(await self.retry(), ("failed", "alt_account", "deny"))
        self.assertEqual(await self.retry(), ("failed", "max_attempts", "deny"))
        self.assertEqual(self.port.did("kick"), [])
        row = await self.row()
        self.assertEqual(row["fails"], 2)
        self.assertIsNotNone(row["limit_reached_at"])

    async def test_a_member_held_at_deny_gets_the_limit_role(self):
        await self.retry()
        await self.retry()
        self.assertIn(("add_role", OLD_USER, LIMIT_ROLE), self.port.calls)

    async def test_later_attempts_stay_a_deny_and_go_quiet(self):
        await self.retry()
        await self.retry()
        before = await self.noise()
        stored = await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,))
        for _ in range(3):
            self.assertEqual(await self.retry(), ("failed", "max_attempts", "deny"))
        self.assertEqual(await self.noise(), before)
        self.assertEqual(self.port.did("kick"), [])
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,)), stored)

    async def test_an_unstamped_member_past_the_limit_is_held_and_stamped(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=2)
        self.assertEqual(await self.retry(), ("failed", "max_attempts", "deny"))
        self.assertEqual(self.port.did("kick"), [])
        self.assertIsNotNone((await self.row())["limit_reached_at"])
        self.assertIn(("add_role", OLD_USER, LIMIT_ROLE), self.port.calls)

    async def test_a_vpn_set_to_kick_alongside_the_link_still_kicks(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        await self.retry()
        with self.on_a_vpn():
            self.assertEqual((await self.retry())[2], "kick")
        self.assertEqual(len(self.port.did("kick")), 1)

    async def test_a_vpn_set_to_deny_alongside_the_link_lets_the_limit_kick(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.retry()
        with self.on_a_vpn():
            self.assertEqual((await self.retry())[2], "kick")

    async def test_a_second_finding_on_the_last_attempt_lets_the_limit_kick(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.retry()
        self.assertEqual(self.port.did("kick"), [])
        with self.on_a_vpn():
            self.assertEqual((await self.retry())[2], "kick")

    async def test_past_the_hold_nothing_new_is_looked_at(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.retry()
        await self.retry()
        with self.on_a_vpn():
            self.assertEqual((await self.retry())[2], "deny")
        self.assertEqual(self.port.did("kick"), [])

    async def test_a_cookie_match_isnt_held(self):
        await self.db.store_identifier(GUILD, OTHER_USER, "cookie", self.keys.digest(int(GUILD), "cookie", "device-1"), time.time() + 86400)
        result = await self.submit_directly(self.token, device="device-1")
        self.assertEqual(result.action, "kick")

    async def test_a_link_below_confirmed_set_to_deny_is_held_too(self):
        await self.change(alt_account={"alt_action": "deny"})
        await self.retry()
        self.assertEqual((await self.retry())[2], "deny")
        self.assertEqual(self.port.did("kick"), [])

    async def test_a_limit_on_ban_is_held_as_well(self):
        await self.change(max_attempts={"action": "ban"})
        await self.retry()
        self.assertEqual((await self.retry())[2], "deny")
        self.assertEqual(self.port.did("ban"), [])

    async def test_auto_kick_still_removes_whoever_didnt_verify(self):
        await self.edit(lambda document: document["core"]["auto_kick"].update(enabled=True, minutes=10))
        await self.retry()
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1)
        await self.service.tick()
        self.assertEqual(len(self.port.did("kick")), 1)


class LimitsWithNoAltCheck(Limited):
    """Button and instant modes run no alt check, so nothing there can hold a limit."""

    async def test_a_kick_limit_on_the_button_kicks_at_the_limit_and_after(self):
        await self.button_mode(action="kick", attempts=2, reset_minutes=0)
        result = await self.fail_on_button(2)
        self.assertEqual(result.action, "kick")
        self.assertEqual(len(self.port.did("kick")), 1)
        result = await self.fail_on_button(1)
        self.assertEqual(result.action, "kick")
        self.assertEqual(len(self.port.did("kick")), 2)

    async def test_a_kick_limit_doesnt_restart_its_clock_on_later_tries(self):
        await self.button_mode(action="kick", attempts=2, reset_minutes=60)
        await self.fail_on_button(2)
        stamped = time.time() - 600
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=stamped)
        await self.fail_on_button(1)
        self.assertEqual((await self.row())["limit_reached_at"], stamped)

    async def test_a_kick_limit_in_instant_mode_kicks_at_the_limit_and_after(self):
        def change(document):
            document["core"]["mode"] = "instant"
            document["checks"]["avatar"].update(enabled=True, action="deny")
            document["checks"]["max_attempts"].update(action="kick", attempts=2, reset_minutes=0)
        await self.edit(change)
        member = self.port.members[(GUILD, OLD_USER)]
        member.avatar = None
        for expected in (0, 1, 2):
            await self.service.on_join(member)
            self.assertEqual(len(self.port.did("kick")), expected)

    async def test_a_kick_limit_with_nothing_else_wrong_on_the_web_still_kicks(self):
        await self.edit(lambda document: document["checks"]["max_attempts"].update(action="kick", attempts=2, reset_minutes=0))
        token = await self.signed_in(OLD_USER)
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=2, limit_reached_at=time.time())
        result = await self.submit_directly(token, device=None)
        self.assertEqual(result.action, "kick")


class PressingVerify(Limited):
    async def verified(self, method):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.mark_verified(GUILD, OLD_USER, method)

    async def test_a_role_staff_took_from_a_verified_member_doesnt_come_back_at_a_press(self):
        await self.verified("web")
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertIsInstance(result, str, "they get a link and run the checks")
        self.assertEqual(self.port.did("add_role"), [])

    async def test_the_same_on_the_button_runs_the_checks(self):
        await self.button_mode(attempts=5, reset_minutes=0)
        await self.verified("button")
        result = await self.fail_on_button(1)
        self.assertEqual((result.status, result.reason), ("failed", "avatar"))
        self.assertEqual(self.port.did("add_role"), [])

    async def test_a_staff_verified_member_runs_the_checks_too(self):
        await self.verified("staff")
        self.assertIsInstance(await self.service.press_verify(self.port.members[(GUILD, OLD_USER)]), str)

    async def test_an_imported_member_gets_the_role_they_never_had(self):
        await self.verified(service_module.IMPORTED_WITHOUT_ROLE)
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(result.status, "already")
        self.assertEqual(len(self.port.did("add_role")), 1)

    async def test_an_approved_appeal_still_finishes_at_a_press(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, status="approved")
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(result.message, "Staff approved your appeal.")
        self.assertEqual((await self.row())["status"], "verified")


IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"


def phone():
    return clean_report(fp={"id": "b" * 32, "confidence": .9}, nav={"ua": IPHONE, "platform": "iPhone", "vendor": "Apple Computer, Inc.", "cores": 6},
                        uad={}, gpu={"renderer": "Apple GPU"}, eng={"evalLen": 37}, worker={}, scr={"w": 390, "h": 844, "iw": 390, "ih": 700, "ow": 390, "oh": 844})


def other_machine():
    """Shares nothing with clean_report but the connection it's sent from."""
    report = clean_report(fp={"id": "c" * 32, "confidence": .9})
    report["scr"] = {**report["scr"], "w": 1111}
    return report


class Links(Prepared):
    """Two accounts' evidence, walked through the real service."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.edit(lambda document: document["core"]["cooldown"].update(enabled=False))
        await self.turn_on_alts()

    async def verified_first(self, report=None, ip=HOME, user=OTHER_USER):
        token = await self.signed_in(user)
        self.assertEqual((await self.submit_directly(token, device=None, ip=ip, report=report)).status, "verified")

    async def second(self, *, report=None, ip=ELSEWHERE, user=OLD_USER):
        token = await self.signed_in(user)
        return await self.submit_directly(token, device=None, ip=ip, report=report)

    async def findings(self, user=OLD_USER):
        row = await self.db.one("SELECT detail FROM attempts WHERE user_id = ? AND outcome IN ('passed', 'failed') ORDER BY id DESC LIMIT 1", (user,))
        return json.loads(row["detail"])["findings"]


class ALinkToABannedAccount(Links):
    async def test_a_fingerprint_and_device_from_another_network_stops_a_ban_evader(self):
        await self.verified_first()
        await self.service.on_ban(GUILD, OTHER_USER)
        self.port.banned.add(OTHER_USER)
        result = await self.second()
        self.assertEqual((result.status, result.reason, result.action, result.appeal), ("failed", "alt_account", "deny", True))
        self.assertEqual(self.port.did("ban"), [])

    async def test_the_same_link_to_an_account_in_good_standing_keeps_the_servers_floor(self):
        await self.verified_first()
        result = await self.second()
        self.assertEqual(result.status, "verified")
        self.assertEqual([(found["check"], found["action"]) for found in await self.findings()], [("alt_account", "watch")])

    async def test_a_floor_of_confirmed_still_catches_the_evader_and_nobody_else(self):
        await self.change(alt_account={"min_confidence": "confirmed"})
        await self.verified_first()
        self.assertEqual((await self.second()).status, "verified")
        await self.service.on_ban(GUILD, OTHER_USER)
        self.port.banned.add(OTHER_USER)
        result = await self.second(user=THIRD_USER)
        self.assertEqual((result.status, result.action), ("failed", "deny"))

    async def test_an_address_alone_doesnt_count(self):
        await self.verified_first(ip=PUBLIC)
        await self.service.on_ban(GUILD, OTHER_USER)
        self.port.banned.add(OTHER_USER)
        result = await self.second(report=other_machine(), ip=PUBLIC)
        self.assertEqual(result.status, "verified")
        self.assertEqual([found["action"] for found in await self.findings()], ["watch"])

    async def test_the_link_is_counted_once(self):
        await self.verified_first()
        await self.service.on_ban(GUILD, OTHER_USER)
        self.port.banned.add(OTHER_USER)
        await self.second()
        found = await self.findings()
        self.assertEqual([(entry["check"], entry["action"], entry["detail"]["capped"]) for entry in found], [("alt_account", "deny", True)])
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM links"), 1)

    async def test_a_ban_lifted_while_the_bot_wasnt_looking_stops_counting(self):
        await self.verified_first()
        await self.service.on_ban(GUILD, OTHER_USER)
        self.assertEqual((await self.second()).status, "verified", "Discord says there's no ban, and asking is what finds that out")
        self.assertFalse(await self.db.is_banned(GUILD, OTHER_USER))

    async def test_a_ban_the_bot_never_saw_counts(self):
        await self.verified_first()
        self.port.banned.add(OTHER_USER)
        self.assertEqual((await self.second()).action, "deny")
        self.assertTrue(await self.db.is_banned(GUILD, OTHER_USER))

    def test_counting_lets_only_a_banned_link_in_below_the_floor(self):
        link = altmatch.Link(OTHER_USER, 65, "possible", ["fingerprint", "device"], banned=True, verified=True)
        same_good = altmatch.Link(OTHER_USER, 65, "possible", ["fingerprint", "device"], banned=False, verified=True)
        low = altmatch.Link(OTHER_USER, 59, "possible", ["ip", "device"], banned=True, verified=True)
        self.assertEqual(altmatch.counting([link, same_good, low], "likely"), [link])
        self.assertEqual(altmatch.counting([link, same_good, low], "confirmed"), [link])
        self.assertEqual(altmatch.counting([link, same_good, low], "possible"), [link, same_good, low])
        self.assertEqual(altmatch.BANNED_LINK_SCORE, 60)
        self.assertGreater(altmatch.BANNED_LINK_SCORE, altmatch.score_for({"ip"}))
        self.assertLessEqual(altmatch.BANNED_LINK_SCORE, altmatch.score_for({"fingerprint", "device"}))


class TheWatchListBelowTheFloor(Links):
    async def from_a_phone(self, token, ip):
        row = await self.service.session(token)
        await self.db.run("UPDATE sessions SET state = 'checking' WHERE token_hash = ?", (crypto.token_hash(token),))
        return await self.service.submit_web(token, row, phone(), ip=ip, headers={"user-agent": IPHONE}, device_id=None)

    def attempt(self, *links):
        document = settings.normalize(self.doc)
        document["checks"]["alt_account"].update(enabled=True, min_confidence="likely")
        return engine.run_checks(engine.Attempt(document, "web", engine.Account(OLD_USER, "x", "abc", True, True, False), {}, links=list(links)))

    async def test_two_phones_of_one_model_ping_nobody(self):
        await self.edit(lambda document: document["core"]["alerts"].update(enabled=True, roles={"alt_account": ALERT_ROLE}))
        first = await self.signed_in(OTHER_USER)
        self.assertEqual((await self.from_a_phone(first, HOME)).status, "verified")
        posts = len(self.posts())
        result = await self.from_a_phone(await self.signed_in(OLD_USER), ELSEWHERE)
        self.assertEqual(result.status, "verified")
        self.assertEqual(await self.findings(), [])
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM links"), 0)
        self.assertNotIn(ALERT_ROLE, json.dumps([notice.mention_roles for notice in self.posts()[posts:]]))

    def test_a_device_with_only_weak_evidence_beside_it_is_left_out(self):
        for methods, weak, score in ((["device"], [], 30), (["fingerprint", "device"], ["fingerprint"], 30), (["fingerprint", "ip", "device"], ["fingerprint", "ip"], 40),
                                     (["ip", "device"], ["ip"], 30), (["fingerprint", "ip"], ["fingerprint", "ip"], 30)):
            link = altmatch.Link(OTHER_USER, score, "possible", methods, verified=True, weak=weak)
            self.assertEqual(self.attempt(link).findings, [], methods)

    def test_real_evidence_below_the_floor_is_still_watched(self):
        for methods, weak, score in ((["ip"], [], 35), (["fingerprint", "device"], [], 65), (["fingerprint", "ip", "device"], ["fingerprint"], 65)):
            link = altmatch.Link(OTHER_USER, score, "possible", methods, verified=True, weak=weak)
            self.assertEqual([finding.action for finding in self.attempt(link).findings], ["watch"], methods)

    def test_the_filter_doesnt_hide_a_banned_link_that_counts(self):
        link = altmatch.Link(OTHER_USER, 65, "possible", ["fingerprint", "ip", "device"], banned=True, verified=True)
        self.assertEqual([finding.action for finding in self.attempt(link).findings], ["deny"])

    def test_a_server_that_asks_for_possible_gets_what_it_asked_for(self):
        document = settings.normalize(self.doc)
        document["checks"]["alt_account"].update(enabled=True, min_confidence="possible")
        link = altmatch.Link(OTHER_USER, 30, "possible", ["fingerprint", "device"], verified=True, weak=["fingerprint"])
        decision = engine.run_checks(engine.Attempt(document, "web", engine.Account(OLD_USER, "x", "abc", True, True, False), {}, links=[link]))
        self.assertEqual([finding.check_id for finding in decision.enforced], ["alt_account"])


class WhatABanKeeps(Base):
    async def store(self, kind, digest="x"):
        await self.db.store_identifier(GUILD, OLD_USER, kind, digest, time.time() + 86400)

    async def expiry(self, kind):
        return await self.db.scalar("SELECT expires_at FROM identifiers WHERE user_id = ? AND kind = ?", (OLD_USER, kind))

    async def test_a_ban_keeps_browser_hashes_and_leaves_the_address_on_its_own_date(self):
        for kind in ("ip", "fingerprint", "device", "cookie"):
            await self.store(kind)
        ip_before = await self.expiry("ip")
        await self.db.record_ban(GUILD, OLD_USER, keep_days=730)
        self.assertEqual(await self.expiry("ip"), ip_before)
        for kind in ("fingerprint", "device", "cookie"):
            self.assertGreater(await self.expiry(kind), time.time() + 700 * 86400, kind)

    async def test_the_purge_ends_a_banned_accounts_address_like_anyone_elses(self):
        await self.store("ip")
        await self.store("fingerprint")
        await self.db.record_ban(GUILD, OLD_USER, keep_days=730)
        await self.db.run("UPDATE identifiers SET last_seen = ?, expires_at = ?", (time.time() - 400 * 86400, time.time() + 300 * 86400))
        await self.service.purge()
        self.assertIsNone(await self.expiry("ip"))
        self.assertIsNotNone(await self.expiry("fingerprint"))

    async def test_one_account_holds_three_device_values_and_ten_fingerprints(self):
        for number in range(6):
            await self.store("device", f"device-{number}")
        for number in range(14):
            await self.store("fingerprint", f"print-{number}")
        rows = await self.db.all("SELECT digest FROM identifiers WHERE user_id = ? AND kind = 'device'", (OLD_USER,))
        self.assertEqual({row["digest"] for row in rows}, {"device-3", "device-4", "device-5"})
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ? AND kind = 'fingerprint'", (OLD_USER,)), 10)


class RecordingAPair(Links):
    async def act(self, link, *, action="watch", user=OLD_USER):
        decision = engine.Decision(alt_link=link, main_action=action)
        return await self.service._act_on_link(GUILD, await self.service.get_settings(GUILD), user, decision, "Test Server")

    async def test_a_weaker_link_doesnt_overwrite_a_stronger_row(self):
        await self.act(altmatch.Link(OTHER_USER, 99, "likely", ["fingerprint", "ip", "device"]))
        await self.act(altmatch.Link(OTHER_USER, 30, "possible", ["fingerprint", "device"]))
        row = await self.db.one("SELECT score, confidence FROM links")
        self.assertEqual((row["score"], row["confidence"]), (99, "likely"))

    async def test_a_stronger_or_equal_link_replaces_the_row(self):
        await self.act(altmatch.Link(OTHER_USER, 65, "possible", ["fingerprint", "device"]))
        await self.act(altmatch.Link(OTHER_USER, 100, "confirmed", ["cookie"]))
        row = await self.db.one("SELECT score, methods FROM links")
        self.assertEqual((row["score"], json.loads(row["methods"])), (100, ["cookie"]))

    async def test_each_retry_by_an_alt_writes_nothing_on_a_main_already_gone(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.mark_verified(GUILD, OTHER_USER, "web")
        link = altmatch.Link(OTHER_USER, 100, "confirmed", ["cookie"], verified=True)
        for _ in range(3):
            self.assertEqual(await self.act(link, action="kick"), ", earlier account had already left")
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE user_id = ?", (OTHER_USER,)), 0)
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["status"], "pending", "a rejoin still doesn't hand the role back")

    async def test_a_kick_that_lands_writes_one_row_a_main_can_appeal(self):
        self.port.add_member(OTHER_USER)
        await self.db.touch_member(GUILD, OTHER_USER)
        link = altmatch.Link(OTHER_USER, 100, "confirmed", ["cookie"], verified=True)
        await self.act(link, action="kick")
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE user_id = ? AND outcome = 'failed'", (OTHER_USER,)), 1)

    async def test_a_kick_that_fails_writes_no_row(self):
        self.port.add_member(OTHER_USER)
        self.port.kick_works = False
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.act(altmatch.Link(OTHER_USER, 100, "confirmed", ["cookie"], verified=True), action="kick")
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE user_id = ?", (OTHER_USER,)), 0)


class TrustingAPair(Limited):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.edit(lambda document: document["checks"]["max_attempts"].update(role=LIMIT_ROLE))
        self.port.add_member(OTHER_USER, roles=(LIMIT_ROLE,))
        self.port.members[(GUILD, OLD_USER)].role_ids = (LIMIT_ROLE,)
        for user in (OLD_USER, OTHER_USER):
            await self.db.touch_member(GUILD, user)
            await self.db.update_member(GUILD, user, fails=5, limit_reached_at=time.time())

    async def cleared(self, user):
        row = await self.row(user)
        return row["fails"], row["limit_reached_at"], LIMIT_ROLE in self.port.members[(GUILD, user)].role_ids

    async def test_trusting_clears_the_limit_on_both_accounts(self):
        await self.service.trust_accounts(GUILD, OLD_USER, OTHER_USER, STAFF, "staff")
        self.assertEqual(await self.cleared(OLD_USER), (0, None, False))
        self.assertEqual(await self.cleared(OTHER_USER), (0, None, False))

    async def test_approving_an_appeal_and_trusting_the_link_clears_both_too(self):
        await self.edit(lambda document: document["appeals"].update(enabled=True))
        await self.db.run("INSERT INTO links (guild_id, main_id, alt_id, confidence, score, methods, at) VALUES (?, ?, ?, 'likely', 80, '[]', 1)", (GUILD, OTHER_USER, OLD_USER))
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="alt_account", action="deny")
        await self.service.submit_appeal(GUILD, OLD_USER, "x", "these are two different people")
        appeal = await self.db.one("SELECT id FROM appeals")
        self.assertIsNone((await self.service.settle_appeal(GUILD, appeal["id"], "trust", STAFF, "staff"))["problem"])
        self.assertEqual(await self.cleared(OTHER_USER), (0, None, False))

    async def test_nothing_to_clear_touches_no_role(self):
        await self.db.update_member(GUILD, OLD_USER, fails=0, limit_reached_at=None)
        await self.db.update_member(GUILD, OTHER_USER, fails=0, limit_reached_at=None)
        self.port.calls.clear()
        await self.service.trust_accounts(GUILD, OLD_USER, OTHER_USER, STAFF, "staff")
        self.assertEqual(self.port.did("remove_role"), [])

    async def test_a_trusted_member_can_try_again(self):
        await self.service.trust_accounts(GUILD, OLD_USER, OTHER_USER, STAFF, "staff")
        self.assertIsNone((await self.row())["limit_reached_at"])
        token = await self.signed_in(OLD_USER)
        self.assertEqual((await self.submit_directly(token, device=None)).status, "verified")


class TheEvidenceLocks(Prepared):
    def locks(self, *, floor="likely", weak_fingerprint=False, weak_ip=False, digests=None, **methods):
        alt = {"enabled": True, "min_confidence": floor, "methods": {"cookie": True, "fingerprint": True, "ip": True, **methods}}
        return set(altmatch.lock_keys(digests or {"cookie": "c", "fingerprint": "f", "ip": "i", "device": "d"}, alt, weak_fingerprint=weak_fingerprint, weak_ip=weak_ip))

    def test_a_device_value_never_locks(self):
        self.assertEqual(self.locks(), {"cookie", "fingerprint", "ip"})

    def test_weak_evidence_doesnt_lock_above_possible(self):
        self.assertEqual(self.locks(weak_fingerprint=True), {"cookie", "ip"})
        self.assertEqual(self.locks(weak_ip=True), {"cookie", "fingerprint"})
        self.assertEqual(self.locks(weak_fingerprint=True, weak_ip=True), {"cookie"})
        self.assertEqual(self.locks(floor="confirmed", weak_fingerprint=True), {"cookie", "ip"})

    def test_weak_evidence_locks_at_a_floor_of_possible(self):
        self.assertEqual(self.locks(floor="possible", weak_fingerprint=True, weak_ip=True), {"cookie", "fingerprint", "ip"})

    def test_a_switched_off_kind_doesnt_lock(self):
        self.assertEqual(self.locks(ip=False), {"cookie", "fingerprint"})
        self.assertEqual(self.locks(fingerprint=False), {"cookie", "ip"})

    def test_a_check_thats_off_locks_nothing(self):
        alt = {"enabled": False, "min_confidence": "likely", "methods": {"cookie": True, "fingerprint": True, "ip": True}}
        self.assertEqual(altmatch.lock_keys({"cookie": "c"}, alt, weak_fingerprint=False, weak_ip=False), {})

    def test_every_score_that_can_count_shares_a_lock(self):
        """Every mix of evidence, on every kind of attempt. A link that can count and shares no lock is a race two accounts could both win."""
        kinds = ("cookie", "fingerprint", "ip", "device")
        for floor, needed in (("possible", 30), ("likely", altmatch.BANNED_LINK_SCORE), ("confirmed", altmatch.BANNED_LINK_SCORE)):
            for weak_fingerprint in (False, True):
                for weak_ip in (False, True):
                    locks = self.locks(floor=floor, weak_fingerprint=weak_fingerprint, weak_ip=weak_ip)
                    weak = [kind for kind, is_weak in (("fingerprint", weak_fingerprint), ("ip", weak_ip)) if is_weak]
                    for size in range(1, 5):
                        for matched in itertools.combinations(kinds, size):
                            if altmatch.score_for(matched, weak) >= needed:
                                self.assertTrue(locks & set(matched), (floor, weak, matched))

    async def race(self, one, two):
        await self.turn_on_alts()
        first, second = await self.signed_in(OTHER_USER), await self.signed_in(THIRD_USER)
        real = self.port.add_role

        async def slow(*args):
            await asyncio.sleep(0.05)
            return await real(*args)
        self.port.add_role = slow
        results = await asyncio.gather(self.submit_directly(first, **one), self.submit_directly(second, **two))
        return sorted(result.status for result in results)

    async def test_two_accounts_sharing_a_cookie_cant_both_pass_at_once(self):
        statuses = await self.race({"device": "device-1", "ip": HOME, "report": other_machine()},
                                   {"device": "device-1", "ip": ELSEWHERE, "report": clean_report(fp={"id": "d" * 32, "confidence": .9})})
        self.assertEqual(statuses, ["failed", "verified"])

    async def test_two_accounts_sharing_a_fingerprint_and_an_address_cant_both_pass_at_once(self):
        statuses = await self.race({"device": None, "ip": PUBLIC}, {"device": None, "ip": PUBLIC})
        self.assertEqual(statuses, ["failed", "verified"])

    async def test_two_accounts_sharing_only_a_kind_of_machine_dont_wait_on_each_other(self):
        await self.turn_on_alts()
        first, second = await self.signed_in(OTHER_USER), await self.signed_in(THIRD_USER)
        gate = Gate()
        real = self.port.add_role

        async def held_for_one(guild_id, user_id, role_id, reason):
            if user_id == OTHER_USER:
                await gate.wait()
            return await real(guild_id, user_id, role_id, reason)
        self.port.add_role = held_for_one
        held = asyncio.ensure_future(self.submit_directly(first, device=None, ip=HOME, report=clean_report(fp={"id": "1" * 32, "confidence": .9})))
        await asyncio.wait_for(gate.reached.wait(), 5)
        done = await asyncio.wait_for(self.submit_directly(second, device=None, ip=ELSEWHERE, report=clean_report(fp={"id": "2" * 32, "confidence": .9})), 5)
        self.assertEqual(done.status, "verified")
        self.assertFalse(held.done())
        gate.open()
        self.assertEqual((await held).status, "verified")


class TheMinuteTimer(Limited):
    async def due(self, user, **fields):
        self.port.add_member(user)
        await self.db.touch_member(GUILD, user)
        await self.db.update_member(GUILD, user, **fields)

    async def test_a_held_member_doesnt_hold_up_anyone_elses_kick(self):
        await self.edit(lambda document: document["core"]["auto_kick"].update(enabled=True, minutes=10))
        past = time.time() - 60
        await self.due(OLD_USER, kick_at=past)
        await self.due(OTHER_USER, kick_at=past)
        async with self.service._lock(GUILD, OLD_USER):
            await asyncio.wait_for(self.service.tick(), 5)
        self.assertEqual([call[1] for call in self.port.did("kick")], [OTHER_USER])
        self.assertEqual((await self.row())["kick_at"], past, "their timer waits for the next minute")
        await self.service.tick()
        self.assertEqual(sorted(call[1] for call in self.port.did("kick")), sorted([OLD_USER, OTHER_USER]))

    async def test_a_held_member_doesnt_hold_up_anyones_reminder(self):
        await self.edit(lambda document: document["core"]["auto_kick"].update(enabled=True, minutes=10))
        soon, past = time.time() + 600, time.time() - 60
        await self.due(OLD_USER, kick_at=soon, kick_warn_at=past)
        await self.due(OTHER_USER, kick_at=soon, kick_warn_at=past)
        async with self.service._lock(GUILD, OLD_USER):
            await asyncio.wait_for(self.service.tick(), 5)
        self.assertEqual([who for who, _ in self.port.dms], [OTHER_USER])
        self.assertEqual((await self.row())["kick_warn_at"], past)

    async def test_a_held_member_doesnt_hold_up_anyones_attempts(self):
        await self.edit(lambda document: document["checks"]["max_attempts"].update(reset_minutes=60))
        past = time.time() - 7200
        await self.due(OLD_USER, fails=5, limit_reached_at=past)
        await self.due(OTHER_USER, fails=5, limit_reached_at=past)
        async with self.service._lock(GUILD, OLD_USER):
            await asyncio.wait_for(self.service.tick(), 5)
        self.assertEqual((await self.row())["fails"], 5)
        self.assertEqual((await self.row(OTHER_USER))["fails"], 0)
        await self.service.tick()
        self.assertEqual((await self.row())["fails"], 0)


class ASubmitThatWaited(Prepared):
    """A submit claims its session, then waits its turn. What happened while it waited stands."""

    async def queued(self):
        token = await self.signed_in(OLD_USER)
        lock = self.service._lock(GUILD, OLD_USER)
        await lock.acquire()
        task = asyncio.ensure_future(self.submit_directly(token, device=None))
        await asyncio.sleep(0.05)
        self.assertFalse(task.done())
        return lock, task

    async def assert_nothing_written(self, result):
        self.assertEqual((result.status, result.reason, result.help_slug), ("problem", "link_expired", "link-expired"))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,)), 0)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE user_id = ? AND outcome != 'started'", (OLD_USER,)), 0)
        self.assertEqual(self.port.did("add_role"), [])

    async def test_a_members_deletion_stands(self):
        lock, task = await self.queued()
        await self.service._delete_in(GUILD, OLD_USER)
        lock.release()
        await self.assert_nothing_written(await task)
        self.assertIsNone(await self.db.member(GUILD, OLD_USER))

    async def test_a_staff_verify_stands(self):
        lock, task = await self.queued()
        await self.db.run("DELETE FROM sessions WHERE user_id = ?", (OLD_USER,))
        lock.release()
        await self.assert_nothing_written(await task)

    async def test_a_session_moved_on_writes_nothing(self):
        lock, task = await self.queued()
        await self.db.run("UPDATE sessions SET state = 'open' WHERE user_id = ?", (OLD_USER,))
        lock.release()
        await self.assert_nothing_written(await task)

    async def test_a_session_still_claimed_goes_ahead(self):
        lock, task = await self.queued()
        lock.release()
        self.assertEqual((await task).status, "verified")

    async def test_a_reset_stands_through_the_route_the_page_uses(self):
        token = await self.signed_in(OLD_USER)
        lock = self.service._lock(GUILD, OLD_USER)
        await lock.acquire()
        task = asyncio.ensure_future(self.submit_directly(token, device=None))
        await asyncio.sleep(0.05)
        await self.db.run("DELETE FROM sessions WHERE guild_id = ? AND user_id = ?", (GUILD, OLD_USER))
        lock.release()
        self.assertEqual((await task).status, "problem")
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["first_verified_at"])


class CountryData(unittest.TestCase):
    def net(self, **files):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        for name, text in files.items():
            (Path(folder.name) / name.replace("_", "-").replace("-txt", ".txt").replace("-csv", ".csv")).write_text(text)
        net = NetIntel(folder.name)
        net.lists = load_lists(Path(folder.name))
        return net

    def test_other_lists_alone_dont_make_an_address_placeable(self):
        net = self.net(vpn_x4b_ipv4_txt="45.33.32.0/24\n")
        self.assertTrue(net.ready)
        self.assertFalse(net.lookup("8.8.8.8").known)

    def test_a_loaded_table_for_that_family_does(self):
        net = self.net(country_ipv4_csv="3221225984,3221226239,US\n")
        self.assertTrue(net.lookup("8.8.8.8").known)
        self.assertFalse(net.lookup("2001:4860:4860::8888").known, "that's the IPv4 table")

    def test_an_allow_list_with_no_table_stops_nobody(self):
        document = settings.defaults()
        document["checks"]["geogate"].update(enabled=True, list="allow", countries=["US"], action="deny")
        attempt = engine.Attempt(document, "web", engine.Account(OLD_USER, "x", "abc", True, True, False), {}, net=NetInfo(known=False))
        self.assertEqual([finding.check_id for finding in engine.run_checks(attempt).findings if finding.check_id == "geogate"], [])

    def test_a_row_too_big_to_store_leaves_the_table_lined_up(self):
        table = RangeTable()
        table.add(10, 20, "US")
        for start, end in ((30, 2 ** 64), (2 ** 64, 40), (-1, 50), (60, -1)):
            with self.assertRaises(OverflowError):
                table.add(start, end, "XX")
        table.add(40, 70, "JP")
        table.finish()
        self.assertEqual((list(table.starts), list(table.ends), table.values), ([10, 40], [20, 70], ["US", "JP"]))
        self.assertEqual((table.find(15), table.find(45), table.find(65), table.find(25)), ("US", "JP", "JP", None))

    def test_the_largest_values_a_row_can_hold_still_fit(self):
        table = RangeTable()
        table.add(0, 2 ** 64 - 1, "ZZ")
        self.assertEqual(table.find(2 ** 63), "ZZ")
        self.assertIsInstance(table.starts, array.array)

    def test_a_list_file_with_an_oversized_row_loads_the_rest(self):
        net = self.net(country_ipv4_csv=f"3221225984,{2 ** 64},XX\n3221226240,3221226495,US\n")
        self.assertEqual(net.lists.country[4].values, ["US"])


class TheCheckpoint(Base):
    async def with_a_reader_open(self):
        """A reader partway through a table, with a write after it, is what a checkpoint has to wait for."""
        for number in range(5):
            await self.db.touch_member(GUILD, str(170000000000000000 + number))
        reader = self.db.reader()
        cursor = reader.execute("SELECT * FROM members")
        cursor.fetchone()
        await self.db.touch_member(GUILD, OTHER_USER)
        return reader, cursor

    async def test_a_reader_doesnt_make_it_wait(self):
        reader, cursor = await self.with_a_reader_open()
        try:
            started = time.monotonic()
            self.assertFalse(await self.db.checkpoint())
            self.assertLess(time.monotonic() - started, 1)
        finally:
            cursor.close()
            reader.close()

    async def test_the_busy_timeout_comes_back(self):
        before = await self.db.scalar("PRAGMA busy_timeout")
        await self.db.checkpoint()
        self.assertEqual(await self.db.scalar("PRAGMA busy_timeout"), before)
        self.assertGreater(before, 0)

    async def test_it_comes_back_after_a_refused_checkpoint_too(self):
        before = await self.db.scalar("PRAGMA busy_timeout")
        reader, cursor = await self.with_a_reader_open()
        try:
            await self.db.checkpoint()
            self.assertEqual(await self.db.scalar("PRAGMA busy_timeout"), before)
        finally:
            cursor.close()
            reader.close()

    async def test_with_no_reader_it_empties_the_log(self):
        await self.db.touch_member(GUILD, OLD_USER)
        self.assertTrue(await self.db.checkpoint())
        self.assertEqual(Path(str(self.db.path) + "-wal").stat().st_size, 0)


class ThePurge(Limited):
    async def old_row(self, **fields):
        await self.db.touch_member(GUILD, OLD_USER)
        then = time.time() - 40 * 86400
        await self.db.update_member(GUILD, OLD_USER, joined_at=then, last_fail_at=then, **fields)
        await self.edit(lambda document: document["privacy"].update(attempt_days=30))

    async def test_a_limit_that_never_returns_keeps_its_row(self):
        await self.old_row(fails=5, limit_reached_at=time.time() - 40 * 86400)
        await self.service.purge()
        self.assertIsNotNone(await self.row())

    async def test_an_old_row_with_no_limit_still_goes(self):
        await self.old_row()
        await self.service.purge()
        self.assertIsNone(await self.row())


class DeletingWithATimer(Limited):
    async def verified_member(self):
        await self.edit(lambda document: document["core"]["auto_kick"].update(enabled=True, minutes=10))
        await self.db.touch_member(GUILD, OLD_USER, username="someone")
        await self.db.mark_verified(GUILD, OLD_USER, "web")
        self.port.members[(GUILD, OLD_USER)].role_ids = (VERIFIED_ROLE,)

    async def test_someone_still_here_gets_a_blank_row_with_a_deadline(self):
        await self.verified_member()
        before = time.time()
        await self.service.delete_my_data(OLD_USER)
        row = await self.row()
        self.assertEqual((row["username"], row["status"], row["first_verified_at"]), ("", "pending", None))
        self.assertAlmostEqual(row["kick_at"], before + 600, delta=5)
        self.assertAlmostEqual(row["kick_warn_at"], before + 300, delta=5)

    async def test_a_timer_already_running_isnt_restarted(self):
        await self.verified_member()
        running = time.time() + 120
        await self.db.update_member(GUILD, OLD_USER, status="pending", kick_at=running)
        await self.service.delete_my_data(OLD_USER)
        self.assertEqual((await self.row())["kick_at"], running)

    async def test_someone_who_left_keeps_no_row(self):
        await self.verified_member()
        del self.port.members[(GUILD, OLD_USER)]
        await self.service.delete_my_data(OLD_USER)
        self.assertIsNone(await self.row())

    async def test_with_auto_kick_off_no_row_stays(self):
        await self.verified_member()
        await self.edit(lambda document: document["core"]["auto_kick"].update(enabled=False))
        await self.service.delete_my_data(OLD_USER)
        self.assertIsNone(await self.row())

    async def test_a_member_who_never_had_a_deadline_doesnt_get_one_from_deleting(self):
        await self.edit(lambda document: document["core"]["auto_kick"].update(enabled=True, minutes=10))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.service.delete_my_data(OLD_USER)
        self.assertIsNone(await self.row())

    async def test_the_deadline_ends_in_a_kick_on_time(self):
        await self.verified_member()
        await self.service.delete_my_data(OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1)
        await self.service.tick()
        self.assertEqual(len(self.port.did("kick")), 1)


class DeletingWhileBanned(Limited):
    async def test_a_banned_person_with_no_row_is_forgotten_at_the_unban(self):
        await self.db.record_ban(GUILD, OTHER_USER, keep_days=730)
        await self.db.store_identifier(GUILD, OTHER_USER, "fingerprint", "x", time.time() + 86400)
        self.port.banned.add(OTHER_USER)
        self.assertEqual((await self.service.delete_my_data(OTHER_USER))["kept_for_ban"], [GUILD])
        row = await self.row(OTHER_USER)
        self.assertEqual((row["forget_on_unban"], row["username"]), (1, ""))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OTHER_USER,)), 1)
        await self.service.on_unban(GUILD, OTHER_USER)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OTHER_USER,)), 0)
        self.assertIsNone(await self.row(OTHER_USER))


class TheOutsideLookup(Limited):
    async def lookups_on(self, *, limit=True):
        await self.edit(lambda document: (document["core"].update(external_vpn_lookup=True), document["checks"]["vpn"].update(enabled=True), document["checks"]["max_attempts"].update(enabled=limit)))
        self.asked = []

        async def proxycheck(ip, key):
            self.asked.append(ip)
            return {}
        self.service.proxycheck = proxycheck

    async def ask(self, user, ip, *, bypass=frozenset()):
        net = NetInfo(known=True)
        rules = await self.service.get_settings(GUILD)
        return await self.service._outside_lookup(GUILD, user, ip, net, rules, bypass), net

    async def test_one_network_spends_at_most_its_daily_budget(self):
        await self.lookups_on()
        for number in range(service_module.LOOKUP_NETWORK_LIMIT + 5):
            note, _ = await self.ask(str(170000000000000000 + number), f"8.8.8.{number}")
        self.assertEqual(note, "skipped")
        self.assertEqual(len(self.asked), service_module.LOOKUP_NETWORK_LIMIT)
        self.assertEqual(service_module.LOOKUP_NETWORK_LIMIT, 50)

    async def test_a_v6_48_is_one_network_and_new_64s_dont_escape_it(self):
        await self.lookups_on()
        for number in range(service_module.LOOKUP_NETWORK_LIMIT + 5):
            note, _ = await self.ask(str(170000000000000000 + number), f"2606:4700:1:{number:x}::1")
        self.assertEqual((note, len(self.asked)), ("skipped", service_module.LOOKUP_NETWORK_LIMIT))

    async def test_another_network_isnt_touched(self):
        await self.lookups_on()
        for number in range(service_module.LOOKUP_NETWORK_LIMIT):
            await self.ask(str(170000000000000000 + number), f"8.8.8.{number}")
        self.assertIsNone((await self.ask(OLD_USER, "8.8.9.1"))[0])

    async def test_the_budget_comes_back_the_next_day(self):
        await self.lookups_on()
        for number in range(service_module.LOOKUP_NETWORK_LIMIT):
            await self.ask(str(170000000000000000 + number), f"8.8.8.{number}")
        real = time.time
        with patch.object(service_module.time, "time", lambda: real() + service_module.DAY + 1):
            self.assertIsNone((await self.ask(OLD_USER, "8.8.8.200"))[0])

    async def test_a_skipped_lookup_costs_the_member_nothing(self):
        await self.lookups_on(limit=False)
        for number in range(service_module.LOOKUP_NETWORK_LIMIT):
            await self.ask(str(170000000000000000 + number), f"8.8.8.{number}")
        for _ in range(service_module.LOOKUP_DAILY_LIMIT + 3):
            note, net = await self.ask(OLD_USER, "8.8.8.250")
        self.assertEqual(note, "skipped")
        self.assertFalse(net.anonymized)

    async def test_the_table_stays_bounded(self):
        await self.lookups_on()
        with patch.object(service_module, "LOOKUP_COUNT_SIZE", 3):
            for number in range(6):
                await self.ask(str(170000000000000000 + number), f"9.{number}.0.1")
        self.assertEqual(len(self.service._lookup_networks), 3)

    async def test_past_a_members_budget_with_the_limit_off_the_connection_counts_as_a_vpn(self):
        await self.lookups_on(limit=False)
        for number in range(service_module.LOOKUP_DAILY_LIMIT):
            self.assertIsNone((await self.ask(OLD_USER, f"9.{number}.8.8"))[0])
        note, net = await self.ask(OLD_USER, "8.8.8.8")
        self.assertEqual(note, "over_limit")
        self.assertTrue(net.anonymized)

    async def test_with_the_limit_on_it_stays_a_skip(self):
        await self.lookups_on(limit=True)
        for number in range(service_module.LOOKUP_DAILY_LIMIT):
            await self.ask(OLD_USER, f"9.{number}.8.8")
        note, net = await self.ask(OLD_USER, "8.8.8.8")
        self.assertEqual(note, "skipped")
        self.assertFalse(net.anonymized)

    async def test_a_link_that_skips_the_limit_counts_as_the_limit_off(self):
        await self.lookups_on(limit=True)
        for number in range(service_module.LOOKUP_DAILY_LIMIT):
            await self.ask(OLD_USER, f"9.{number}.8.8", bypass=frozenset({"max_attempts"}))
        note, _ = await self.ask(OLD_USER, "8.8.8.8", bypass=frozenset({"max_attempts"}))
        self.assertEqual(note, "over_limit")

    async def test_an_answer_from_memory_isnt_charged(self):
        await self.lookups_on(limit=False)
        for _ in range(service_module.LOOKUP_DAILY_LIMIT + 5):
            self.assertIsNone((await self.ask(OLD_USER, "8.8.8.8"))[0])
        self.assertEqual(self.asked, ["8.8.8.8"])

    async def test_the_note_reaches_the_attempt_and_the_vpn_check_acts_on_it(self):
        await self.lookups_on(limit=False)
        for number in range(service_module.LOOKUP_DAILY_LIMIT):
            await self.ask(OLD_USER, f"9.{number}.8.8")
        token = await self.signed_in(OLD_USER)
        result = await self.submit_directly(token, device=None, ip="8.8.8.8")
        self.assertEqual((result.status, result.reason), ("failed", "vpn"))
        row = await self.db.one("SELECT detail FROM attempts WHERE outcome = 'failed' ORDER BY id DESC LIMIT 1")
        self.assertEqual(json.loads(row["detail"])["lookup"], "over_limit")


class AFailedAutoKick(Limited):
    async def test_the_correction_says_it_may_be_tried_again(self):
        await self.edit(lambda document: document["core"]["auto_kick"].update(enabled=True, minutes=10))
        self.port.kick_works = False
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1)
        await self.service.tick()
        last = self.dm_text()[-1]
        self.assertIn("didn't go through this time", last)
        self.assertIn("tried again", last)

    async def test_a_removal_that_wont_retry_keeps_the_plain_correction(self):
        self.assertNotIn("tried again", json.dumps(notices.not_removed_notice("x").embeds))


class FrozenLimits(WebBase):
    """The limiter's clock stands still, so a bucket's count doesn't depend on how fast this machine runs the requests."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        frozen = patch.object(app_module, "time", SimpleNamespace(monotonic=lambda: 1000.0, time=time.time))
        frozen.start()
        self.addCleanup(frozen.stop)


class SharingAWiderBlock(FrozenLimits):
    async def from_address(self, path, address):
        return (await self.client.get(path, allow_redirects=False, headers={"X-Forwarded-For": address})).status

    async def flood_one_64(self, path):
        return {await self.from_address(path, "2606:4700:1:1::1") for _ in range(85)}

    async def test_one_64_doesnt_lock_out_its_neighbors(self):
        self.assertEqual(await self.flood_one_64("/login"), {302, 429})
        self.assertEqual(await self.from_address("/login", "2606:4700:1:2::1"), 302)

    async def test_the_flooding_64_itself_stays_refused(self):
        await self.flood_one_64("/login")
        self.assertEqual(await self.from_address("/login", "2606:4700:1:1::1"), 429)

    async def test_many_64s_of_one_48_still_run_out(self):
        answers = [await self.from_address("/login", f"2606:4700:1:{number:x}::1") for number in range(200)]
        self.assertEqual(answers[0], 302)
        self.assertEqual(answers[-1], 429)
        self.assertEqual(answers.count(302), 80, "the /48's burst is the /64's times eight")

    async def test_another_48_isnt_touched(self):
        for number in range(200):
            await self.from_address("/login", f"2606:4700:1:{number:x}::1")
        self.assertEqual(await self.from_address("/login", "2606:4700:2::1"), 302)

    async def test_an_ipv4_address_counts_alone(self):
        for _ in range(30):
            await self.from_address("/login", "8.8.8.8")
        self.assertEqual(await self.from_address("/login", "8.8.8.9"), 302)


class LinksThatDontExist(WebBase):
    MADE_UP = "x" * 43

    async def signin_status(self, token, address="203.0.113.9"):
        return (await self.client.get(f"/v/{token}/signin", allow_redirects=False, headers={"X-Forwarded-For": address})).status

    async def test_made_up_sign_ins_dont_lock_out_a_real_link_on_the_same_address(self):
        token = await self.link_for()
        answers = [await self.signin_status(self.MADE_UP) for _ in range(12)]
        self.assertEqual(answers[-1], 429, "they run out in their own bucket")
        self.assertEqual(await self.signin_status(token), 302)

    async def test_a_real_link_still_has_its_own_limit(self):
        token = await self.link_for()
        self.assertIn(429, [await self.signin_status(token) for _ in range(30)])

    async def test_made_up_submits_dont_lock_out_a_real_submit(self):
        token = await self.link_for()
        await self.sign_in(token)
        for _ in range(8):
            response = await self.client.post(f"/api/verify/{self.MADE_UP}/submit", json={})
        self.assertEqual(response.status, 429)
        self.assertEqual((await self.attempt(token)).status, 200)

    async def test_made_up_challenges_dont_lock_out_a_real_one(self):
        token = await self.link_for()
        await self.sign_in(token)
        for _ in range(12):
            response = await self.client.post(f"/api/verify/{self.MADE_UP}/challenge")
        self.assertEqual(response.status, 429)
        self.assertEqual((await self.attempt(token)).status, 200)

    async def test_made_up_state_reads_dont_lock_out_a_real_page(self):
        token = await self.link_for()
        for _ in range(32):
            response = await self.client.get(f"/api/verify/{self.MADE_UP}")
        self.assertEqual(response.status, 429)
        self.assertEqual((await self.client.get(f"/api/verify/{token}")).status, 200)

    async def test_made_up_help_requests_dont_lock_out_a_real_one(self):
        token = await self.link_for()
        for _ in range(5):
            response = await self.client.post(f"/api/verify/{self.MADE_UP}/help")
        self.assertEqual(response.status, 429)
        self.assertNotEqual((await self.client.post(f"/api/verify/{token}/help")).status, 429)


class ThePerLinkSignInCap(WebBase):
    async def walk(self, token, number):
        address = f"8.8.{number}.1"
        start = await self.client.get(f"/v/{token}/signin", allow_redirects=False, headers={"X-Forwarded-For": address})
        self.assertEqual(start.status, 302)
        state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
        return await self.client.get("/verify/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                     headers={"X-Forwarded-For": address, "Cookie": f"{VERIFY_FLOW_COOKIE}={start.cookies[VERIFY_FLOW_COOKIE].value}"})

    async def test_someone_loading_a_stolen_link_doesnt_lock_out_its_owner(self):
        token = await self.link_for()
        for number in range(12):
            self.assertEqual(await self.status_of(token, number), 302)
        self.assertEqual(self.discord.exchanged, [], "loading the page asks Discord for nothing")
        self.assertEqual((await self.walk(token, 200)).headers["Location"], f"/v/{token}")

    async def status_of(self, token, number):
        return (await self.client.get(f"/v/{token}/signin", allow_redirects=False, headers={"X-Forwarded-For": f"8.8.{number}.1"})).status

    async def test_one_link_makes_only_so_many_token_exchanges_from_any_number_of_addresses(self):
        token = await self.link_for()
        answers = [(await self.walk(token, number)).headers["Location"] for number in range(14)]
        self.assertEqual(len(self.discord.exchanged), 10)
        self.assertEqual(answers[-1], f"/v/{token}?signin=failed")

    async def test_a_declined_sign_in_costs_no_exchange(self):
        token = await self.link_for()
        for number in range(14):
            start = await self.client.get(f"/v/{token}/signin", allow_redirects=False, headers={"X-Forwarded-For": f"8.8.{number}.1"})
            state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
            await self.client.get("/verify/callback", params={"error": "access_denied", "state": state}, allow_redirects=False,
                                  headers={"X-Forwarded-For": f"8.8.{number}.1", "Cookie": f"{VERIFY_FLOW_COOKIE}={start.cookies[VERIFY_FLOW_COOKIE].value}"})
        self.assertEqual((await self.walk(token, 200)).headers["Location"], f"/v/{token}")
        self.assertEqual(len(self.discord.exchanged), 1)


class TwoTabs(WebBase):
    async def test_an_older_tab_doesnt_end_a_newer_tabs_dashboard_sign_in(self):
        older = await self.client.get("/login", allow_redirects=False)
        old_state = parse_qs(urlsplit(older.headers["Location"]).query)["state"][0]
        newer = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(newer.headers["Location"]).query)["state"][0]
        cookie = {"Cookie": f"{FLOW_COOKIE}={newer.cookies[FLOW_COOKIE].value}"}
        first = await self.client.get("/dashboard/callback", params={"code": "x", "state": old_state}, allow_redirects=False, headers=cookie)
        self.assertEqual(first.status, 302)
        self.assertNotIn(FLOW_COOKIE, first.cookies)
        self.port.add_member(STAFF)
        self.discord.user["id"] = STAFF
        second = await self.client.get("/dashboard/callback", params={"code": "x", "state": state}, allow_redirects=False, headers=cookie)
        self.assertEqual(second.cookies[FLOW_COOKIE].value, "")
        self.assertIn("__Host-aw_session", second.cookies)

    async def test_an_older_tab_doesnt_end_a_newer_tabs_verify_sign_in(self):
        token = await self.link_for()
        older = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        old_state = parse_qs(urlsplit(older.headers["Location"]).query)["state"][0]
        newer = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        state = parse_qs(urlsplit(newer.headers["Location"]).query)["state"][0]
        cookie = {"Cookie": f"{VERIFY_FLOW_COOKIE}={newer.cookies[VERIFY_FLOW_COOKIE].value}"}
        first = await self.client.get("/verify/callback", params={"code": "abc", "state": old_state}, allow_redirects=False, headers=cookie)
        self.assertEqual(first.headers["Location"], "/help/link-expired")
        self.assertNotIn(VERIFY_FLOW_COOKIE, first.cookies)
        second = await self.client.get("/verify/callback", params={"code": "abc", "state": state}, allow_redirects=False, headers=cookie)
        self.assertEqual(second.headers["Location"], f"/v/{token}")
        self.assertEqual(second.cookies[VERIFY_FLOW_COOKIE].value, "")

    async def test_a_forged_signature_still_clears_the_cookie(self):
        token = await self.link_for()
        start = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
        forged = f"{state}.{token}.nonsense"
        response = await self.client.get("/verify/callback", params={"code": "abc", "state": state}, allow_redirects=False, headers={"Cookie": f"{VERIFY_FLOW_COOKIE}={forged}"})
        self.assertEqual(response.cookies[VERIFY_FLOW_COOKIE].value, "")


class StaffWrites(FrozenLimits):
    async def test_a_plain_member_runs_out_before_discord_is_asked_without_limit(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=())
        self.port.calls.clear()
        answers = [(await self.send("POST", "/settings/preset", {"preset": "strict"}))[0] for _ in range(100)]
        self.assertEqual(answers[0], 403)
        self.assertEqual(answers[-1], 429)
        self.assertEqual(len(self.port.did("fresh_member")), 60)

    async def test_one_persons_writes_dont_use_up_anothers(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=())
        for _ in range(70):
            await self.send("POST", "/settings/preset", {"preset": "strict"})
        await self.log_in()
        self.assertNotEqual((await self.send("POST", "/settings/preset", {"preset": "strict"}))[0], 429)

    async def test_reads_arent_counted(self):
        await self.log_in()
        for _ in range(70):
            self.assertEqual((await self.get("/health"))[0], 200)
        self.assertNotEqual((await self.send("POST", "/settings/preset", {"preset": "strict"}))[0], 429)

    async def test_a_write_without_the_csrf_token_isnt_counted(self):
        await self.log_in()
        for _ in range(70):
            response = await self.client.post(f"/api/guilds/{GUILD}/settings/preset", json={}, headers=self.session_cookie)
            self.assertEqual(response.status, 403)
        self.assertNotEqual((await self.send("POST", "/settings/preset", {"preset": "strict"}))[0], 429)


class TheServerList(WebBase):
    async def listed(self):
        await self.log_in()
        return [guild["id"] for guild in (await (await self.client.get("/api/session", headers=self.session_cookie)).json())["guilds"]]

    async def test_a_server_discord_is_still_handing_over_stays_listed(self):
        self.assertEqual(await self.listed(), [GUILD])
        self.port.absent = True
        self.port.loading = True
        data = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        self.assertEqual([guild["id"] for guild in data["guilds"]], [GUILD])

    async def test_a_server_the_bot_left_goes(self):
        self.assertEqual(await self.listed(), [GUILD])
        self.port.absent = True
        data = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        self.assertEqual(data["guilds"], [])

    def test_the_empty_list_says_how_to_see_a_server_just_added(self):
        source = (Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static" / "dash" / "app.js").read_text(encoding="utf-8")
        self.assertIn("If you just added it, reload this page.", source)


class TheAccessRuleAndDiscord(unittest.IsolatedAsyncioTestCase):
    """An authored rule is final. Discord's allow counts only while the rule is still the command's default."""

    GUILD = "970000000000000001"
    ME = "175928847299117065"
    ROLE = "970000000000000009"
    CHANNEL_A = "970000000000000010"
    CHANNEL_B = "970000000000000011"
    BLOCK = {"required": ["manage_roles"], "overrides": [{"type": "user", "id": ME, "allow": False}]}
    RAISED = {"required": ["administrator"], "overrides": []}

    async def ask(self, rule, overrides, perms, *, command="reset-user", button=False, owner=False):
        document = settings.defaults()
        if rule is not None:
            document["permissions"]["commands"][command] = rule
        info = MemberInfo(self.GUILD, self.ME, "mod", None, False, (self.ROLE, self.GUILD), frozenset(perms), owner, False)
        self.replies = []

        async def loading(_):
            return False

        async def get_settings(_):
            return document

        async def get_overrides(_):
            return overrides

        async def send(text, **_):
            self.replies.append(text)
        bot = SimpleNamespace(gateway=SimpleNamespace(guild_loading=loading, info=lambda _: info), service=SimpleNamespace(get_settings=get_settings), command_overrides=get_overrides)
        interaction = SimpleNamespace(guild_id=int(self.GUILD), channel_id=int(self.CHANNEL_B), channel=None, user=info, command=None if button else SimpleNamespace(name=command),
                                      response=SimpleNamespace(is_done=lambda: False, send_message=send))
        return await client_module.allowed(bot, interaction, command)

    def discord(self, *entries, command="reset-user", app=()):
        return {"application": "1", "all": list(app), "commands": [{"name": command, "id": "900000000000000001", "overrides": list(entries)}]}

    def me(self, allow=True):
        return {"type": "user", "id": self.ME, "allow": allow}

    def my_role(self, allow=True):
        return {"type": "role", "id": self.ROLE, "allow": allow}

    async def test_a_block_holds_against_a_discord_allow(self):
        for entry in (self.me(), self.my_role()):
            self.assertFalse(await self.ask(self.BLOCK, self.discord(entry), ["manage_roles", "manage_guild"]), entry)

    async def test_a_raised_rule_holds_against_a_discord_allow(self):
        self.assertFalse(await self.ask(self.RAISED, self.discord(self.me()), ["manage_roles", "manage_guild"]))

    async def test_a_channel_limit_holds_against_a_discord_allow(self):
        limited_to_a = {"required": ["manage_roles"], "overrides": [{"type": "channel", "id": self.CHANNEL_A, "allow": True}]}
        blocks_b = {"required": ["manage_roles"], "overrides": [{"type": "channel", "id": self.CHANNEL_B, "allow": False}]}
        for rule in (limited_to_a, blocks_b):
            self.assertFalse(await self.ask(rule, self.discord(self.my_role()), ["manage_roles"]), rule)

    async def test_the_refusal_is_said_out_loud(self):
        await self.ask(self.BLOCK, self.discord(self.me()), ["manage_roles"])
        self.assertEqual(self.replies, ["You don't have access to this command."])

    async def test_a_default_rule_with_a_discord_allow_still_passes(self):
        self.assertTrue(await self.ask(None, self.discord(self.my_role()), []))
        self.assertTrue(await self.ask(None, self.discord(self.me()), []))

    async def test_a_rule_saved_back_to_the_default_counts_as_untouched(self):
        rule = settings.command_rule(settings.defaults(), "reset-user")
        self.assertTrue(await self.ask(rule, self.discord(self.me()), []))

    async def test_the_order_of_a_rules_permissions_doesnt_make_it_authored(self):
        rule = {"required": ["kick_members", "manage_guild"], "overrides": []}
        self.assertTrue(await self.ask(rule, self.discord(self.me(), command="raid"), [], command="raid"))

    async def test_a_default_rule_with_nothing_on_discord_is_refused(self):
        self.assertFalse(await self.ask(None, self.discord(), []))

    async def test_a_read_failure_leaves_the_rules_answer(self):
        self.assertFalse(await self.ask(None, None, []))
        self.assertTrue(await self.ask(None, None, ["manage_roles"]))

    async def test_a_discord_deny_refuses_a_button(self):
        for entry in (self.me(False), self.my_role(False)):
            self.assertFalse(await self.ask(None, self.discord(entry), ["manage_roles"], button=True), entry)

    async def test_a_discord_deny_on_the_app_refuses_a_button(self):
        self.assertFalse(await self.ask(None, self.discord(app=[self.me(False)]), ["manage_roles"], button=True))

    async def test_a_discord_deny_in_this_channel_refuses_a_button(self):
        entry = {"type": "channel", "id": self.CHANNEL_B, "allow": False}
        self.assertFalse(await self.ask(None, self.discord(self.me(), entry), ["manage_roles"], button=True))

    async def test_a_command_allow_beats_an_app_deny_on_a_button_as_on_discord(self):
        self.assertTrue(await self.ask(None, self.discord(self.me(), app=[self.me(False)]), ["manage_roles"], button=True))

    async def test_a_button_with_nothing_on_discord_goes_by_the_rule(self):
        self.assertTrue(await self.ask(None, self.discord(), ["manage_roles"], button=True))
        self.assertFalse(await self.ask(None, self.discord(), [], button=True))

    async def test_a_read_failure_leaves_a_button_with_the_rules_answer(self):
        self.assertTrue(await self.ask(None, None, ["manage_roles"], button=True))

    async def test_an_administrator_can_use_every_command_as_discord_says(self):
        """application-commands.mdx: Members with the Administrator permission can use all commands."""
        self.assertTrue(await self.ask(None, self.discord(self.me(False)), ["administrator"], button=True))
        self.assertTrue(await self.ask(None, self.discord(self.me(False)), [], button=True, owner=True))

    async def test_a_slash_command_doesnt_read_discords_deny_since_discord_enforces_it(self):
        self.assertTrue(await self.ask(None, self.discord(self.me(False)), ["manage_roles"]))

    def test_the_page_and_the_docs_say_an_authored_rule_is_final(self):
        static = Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static"
        page = (static / "dash" / "permissions.js").read_text(encoding="utf-8")
        docs = (static / "docs.html").read_text(encoding="utf-8")
        self.assertNotIn("An allow on Discord's side also counts here, so a role allowed there can use the command.", page)
        self.assertIn("A rule you change here is final", page)
        self.assertIn("A rule you change there is final", docs)


class ShuttingDown(Client):
    async def waits_for(self, name):
        gate = asyncio.Event()

        async def work():
            await gate.wait()
        task = asyncio.create_task(work(), name=name)
        closer = asyncio.ensure_future(self.bot.close())
        await asyncio.sleep(0.05)
        self.assertFalse(closer.done(), name)
        gate.set()
        await closer
        self.assertTrue(task.done())

    async def test_a_running_slash_command_gets_to_finish(self):
        await self.waits_for("CommandTree-invoker")

    async def test_a_running_view_callback_gets_to_finish(self):
        await self.waits_for("discord-ui-view-dispatch-abc123")

    async def test_a_running_event_handler_still_gets_to_finish(self):
        await self.waits_for("discord.py: on_member_join")

    async def test_the_names_are_the_ones_discord_py_uses(self):
        import discord.app_commands.tree as tree
        import discord.ui.view as view
        self.assertIn("name='CommandTree-invoker'", Path(tree.__file__).read_text(encoding="utf-8"))
        self.assertIn("name=f'discord-ui-view-dispatch-", Path(view.__file__).read_text(encoding="utf-8"))

    async def test_an_unrelated_task_doesnt_hold_the_stop_up(self):
        task = asyncio.create_task(asyncio.Event().wait(), name="something-else")
        await asyncio.wait_for(self.bot.close(), 2)
        task.cancel()


class CachedOverrides(Client):
    async def test_discords_event_drops_the_copy_for_that_server(self):
        self.bot._overrides[GUILD] = (time.monotonic(), {"all": [], "commands": []})
        self.bot._overrides["other"] = (time.monotonic(), {"all": [], "commands": []})
        await self.bot.on_raw_app_command_permissions_update(SimpleNamespace(guild=SimpleNamespace(id=int(GUILD))))
        self.assertNotIn(GUILD, self.bot._overrides)
        self.assertIn("other", self.bot._overrides)

    async def test_the_next_read_asks_discord_again(self):
        answers = [{"all": [], "commands": []}, {"all": [{"type": "user", "id": "1", "allow": False}], "commands": []}]
        self.bot.gateway.command_permissions = AsyncMock(side_effect=answers)
        self.assertEqual(await self.bot.command_overrides(GUILD), answers[0])
        self.assertEqual(await self.bot.command_overrides(GUILD), answers[0], "kept for a minute")
        await self.bot.on_raw_app_command_permissions_update(SimpleNamespace(guild=SimpleNamespace(id=int(GUILD))))
        self.assertEqual(await self.bot.command_overrides(GUILD), answers[1])

    async def test_an_event_with_nothing_kept_does_nothing(self):
        await self.bot.on_raw_app_command_permissions_update(SimpleNamespace(guild=SimpleNamespace(id=int(GUILD))))

    def test_the_handler_has_the_name_discord_py_dispatches(self):
        import discord.state
        self.assertIn("self.dispatch('raw_app_command_permissions_update', raw)", Path(discord.state.__file__).read_text(encoding="utf-8"))


class PostingAMessage(Client):
    async def post(self, which="verification"):
        interaction = fake_interaction()
        await self.command("post-message")(interaction, SimpleNamespace(value=which))
        return interaction.said[-1][0]

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.bot.post_message = AsyncMock(return_value=True)

    async def test_the_slash_command_writes_the_same_audit_row(self):
        self.assertEqual(await self.post(), "Posted.")
        row = await self.db.one("SELECT actor_id, kind, detail FROM audit WHERE kind = 'post_message'")
        self.assertEqual((row["actor_id"], json.loads(row["detail"])), (STAFF, {"message": "verification"}))

    async def test_a_failed_post_writes_no_audit_row(self):
        self.bot.post_message.return_value = False
        self.assertIn("Couldn't post it", await self.post())
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM audit WHERE kind = 'post_message'"), 0)


class SavingTheAccessPage(WebBase):
    async def test_a_save_with_no_rules_in_it_is_refused(self):
        await self.log_in()
        await self.send("PUT", "/permissions", {"permissions": {"commands": {"reset-user": {"required": ["administrator"], "overrides": []}}, "pages": {}}})
        for body in ({}, {"permissions": None}, {"permissions": []}, {"permissions": "x"}):
            self.assertEqual((await self.send("PUT", "/permissions", body))[0], 400, body)
        self.assertEqual((await self.service.get_settings(GUILD))["permissions"]["commands"]["reset-user"]["required"], ["administrator"])

    async def test_a_full_save_still_lands(self):
        await self.log_in()
        status, _ = await self.send("PUT", "/permissions", {"permissions": {"commands": {}, "pages": {}}})
        self.assertEqual(status, 200)


class HealthWithNoLists(WebBase):
    async def no_lists(self, *, fail_open=False, mode="web"):
        await self.log_in()
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.service.net = NetIntel(folder.name)
        self.service.net.lists = load_lists(Path(folder.name))
        document = await self.service.get_settings(GUILD)
        document["core"].update(fail_open=fail_open, mode=mode)
        await self.service.save_settings(GUILD, document)
        await self.db.set_guild_field(GUILD, "verify_message_id", "1:2")

    async def test_every_member_being_stopped_is_an_issue(self):
        await self.no_lists()
        data = (await self.get("/health"))[1]
        self.assertFalse(data["healthy"])
        self.assertIn("Members can't verify until the network lists load", [issue["title"] for issue in data["issues"]])
        self.assertIn("Let members through if network data is missing", json.dumps(data["issues"]))

    async def test_the_red_dot_says_the_same(self):
        await self.no_lists()
        self.assertFalse((await self.get(""))[1]["healthy"])

    async def test_letting_members_through_isnt_an_issue(self):
        await self.no_lists(fail_open=True)
        data = (await self.get("/health"))[1]
        self.assertTrue(data["healthy"], data["issues"])
        self.assertTrue((await self.get(""))[1]["healthy"])

    async def test_a_mode_with_no_network_check_isnt_an_issue(self):
        for mode in ("button", "instant"):
            await self.no_lists(mode=mode)
            self.assertTrue((await self.get("/health"))[1]["healthy"], mode)

    async def test_a_loaded_list_isnt_an_issue(self):
        await self.log_in()
        await self.db.set_guild_field(GUILD, "verify_message_id", "1:2")
        self.assertTrue((await self.get("/health"))[1]["healthy"])

    async def test_a_list_never_downloaded_isnt_promised_a_last_good_copy(self):
        await self.log_in()
        data = (await self.get("/health"))[1]
        last_good = [notice["fix"] for notice in data["notices"] if "last good copy" in notice["fix"]]
        never = [row["name"] for row in data["lists"] if row["age_days"] is None or not row["rows"]]
        self.assertTrue(never)
        for text in last_good:
            for name in never:
                self.assertNotIn(name, text)
        self.assertIn(never[0], json.dumps(data["notices"]))

    async def test_the_command_uses_the_same_answer(self):
        await self.no_lists()
        guild = await self.port.guild(GUILD)
        report = await health.full_report(self.service, GUILD, guild, await self.service.get_settings(GUILD))
        self.assertFalse(report["healthy"])


class TheVerifyPostAndTheDot(WebBase):
    async def test_the_dot_and_the_page_agree_about_a_missing_post(self):
        await self.log_in()
        await self.db.set_guild_field(GUILD, "verify_message_id", None)
        self.assertFalse((await self.get(""))[1]["healthy"])
        self.assertFalse((await self.get("/health"))[1]["healthy"])
        await self.db.set_guild_field(GUILD, "verify_message_id", "1:2")
        self.assertTrue((await self.get(""))[1]["healthy"])

    async def test_a_server_not_set_up_shows_no_dot(self):
        await self.log_in()
        await self.db.run("UPDATE guilds SET setup_done = 0")
        self.assertTrue((await self.get(""))[1]["healthy"])


class TheSetupScreen(WebBase):
    async def not_set_up(self):
        await self.db.run("UPDATE guilds SET setup_done = 0")

    async def test_someone_who_can_run_setup_gets_the_form_and_the_pickers(self):
        await self.log_in(owner=False, perms=("manage_guild",))
        await self.not_set_up()
        data = (await self.get(""))[1]
        self.assertTrue(data["can_setup"])
        self.assertTrue(data["roles"])
        self.assertTrue(data["channels"])

    async def test_someone_with_rules_edit_and_no_setup_rule_doesnt(self):
        document = await self.service.get_settings(GUILD)
        document["permissions"]["pages"]["settings"] = {"edit": {"required": [], "overrides": [{"type": "user", "id": OTHER_USER, "allow": True}]}, "view": {"required": ["manage_guild"], "overrides": []}}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=())
        await self.not_set_up()
        data = (await self.get(""))[1]
        self.assertEqual(data["pages"]["settings"]["edit"], True)
        self.assertFalse(data["can_setup"])
        self.assertEqual((await self.send("POST", "/setup", {"verified_role": VERIFIED_ROLE, "channel": CHANNEL}))[0], 403)

    async def test_a_setup_rule_alone_opens_the_server_until_setup_is_done(self):
        document = await self.service.get_settings(GUILD)
        document["permissions"]["commands"]["setup"] = {"required": ["administrator"], "overrides": [{"type": "user", "id": OTHER_USER, "allow": True}]}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=())
        await self.not_set_up()
        status, data = await self.get("")
        self.assertEqual(status, 200)
        self.assertTrue(data["can_setup"])
        self.assertTrue(data["roles"], "setup picks a role and a channel")
        session = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        self.assertEqual([server["id"] for server in session["guilds"]], [GUILD])
        await self.db.run("UPDATE guilds SET setup_done = 1")
        self.assertEqual((await self.get(""))[0], 403, "once it's set up, the rule opens nothing")
        session = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        self.assertEqual(session["guilds"], [])

    async def test_a_server_already_set_up_has_nothing_to_set_up(self):
        await self.log_in()
        self.assertFalse((await self.get(""))[1]["can_setup"])

    async def test_the_screen_gates_on_what_the_route_checks(self):
        source = (Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static" / "dash" / "setup.js").read_text(encoding="utf-8")
        self.assertIn("state.guild.can_setup", source)
        self.assertNotIn("pages.settings", source)
        self.assertIn("Someone who can run /setup", source)


class StaffWords(unittest.TestCase):
    def test_the_rules_page_goes_by_its_name(self):
        root = Path(__file__).resolve().parent.parent / "altwarden"
        for path in (root / "health.py", root / "bot" / "client.py"):
            self.assertNotIn("Settings page", path.read_text(encoding="utf-8"), path.name)

    def test_the_health_page_says_each_thing_once(self):
        source = (Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static" / "dash" / "health.js").read_text(encoding="utf-8")
        self.assertNotIn("data.lookup_refused", source)
        self.assertNotIn("lists_missing", source)

    def test_a_gentle_server_is_told_two_factor_keeps_its_setting(self):
        self.assertIn("Two-factor login keeps its own setting.", catalog.PRESETS["gentle"]["blurb"])

    def test_the_card_for_an_alt_appeal_says_what_each_button_does(self):
        card = notices.appeal_card(1, OLD_USER, "x", "alt_account", "this is my sibling")
        text = json.dumps(card.embeds)
        self.assertIn("the link still stands", text)
        self.assertIn("different people", text)
        self.assertNotIn("the link still stands", json.dumps(notices.appeal_card(1, OLD_USER, "x", "vpn", "this is my sibling").embeds))

    def test_the_dashboard_says_it_too(self):
        source = (Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static" / "dash" / "appeals.js").read_text(encoding="utf-8")
        self.assertIn("the link still stands", source)


class CookiesBlocked(unittest.TestCase):
    SENTENCE = "If your browser blocks cookies, allow them for this site, then try again."

    def test_the_expired_link_page_says_so_in_every_language(self):
        static = Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static"
        page = (static / "js" / "help.js").read_text(encoding="utf-8")
        self.assertIn(self.SENTENCE, page[page.index('"link-expired"'):page.index('"security-check"')])
        self.assertIn(self.SENTENCE, json.loads((static / "i18n" / "en.json").read_text(encoding="utf-8")))
        for language in ("de", "es", "fr", "ja", "ko", "pt", "ru", "zh"):
            table = json.loads((static / "i18n" / f"{language}.json").read_text(encoding="utf-8"))
            self.assertTrue(table.get(self.SENTENCE), language)
            self.assertNotEqual(table[self.SENTENCE], self.SENTENCE, language)


class ACheckpointBesideWrites(Base):
    async def test_the_statement_runs_as_one_job_on_the_worker_thread(self):
        real = self.db.conn.execute
        asked = []

        def spying(sql, *args):
            asked.append(sql)
            return real(sql, *args)
        with patch.object(self.db.conn, "execute", spying):
            await self.db.checkpoint()
        self.assertEqual([sql for sql in asked if "wal_checkpoint" in sql], [], "started and read in two jobs, another commit can land between them and be refused")


if __name__ == "__main__":
    unittest.main()
