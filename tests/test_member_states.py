"""The service state machine: who waits for whom, what staff and members are told, and what each failure leaves behind."""
import asyncio
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import crypto, netintel, notices, service as service_module, settings
from altwarden.netintel import NetInfo
from altwarden.ports import DISCORD_BUSY, MEMBER_GONE, ROLE_TOO_LOW, DiscordUnavailable, MemberInfo
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, UNVERIFIED_ROLE, VERIFIED_ROLE
from test_detection import FakeSession, clean_report, proxycheck_answer
from test_flow import Base as FlowBase

THIRD_USER = "175928847299117066"
LIMIT_ROLE = "970000000000000060"
ALERT_ROLE = "970000000000000061"
OTHER_LOG = "970000000000000062"


class Base(FlowBase):
    def posts(self, channel=None):
        return [notice for where, notice in self.port.sent if channel is None or where == channel]

    def log_titles(self):
        return [embed.get("title") for notice in self.posts() for embed in notice.embeds]

    def log_text(self):
        return json.dumps([notice.embeds for notice in self.posts()])

    def dm_text(self, user=None):
        return [json.dumps(notice.embeds) for who, notice in self.port.dms if user is None or who == user]

    async def edit(self, change):
        document = await self.service.get_settings(GUILD)
        change(document)
        await self.service.save_settings(GUILD, document)

    async def attempts(self, user=OLD_USER):
        return await self.db.all("SELECT * FROM attempts WHERE guild_id = ? AND user_id = ? ORDER BY id", (GUILD, user))


class SavingSettings(Base):
    async def test_a_save_on_an_old_revision_is_refused_and_changes_nothing(self):
        before = settings.revision(await self.service.get_settings(GUILD), "rules")
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 99}}, section="rules")
        with self.assertRaises(settings.Conflict):
            await self.service.edit_settings(GUILD, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 50}}, section="rules", base=before)
        self.assertEqual((await self.service.get_settings(GUILD))["raid"]["joins"], 99)

    async def test_a_save_on_the_latest_revision_lands(self):
        base = settings.revision(await self.service.get_settings(GUILD), "rules")
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 50}}, section="rules", base=base)
        self.assertEqual((await self.db.guild(GUILD))["settings"]["raid"]["joins"], 50)

    async def test_a_save_elsewhere_doesnt_conflict(self):
        base = settings.revision(await self.service.get_settings(GUILD), "access")
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 99}}, section="rules")
        await self.service.edit_settings(GUILD, lambda doc: doc, section="access", base=base)

    async def test_two_saves_at_once_both_land(self):
        real = self.db.save_settings

        async def slow(*args, **kwargs):
            await asyncio.sleep(0.02)
            await real(*args, **kwargs)
        with patch.object(self.db, "save_settings", slow):
            await asyncio.gather(
                self.service.edit_settings(GUILD, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 77}}, section="rules"),
                self.service.edit_settings(GUILD, lambda doc: {**doc, "honeypot": {**doc["honeypot"], "timeout_minutes": 77}}, section="rules"))
        stored = (await self.db.guild(GUILD))["settings"]
        self.assertEqual((stored["raid"]["joins"], stored["honeypot"]["timeout_minutes"]), (77, 77))

    async def test_a_build_that_fails_leaves_the_settings_as_they_were(self):
        def broken(document):
            document["raid"]["joins"] = 99
            raise ValueError("bad")
        with self.assertRaises(ValueError):
            await self.service.edit_settings(GUILD, broken, section="rules")
        self.assertNotEqual((await self.service.get_settings(GUILD))["raid"]["joins"], 99)

    async def test_an_edit_records_who_changed_what(self):
        changes = await self.service.edit_settings(GUILD, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 99}}, section="rules",
                                                   actor_id=STAFF, actor_name="staff")
        self.assertEqual([change["path"] for change in changes], ["raid.joins"])
        audit = await self.db.one("SELECT * FROM audit WHERE kind = 'settings' ORDER BY id DESC LIMIT 1")
        self.assertEqual(audit["actor_id"], STAFF)
        self.assertIn(f"<@{STAFF}>", self.log_text())

    async def test_a_new_server_can_be_set_up_through_an_edit(self):
        guild = "970000000000000123"
        await self.service.edit_settings(guild, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 9}}, section="rules", setup_done=True)
        row = await self.db.guild(guild)
        self.assertEqual((row["settings"]["raid"]["joins"], row["setup_done"]), (9, 1))

    async def test_a_members_delete_keeps_a_staff_save_made_while_it_runs(self):
        document = await self.service.get_settings(GUILD)
        document["messages"]["verification"]["author"] = OLD_USER
        await self.service.save_settings(GUILD, document)
        await self.db.touch_member(GUILD, OLD_USER)
        real = self.db.read_all
        saved = []

        async def staff_saves_meanwhile(sql, args=()):
            if not saved and "FROM attempts WHERE guild_id" in sql:
                saved.append(True)
                await self.service.save_settings(GUILD, {**await self.service.get_settings(GUILD), "raid": {**document["raid"], "joins": 99}})
            return await real(sql, args)
        with patch.object(self.db, "read_all", staff_saves_meanwhile):
            await self.service.delete_my_data(OLD_USER)
        stored = (await self.db.guild(GUILD))["settings"]
        self.assertEqual(saved, [True])
        self.assertEqual(stored["raid"]["joins"], 99)
        self.assertIsNone(stored["messages"]["verification"]["author"])


class Gate:
    """Holds a fake Discord call open until a test lets it go, so a race runs the same way every time."""

    def __init__(self):
        self.reached = asyncio.Event()
        self.opened = asyncio.Event()

    async def wait(self):
        self.reached.set()
        await self.opened.wait()

    def open(self):
        self.opened.set()


class Prepared(Base):
    """Links signed in ahead of time, so two submits can start at the same moment with the cookie they choose."""

    async def signed_in(self, user):
        self.port.add_member(user)
        token = await self.link_for(user)
        await self.sign_in(token, user=user)
        return token

    async def submit_directly(self, token, *, device="device-1", ip="203.0.113.9", report=None):
        row = await self.service.session(token)
        await self.db.run("UPDATE sessions SET state = 'checking' WHERE token_hash = ?", (crypto.token_hash(token),))
        return await self.service.submit_web(token, row, report or clean_report(), ip=ip, headers={"user-agent": clean_report()["nav"]["ua"]}, device_id=device)

    async def turn_on_alts(self, **options):
        await self.change(alt_account={"enabled": True, "alt_action": "kick", "banned_alt_action": "ban", "main_action": "watch", "min_confidence": "likely", **options})


class WhoWaitsForWhom(Prepared):
    async def test_two_accounts_sharing_evidence_at_once_give_one_verified(self):
        await self.turn_on_alts()
        first, second = await self.signed_in(OTHER_USER), await self.signed_in(THIRD_USER)
        real = self.port.add_role

        async def slow(*args):
            await asyncio.sleep(0.05)
            return await real(*args)
        self.port.add_role = slow
        results = await asyncio.gather(self.submit_directly(first), self.submit_directly(second))
        self.assertEqual(sorted(result.status for result in results), ["failed", "verified"], [result.as_dict() for result in results])
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM members WHERE guild_id = ? AND status = 'verified'", (GUILD,)), 1)

    async def test_two_accounts_sharing_nothing_dont_wait_on_each_other(self):
        await self.turn_on_alts()
        first, second = await self.signed_in(OTHER_USER), await self.signed_in(THIRD_USER)
        gate = Gate()
        real = self.port.add_role

        async def held_for_one(guild_id, user_id, role_id, reason):
            if user_id == OTHER_USER:
                await gate.wait()
            return await real(guild_id, user_id, role_id, reason)
        self.port.add_role = held_for_one
        held = asyncio.ensure_future(self.submit_directly(first, device="device-1", ip="203.0.113.9"))
        await asyncio.wait_for(gate.reached.wait(), 5)
        with patch.object(self.service, "_digests", lambda guild, ip, device, verdict: {"cookie": device, "ip": ip}):
            done = await asyncio.wait_for(self.submit_directly(second, device="device-2", ip="198.51.100.7"), 5)
        self.assertEqual(done.status, "verified", "the second account finished while the first was still held")
        self.assertFalse(held.done())
        gate.open()
        self.assertEqual((await held).status, "verified")

    async def test_locks_are_always_taken_in_one_order_so_opposite_submits_cant_deadlock(self):
        await self.turn_on_alts()
        taken = []
        real = self.service._lock

        def recording(*key):
            taken.append(key)
            return real(*key)
        with patch.object(self.service, "_lock", recording):
            async with self.service._evidence_held(GUILD, {"ip": "b", "cookie": "a"}):
                pass
        self.assertEqual(taken, [(GUILD, "cookie", "a"), (GUILD, "ip", "b")])
        evidence = [{"ip": "x", "cookie": "y", "device": "z"}, {"device": "z", "cookie": "y", "ip": "x"}]

        async def hold(digests):
            for _ in range(20):
                async with self.service._evidence_held(GUILD, digests):
                    await asyncio.sleep(0)
        await asyncio.wait_for(asyncio.gather(hold(evidence[0]), hold(evidence[1])), 5)

    async def test_a_member_lock_comes_before_the_evidence_locks(self):
        await self.turn_on_alts()
        token = await self.signed_in(OTHER_USER)
        seen = []
        real = self.service._evidence_held

        def spying(guild_id, digests):
            seen.append(self.service._lock(GUILD, OTHER_USER).locked())
            return real(guild_id, digests)
        with patch.object(self.service, "_evidence_held", spying):
            await self.submit_directly(token)
        self.assertEqual(seen, [True])

    async def test_a_server_with_the_alt_check_off_doesnt_queue_people_on_one_connection(self):
        await self.change(alt_account={"enabled": False})
        first, second = await self.signed_in(OTHER_USER), await self.signed_in(THIRD_USER)
        gate = Gate()
        real = self.port.add_role

        async def held_for_one(guild_id, user_id, role_id, reason):
            if user_id == OTHER_USER:
                await gate.wait()
            return await real(guild_id, user_id, role_id, reason)
        self.port.add_role = held_for_one
        held = asyncio.ensure_future(self.submit_directly(first))
        await asyncio.wait_for(gate.reached.wait(), 5)
        done = await asyncio.wait_for(self.submit_directly(second), 5)
        self.assertEqual(done.status, "verified")
        gate.open()
        await held

    async def test_auto_kick_waits_for_a_check_that_is_letting_the_member_in(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=5))
        token = await self.signed_in(OTHER_USER)
        await self.db.update_member(GUILD, OTHER_USER, kick_at=time.time() - 1)
        gate = Gate()
        real = self.port.add_role

        async def held(*args):
            await gate.wait()
            return await real(*args)
        self.port.add_role = held
        submit = asyncio.ensure_future(self.submit_directly(token))
        await asyncio.wait_for(gate.reached.wait(), 5)
        tick = asyncio.ensure_future(self.service.tick())
        await asyncio.sleep(0.05)
        gate.open()
        self.assertEqual((await submit).status, "verified")
        await tick
        self.assertEqual(self.port.did("kick"), [])
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_at"])

    async def test_a_reset_waits_for_a_running_check_and_stands(self):
        token = await self.signed_in(OTHER_USER)
        gate = Gate()
        real = self.port.add_role

        async def held(guild_id, user_id, role_id, reason):
            if role_id == VERIFIED_ROLE:
                await gate.wait()
            return await real(guild_id, user_id, role_id, reason)
        self.port.add_role = held
        submit = asyncio.ensure_future(self.submit_directly(token))
        await asyncio.wait_for(gate.reached.wait(), 5)
        reset = asyncio.ensure_future(self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff"))
        await asyncio.sleep(0.05)
        gate.open()
        await submit
        await reset
        record = await self.db.member(GUILD, OTHER_USER)
        self.assertEqual(record["status"], "pending")
        self.assertNotIn(VERIFIED_ROLE, self.port.members[(GUILD, OTHER_USER)].role_ids)

    async def test_a_delete_waits_for_a_running_check_so_it_cant_recreate_records(self):
        token = await self.signed_in(OTHER_USER)
        gate = Gate()
        real = self.port.add_role

        async def held(guild_id, user_id, role_id, reason):
            if role_id == VERIFIED_ROLE:
                await gate.wait()
            return await real(guild_id, user_id, role_id, reason)
        self.port.add_role = held
        submit = asyncio.ensure_future(self.submit_directly(token))
        await asyncio.wait_for(gate.reached.wait(), 5)
        delete = asyncio.ensure_future(self.service.delete_my_data(OTHER_USER))
        await asyncio.sleep(0.05)
        gate.open()
        await submit
        await delete
        for table in ("identifiers", "attempts", "members"):
            self.assertEqual(await self.db.scalar(f"SELECT COUNT(*) FROM {table} WHERE user_id = ?", (OTHER_USER,)), 0, table)

    async def test_two_presses_of_get_help_open_one_thread(self):
        await self.edit(lambda doc: doc["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, require_attempt=False))
        member = self.port.add_member(OTHER_USER)
        real = self.port.open_help_thread

        async def slow(*args, **kwargs):
            await asyncio.sleep(0.05)
            return await real(*args, **kwargs)
        self.port.open_help_thread = slow
        answers = await asyncio.gather(self.service.open_help(member), self.service.open_help(member))
        self.assertEqual(len(self.port.did("open_help_thread")), 1)
        self.assertEqual(answers[0][0], answers[1][0])

    async def test_a_crash_after_the_role_still_leaves_a_verified_record(self):
        token = await self.signed_in(OTHER_USER)

        async def crash(*args):
            raise RuntimeError("after the role")
        with patch.object(self.service, "_act_on_link", crash), self.assertRaises(RuntimeError):
            await self.submit_directly(token)
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["status"], "verified")


class AttemptLimit(Prepared):
    async def fail_with_vpn(self, user=OLD_USER):
        return await self.verify_through(user, ip="45.33.32.7")

    async def limit(self, **options):
        await self.change(vpn={"enabled": True, "action": "deny"}, max_attempts={"enabled": True, "action": "deny", "attempts": 3, "reset_minutes": 60, "role": LIMIT_ROLE, **options})

    async def test_the_attempt_that_reaches_a_kick_limit_kicks(self):
        await self.limit(action="kick")
        results = [await self.fail_with_vpn() for _ in range(3)]
        self.assertEqual([result["action"] for result in results], ["deny", "deny", "kick"])
        self.assertEqual(results[2]["reason"], "max_attempts")
        self.assertEqual(len(self.port.did("kick")), 1)
        self.assertEqual((await self.attempts())[-1]["action"], "kick")
        self.assertEqual((await self.attempts())[-1]["check_id"], "max_attempts")

    async def test_the_attempt_that_reaches_a_deny_limit_says_so(self):
        await self.limit()
        results = [await self.fail_with_vpn() for _ in range(3)]
        self.assertEqual(results[2]["template"], "You have used all your verification attempts for this server.")
        self.assertAlmostEqual(results[2]["retry_on"], time.time() + 3600, delta=30)
        self.assertFalse(results[2]["retry"])
        self.assertIn("used all your verification attempts", self.dm_text(OLD_USER)[-1])

    async def test_the_stronger_action_wins_on_the_attempt_that_reaches_the_limit(self):
        await self.change(vpn={"enabled": True, "action": "kick"}, max_attempts={"enabled": True, "action": "deny", "attempts": 1, "reset_minutes": 60})
        result = await self.fail_with_vpn()
        self.assertEqual(result["action"], "kick")
        self.assertEqual(result["reason"], "max_attempts")
        self.assertEqual(len(self.port.did("kick")), 1)
        self.assertIn("used all your verification attempts", self.dm_text(OLD_USER)[0])

    async def test_the_limit_role_and_clock_start_on_the_attempt_that_reaches_it(self):
        await self.limit()
        await self.fail_with_vpn()
        await self.fail_with_vpn()
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["limit_reached_at"])
        self.assertNotIn(("add_role", OLD_USER, LIMIT_ROLE), self.port.calls)
        await self.fail_with_vpn()
        self.assertIsNotNone((await self.db.member(GUILD, OLD_USER))["limit_reached_at"])
        self.assertEqual(self.port.calls.count(("add_role", OLD_USER, LIMIT_ROLE)), 1)

    async def test_a_watch_limit_stops_nobody_and_says_nothing(self):
        await self.limit(action="watch")
        results = [await self.fail_with_vpn() for _ in range(3)]
        self.assertEqual(results[2]["reason"], "vpn")
        self.assertEqual([result["attempts_left"] for result in results], [None, None, None])
        self.assertEqual(results[2]["action"], "deny")

    async def test_past_a_deny_limit_nothing_is_written_or_sent(self):
        await self.limit()
        for _ in range(3):
            last = await self.fail_with_vpn()
        dms, posts, fails = len(self.port.dms), len(self.port.sent), (await self.db.member(GUILD, OLD_USER))["fails"]
        hashes = await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,))
        emitted = []

        async def sender(*args):
            emitted.append(args)
        self.service.webhook_sender = sender
        for number in range(10):
            self.app["limits"].buckets.clear()  # ten sign-ins in a burst is what the site's own limit stops, and this is about the attempt limit
            result = await self.verify_through(ip=f"45.33.32.{number + 10}")
            self.assertEqual(result["reason"], "max_attempts")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["action"], "deny")
            self.assertEqual(result["retry_on"], last["retry_on"])
        await asyncio.sleep(0)
        self.assertEqual((len(self.port.dms), len(self.port.sent), emitted), (dms, posts, []))
        self.assertEqual(len([row for row in await self.attempts() if row["outcome"] == "failed"]), 3)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], fails)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,)), hashes)

    async def test_past_a_deny_limit_the_link_can_be_seen_again(self):
        await self.limit(attempts=1)
        await self.fail_with_vpn()
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.attempt(token, ip="45.33.32.7")
        self.assertEqual((await response.json())["reason"], "max_attempts")
        row = await self.service.session(token)
        self.assertEqual(row["state"], "signed_in")
        self.assertIsNotNone(row["finished_at"])

    async def test_past_a_kick_limit_each_rejoin_still_acts(self):
        await self.limit(action="kick", attempts=1)
        await self.fail_with_vpn()
        await self.fail_with_vpn()
        self.assertEqual(len(self.port.did("kick")), 2)

    async def test_a_bypass_of_the_limit_is_honored_past_it(self):
        await self.limit(attempts=1)
        await self.fail_with_vpn()
        url, _ = await self.service.create_bypass(GUILD, OLD_USER, ["max_attempts"], 1, "none", STAFF, "staff")
        token = url.rsplit("/", 1)[1]
        await self.sign_in(token)
        result = await (await self.attempt(token)).json()
        self.assertEqual(result["status"], "verified")

    async def test_a_bypass_of_the_limit_doesnt_reach_it(self):
        await self.limit(attempts=1)
        url, _ = await self.service.create_bypass(GUILD, OLD_USER, ["max_attempts"], 1, "none", STAFF, "staff")
        token = url.rsplit("/", 1)[1]
        await self.sign_in(token)
        result = await (await self.attempt(token, ip="45.33.32.7")).json()
        self.assertEqual(result["reason"], "vpn")
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["limit_reached_at"])

    async def test_button_mode_past_the_limit_is_quiet_too(self):
        await self.edit(lambda doc: doc["core"].update(mode="button"))
        await self.change(avatar={"enabled": True, "action": "deny"}, max_attempts={"enabled": True, "action": "deny", "attempts": 1, "reset_minutes": 60})
        member = self.port.add_member(OTHER_USER, avatar=None)
        await self.service.press_verify(member)
        dms, posts = len(self.port.dms), len(self.port.sent)
        result = await self.service.press_verify(member)
        self.assertEqual(result.reason, "max_attempts")
        self.assertEqual((len(self.port.dms), len(self.port.sent)), (dms, posts))
        self.assertEqual(len(await self.attempts(OTHER_USER)), 1)

    async def test_time_returns_attempts_and_takes_the_role_with_no_member_action(self):
        await self.limit(attempts=1, reset_minutes=5)
        await self.fail_with_vpn()
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=time.time() - 301)
        await self.service.tick()
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["fails"], record["limit_reached_at"]), (0, None))
        self.assertIn(("remove_role", OLD_USER, LIMIT_ROLE), self.port.calls)

    async def test_the_timer_leaves_alone_who_isnt_due_and_a_limit_with_no_reset(self):
        await self.limit(attempts=1, reset_minutes=5)
        await self.fail_with_vpn()
        await self.service.tick()
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], 1)
        await self.limit(attempts=1, reset_minutes=0)
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=time.time() - 86400 * 400)
        await self.service.tick()
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], 1)
        self.assertNotIn(("remove_role", OLD_USER, LIMIT_ROLE), self.port.calls)

    async def test_trying_just_after_the_reset_takes_the_role_too(self):
        await self.limit(attempts=2, reset_minutes=5)
        await self.fail_with_vpn()
        await self.fail_with_vpn()
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=time.time() - 301)
        result = await self.fail_with_vpn()  # a failure, so that passing can't be what takes the role
        self.assertEqual(result["reason"], "vpn")
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], 1)
        self.assertIn(("remove_role", OLD_USER, LIMIT_ROLE), self.port.calls)

    async def test_a_refused_role_at_the_reset_is_reported(self):
        await self.limit(attempts=1, reset_minutes=5)
        await self.fail_with_vpn()
        await self.db.update_member(GUILD, OLD_USER, limit_reached_at=time.time() - 301)
        self.port.role_refusals[LIMIT_ROLE] = ROLE_TOO_LOW
        await self.service.tick()
        self.assertIn(LIMIT_ROLE, self.log_text())
        self.assertIn(ROLE_TOO_LOW, self.log_text())

    async def test_a_failed_result_counts_down_the_attempts(self):
        await self.limit()
        results = [await self.fail_with_vpn() for _ in range(3)]
        self.assertEqual([result["attempts_left"] for result in results], [2, 1, None])
        self.assertIn("2 tries left", self.dm_text(OLD_USER)[0])
        self.assertIn("1 try left", self.dm_text(OLD_USER)[1])

    async def test_with_no_limit_there_is_no_count(self):
        await self.change(vpn={"enabled": True, "action": "deny"}, max_attempts={"enabled": False})
        self.assertIsNone((await self.fail_with_vpn())["attempts_left"])

    async def test_a_reply_in_discord_counts_down_too(self):
        await self.edit(lambda doc: doc["core"].update(mode="button"))
        await self.change(avatar={"enabled": True, "action": "deny"}, max_attempts={"enabled": True, "action": "deny", "attempts": 3})
        result = await self.service.press_verify(self.port.add_member(OTHER_USER, avatar=None))
        self.assertEqual(result.attempts_left, 2)
        self.assertIn("2 tries left", result.discord_text())


class TryingAgain(Prepared):
    async def test_try_again_isnt_offered_when_it_cant_help(self):
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        self.port.add_member(young)
        await self.change(account_age={"enabled": True, "action": "deny", "days": 30})
        result = await self.verify_through(young)
        self.assertEqual(result["reason"], "account_age")
        self.assertFalse(result["retry"])
        self.assertIsNotNone(result["retry_on"])

    async def test_a_one_day_minimum_counts_as_the_same_check(self):
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        self.port.add_member(young)
        await self.change(account_age={"enabled": True, "action": "deny", "days": 1})
        result = await self.verify_through(young)
        self.assertEqual(result["reason"], "account_age_one")
        self.assertFalse(result["retry"])

    async def test_a_blocked_country_gets_no_try_again(self):
        await self.change(geogate={"enabled": True, "action": "deny", "list": "block", "countries": ["US"]})
        with patch.object(self.net, "lookup", lambda ip: NetInfo(country="US")):
            result = await self.verify_through()
        self.assertEqual(result["reason"], "geogate")
        self.assertFalse(result["retry"])

    async def test_a_check_that_can_be_fixed_keeps_try_again(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.assertTrue((await self.verify_through(ip="45.33.32.7"))["retry"])

    async def test_with_reasons_hidden_try_again_gives_nothing_away(self):
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        self.port.add_member(young)
        await self.edit(lambda doc: doc["core"].update(show_reason=False))
        await self.change(account_age={"enabled": True, "action": "deny", "days": 30})
        result = await self.verify_through(young)
        self.assertTrue(result["retry"])
        self.assertIsNone(result["retry_on"])

    async def test_no_date_is_promised_when_attempts_are_gone_for_good(self):
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        self.port.add_member(young)
        await self.change(account_age={"enabled": True, "action": "kick", "days": 30},
                          max_attempts={"enabled": True, "action": "deny", "attempts": 1, "reset_minutes": 0})
        result = await self.verify_through(young)
        self.assertEqual(result["action"], "kick")
        self.assertIsNone(result["retry_on"])
        self.assertNotIn("<t:", self.dm_text(young)[-1])

    async def test_a_date_past_a_limit_that_kicks_is_dropped_when_attempts_never_return(self):
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        self.port.add_member(young)
        await self.change(account_age={"enabled": True, "action": "ban", "days": 30},
                          max_attempts={"enabled": True, "action": "kick", "attempts": 1, "reset_minutes": 0})
        await self.db.touch_member(GUILD, young)
        await self.db.update_member(GUILD, young, fails=1, limit_reached_at=time.time())
        result = await self.verify_through(young)
        self.assertEqual((result["reason"], result["action"]), ("account_age", "ban"))
        self.assertIsNone(result["retry_on"])


PUBLIC_IP = "8.8.4.4"


class OutsideLookup(Prepared):
    """A global address, since a reserved one never goes out."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.asked = []
        self.answer = {"proxy": False, "vpn": False, "tor": False, "hosting": False}

        async def lookup(ip, key):
            self.asked.append((ip, key))
            return self.answer
        self.service.proxycheck = lookup
        await self.edit(lambda doc: doc["core"].update(external_vpn_lookup=True))
        await self.change(vpn={"enabled": True, "action": "deny"}, max_attempts={"enabled": False})

    async def submit(self, user=OLD_USER, ip=PUBLIC_IP, **extra):
        return await self.verify_through(user, ip=ip, **extra)

    async def test_each_kind_of_answer_lands_on_its_own_flag(self):
        for name, flag in (("proxy", "vpn"), ("vpn", "vpn"), ("tor", "tor"), ("hosting", "hosting")):
            net = NetInfo()
            self.service._apply_detections(net, {name: True})
            self.assertTrue(getattr(net, flag), name)
            self.assertTrue(net.anonymized)
        net = NetInfo()
        self.service._apply_detections(net, {"proxy": False, "vpn": False, "tor": False, "hosting": False})
        self.assertFalse(net.anonymized)

    async def test_a_detection_stops_the_member(self):
        self.answer = {"proxy": False, "vpn": True, "tor": False, "hosting": False}
        result = await self.submit()
        self.assertEqual(result["reason"], "vpn")

    async def test_a_tor_answer_reads_as_tor_in_the_log(self):
        self.answer = {"proxy": False, "vpn": False, "tor": True, "hosting": False}
        await self.submit()
        self.assertIn('"network": ["tor"]', (await self.attempts())[-1]["detail"])

    async def test_a_repeat_from_one_network_within_the_hour_costs_no_lookup(self):
        await self.submit()
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.submit()
        self.assertEqual(len(self.asked), 1)

    async def test_the_cache_keeps_what_the_answer_said(self):
        self.answer = {"proxy": False, "vpn": True, "tor": False, "hosting": False}
        self.assertEqual((await self.submit())["reason"], "vpn")
        self.assertEqual((await self.submit())["reason"], "vpn")
        self.assertEqual(len(self.asked), 1)

    async def test_an_hour_later_the_network_is_asked_again(self):
        await self.submit()
        for key, (until, answer) in list(self.service._lookup_cache.items()):
            self.service._lookup_cache[key] = (time.time() - 1, answer)
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.submit()
        self.assertEqual(len(self.asked), 2)

    async def test_the_cache_is_per_server_and_holds_no_address(self):
        await self.submit()
        self.assertTrue(all(key[0] == GUILD for key in self.service._lookup_cache))
        self.assertNotIn(PUBLIC_IP, repr(self.service._lookup_cache))

    async def test_a_failure_is_not_cached(self):
        self.answer = None
        await self.submit()
        self.answer = {"proxy": False, "vpn": False, "tor": False, "hosting": False}
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.submit()
        self.assertEqual(len(self.asked), 2)

    async def test_the_cache_stays_bounded(self):
        with patch("altwarden.service.LOOKUP_CACHE_SIZE", 2):
            for number in range(5):
                self.service._remember_lookup((GUILD, str(number)), {})
        self.assertEqual(list(self.service._lookup_cache), [(GUILD, "3"), (GUILD, "4")])

    async def test_one_member_gets_at_most_twenty_lookups_a_day(self):
        self.answer = None
        for number in range(25):
            self.assertEqual(self.service._lookup_allowed(GUILD, OLD_USER, 1000.0 + number), number < 20, number)
        self.assertTrue(self.service._lookup_allowed(GUILD, OTHER_USER, 1000.0))
        self.assertTrue(self.service._lookup_allowed(GUILD, OLD_USER, 1000.0 + 86401))

    async def test_past_a_days_lookups_with_a_limit_on_the_member_is_still_checked_and_it_is_noted(self):
        await self.change(max_attempts={"enabled": True, "attempts": 50})
        for _ in range(20):
            self.service._lookup_allowed(GUILD, OLD_USER, time.time())
        result = await self.submit()
        self.assertEqual(self.asked, [])
        self.assertEqual(result["status"], "verified")
        self.assertEqual(json.loads([row for row in await self.attempts() if row["outcome"] == "passed"][-1]["detail"])["lookup"], "skipped")

    async def test_past_a_days_lookups_with_the_limit_off_the_connection_counts_as_a_vpn(self):
        # Twenty networks in a day isn't someone at home, and with no limit nothing else would ever end this.
        for _ in range(20):
            self.service._lookup_allowed(GUILD, OLD_USER, time.time())
        result = await self.submit()
        self.assertEqual(self.asked, [])
        self.assertEqual((result["status"], result["reason"]), ("failed", "vpn"))
        self.assertEqual(json.loads([row for row in await self.attempts() if row["outcome"] == "failed"][-1]["detail"])["lookup"], "over_limit")

    async def test_the_switch_being_off_sends_nothing(self):
        await self.edit(lambda doc: doc["core"].update(external_vpn_lookup=False))
        await self.submit()
        self.assertEqual(self.asked, [])

    async def test_with_the_vpn_and_threat_checks_off_nothing_goes_out(self):
        await self.change(vpn={"enabled": False}, threat={"enabled": False})
        await self.submit()
        self.assertEqual(self.asked, [])

    async def test_the_threat_check_alone_is_reason_enough(self):
        await self.change(vpn={"enabled": False}, threat={"enabled": True})
        await self.submit()
        self.assertEqual(len(self.asked), 1)

    async def test_a_bypass_of_the_vpn_check_sends_nothing(self):
        url, _ = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 1, "none", STAFF, "staff")
        token = url.rsplit("/", 1)[1]
        await self.sign_in(token)
        await self.attempt(token, ip=PUBLIC_IP)
        self.assertEqual(self.asked, [])

    async def test_cooldown_and_a_used_up_limit_send_nothing(self):
        await self.edit(lambda doc: doc["core"]["cooldown"].update(enabled=True, seconds=300))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, last_fail_at=time.time())
        self.assertEqual((await self.submit())["status"], "cooldown")
        self.assertEqual(self.asked, [])
        await self.edit(lambda doc: doc["core"]["cooldown"].update(enabled=False))
        await self.change(max_attempts={"enabled": True, "action": "kick", "attempts": 1, "reset_minutes": 60})
        await self.db.update_member(GUILD, OLD_USER, fails=1, limit_reached_at=time.time())
        await self.submit()
        self.assertEqual(self.asked, [])

    async def test_an_address_the_lists_already_placed_or_a_reserved_one_stays_home(self):
        await self.submit(ip="45.33.32.7")
        self.assertEqual(self.asked, [])
        await self.submit(ip="192.0.2.5")
        self.assertEqual(self.asked, [])

    async def test_the_key_goes_out_unsealed(self):
        await self.service.set_lookup_key(GUILD, "abcdef-123456", actor_id=STAFF, actor_name="staff")
        await self.submit()
        self.assertEqual(self.asked[0][1], "abcdef-123456")

    async def test_a_failed_lookup_never_blocks_anyone_whatever_fail_open_says(self):
        self.answer = None
        for fail_open in (False, True):
            await self.edit(lambda doc, fail_open=fail_open: doc["core"].update(fail_open=fail_open))
            self.port.members[(GUILD, OLD_USER)].role_ids = ()
            self.assertEqual((await self.submit())["status"], "verified", fail_open)

    async def test_a_failed_lookup_is_noted_on_the_attempt(self):
        self.answer = None
        await self.submit()
        self.assertEqual(json.loads([row for row in await self.attempts() if row["outcome"] == "passed"][-1]["detail"])["lookup"], "unavailable")

    async def test_a_working_lookup_leaves_no_note(self):
        await self.submit()
        self.assertNotIn("lookup", json.loads([row for row in await self.attempts() if row["outcome"] == "passed"][-1]["detail"]))

    async def test_a_failure_latches_with_time_and_message_until_the_next_success(self):
        self.answer = None
        self.assertIsNone(self.service.lookup_refused(GUILD))
        await self.submit()
        latch = self.service.lookup_refused(GUILD)
        self.assertAlmostEqual(latch["at"], time.time(), delta=30)
        self.assertIn("proxycheck.io", latch["message"])
        self.answer = {"proxy": False, "vpn": False, "tor": False, "hosting": False}
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.submit()
        self.assertIsNone(self.service.lookup_refused(GUILD))

    async def test_staff_hear_about_a_failure_once_a_day(self):
        self.answer = None
        await self.submit()
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.submit()
        title = "The outside VPN lookup isn't answering"
        self.assertEqual(self.log_titles().count(title), 1)
        self.service._lookup_warned[GUILD] = time.time() - 86401
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.submit()
        self.assertEqual(self.log_titles().count(title), 2)

    async def test_the_message_proxycheck_gave_reaches_the_latch(self):
        async def refused(ip, key):
            netintel.last_refusal.set("Your daily limit is used up.")
            return None
        self.service.proxycheck = refused
        await self.submit()
        self.assertEqual(self.service.lookup_refused(GUILD)["message"], "Your daily limit is used up.")


class LookupCalls(unittest.IsolatedAsyncioTestCase):
    async def test_the_answer_is_every_detection_it_gave(self):
        answer = await netintel.external_lookup(FakeSession(proxycheck_answer("1.2.3.4", tor=True, hosting=True)), "1.2.3.4", "k")
        self.assertEqual(answer, {"proxy": False, "vpn": False, "tor": True, "hosting": True})

    async def test_a_non_true_value_isnt_a_detection(self):
        answer = await netintel.external_lookup(FakeSession(proxycheck_answer("1.2.3.4", vpn="yes", proxy=1)), "1.2.3.4", "k")
        self.assertEqual(answer, {"proxy": False, "vpn": False, "tor": False, "hosting": False})

    async def test_a_refusal_logs_the_message_without_the_key_and_cut_short(self):
        message = "Key secret-key was refused. " + "x" * 500
        with self.assertLogs("altwarden", "WARNING") as logs:
            self.assertIsNone(await netintel.external_lookup(FakeSession({"status": "denied", "message": message}), "1.2.3.4", "secret-key"))
        text = " ".join(logs.output)
        self.assertIn("was refused", text)
        self.assertNotIn("secret-key", text)
        self.assertLess(len(text), 400)
        self.assertNotIn("secret-key", netintel.last_refusal.get())

    async def test_a_message_that_isnt_text_doesnt_break_the_refusal(self):
        for message in ({"a": 1}, None, 5):
            self.assertIsNone(await netintel.external_lookup(FakeSession({"status": "denied", "message": message}), "1.2.3.4", "k"))

    async def test_a_success_clears_the_last_refusal(self):
        await netintel.external_lookup(FakeSession({"status": "denied", "message": "no"}), "1.2.3.4", "k")
        self.assertEqual(netintel.last_refusal.get(), "no")
        await netintel.external_lookup(FakeSession(proxycheck_answer("1.2.3.4")), "1.2.3.4", "k")
        self.assertIsNone(netintel.last_refusal.get())

    async def test_a_refusal_in_one_task_cant_reach_another(self):
        async def refused():
            await netintel.external_lookup(FakeSession({"status": "denied", "message": "theirs"}), "1.2.3.4", "k")
        await asyncio.ensure_future(refused())
        self.assertIsNone(netintel.last_refusal.get())

    async def test_a_key_check_reads_the_usage_export(self):
        session = FakeSession({"Queries Today": 3, "Daily Limit": 1000})
        self.assertIs(await netintel.check_lookup_key(session, "abc"), True)
        self.assertEqual(session.urls, ["https://proxycheck.io/dashboard/export/usage/"])
        self.assertEqual(session.params, [{"key": "abc"}])

    async def test_a_key_proxycheck_refuses_is_false(self):
        self.assertIs(await netintel.check_lookup_key(FakeSession({"error": "Invalid API Key."}), "abc"), False)

    async def test_no_clear_answer_is_none(self):
        for body in ([], None, "text"):
            self.assertIsNone(await netintel.check_lookup_key(FakeSession(body), "abc"), body)

    async def test_a_network_failure_is_none_and_logs_no_key(self):
        class Broken:
            def get(self, *args, **kwargs):
                raise OSError("unreachable with secret-key")
        with self.assertLogs("altwarden", "WARNING") as logs:
            self.assertIsNone(await netintel.check_lookup_key(Broken(), "secret-key"))
        self.assertNotIn("secret-key", " ".join(logs.output))


class TheRestOfAnAttempt(Prepared):
    async def test_a_time_zone_of_the_wrong_type_is_a_normal_attempt(self):
        for name in ([1], {"a": 1}, 5):
            report = clean_report()
            report["tz"] = {"name": name}
            self.assertIn((await self.verify_through(report=report))["status"], ("verified", "failed"), name)

    async def test_an_address_that_isnt_public_is_noted_on_the_attempt(self):
        await self.verify_through(ip="192.0.2.5")
        detail = json.loads([row for row in await self.attempts() if row["outcome"] == "passed"][-1]["detail"])
        self.assertEqual(detail["network"], "address not public")

    async def test_a_public_address_with_no_lists_is_noted_too(self):
        await self.edit(lambda document: document["core"].update(fail_open=True))
        with patch.object(self.net, "lookup", lambda ip: NetInfo(known=False)):
            await self.verify_through(ip=PUBLIC_IP)
        detail = json.loads([row for row in await self.attempts() if row["outcome"] == "passed"][-1]["detail"])
        self.assertEqual(detail["network"], "network data unavailable")

    async def test_a_public_address_with_lists_carries_no_note(self):
        await self.verify_through(ip=PUBLIC_IP)
        detail = json.loads([row for row in await self.attempts() if row["outcome"] == "passed"][-1]["detail"])
        self.assertNotIn("network", detail)

    async def test_a_raid_makes_the_puzzle_harder(self):
        document = await self.service.get_settings(GUILD)
        token = await self.signed_in(OTHER_USER)
        normal = await self.service.issue_challenge(token)
        await self.service.start_raid(GUILD, document, "test")
        raid = await self.service.issue_challenge(token)
        self.assertEqual(raid["bits"], service_module.POW_BITS_RAID)
        self.assertEqual(service_module.POW_BITS_RAID, 19)
        self.assertLess(normal["bits"], raid["bits"])
        self.assertEqual((await self.service.session(token))["pow_bits"], 19)

    async def test_a_browser_that_refused_the_cookie_counts_as_automated(self):
        await self.change(automation={"enabled": True, "action": "deny"})
        token = await self.signed_in(OTHER_USER)
        row = await self.service.session(token)
        await self.db.run("UPDATE sessions SET state = 'checking' WHERE token_hash = ?", (crypto.token_hash(token),))
        result = await self.service.submit_web(token, row, clean_report(), ip=PUBLIC_IP, headers={"user-agent": clean_report()["nav"]["ua"]}, device_id=None, cookie_refused=True)
        self.assertEqual(result.reason, "automation")
        self.assertIn("browser refused the cookie", (await self.attempts(OTHER_USER))[-1]["detail"])

    async def test_a_browser_that_kept_the_cookie_doesnt(self):
        await self.change(automation={"enabled": True, "action": "deny"})
        token = await self.signed_in(OTHER_USER)
        row = await self.service.session(token)
        await self.db.run("UPDATE sessions SET state = 'checking' WHERE token_hash = ?", (crypto.token_hash(token),))
        result = await self.service.submit_web(token, row, clean_report(), ip=PUBLIC_IP, headers={"user-agent": clean_report()["nav"]["ua"]}, device_id="d")
        self.assertEqual(result.status, "verified")


class StaffLogs(Prepared):
    async def alerts(self, **roles):
        def change(doc):
            doc["core"]["logs"] = {"enabled": True, "modules": {name: LOG_CHANNEL for name in ("general", "success", "vpn", "auto_kick", "help_desk", "honeypot", "raid", "settings", "account_age", "avatar")}}
            doc["core"]["alerts"] = {"enabled": True, "roles": roles}
        await self.edit(change)

    def pinged(self, role=ALERT_ROLE):
        return [notice for notice in self.posts() if f"<@&{role}>" in notice.content and role in notice.mention_roles]

    async def test_a_log_of_each_kind_pings_the_role_set_for_it(self):
        await self.alerts(honeypot=ALERT_ROLE)
        await self.edit(lambda doc: doc["honeypot"].update(enabled=True, channel=CHANNEL, action="log"))
        await self.service.honeypot_hit(GUILD, OLD_USER, CHANNEL, "1", role_ids=())
        self.assertEqual(len(self.pinged()), 1)

    async def test_an_auto_kick_pings(self):
        await self.alerts(auto_kick=ALERT_ROLE)
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=5))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1)
        await self.service.tick()
        self.assertEqual(len(self.pinged()), 1)

    async def test_a_help_thread_opening_pings_and_closing_doesnt(self):
        await self.alerts(help_desk=ALERT_ROLE)
        await self.edit(lambda doc: doc["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, require_attempt=False))
        member = self.port.add_member(OTHER_USER)
        thread, _ = await self.service.open_help(member)
        self.assertEqual(len(self.pinged()), 1)
        staff = MemberInfo(GUILD, STAFF, "staff", None, False, (), frozenset(), True)
        self.assertTrue((await self.service.close_help(GUILD, thread, staff))[0])
        self.assertIn("Help thread closed", self.log_titles())
        self.assertEqual(len(self.pinged()), 1)

    async def test_staff_actions_settings_and_a_clean_pass_ping(self):
        await self.alerts(general=ALERT_ROLE, settings=ALERT_ROLE, success=ALERT_ROLE)
        await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff")
        self.assertEqual(len(self.pinged()), 1)
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "raid": {**doc["raid"], "joins": 99}}, section="rules")
        self.assertEqual(len(self.pinged()), 2)
        self.port.add_member(THIRD_USER)
        await self.verify_through(THIRD_USER)
        self.assertEqual(len(self.pinged()), 3)

    async def test_a_channel_only_pings_for_the_modules_that_log_there(self):
        await self.change(account_age={"enabled": True, "action": "deny", "days": 30}, avatar={"enabled": True, "action": "deny"})
        def change(doc):
            doc["core"]["logs"] = {"enabled": True, "modules": {"account_age": LOG_CHANNEL, "avatar": OTHER_LOG}}
            doc["core"]["alerts"] = {"enabled": True, "roles": {"account_age": ALERT_ROLE}}
        await self.edit(change)
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        self.port.add_member(young)
        self.discord.user["avatar"] = None
        await self.verify_through(young)
        self.assertIn(ALERT_ROLE, self.posts(LOG_CHANNEL)[-1].mention_roles)
        self.assertEqual(self.posts(OTHER_LOG)[-1].mention_roles, [])
        self.assertEqual(self.posts(OTHER_LOG)[-1].content, "")

    async def test_a_channel_with_two_alerting_modules_pings_each_role_once(self):
        await self.change(account_age={"enabled": True, "action": "deny", "days": 30}, avatar={"enabled": True, "action": "deny"})
        def change(doc):
            doc["core"]["logs"] = {"enabled": True, "modules": {"account_age": LOG_CHANNEL, "avatar": LOG_CHANNEL}}
            doc["core"]["alerts"] = {"enabled": True, "roles": {"account_age": ALERT_ROLE, "avatar": ALERT_ROLE}}
        await self.edit(change)
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        self.port.add_member(young)
        self.discord.user["avatar"] = None
        await self.verify_through(young)
        self.assertEqual(self.posts(LOG_CHANNEL)[-1].mention_roles, [ALERT_ROLE])

    async def test_the_raid_role_pings_once_when_two_channels_log_a_raid(self):
        def change(doc):
            doc["core"]["logs"] = {"enabled": True, "modules": {"raid": LOG_CHANNEL, "general": OTHER_LOG}}
            doc["raid"]["alert_role"] = ALERT_ROLE
        await self.edit(change)
        await self.service.start_raid(GUILD, await self.service.get_settings(GUILD), "test")
        self.assertEqual(self.posts(LOG_CHANNEL)[-1].mention_roles, [ALERT_ROLE])
        self.assertEqual(self.posts(OTHER_LOG)[-1].mention_roles, [])

    async def test_alerts_turned_off_ping_nobody(self):
        await self.alerts(general=ALERT_ROLE)
        await self.edit(lambda doc: doc["core"]["alerts"].update(enabled=False))
        await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff")
        self.assertEqual(self.pinged(), [])

    async def test_a_log_says_whether_it_reached_anyone(self):
        document = await self.service.get_settings(GUILD)
        embed = notices.staff_log("x", "y")
        self.assertIs(await self.service._log(GUILD, document, ["general"], embed), True)
        self.assertIs(await self.service._log(GUILD, document, ["unset module"], embed), False)
        self.port.channel_posts_work = False
        self.assertIs(await self.service._log(GUILD, document, ["general"], embed), False)
        self.port.channel_posts_work = True
        await self.edit(lambda doc: doc["core"]["logs"].update(enabled=False))
        self.assertIs(await self.service._log(GUILD, await self.service.get_settings(GUILD), ["general"], embed), False)

    async def test_the_pass_log_names_the_role_given(self):
        await self.verify_through()
        fields = [embed for notice in self.posts(LOG_CHANNEL) for embed in notice.embeds if embed.get("title") == "Member verified"][-1]["fields"]
        self.assertIn({"name": "Role given", "value": f"<@&{VERIFIED_ROLE}>", "inline": True}, fields)

    async def test_the_failure_log_names_no_role(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        self.assertNotIn("Role given", self.log_text())

    async def test_a_very_large_save_records_how_many_changes_it_held(self):
        many = [{"path": f"x.{number}", "before": 1, "after": 2} for number in range(201)]
        with patch.object(settings, "diff", lambda before, after: many):
            await self.service.edit_settings(GUILD, lambda doc: doc, section="rules", actor_id=STAFF, actor_name="staff")
        detail = json.loads((await self.db.one("SELECT detail FROM audit WHERE kind = 'settings' ORDER BY id DESC LIMIT 1"))["detail"])
        self.assertEqual((len(detail["changes"]), detail["total"]), (200, 201))

    async def test_a_backtick_in_a_setting_stays_inside_its_code_span(self):
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "messages": {**doc["messages"], "verification": {**doc["messages"]["verification"], "title": "a`**b**`c"}}}, section="look")
        value = next(field["value"] for notice in self.posts() for embed in notice.embeds for field in embed.get("fields", []) if "a'" in field["value"])
        self.assertEqual(value.count("`"), 4, value)
        self.assertIn("a'**b**'c", value)


class RoleProblems(Prepared):
    async def test_staff_who_were_told_are_named_as_told(self):
        self.port.role_problem = ROLE_TOO_LOW
        result = await self.verify_through()
        self.assertEqual(result["message"], "You passed, but the server's roles need fixing. Staff have been told.")

    async def test_with_logs_off_the_member_is_asked_to_tell_them(self):
        self.port.role_problem = ROLE_TOO_LOW
        await self.edit(lambda doc: doc["core"]["logs"].update(enabled=False))
        result = await self.verify_through()
        self.assertEqual(result["message"], "You passed, but the server's roles need fixing. Please tell the server's staff.")

    async def test_a_log_post_that_failed_isnt_counted_as_telling_them(self):
        self.port.role_problem = ROLE_TOO_LOW
        self.port.channel_posts_work = False
        self.assertIn("Please tell", (await self.verify_through())["message"])

    async def test_discord_not_answering_isnt_blamed_on_the_roles(self):
        self.port.role_problem = DISCORD_BUSY
        result = await self.verify_through()
        self.assertEqual(result["message"], "You passed, but Discord didn't answer. Try again in a moment.")
        self.assertTrue(result["retry"])

    async def test_a_pass_stops_the_kick_timer_even_with_a_role_problem(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=5))
        await self.service.on_join(self.port.members[(GUILD, OLD_USER)])
        self.port.role_problem = ROLE_TOO_LOW
        await self.verify_through()
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["kick_at"], record["kick_warn_at"]), (None, None))

    async def test_a_role_problem_is_on_the_record(self):
        self.port.role_problem = ROLE_TOO_LOW
        await self.verify_through()
        row = (await self.attempts())[-1]
        self.assertEqual((row["outcome"], row["check_id"], row["mode"]), ("role_problem", "role_problem", "web"))

    async def test_a_role_problem_opens_the_help_desk(self):
        await self.edit(lambda doc: doc["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, require_attempt=True, redirect=True))
        self.port.role_problem = ROLE_TOO_LOW
        result = await self.verify_through()
        self.assertTrue(result["staff_help"])
        self.assertTrue(result["appeal"])
        thread, _ = await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        self.assertIsNotNone(thread)
        self.assertIn("Role problem", json.dumps(self.port.threads[-1].embeds))

    async def test_a_staff_approval_with_a_broken_role_says_who_was_told(self):
        await self.edit(lambda doc: doc["core"].update(mode="button"))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, status="approved")
        self.port.role_problem = ROLE_TOO_LOW
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertIn("Staff have been told", result.message)
        self.assertIn(ROLE_TOO_LOW, self.log_text())
        await self.edit(lambda doc: doc["core"]["logs"].update(enabled=False))
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertIn("Please tell", result.message)

    async def test_a_help_desk_that_cant_open_only_claims_a_notice_that_went_out(self):
        await self.edit(lambda doc: (doc["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, require_attempt=False),
                                     doc["core"]["logs"]["modules"].update(help_desk=LOG_CHANNEL)))
        async def refused(*args, **kwargs):
            pass
        self.port.open_help_thread = refused
        member = self.port.add_member(OTHER_USER)
        self.assertIn("Staff have been told", (await self.service.open_help(member))[1])
        await self.edit(lambda doc: doc["core"]["logs"].update(enabled=False))
        self.assertIn("Please tell", (await self.service.open_help(member))[1])

    async def test_a_role_that_couldnt_be_taken_after_a_pass_is_reported(self):
        await self.edit(lambda doc: doc["core"].update(unverified_enabled=True, unverified_role=UNVERIFIED_ROLE))
        self.port.role_refusals[UNVERIFIED_ROLE] = ROLE_TOO_LOW
        result = await self.verify_through()
        self.assertEqual(result["status"], "verified")
        self.assertIn(UNVERIFIED_ROLE, self.log_text())
        self.assertIn(ROLE_TOO_LOW, self.log_text())

    async def test_a_limit_role_that_couldnt_be_given_is_reported(self):
        await self.change(vpn={"enabled": True, "action": "deny"}, max_attempts={"enabled": True, "action": "deny", "attempts": 1, "role": LIMIT_ROLE})
        self.port.role_refusals[LIMIT_ROLE] = ROLE_TOO_LOW
        await self.verify_through(ip="45.33.32.7")
        self.assertIn(f"give <@&{LIMIT_ROLE}>", self.log_text())

    async def test_a_member_who_left_isnt_reported_as_a_role_problem(self):
        document = await self.service.get_settings(GUILD)
        await self.service._note_role_problem(GUILD, document, OLD_USER, "take it", MEMBER_GONE)
        self.assertEqual(self.posts(), [])

    async def test_each_language_has_the_new_page_text(self):
        folder = Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static" / "i18n"
        english = json.loads((folder / "en.json").read_text(encoding="utf-8"))
        texts = ["Almost there", "You passed, but the server's roles need fixing. Staff have been told.",
                 "You passed, but the server's roles need fixing. Please tell the server's staff.",
                 "You passed, but Discord didn't answer. Try again in a moment."]
        for text in texts:
            self.assertIn(text, english)
            for language in ("de", "es", "fr", "ja", "ko", "pt", "ru", "zh"):
                table = json.loads((folder / f"{language}.json").read_text(encoding="utf-8"))
                self.assertNotEqual(table[text], text, language)


class RaidMode(Prepared):
    async def raid_on(self, joins=3):
        await self.edit(lambda doc: doc["raid"].update(enabled=True, joins=joins, seconds=60))

    async def join(self, count, base=175928847299200000):
        for number in range(count):
            await self.service.on_join(self.port.add_member(str(base + number)))

    async def test_one_account_rejoining_isnt_a_raid(self):
        await self.raid_on()
        member = self.port.add_member(OTHER_USER)
        for _ in range(10):
            await self.service.on_join(member)
        self.assertFalse(await self.service.raid_active(GUILD))

    async def test_that_many_accounts_are(self):
        await self.raid_on()
        await self.join(3)
        self.assertTrue(await self.service.raid_active(GUILD))

    async def test_joins_leave_the_window_when_their_time_is_up(self):
        watch = service_module.RaidWatch()
        self.assertFalse(watch.joined(GUILD, "1", 100.0, 60, 2))
        self.assertFalse(watch.joined(GUILD, "2", 161.0, 60, 2))
        self.assertTrue(watch.joined(GUILD, "3", 162.0, 60, 2))

    async def test_staff_turning_raid_mode_off_starts_the_count_over(self):
        await self.raid_on()
        await self.join(3)
        await self.service.stop_raid(GUILD, await self.service.get_settings(GUILD))
        await self.join(1, base=175928847299300000)
        self.assertFalse(await self.service.raid_active(GUILD))

    async def test_a_raid_ending_on_time_starts_the_count_over(self):
        await self.raid_on()
        await self.join(3)
        await self.db.set_guild_field(GUILD, "raid_until", time.time() - 1)
        await self.service.tick()
        await self.join(1, base=175928847299300000)
        self.assertFalse(await self.service.raid_active(GUILD))

    async def test_a_raid_ending_on_time_is_in_the_audit_log(self):
        await self.db.set_guild_field(GUILD, "raid_until", time.time() - 1)
        await self.service.tick()
        row = await self.db.one("SELECT * FROM audit WHERE kind = 'raid_stop'")
        self.assertIsNone(row["actor_id"])
        self.assertEqual(json.loads(row["detail"]), {"why": "Its time ran out"})

    async def test_raid_records_name_who_did_it(self):
        document = await self.service.get_settings(GUILD)
        await self.service.start_raid(GUILD, document, "Started by staff", actor_id=STAFF, actor_name="boss")
        row = await self.db.one("SELECT * FROM audit WHERE kind = 'raid_start'")
        self.assertEqual((row["actor_id"], row["actor_name"]), (STAFF, "boss"))
        self.assertIn(f"<@{STAFF}>", self.log_text())
        await self.service.stop_raid(GUILD, document, actor_id=OLD_USER, actor_name="other")
        row = await self.db.one("SELECT * FROM audit WHERE kind = 'raid_stop'")
        self.assertEqual((row["actor_id"], row["actor_name"]), (OLD_USER, "other"))
        self.assertIn(f"<@{OLD_USER}> turned it off", self.log_text())

    async def test_trusting_two_accounts_is_recorded_and_logged(self):
        await self.service.trust_accounts(GUILD, OLD_USER, OTHER_USER, STAFF, "boss")
        self.assertTrue(await self.db.is_trusted_pair(GUILD, OLD_USER, OTHER_USER))
        row = await self.db.one("SELECT * FROM audit WHERE kind = 'trust'")
        self.assertEqual((row["actor_id"], row["actor_name"], json.loads(row["detail"])), (STAFF, "boss", {"first": OLD_USER, "second": OTHER_USER}))
        self.assertIn(f"<@{STAFF}>", self.log_text())
        self.assertIn(f"<@{OTHER_USER}>", self.log_text())


class Removals(Prepared):
    async def due_for_kick(self, user=OLD_USER):
        await self.edit(lambda doc: (doc["core"]["auto_kick"].update(enabled=True, minutes=10), doc["core"]["logs"]["modules"].update(auto_kick=LOG_CHANNEL)))
        await self.db.touch_member(GUILD, user)
        await self.db.update_member(GUILD, user, kick_at=time.time() - 1, joined_at=time.time() - 3600)

    async def test_a_failed_auto_kick_tries_again_in_an_hour(self):
        await self.due_for_kick()
        self.port.kick_works = False
        await self.service.tick()
        record = await self.db.member(GUILD, OLD_USER)
        self.assertAlmostEqual(record["kick_at"], time.time() + 3600, delta=60)
        rows = await self.attempts()
        self.assertEqual([(row["outcome"], row["action"]) for row in rows], [("auto_kick_failed", None)])

    async def test_a_failed_auto_kick_corrects_what_the_member_was_told(self):
        await self.due_for_kick()
        self.port.kick_works = False
        await self.service.tick()
        self.assertEqual(len(self.port.dms), 2)
        self.assertIn("ran out", self.dm_text()[0])
        self.assertIn("still in the server", self.dm_text()[1])
        self.assertIn("The kick failed", self.log_text())
        self.assertIn("in an hour", self.log_text())

    async def test_retries_stay_quiet_until_one_works(self):
        await self.due_for_kick()
        self.port.kick_works = False
        await self.service.tick()
        dms, posts = len(self.port.dms), len(self.port.sent)
        for _ in range(3):
            await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1)
            await self.service.tick()
        self.assertEqual(len(self.port.did("kick")), 4)
        self.assertEqual((len(self.port.dms), len(self.port.sent)), (dms, posts))
        self.assertEqual(len(await self.attempts()), 1)
        self.port.kick_works = True
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1)
        await self.service.tick()
        self.assertEqual((await self.attempts())[-1]["action"], "kick")
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["kick_at"])
        self.assertEqual(len(self.port.sent), posts + 1)

    async def test_a_rejoin_starts_the_notices_over(self):
        await self.due_for_kick()
        self.port.kick_works = False
        await self.service.tick()
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1, joined_at=time.time() + 5)
        dms = len(self.port.dms)
        await self.service.tick()
        self.assertEqual(len(self.port.dms), dms + 2)

    async def test_a_successful_auto_kick_clears_the_timer_and_says_nothing_more(self):
        await self.due_for_kick()
        await self.service.tick()
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["kick_at"], record["kick_warn_at"]), (None, None))
        self.assertEqual(len(self.port.dms), 1)
        self.assertEqual([(row["outcome"], row["action"]) for row in await self.attempts()], [("auto_kick", "kick")])

    async def test_a_failed_kick_for_a_check_corrects_the_member_and_the_record(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        self.port.kick_works = False
        result = await self.verify_through(ip="45.33.32.7")
        self.assertEqual(result["action"], "deny")
        self.assertTrue(result["retry"])
        self.assertIn("You were removed", self.dm_text(OLD_USER)[-2])
        self.assertIn("still in the server", self.dm_text(OLD_USER)[-1])
        self.assertEqual((await self.attempts())[-1]["action"], "deny")

    async def test_a_failed_ban_corrects_the_member_and_the_record(self):
        await self.change(vpn={"enabled": True, "action": "ban"})
        self.port.ban_works = False
        result = await self.verify_through(ip="45.33.32.7")
        self.assertEqual(result["action"], "deny")
        self.assertIn("still in the server", self.dm_text(OLD_USER)[-1])
        self.assertEqual((await self.attempts())[-1]["action"], "deny")
        self.assertFalse(await self.db.is_banned(GUILD, OLD_USER))

    async def test_a_kick_that_works_sends_no_correction(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        result = await self.verify_through(ip="45.33.32.7")
        self.assertEqual(result["action"], "kick")
        self.assertEqual((await self.attempts())[-1]["action"], "kick")
        self.assertNotIn("still in the server", " ".join(self.dm_text(OLD_USER)))

    async def test_the_webhook_says_what_really_happened(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        self.port.kick_works = False
        sent = []

        async def sender(guild_id, event, payload):
            sent.append((event, payload))
        self.service.webhook_sender = sender
        await self.verify_through(ip="45.33.32.7")
        await asyncio.sleep(0)
        self.assertEqual(next(payload for event, payload in sent if event == "member.failed")["action"], "deny")

    async def test_a_dm_that_didnt_arrive_is_in_the_log(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.port.dm_open = False
        await self.verify_through(ip="45.33.32.7")
        self.assertIn("couldn't tell them by DM", self.log_text())

    async def test_a_dm_that_arrived_isnt_noted(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        self.assertNotIn("couldn't tell them", self.log_text())

    async def linked_main(self, action):
        """An earlier account, verified in this browser, about to be acted on when a second account signs in."""
        await self.turn_on_alts(main_action=action)
        await self.submit_directly(await self.signed_in(THIRD_USER))
        self.port.dms.clear()

    async def test_an_earlier_account_that_already_left_gets_no_dm_or_kick(self):
        await self.linked_main("kick")
        del self.port.members[(GUILD, THIRD_USER)]
        await self.submit_directly(await self.signed_in(OTHER_USER))
        self.assertEqual(self.dm_text(THIRD_USER), [])
        self.assertEqual(self.port.did("kick")[-1][1], OTHER_USER)
        self.assertEqual(len(self.port.did("kick")), 1)
        rows = [row for row in await self.attempts(THIRD_USER) if row["check_id"] == "alt_account" and row["outcome"] == "failed"]
        self.assertEqual(rows, [], "nothing happened to them, so an alt's retries write nothing on their record")
        self.assertEqual((await self.db.member(GUILD, THIRD_USER))["status"], "pending")
        self.assertIn("earlier account had already left", self.log_text())

    async def test_an_earlier_account_that_left_can_still_be_banned(self):
        await self.linked_main("ban")
        del self.port.members[(GUILD, THIRD_USER)]
        await self.submit_directly(await self.signed_in(OTHER_USER))
        self.assertEqual(self.dm_text(THIRD_USER), [])
        self.assertIn(THIRD_USER, [call[1] for call in self.port.did("ban")])

    async def test_a_failed_kick_of_an_earlier_account_is_corrected_too(self):
        await self.linked_main("kick")
        real = self.port.kick

        async def only_the_alt(guild_id, user_id, reason):
            return user_id != THIRD_USER and await real(guild_id, user_id, reason)
        self.port.kick = only_the_alt
        await self.submit_directly(await self.signed_in(OTHER_USER))
        self.assertIn("You were removed", self.dm_text(THIRD_USER)[0])
        self.assertIn("still in the server", self.dm_text(THIRD_USER)[1])
        self.assertEqual((await self.db.member(GUILD, THIRD_USER))["status"], "verified")

    async def test_an_earlier_account_is_still_acted_on_when_discord_cant_say_who_is_there(self):
        await self.linked_main("kick")
        real = self.port.member

        async def down_for_the_earlier_account(guild_id, user_id):
            if user_id == THIRD_USER:
                raise DiscordUnavailable("down")
            return await real(guild_id, user_id)
        self.port.member = down_for_the_earlier_account
        await self.submit_directly(await self.signed_in(OTHER_USER))
        self.assertIn(THIRD_USER, [call[1] for call in self.port.did("kick")])

    async def test_a_member_who_hasnt_passed_screening_gets_more_time(self):
        await self.due_for_kick()
        self.port.members[(GUILD, OLD_USER)].pending = True
        await self.service.tick()
        self.assertEqual(self.port.did("kick"), [])
        record = await self.db.member(GUILD, OLD_USER)
        self.assertAlmostEqual(record["kick_at"], time.time() + 600, delta=60)
        self.assertAlmostEqual(record["kick_warn_at"], time.time() + 300, delta=60)
        self.assertEqual(self.port.dms, [])

    async def test_a_member_held_by_screening_gets_no_reminder_either(self):
        await self.due_for_kick()
        self.port.members[(GUILD, OLD_USER)].pending = True
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() + 600, kick_warn_at=time.time() - 1)
        await self.service.tick()
        self.assertEqual(self.port.dms, [])
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["kick_warn_at"])

    async def test_a_correction_only_follows_a_message_that_arrived(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        self.port.kick_works = False
        self.port.dm_open = False
        await self.verify_through(ip="45.33.32.7")
        self.assertEqual([text for text in self.dm_text(OLD_USER) if "still in the server" in text], [])

    async def test_an_auto_kick_correction_only_follows_a_message_that_arrived(self):
        await self.due_for_kick()
        self.port.kick_works = False
        self.port.dm_open = False
        await self.service.tick()
        self.assertEqual(len(self.port.dms), 1)

    async def test_an_earlier_accounts_correction_only_follows_a_message_that_arrived(self):
        await self.linked_main("kick")
        real, real_dm = self.port.kick, self.port.dm

        async def only_the_alt(guild_id, user_id, reason):
            return user_id != THIRD_USER and await real(guild_id, user_id, reason)

        async def closed_for_the_earlier_account(user_id, notice):
            await real_dm(user_id, notice)
            return user_id != THIRD_USER
        self.port.kick, self.port.dm = only_the_alt, closed_for_the_earlier_account
        await self.submit_directly(await self.signed_in(OTHER_USER))
        self.assertEqual(len(self.dm_text(THIRD_USER)), 1)


class ClosedDms(Prepared):
    async def test_the_public_notice_is_for_closed_dms_only(self):
        self.port.dm_fails = True
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertEqual(self.posts(CHANNEL), [])
        self.port.dm_fails = False
        self.port.dm_open = False
        await self.service.on_join(self.port.add_member(THIRD_USER))
        self.assertEqual(len(self.posts(CHANNEL)), 1)

    async def test_a_reset_treats_them_the_same(self):
        self.port.dm_fails = True
        told = (await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff"))
        self.assertFalse(told)
        self.assertEqual(self.posts(CHANNEL), [])
        self.port.dm_fails = False
        self.port.dm_open = False
        self.assertTrue(await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff"))
        self.assertEqual(len(self.posts(CHANNEL)), 1)

    async def test_a_bypass_link_reports_delivery_as_true_or_false(self):
        self.port.dm_fails = True
        _, told = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 1, "dm", STAFF, "staff")
        self.assertIs(told, False)
        self.port.dm_fails = False
        _, told = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 1, "dm", STAFF, "staff")
        self.assertIs(told, True)


class KickReminders(Prepared):
    async def joined(self, user=OTHER_USER, minutes=10, **core):
        await self.edit(lambda doc: (doc["core"]["auto_kick"].update(enabled=True, minutes=minutes), doc["core"].update(core)))
        member = self.port.add_member(user)
        await self.service.on_join(member)
        self.port.dms.clear()
        return member

    async def halfway(self, user=OTHER_USER):
        await self.db.update_member(GUILD, user, kick_warn_at=time.time() - 1)

    async def test_joining_sets_the_reminder_for_halfway(self):
        await self.joined()
        record = await self.db.member(GUILD, OTHER_USER)
        self.assertAlmostEqual(record["kick_warn_at"], time.time() + 300, delta=30)
        self.assertAlmostEqual(record["kick_at"], time.time() + 600, delta=30)

    async def test_with_auto_kick_off_no_reminder_is_set(self):
        self.port.add_member(OTHER_USER)
        await self.service.on_join(self.port.members[(GUILD, OTHER_USER)])
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_warn_at"])

    async def test_not_before_halfway(self):
        await self.joined()
        await self.service.tick()
        self.assertEqual(self.port.dms, [])

    async def test_one_reminder_saying_when(self):
        await self.joined()
        await self.halfway()
        await self.service.tick()
        await self.service.tick()
        self.assertEqual(len(self.port.dms), 1)
        kick_at = (await self.db.member(GUILD, OTHER_USER))["kick_at"]
        self.assertIn(f"<t:{int(kick_at)}:R>", self.dm_text()[0])
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_warn_at"])

    async def test_each_mode_says_how_to_verify(self):
        await self.joined(mode="button")
        await self.halfway()
        await self.service.tick()
        self.assertIn(f"<#{CHANNEL}>", self.dm_text()[0])
        self.port.dms.clear()
        await self.joined(THIRD_USER, mode="web")
        await self.halfway(THIRD_USER)
        await self.service.tick()
        self.assertIn("the link AltWarden sent you", self.dm_text()[0])

    async def test_instant_mode_says_to_rejoin(self):
        await self.change(avatar={"enabled": True, "action": "deny"})
        await self.edit(lambda doc: (doc["core"]["auto_kick"].update(enabled=True, minutes=10), doc["core"].update(mode="instant")))
        await self.service.on_join(self.port.add_member(OTHER_USER, avatar=None))
        self.port.dms.clear()
        await self.halfway()
        await self.service.tick()
        self.assertIn("rejoin", self.dm_text()[0])

    async def test_nobody_verified_is_reminded(self):
        await self.joined()
        await self.db.update_member(GUILD, OTHER_USER, status="verified")
        await self.halfway()
        await self.service.tick()
        self.assertEqual(self.port.dms, [])

    async def test_someone_holding_the_role_isnt_reminded(self):
        await self.joined()
        self.port.members[(GUILD, OTHER_USER)].role_ids = (VERIFIED_ROLE,)
        await self.halfway()
        await self.service.tick()
        self.assertEqual(self.port.dms, [])

    async def test_someone_who_left_isnt_reminded(self):
        await self.joined()
        del self.port.members[(GUILD, OTHER_USER)]
        await self.halfway()
        await self.service.tick()
        self.assertEqual(self.port.dms, [])

    async def test_with_auto_dm_off_there_is_no_reminder(self):
        await self.joined()
        await self.edit(lambda doc: doc["core"].update(auto_dm=False))
        await self.halfway()
        await self.service.tick()
        self.assertEqual(self.port.dms, [])

    async def test_auto_kick_turned_off_cancels_it(self):
        await self.joined()
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=False))
        await self.halfway()
        await self.service.tick()
        self.assertEqual(self.port.dms, [])

    async def test_discord_not_answering_keeps_the_reminder_for_later(self):
        await self.joined()
        await self.halfway()
        self.port.discord_down = True
        with self.assertLogs("altwarden", "ERROR"):
            await self.service.tick()
        self.assertEqual(self.port.dms, [])
        self.assertIsNotNone((await self.db.member(GUILD, OTHER_USER))["kick_warn_at"])
        self.port.discord_down = False
        await self.service.tick()
        self.assertEqual(len(self.port.dms), 1)

    async def test_while_discord_is_loading_the_server_it_waits(self):
        await self.joined()
        await self.halfway()
        self.port.loading = True
        await self.service.tick()
        self.assertEqual(self.port.dms, [])
        self.assertIsNotNone((await self.db.member(GUILD, OTHER_USER))["kick_warn_at"])

    async def test_a_kick_due_now_skips_the_reminder(self):
        await self.joined()
        await self.db.update_member(GUILD, OTHER_USER, kick_warn_at=time.time() - 1, kick_at=time.time() - 1)
        await self.service.tick()
        self.assertEqual(len(self.port.dms), 1)
        self.assertIn("ran out", self.dm_text()[0])

    async def test_leaving_clears_it(self):
        await self.joined()
        await self.service.on_leave(GUILD, OTHER_USER)
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_warn_at"])

    async def test_an_import_clears_it(self):
        await self.joined()
        await self.service.import_members(GUILD, [OTHER_USER], STAFF, "staff")
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_warn_at"])

    async def test_auto_kick_finding_nothing_to_do_clears_it(self):
        await self.joined()
        self.port.members[(GUILD, OTHER_USER)].role_ids = (VERIFIED_ROLE,)
        await self.db.update_member(GUILD, OTHER_USER, kick_at=time.time() - 1)
        await self.service.tick()
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_warn_at"])


class Joining(Prepared):
    async def test_a_join_that_breaks_midway_stays_unhandled_for_the_catch_up(self):
        member = self.port.add_member(OTHER_USER)
        real = self.port.dm

        async def broken(*args):
            raise RuntimeError("process died here")
        self.port.dm = broken
        with self.assertRaises(RuntimeError):
            await self.service.on_join(member)
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["joined_at"])
        self.port.dm = real
        await self.service.on_join(member, catching_up=True)
        self.assertAlmostEqual((await self.db.member(GUILD, OTHER_USER))["joined_at"], time.time(), delta=30)

    async def test_a_rejoin_that_breaks_midway_keeps_the_old_join_time(self):
        member = self.port.add_member(OTHER_USER)
        await self.service.on_join(member)
        await self.db.update_member(GUILD, OTHER_USER, joined_at=1000.0)

        async def broken(*args):
            raise RuntimeError("process died here")
        self.port.dm = broken
        with self.assertRaises(RuntimeError):
            await self.service.on_join(member)
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["joined_at"], 1000.0)

    async def test_every_way_through_a_join_writes_the_time(self):
        cases = {
            "instant": lambda doc: doc["core"].update(mode="instant"),
            "no dm": lambda doc: doc["core"].update(mode="web", auto_dm=False),
            "remembered": lambda doc: doc["core"].update(auto_dm=True, remember_rejoin=True),
        }
        for number, (name, change) in enumerate(cases.items()):
            await self.edit(change)
            user = str(175928847299118000 + number)
            if name == "remembered":
                await self.db.touch_member(GUILD, user)
                await self.db.update_member(GUILD, user, status="verified")
            await self.service.on_join(self.port.add_member(user))
            self.assertAlmostEqual((await self.db.member(GUILD, user))["joined_at"], time.time(), delta=30, msg=name)

    async def test_a_member_already_holding_the_role_isnt_treated_as_new(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=5))
        await self.service.on_join(self.port.add_member(OTHER_USER, roles=(VERIFIED_ROLE,)))
        record = await self.db.member(GUILD, OTHER_USER)
        self.assertEqual((record["status"], record["method"], record["kick_at"], record["kick_warn_at"]), ("verified", "imported", None, None))
        self.assertIsNotNone(record["first_verified_at"])
        self.assertIsNotNone(record["joined_at"])
        self.assertEqual(self.port.dms, [])

    async def test_a_verified_member_already_holding_the_role_keeps_their_record(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.mark_verified(GUILD, OTHER_USER, "web", when=1000.0)
        await self.service.on_join(self.port.add_member(OTHER_USER, roles=(VERIFIED_ROLE,)))
        record = await self.db.member(GUILD, OTHER_USER)
        self.assertEqual((record["method"], record["verified_at"]), ("web", 1000.0))

    async def test_a_button_mode_join_dm_gives_the_deadline(self):
        await self.edit(lambda doc: (doc["core"].update(mode="button"), doc["core"]["auto_kick"].update(enabled=True, minutes=10)))
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn("within 10 minutes", self.dm_text()[0])

    async def test_a_button_mode_join_dm_with_no_auto_kick_gives_no_deadline(self):
        await self.edit(lambda doc: doc["core"].update(mode="button"))
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertNotIn("within", self.dm_text()[0])

    async def test_the_closed_dms_ping_gives_the_deadline(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=10))
        self.port.dm_open = False
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn("within 10 minutes", self.posts(CHANNEL)[-1].content)

    async def test_an_instant_mode_failure_dm_says_to_rejoin(self):
        await self.change(avatar={"enabled": True, "action": "deny"})
        await self.edit(lambda doc: doc["core"].update(mode="instant"))
        await self.service.on_join(self.port.add_member(OTHER_USER, avatar=None))
        self.assertIn("rejoin", self.dm_text(OTHER_USER)[-1])

    async def test_an_instant_mode_wait_says_to_rejoin(self):
        await self.edit(lambda doc: (doc["core"].update(mode="instant"), doc["core"]["cooldown"].update(enabled=True, seconds=300)))
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.update_member(GUILD, OTHER_USER, last_fail_at=time.time())
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn("rejoin", self.dm_text(OTHER_USER)[-1])

    async def test_a_web_failure_dm_doesnt_mention_rejoining(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        self.assertNotIn("rejoin", self.dm_text(OLD_USER)[-1])


class BypassLinks(Prepared):
    async def bypass(self, user=OLD_USER, hours=24, notify="none"):
        url, told = await self.service.create_bypass(GUILD, user, ["vpn"], hours, notify, STAFF, "staff")
        return url.rsplit("/", 1)[1], told

    async def test_a_bypass_starts_the_kick_time_after_the_link_ends(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=10))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.bypass()
        record = await self.db.member(GUILD, OLD_USER)
        self.assertAlmostEqual(record["kick_at"], time.time() + 24 * 3600 + 600, delta=30)
        self.assertAlmostEqual(record["kick_warn_at"], time.time() + 24 * 3600 + 300, delta=30)

    async def test_a_bypass_on_a_server_with_no_auto_kick_sets_no_timer(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() + 100, kick_warn_at=time.time() + 50)
        await self.bypass()
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["kick_at"], record["kick_warn_at"]), (None, None))

    async def test_a_rejoin_with_a_live_bypass_gets_no_shorter_timer(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=5))
        member = self.port.add_member(OTHER_USER)
        await self.bypass(OTHER_USER)
        await self.service.on_leave(GUILD, OTHER_USER)
        await self.service.on_join(member)
        record = await self.db.member(GUILD, OTHER_USER)
        self.assertAlmostEqual(record["kick_at"], time.time() + 24 * 3600 + 300, delta=60)

    async def test_a_rejoin_with_a_live_bypass_is_told_about_it_and_keeps_the_skips(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=5))
        member = self.port.add_member(OTHER_USER)
        await self.bypass(OTHER_USER)
        self.port.dms.clear()
        await self.service.on_join(member)
        self.assertIn("skips the checks", self.dm_text(OTHER_USER)[0])
        self.assertNotIn("are removed", self.dm_text(OTHER_USER)[0])
        token = self.port.dms[0][1].buttons[0].url.rsplit("/", 1)[1]
        self.assertEqual((await self.service.session(token))["bypass"], ["vpn"])

    async def test_a_rejoin_in_button_mode_with_a_live_bypass_still_gets_the_link(self):
        await self.edit(lambda doc: doc["core"].update(mode="button"))
        member = self.port.add_member(OTHER_USER)
        await self.bypass(OTHER_USER)
        self.port.dms.clear()
        await self.service.on_join(member)
        self.assertIn("skips the checks", self.dm_text(OTHER_USER)[0])

    async def test_a_ban_ends_a_members_links(self):
        await self.db.touch_member(GUILD, OLD_USER)
        token, _ = await self.bypass()
        await self.service.on_ban(GUILD, OLD_USER)
        self.assertIsNone(await self.service.session(token))

    async def test_a_ban_on_a_server_with_no_record_still_ends_them(self):
        await self.db.touch_member(GUILD, OLD_USER)
        token, _ = await self.bypass()
        await self.service.on_ban(GUILD, OLD_USER)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (OLD_USER,)), 0)


class OldLinks(Prepared):
    async def finished(self):
        token = await self.link_for()
        await self.sign_in(token)
        await (await self.attempt(token)).json()
        self.assertEqual((await self.service.session(token))["state"], "done")
        return token

    async def test_leaving_ends_a_finished_link(self):
        token = await self.finished()
        await self.service.on_leave(GUILD, OLD_USER)
        self.assertIsNone(await self.service.session(token))

    async def test_a_ban_ends_a_finished_link(self):
        token = await self.finished()
        await self.service.on_ban(GUILD, OLD_USER)
        self.assertIsNone(await self.service.session(token))

    async def test_a_rejoin_ends_a_finished_link(self):
        token = await self.finished()
        await self.service.on_join(self.port.members[(GUILD, OLD_USER)])
        self.assertIsNone(await self.service.session(token))

    async def test_failing_a_later_check_ends_a_finished_link(self):
        token = await self.finished()
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        self.assertIsNone(await self.service.session(token))

    async def test_leaving_keeps_a_link_still_in_use(self):
        token = await self.link_for()
        await self.service.on_leave(GUILD, OLD_USER)
        self.assertIsNotNone(await self.service.session(token))


class TimeToVerify(Prepared):
    async def test_the_clock_starts_at_the_first_page_view(self):
        token = await self.link_for()
        await self.service.mark_opened(token)
        await self.sign_in(token)
        await self.db.run("UPDATE sessions SET opened_at = opened_at - 300 WHERE token_hash = ?", (crypto.token_hash(token),))
        await self.attempt(token)
        row = [row for row in await self.attempts() if row["outcome"] == "passed"][-1]
        self.assertGreaterEqual(row["seconds"], 300)
        self.assertLess(row["seconds"], 400)

    async def test_a_later_view_doesnt_move_it(self):
        token = await self.link_for()
        await self.service.mark_opened(token)
        first = (await self.service.session(token))["opened_at"]
        await self.db.run("UPDATE sessions SET opened_at = 1000 WHERE token_hash = ?", (crypto.token_hash(token),))
        await self.service.mark_opened(token)
        self.assertEqual((await self.service.session(token))["opened_at"], 1000)
        self.assertIsNotNone(first)

    async def test_signing_in_twice_counts_as_one_start_after_a_view(self):
        token = await self.link_for()
        await self.service.mark_opened(token)
        await self.sign_in(token)
        await self.sign_in(token)
        self.assertEqual(len([row for row in await self.attempts() if row["outcome"] == "started"]), 1)

    async def test_signing_in_without_a_view_still_starts_the_clock(self):
        token = await self.link_for()
        await self.sign_in(token)
        row = await self.service.session(token)
        self.assertIsNotNone(row["opened_at"])
        self.assertIsNotNone(row["signed_in_at"])


class Honeypot(Prepared):
    async def trap(self, action="kick", **options):
        await self.edit(lambda doc: (doc["honeypot"].update(enabled=True, channel=LOG_CHANNEL, action=action, timeout_minutes=15, **options),
                                     doc["core"]["logs"]["modules"].update(honeypot=LOG_CHANNEL)))

    async def hit(self, user=OLD_USER, message="55", **extra):
        await self.service.honeypot_hit(GUILD, user, LOG_CHANNEL, message, role_ids=(), **extra)

    async def test_a_bot_post_is_deleted_and_logged_and_nothing_more(self):
        for action in ("timeout", "kick", "softban", "ban"):
            await self.trap(action)
            self.port.calls.clear()
            await self.hit("4242", message=action, is_bot=True)
            self.assertEqual([call[0] for call in self.port.calls], ["delete_message"], action)
        self.assertEqual(self.port.dms, [])
        self.assertEqual(await self.attempts("4242"), [])
        self.assertIn("A bot", self.log_text())

    async def test_a_webhook_post_is_deleted_and_logged_and_nothing_more(self):
        await self.trap("ban")
        await self.hit("4242", is_webhook=True)
        self.assertEqual([call[0] for call in self.port.calls], ["delete_message"])
        self.assertEqual(self.port.dms, [])
        self.assertEqual(await self.attempts("4242"), [])
        self.assertIn("A webhook", self.log_text())

    async def test_a_bot_with_a_whitelisted_role_is_left_alone(self):
        await self.trap("ban", whitelist_roles=[VERIFIED_ROLE])
        await self.service.honeypot_hit(GUILD, "4242", LOG_CHANNEL, "1", role_ids=(VERIFIED_ROLE,), is_bot=True)
        self.assertEqual(self.port.calls, [])

    async def test_a_member_is_told_before_the_action(self):
        order = []
        real_dm, real_kick = self.port.dm, self.port.kick

        async def dm(user, notice):
            order.append("dm")
            return await real_dm(user, notice)

        async def kick(*args):
            order.append("kick")
            return await real_kick(*args)
        self.port.dm, self.port.kick = dm, kick
        await self.trap("kick")
        await self.hit()
        self.assertEqual(order, ["dm", "kick"])

    async def test_each_action_says_what_happened(self):
        expected = {"timeout": "timed out for 15 minutes", "kick": "removed", "softban": "removed", "ban": "banned"}
        for number, (action, words) in enumerate(expected.items()):
            await self.trap(action)
            user = str(175928847299119000 + number)
            await self.hit(user)
            self.assertIn(words, self.dm_text(user)[0], action)
            self.assertIn("honeypot", self.dm_text(user)[0].lower())

    async def test_the_dm_offers_an_appeal_only_when_the_server_takes_them(self):
        await self.trap("kick")
        await self.hit()
        self.assertEqual([button.label for button in self.port.dms[-1][1].buttons], ["Appeal"])
        await self.edit(lambda doc: doc["appeals"].update(enabled=False))
        await self.hit(OTHER_USER)
        self.assertEqual(self.port.dms[-1][1].buttons, [])

    async def test_a_log_action_sends_no_dm_and_leaves_nothing_to_appeal(self):
        await self.trap("log")
        await self.hit()
        self.assertEqual(self.port.dms, [])
        self.assertEqual(await self.service.submit_appeal(GUILD, OLD_USER, "x", "this wasn't me at all"), "There is no recent failed attempt to appeal.")

    async def test_each_action_can_be_appealed(self):
        for number, action in enumerate(("timeout", "kick", "softban", "ban")):
            await self.trap(action)
            user = str(175928847299119100 + number)
            await self.hit(user)
            self.assertIsNone(await self.service.submit_appeal(GUILD, user, "x", "this wasn't me at all"), action)
            self.assertEqual((await self.db.one("SELECT check_id FROM appeals WHERE user_id = ?", (user,)))["check_id"], "honeypot")

    async def test_the_appeal_card_names_the_honeypot(self):
        await self.trap("kick")
        await self.hit()
        await self.service.submit_appeal(GUILD, OLD_USER, "x", "this wasn't me at all")
        self.assertIn('"value": "Honeypot"', json.dumps(self.port.sent[-1][1].embeds))

    async def test_an_action_that_failed_leaves_nothing_to_appeal_and_corrects_the_dm(self):
        await self.trap("kick")
        self.port.kick_works = False
        await self.hit()
        self.assertIn("still in the server", self.dm_text(OLD_USER)[-1])
        self.assertEqual((await self.attempts())[-1]["action"], None)
        self.assertIn("failed, usually a missing permission", self.log_text())
        self.assertEqual(await self.service.submit_appeal(GUILD, OLD_USER, "x", "this wasn't me at all"), "There is no recent failed attempt to appeal.")

    async def test_a_correction_only_follows_a_message_that_arrived(self):
        await self.trap("kick")
        self.port.kick_works = False
        self.port.dm_open = False
        await self.hit()
        self.assertEqual(len(self.port.dms), 1)

    async def test_a_failed_timeout_is_corrected_too(self):
        await self.trap("timeout")
        self.port.timeout_works = False
        await self.hit()
        self.assertIn("weren't timed out", self.dm_text(OLD_USER)[-1])

    async def test_a_softban_whose_unban_fails_says_so(self):
        await self.trap("softban")
        self.port.unban_works = False
        await self.hit()
        self.assertEqual(len(self.port.did("unban")), 2, "it tries twice")
        self.assertIn("Banned, and the unban failed", self.log_text())
        self.assertNotIn("Softbanned", self.log_text())

    async def test_a_softban_whose_unban_works_the_second_time_is_a_softban(self):
        await self.trap("softban")
        real = self.port.unban
        calls = []

        async def flaky(*args):
            calls.append(args)
            return False if len(calls) == 1 else await real(*args)
        self.port.unban = flaky
        await self.hit()
        self.assertEqual(len(calls), 2)
        self.assertIn("Softbanned", self.log_text())

    async def test_a_softban_that_lands_first_time_unbans_once(self):
        await self.trap("softban")
        await self.hit()
        self.assertEqual(len(self.port.did("unban")), 1)
        self.assertIn("Softbanned", self.log_text())

    async def test_a_flood_from_one_bot_is_logged_once(self):
        await self.trap("kick")
        await self.hit("4242", message="1", is_bot=True)
        await self.hit("4242", message="2", is_bot=True)
        self.assertEqual(len(self.port.did("delete_message")), 2)
        self.assertEqual(self.log_titles().count("Honeypot triggered"), 1)


LOW_ROLE = "970000000000000070"
MOD_ROLE = "970000000000000071"
HIGH_ROLE = "970000000000000072"


class StaffAgainstATarget(Prepared):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        # The verified role sits at 2, and the fake's bot at 5.
        self.port.extra_roles = [{"id": LOW_ROLE, "name": "low", "color": 0, "position": 1, "managed": False, "mentionable": False},
                                 {"id": MOD_ROLE, "name": "mod", "color": 0, "position": 3, "managed": False, "mentionable": False},
                                 {"id": HIGH_ROLE, "name": "high", "color": 0, "position": 4, "managed": False, "mentionable": False}]

    def actor(self, roles=(MOD_ROLE,), perms=("manage_roles",), **extra):
        return MemberInfo(GUILD, THIRD_USER, "mod", None, False, roles, frozenset(perms), **extra)

    async def test_an_administrator_and_the_owner_pass_whatever_the_roles_say(self):
        self.port.add_member(OTHER_USER, roles=(HIGH_ROLE,))
        await self.db.record_ban(GUILD, OTHER_USER)
        for actor in (self.actor(roles=(), perms=("administrator",)), self.actor(roles=(), perms=(), is_owner=True)):
            for action in ("verify", "reset", "bypass", "trust", "unban"):
                self.assertIsNone(await self.service.staff_refusal(GUILD, actor, OTHER_USER, action), action)

    async def test_a_target_above_or_level_with_the_actor_is_refused(self):
        for role in (HIGH_ROLE, MOD_ROLE):
            self.port.add_member(OTHER_USER, roles=(role,))
            for action in ("verify", "reset", "bypass", "trust"):
                self.assertIn("at or above yours", await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, action), (role, action))

    async def test_a_target_below_the_actor_passes(self):
        self.port.add_member(OTHER_USER, roles=(LOW_ROLE,))
        for action in ("verify", "reset", "bypass", "trust"):
            self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, action), action)

    async def test_the_actors_highest_role_is_what_counts(self):
        self.port.add_member(OTHER_USER, roles=(MOD_ROLE,))
        self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(roles=(LOW_ROLE, HIGH_ROLE)), OTHER_USER, "reset"))

    async def test_the_targets_highest_role_is_what_counts(self):
        self.port.add_member(OTHER_USER, roles=(LOW_ROLE, HIGH_ROLE))
        self.assertIsNotNone(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "reset"))

    async def test_a_target_who_isnt_in_the_server_has_no_rank(self):
        self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "reset"))

    async def test_the_server_owner_can_never_be_a_target(self):
        self.port.add_member(STAFF)  # the fake's owner, with no roles
        self.assertIn("at or above yours", await self.service.staff_refusal(GUILD, self.actor(), STAFF, "reset"))
        self.port.add_member(OTHER_USER, owner=True)
        self.assertIn("at or above yours", await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "reset"))

    async def test_the_verified_role_must_sit_below_the_actor(self):
        self.port.add_member(OTHER_USER)
        self.assertIn("verified role", await self.service.staff_refusal(GUILD, self.actor(roles=(LOW_ROLE,)), OTHER_USER, "verify"))
        self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "verify"))
        self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(roles=(LOW_ROLE,)), OTHER_USER, "bypass"))

    async def test_a_banned_account_takes_ban_members(self):
        await self.db.record_ban(GUILD, OTHER_USER)
        for action in ("reset", "trust", "unban"):
            self.assertIn("Ban Members", await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, action), action)
            self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(perms=("manage_roles", "ban_members")), OTHER_USER, action), action)

    async def test_a_ban_only_discord_knows_about_counts(self):
        self.port.banned.add(OTHER_USER)
        self.assertIn("Ban Members", await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "reset"))

    async def test_an_account_that_isnt_banned_doesnt_take_ban_members(self):
        for action in ("reset", "trust", "unban"):
            self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, action), action)

    async def test_verify_and_bypass_dont_care_about_a_ban(self):
        await self.db.record_ban(GUILD, OTHER_USER)
        for action in ("verify", "bypass"):
            self.assertIsNone(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, action), action)

    async def test_discord_failing_refuses_and_says_why(self):
        self.port.discord_down = True
        self.assertEqual(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "reset"), DISCORD_BUSY)

    async def test_a_server_the_bot_cant_see_refuses(self):
        self.port.absent = True
        self.assertIn("can't see", await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "reset"))

    async def test_an_uninstalled_server_refuses_a_verify_without_breaking(self):
        await self.db.forget_guild(GUILD)
        self.service.forget_cached(GUILD)
        self.assertIsNotNone(await self.service.staff_refusal(GUILD, self.actor(), OTHER_USER, "verify"))


class Resetting(Prepared):
    async def test_it_says_who_was_told_and_what_went_wrong(self):
        result = await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertEqual((result.told, result.problem, result.kept_hashes), (True, None, False))
        self.assertEqual(result.as_dict(), {"told": True, "problem": None, "kept_hashes": False})
        self.assertTrue(result)

    async def test_a_role_that_couldnt_be_taken_is_reported(self):
        self.port.role_refusals[VERIFIED_ROLE] = ROLE_TOO_LOW
        result = await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertEqual(result.problem, ROLE_TOO_LOW)
        self.assertIn(ROLE_TOO_LOW, self.log_text())

    async def test_a_limit_role_or_an_unverified_role_that_went_wrong_is_reported(self):
        await self.change(max_attempts={"enabled": True, "role": LIMIT_ROLE})
        self.port.role_refusals[LIMIT_ROLE] = "limit role refused"
        self.assertEqual((await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")).problem, "limit role refused")
        self.port.role_refusals.clear()
        await self.edit(lambda doc: doc["core"].update(unverified_enabled=True, unverified_role=UNVERIFIED_ROLE))
        self.port.role_refusals[UNVERIFIED_ROLE] = "unverified role refused"
        self.assertEqual((await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")).problem, "unverified role refused")

    async def test_a_member_who_left_has_no_role_problem(self):
        self.assertIsNone((await self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff")).problem)

    async def test_a_banned_accounts_hashes_stay(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.store_identifier(GUILD, OTHER_USER, "ip", "digest", time.time() + 1000)
        await self.db.record_ban(GUILD, OTHER_USER)
        result = await self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff")
        self.assertTrue(result.kept_hashes)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OTHER_USER,)), 1)
        self.assertIn("hashes", self.log_text())
        self.assertIs(json.loads((await self.db.one("SELECT detail FROM audit WHERE kind = 'reset'"))["detail"])["kept_hashes"], True)

    async def test_a_ban_only_discord_knows_about_keeps_them_too(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.store_identifier(GUILD, OTHER_USER, "ip", "digest", time.time() + 1000)
        self.port.banned.add(OTHER_USER)
        self.assertTrue((await self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff")).kept_hashes)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OTHER_USER,)), 1)

    async def test_anyone_elses_hashes_go(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.store_identifier(GUILD, OTHER_USER, "ip", "digest", time.time() + 1000)
        self.assertFalse((await self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff")).kept_hashes)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OTHER_USER,)), 0)

    async def test_the_first_verified_date_survives(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.mark_verified(GUILD, OLD_USER, "web", when=1000.0)
        await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["first_verified_at"], record["verified_at"], record["status"]), (1000.0, None, "pending"))

    async def test_a_reset_main_account_is_still_the_main_account(self):
        await self.turn_on_alts()
        await self.submit_directly(await self.signed_in(OTHER_USER))
        self.port.add_member(THIRD_USER)
        await self.db.touch_member(GUILD, THIRD_USER)
        await self.db.mark_verified(GUILD, THIRD_USER, "web")  # the alt got in anyway, by an appeal
        self.assertGreater((await self.db.member(GUILD, THIRD_USER))["first_verified_at"], (await self.db.member(GUILD, OTHER_USER))["first_verified_at"])
        await self.db.store_identifier(GUILD, THIRD_USER, "cookie", self.keys.digest(int(GUILD), "cookie", "device-1"), time.time() + 1000)
        await self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff")
        token = await self.link_for(OTHER_USER)
        await self.sign_in(token, user=OTHER_USER)
        result = await self.submit_directly(token)
        self.assertEqual(result.status, "verified", "the main account gets the main action, Watch, and isn't kicked as an alt")

    async def test_a_reset_starts_the_time_to_verify_over(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=10))
        await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        record = await self.db.member(GUILD, OLD_USER)
        self.assertAlmostEqual(record["kick_at"], time.time() + 600, delta=30)
        self.assertAlmostEqual(record["kick_warn_at"], time.time() + 300, delta=30)
        self.assertIn("10 minutes", self.dm_text(OLD_USER)[-1])

    async def test_someone_not_in_the_server_gets_no_timer(self):
        await self.edit(lambda doc: doc["core"]["auto_kick"].update(enabled=True, minutes=10))
        await self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff")
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_at"])

    async def test_auto_kick_off_sets_no_timer(self):
        await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["kick_at"])

    async def test_discord_failing_first_changes_nothing(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.store_identifier(GUILD, OLD_USER, "ip", "digest", time.time() + 1000)
        self.port.discord_down = True
        with self.assertRaises(DiscordUnavailable):
            await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,)), 1)


class Appeals(Prepared):
    async def failed(self, user=OLD_USER):
        await self.db.touch_member(GUILD, user)
        await self.db.add_attempt(GUILD, user, "failed", check_id="vpn", action="deny")

    async def appealed(self, user=OLD_USER):
        await self.failed(user)
        self.assertIsNone(await self.service.submit_appeal(GUILD, user, "x", "please look at this"))
        return (await self.db.one("SELECT id FROM appeals WHERE user_id = ? AND status = 'open'", (user,)))["id"]

    async def test_settling_says_whether_the_member_was_told(self):
        appeal = await self.appealed()
        self.assertEqual(await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff"), {"problem": None, "told": True})

    async def test_closed_dms_or_any_other_failure_count_as_not_told(self):
        for setting in ({"dm_open": False}, {"dm_fails": True}):
            for name, value in setting.items():
                setattr(self.port, name, value)
            appeal = await self.appealed()
            self.assertEqual(await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff"), {"problem": None, "told": False})
            self.port.dm_open, self.port.dm_fails = True, False

    async def test_a_refusal_comes_back_as_the_problem(self):
        answer = await self.service.settle_appeal(GUILD, 999, "deny", STAFF, "staff")
        self.assertEqual(answer, {"problem": "That appeal doesn't exist.", "told": False})

    async def test_the_old_call_still_answers_with_only_the_problem(self):
        appeal = await self.appealed()
        self.assertIsNone(await self.service.decide_appeal(GUILD, appeal, "deny", STAFF, "staff"))
        self.assertIn("already", await self.service.decide_appeal(GUILD, appeal, "deny", STAFF, "staff"))

    async def test_the_record_and_the_card_say_who_was_told(self):
        self.port.dm_open = False
        appeal = await self.appealed()
        await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff")
        self.assertIs(json.loads((await self.db.one("SELECT detail FROM audit WHERE kind = 'appeal'"))["detail"])["told"], False)
        edited = []
        real = self.port.edit_message

        async def spy(channel, message, notice):
            edited.append(notice)
            return await real(channel, message, notice)
        self.port.edit_message = spy
        self.port.dm_open = True
        appeal = await self.appealed(OTHER_USER)
        await self.service.settle_appeal(GUILD, appeal, "approve", STAFF, "staff")
        self.assertIn({"name": "Member told", "value": "Yes", "inline": True}, edited[-1].embeds[0]["fields"])

    async def test_a_decided_card_keeps_member_text_as_plain_text(self):
        await self.failed()
        await self.service.submit_appeal(GUILD, OLD_USER, "x", "**URGENT** [Approve](https://evil.example)")
        edited = []
        real = self.port.edit_message

        async def spy(channel, message, notice):
            edited.append(notice)
            return await real(channel, message, notice)
        self.port.edit_message = spy
        appeal = (await self.db.one("SELECT id FROM appeals"))["id"]
        await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff")
        self.assertEqual(edited[0].embeds[0]["description"], notices.escape_text("**URGENT** [Approve](https://evil.example)"))

    async def test_an_approval_for_someone_not_in_the_server_ends_their_links(self):
        await self.failed(OTHER_USER)
        document = await self.service.get_settings(GUILD)
        live, _ = await self.service.new_link(GUILD, OTHER_USER, document)
        self.assertIsNone(await self.service.submit_appeal(GUILD, OTHER_USER, "x", "please look at this"))
        appeal = (await self.db.one("SELECT id FROM appeals"))["id"]
        await self.service.settle_appeal(GUILD, appeal, "approve", STAFF, "staff")
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["status"], "approved")
        self.assertIsNone(await self.service.session(live.rsplit("/", 1)[1]))

    async def test_a_decided_appeal_cant_be_made_again_on_the_same_failure(self):
        for decision in ("deny", "approve"):
            appeal = await self.appealed()
            await self.service.settle_appeal(GUILD, appeal, decision, STAFF, "staff")
            self.assertIn("already decided", await self.service.submit_appeal(GUILD, OLD_USER, "x", "please look again"))
            await asyncio.sleep(0.01)

    async def test_a_new_failure_after_a_decision_can_be_appealed(self):
        appeal = await self.appealed()
        await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff")
        await asyncio.sleep(0.01)
        await self.failed()
        self.assertIsNone(await self.service.submit_appeal(GUILD, OLD_USER, "x", "please look again"))

    async def test_a_server_the_bot_has_left_takes_no_appeal(self):
        await self.failed()
        self.port.absent = True
        self.assertEqual(await self.service.submit_appeal(GUILD, OLD_USER, "x", "please look at this"), "AltWarden isn't in this server any more.")
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM appeals"), 0)

    async def test_a_server_still_loading_asks_to_wait(self):
        await self.failed()
        self.port.absent = True
        self.port.loading = True
        self.assertIn("Try again", await self.service.submit_appeal(GUILD, OLD_USER, "x", "please look at this"))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM appeals"), 0)

    async def test_any_failure_while_deciding_hands_the_appeal_back(self):
        appeal = await self.appealed()

        async def broken(*args, **kwargs):
            raise RuntimeError("database trouble")
        with patch.object(self.db, "trust_pair", broken):
            await self.db.run("INSERT INTO links (guild_id, main_id, alt_id, confidence, score, methods, at) VALUES (?, ?, ?, 'likely', 70, '[]', 1)", (GUILD, OLD_USER, OTHER_USER))
            with self.assertRaises(RuntimeError):
                await self.service.settle_appeal(GUILD, appeal, "trust", STAFF, "staff")
        self.assertEqual((await self.db.one("SELECT status FROM appeals WHERE id = ?", (appeal,)))["status"], "open")

    async def test_the_final_write_failing_hands_it_back_too(self):
        appeal = await self.appealed()
        real = self.db.run

        async def broken(sql, args=()):
            if "decided_by = ?, decided_at" in sql:
                raise RuntimeError("database trouble")
            return await real(sql, args)
        with patch.object(self.db, "run", broken), self.assertRaises(RuntimeError):
            await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff")
        self.assertEqual((await self.db.one("SELECT status FROM appeals WHERE id = ?", (appeal,)))["status"], "open")

    async def test_the_appeal_page_gets_the_state_from_one_place(self):
        state = await self.service.appeal_state(GUILD, OLD_USER)
        self.assertEqual(state, {"enabled": True, "present": True, "failed_at": None, "problem": "There is no recent failed attempt to appeal.", "open": False, "latest": None})
        appeal = await self.appealed()
        state = await self.service.appeal_state(GUILD, OLD_USER)
        self.assertTrue(state["open"])
        self.assertIsNotNone(state["failed_at"])
        self.assertEqual(state["problem"], "You already have an appeal waiting.")
        await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff", "Not this time")
        state = await self.service.appeal_state(GUILD, OLD_USER)
        self.assertFalse(state["open"])
        self.assertEqual((state["latest"]["status"], state["latest"]["note"]), ("denied", "Not this time"))
        self.assertIn("already decided", state["problem"])

    async def test_the_appeal_state_names_no_check(self):
        await self.appealed()
        self.assertNotIn("vpn", json.dumps(await self.service.appeal_state(GUILD, OLD_USER)))

    async def test_the_appeal_state_with_appeals_off_or_the_bot_gone(self):
        await self.edit(lambda doc: doc["appeals"].update(enabled=False))
        self.assertFalse((await self.service.appeal_state(GUILD, OLD_USER))["enabled"])
        self.port.absent = True
        self.assertFalse((await self.service.appeal_state(GUILD, OLD_USER))["present"])


class AfterUninstall(Prepared):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.db.forget_guild(GUILD)
        self.service.forget_cached(GUILD)

    async def test_every_old_button_gets_an_answer(self):
        member = self.port.members[(GUILD, OLD_USER)]
        self.assertEqual(await self.service.open_help(member), (None, "This server isn't set up."))
        self.assertEqual(await self.service.close_help(GUILD, "1", member), (False, "This server isn't set up."))
        self.assertEqual(await self.service.manual_verify(GUILD, OLD_USER, STAFF), "This server isn't set up.")
        self.assertEqual((await self.service.reset_member(GUILD, OLD_USER, STAFF)).problem, "This server isn't set up.")
        self.assertEqual(await self.service.settle_appeal(GUILD, 1, "approve", STAFF), {"problem": "That appeal doesn't exist.", "told": False})

    async def test_an_appeal_row_with_no_settings_left_gets_an_answer(self):
        await self.db.touch_member(GUILD, OLD_USER)
        appeal = await self.db.open_appeal(GUILD, OLD_USER, "vpn", "please look at this")
        answer = await self.service.settle_appeal(GUILD, appeal, "approve", STAFF)
        self.assertEqual(answer["problem"], "This server isn't set up.")
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "open")


class HelpThreads(Prepared):
    async def desk(self, **options):
        await self.edit(lambda doc: (doc["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, require_attempt=False, auto_close=True, **options),
                                     doc["core"]["logs"]["modules"].update(help_desk=LOG_CHANNEL)))

    async def records(self, count=3):
        await self.db.touch_member(GUILD, OLD_USER)
        for _ in range(count):
            await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny")

    async def opened(self):
        return (await self.service.open_help(self.port.members[(GUILD, OLD_USER)]))[0]

    def first_post(self):
        return self.port.threads[-1]

    async def test_with_reasons_hidden_the_thread_lists_only_times(self):
        await self.desk()
        await self.edit(lambda doc: doc["core"].update(show_reason=False))
        await self.records()
        await self.opened()
        description = self.first_post().embeds[-1]["description"]
        self.assertIn("<t:", description)
        self.assertNotIn("VPN", description)

    async def test_with_reasons_shown_it_names_the_check(self):
        await self.desk()
        await self.records()
        await self.opened()
        self.assertIn("VPN", self.first_post().embeds[-1]["description"])

    async def test_the_first_post_fits_discords_limit_with_records_on_a_long_message(self):
        await self.desk()
        await self.edit(lambda doc: doc["messages"]["help_desk"].update(title="t" * 256, description="d" * 4000, footer="f" * 1500))
        await self.records(10)
        await self.opened()
        # Counted here by hand, so a mistake in the code's own count can't hide.
        total = sum(len(embed.get("title", "")) + len(embed.get("description", "")) + len(embed.get("footer", {}).get("text", "")) for embed in self.first_post().embeds)
        self.assertGreater(total, 5000)
        self.assertLessEqual(total, 6000)
        self.assertEqual(self.first_post().embeds[-1]["title"], "Verification records")
        self.assertIn("<t:", self.first_post().embeds[-1]["description"])

    async def test_records_are_cut_at_whole_lines_with_the_newest_kept(self):
        rows = [{"at": 2000 + number, "check_id": "vpn"} for number in range(10)]
        whole = notices.records_embed(rows, True, 6000)
        self.assertEqual(whole["description"].count("\n"), 9)
        cut = notices.records_embed(rows, True, notices.embed_size(whole) - 5)
        self.assertEqual(cut["description"].count("\n"), 8)
        self.assertTrue(cut["description"].startswith("<t:2000:R>"))

    async def test_with_no_room_there_is_no_records_embed(self):
        self.assertIsNone(notices.records_embed([{"at": 1, "check_id": "vpn"}], True, 10))
        self.assertIsNone(notices.records_embed([], True, 6000))

    async def test_the_first_post_has_the_staff_buttons(self):
        await self.desk()
        await self.opened()
        ids = [button.custom_id for button in self.first_post().buttons]
        self.assertEqual(ids, [f"aw:staff:verify:{OLD_USER}", f"aw:staff:bypass:{OLD_USER}", "aw:help:close"])

    async def test_a_close_that_failed_says_so_and_keeps_the_link(self):
        await self.desk()
        thread = await self.opened()
        self.port.close_works = False
        staff = MemberInfo(GUILD, STAFF, "staff", None, False, (VERIFIED_ROLE,), frozenset())
        closed, text = await self.service.close_help(GUILD, thread, staff)
        self.assertFalse(closed)
        self.assertIn("couldn't close", text)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["help_thread_id"], thread)
        self.assertNotIn("Help thread closed", self.log_titles())

    async def test_a_close_that_worked_clears_the_link_and_logs_it(self):
        await self.desk()
        thread = await self.opened()
        staff = MemberInfo(GUILD, STAFF, "staff", None, False, (VERIFIED_ROLE,), frozenset())
        self.assertEqual(await self.service.close_help(GUILD, thread, staff), (True, "Closed."))
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["help_thread_id"])
        self.assertIn("Help thread closed", self.log_titles())

    async def test_closing_after_a_pass_keeps_the_link_when_discord_refuses(self):
        await self.desk()
        thread = await self.opened()
        self.port.close_works = False
        await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff")
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["help_thread_id"], thread)
        self.assertNotIn("Help thread closed", self.log_titles())
        self.assertIn("Couldn't close a help thread", self.log_titles())

    async def test_closing_after_leaving_clears_the_link_when_it_works(self):
        await self.desk()
        await self.opened()
        await self.service.on_leave(GUILD, OLD_USER)
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["help_thread_id"])
        self.assertIn("Help thread closed", self.log_titles())


class SealedSecrets(Prepared):
    async def test_a_saved_key_is_sealed_and_reads_back(self):
        await self.service.set_lookup_key(GUILD, "abcdef-123456", actor_id=STAFF, actor_name="staff")
        stored = await self.db.lookup_key(GUILD)
        self.assertTrue(crypto.is_sealed(stored))
        self.assertNotIn("abcdef-123456", self.database_dump())
        self.assertEqual(await self.service.lookup_key(GUILD), "abcdef-123456")

    async def test_each_server_has_its_own_seal(self):
        stored = self.keys.seal("lookup_keys.lookup_key", "1", "abc")
        with self.assertRaises(ValueError):
            self.keys.unseal("lookup_keys.lookup_key", "2", stored)

    async def test_no_key_reads_as_none_and_removing_one_works(self):
        self.assertIsNone(await self.service.lookup_key(GUILD))
        await self.service.set_lookup_key(GUILD, "abc", actor_id=STAFF, actor_name="staff")
        await self.service.set_lookup_key(GUILD, None, actor_id=STAFF, actor_name="staff")
        self.assertIsNone(await self.service.lookup_key(GUILD))

    async def test_a_key_saved_before_sealing_reads_as_it_is(self):
        await self.db.set_lookup_key(GUILD, "plain-key")
        self.assertEqual(await self.service.lookup_key(GUILD), "plain-key")

    async def test_a_key_that_cant_be_opened_reads_as_no_key_and_doesnt_stop_anyone(self):
        await self.db.set_lookup_key(GUILD, self.keys.seal("something else", GUILD, "abc"))
        with self.assertLogs("altwarden", "WARNING"):
            self.assertIsNone(await self.service.lookup_key(GUILD))

    async def test_a_webhook_is_sealed_and_reads_back(self):
        hook = await self.service.add_webhook(GUILD, "https://example.org/hook", "the-secret", ["member.failed"])
        self.assertNotIn("example.org", self.database_dump())
        self.assertNotIn("the-secret", self.database_dump())
        row = (await self.service.webhooks(GUILD))[0]
        self.assertEqual((row["id"], row["url"], row["secret"], row["events"]), (hook, "https://example.org/hook", "the-secret", '["member.failed"]'))

    async def test_a_webhook_saved_before_sealing_reads_as_it_is(self):
        await self.db.insert("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, ?, ?, '[]', 1)", (GUILD, "https://a.example", "s"))
        row = (await self.service.webhooks(GUILD))[0]
        self.assertEqual((row["url"], row["secret"]), ("https://a.example", "s"))

    async def test_a_webhook_that_cant_be_opened_is_left_out(self):
        await self.db.insert("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, ?, ?, '[]', 1)", (GUILD, self.keys.seal("x", GUILD, "u"), "s"))
        with self.assertLogs("altwarden", "WARNING"):
            self.assertEqual(await self.service.webhooks(GUILD), [])

    async def test_only_this_servers_webhooks_come_back(self):
        await self.db.insert("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, ?, ?, '[]', 1)", (GUILD, "https://a.example", "s"))
        self.assertEqual(await self.service.webhooks("970000000000000999"), [])

    async def test_startup_seals_whatever_is_plain_and_can_run_again(self):
        await self.db.set_lookup_key(GUILD, "plain-key")
        await self.db.insert("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, ?, ?, '[]', 1)", (GUILD, "https://a.example", "plain-secret"))
        self.assertEqual(await self.service.seal_stored_secrets(), 3)
        dump = self.database_dump()
        self.assertNotIn("plain-key", dump)
        self.assertNotIn("plain-secret", dump)
        self.assertNotIn("a.example", dump)
        self.assertEqual(await self.service.lookup_key(GUILD), "plain-key")
        row = (await self.service.webhooks(GUILD))[0]
        self.assertEqual((row["url"], row["secret"]), ("https://a.example", "plain-secret"))
        sealed = await self.db.lookup_key(GUILD)
        self.assertEqual(await self.service.seal_stored_secrets(), 0)
        self.assertEqual(await self.db.lookup_key(GUILD), sealed)

    async def test_startup_clears_the_plain_values_from_the_log(self):
        await self.db.set_lookup_key(GUILD, "plain-key")
        calls = []
        real = self.db.checkpoint

        async def spy():
            calls.append(True)
            return await real()
        with patch.object(self.db, "checkpoint", spy):
            await self.service.seal_stored_secrets()
        self.assertEqual(calls, [True])
        with patch.object(self.db, "checkpoint", spy):
            await self.service.seal_stored_secrets()
        self.assertEqual(calls, [True], "nothing to seal, so nothing to clear")


class DeletingData(Prepared):
    async def member_with_records(self, user=OLD_USER):
        await self.db.touch_member(GUILD, user)
        await self.db.add_attempt(GUILD, user, "failed", check_id="vpn", action="deny")

    async def test_an_override_naming_the_member_goes_from_the_settings_and_the_audit_log(self):
        rule = {"required": [], "overrides": [{"type": "user", "id": OLD_USER, "allow": True}, {"type": "role", "id": VERIFIED_ROLE, "allow": True}]}
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "permissions": {"pages": {"members": {"view": rule}}, "commands": {"lookup": rule}}},
                                         section="access", actor_id=STAFF, actor_name="staff")
        self.assertTrue(await self.service.my_data(OLD_USER))
        await self.service.delete_my_data(OLD_USER)
        stored = (await self.db.guild(GUILD))["settings"]["permissions"]
        for held in (stored["pages"]["members"]["view"], stored["commands"]["lookup"]):
            self.assertEqual(held["overrides"], [{"type": "role", "id": VERIFIED_ROLE, "allow": True}])
        self.assertNotIn(OLD_USER, self.database_dump())
        self.assertEqual(await self.service.my_data(OLD_USER), [])

    async def test_a_message_author_with_no_other_record_is_found_and_removed(self):
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "messages": {**doc["messages"], "verification": {**doc["messages"]["verification"], "author": OTHER_USER}}}, section="look")
        self.assertEqual(len(await self.service.my_data(OTHER_USER)), 1)
        await self.service.delete_my_data(OTHER_USER)
        self.assertNotIn(OTHER_USER, self.database_dump())
        self.assertEqual(await self.service.my_data(OTHER_USER), [])

    async def test_removing_it_writes_no_new_copy_to_the_audit_log_or_a_channel(self):
        rule = {"required": [], "overrides": [{"type": "user", "id": OLD_USER, "allow": True}]}
        await self.service.edit_settings(GUILD, lambda doc: {**doc, "permissions": {"pages": {"members": {"view": rule}}, "commands": {}}}, section="access")
        self.port.sent.clear()
        await self.service.delete_my_data(OLD_USER)
        self.assertNotIn(OLD_USER, self.log_text())
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM audit WHERE kind = 'settings' AND detail LIKE ?", (f"%{OLD_USER}%",)), 0)

    async def test_a_ban_only_discord_knows_about_keeps_the_hashes(self):
        await self.member_with_records()
        await self.db.store_identifier(GUILD, OLD_USER, "ip", "digest", time.time() + 1000)
        self.port.banned.add(OLD_USER)
        result = await self.service.delete_my_data(OLD_USER)
        self.assertEqual(result["kept_for_ban"], [GUILD])
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,)), 1)
        self.assertTrue(await self.db.is_banned(GUILD, OLD_USER), "the ban is on record now, so the purge keeps the hashes too")

    async def test_discord_not_answering_goes_by_the_record(self):
        await self.member_with_records()
        await self.db.store_identifier(GUILD, OLD_USER, "ip", "digest", time.time() + 1000)
        self.port.discord_down = True
        result = await self.service.delete_my_data(OLD_USER)
        self.assertEqual(result["removed"], [GUILD])

    async def test_a_delete_for_one_server_keeps_the_person_signed_in(self):
        await self.member_with_records()
        await self.db.run("INSERT INTO web_sessions (token_hash, user_id, username, csrf, created_at, expires_at) VALUES ('t', ?, 'n', 'c', 1, 9e12)", (OLD_USER,))
        await self.db.run("INSERT INTO command_syncs (state_hash, guild_id, user_id, changes, expires_at) VALUES ('a', ?, ?, '[]', 9e12)", (GUILD, OLD_USER))
        await self.db.run("INSERT INTO command_syncs (state_hash, guild_id, user_id, changes, expires_at) VALUES ('b', '970000000000000999', ?, '[]', 9e12)", (OLD_USER,))
        await self.service.delete_my_data(OLD_USER, GUILD)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM web_sessions WHERE user_id = ?", (OLD_USER,)), 1)
        self.assertEqual([row["state_hash"] for row in await self.db.all("SELECT state_hash FROM command_syncs")], ["b"])

    async def test_a_delete_of_everything_signs_them_out(self):
        await self.member_with_records()
        await self.db.run("INSERT INTO web_sessions (token_hash, user_id, username, csrf, created_at, expires_at) VALUES ('t', ?, 'n', 'c', 1, 9e12)", (OLD_USER,))
        await self.db.run("INSERT INTO command_syncs (state_hash, guild_id, user_id, changes, expires_at) VALUES ('b', '970000000000000999', ?, '[]', 9e12)", (OLD_USER,))
        await self.service.delete_my_data(OLD_USER)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM web_sessions WHERE user_id = ?", (OLD_USER,)), 0)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM command_syncs"), 0)

    async def test_a_deletion_clears_the_log_file_too(self):
        await self.member_with_records()
        calls = []
        real = self.db.checkpoint

        async def spy():
            calls.append(True)
            return await real()
        with patch.object(self.db, "checkpoint", spy):
            await self.service.delete_my_data(OLD_USER)
        self.assertEqual(calls, [True])

    async def test_staff_hear_about_a_deletion_once_with_no_name(self):
        await self.member_with_records()
        await self.service.delete_my_data(OLD_USER)
        rows = [notice for notice in self.posts() if "A member deleted their records" in json.dumps(notice.embeds)]
        self.assertEqual(len(rows), 1)
        self.assertNotIn(OLD_USER, json.dumps(rows[0].embeds))
        audit = await self.db.all("SELECT * FROM audit WHERE kind = 'data_deleted'")
        self.assertEqual(len(audit), 1)
        self.assertIsNone(audit[0]["actor_id"])
        self.assertNotIn(OLD_USER, audit[0]["detail"])

    async def test_the_notice_says_the_role_went_and_how_many_actions_lost_their_name(self):
        await self.member_with_records()
        await self.db.add_audit(GUILD, "manual_verify", actor_id=OLD_USER, actor_name="x", detail={"user": "1"})
        await self.db.add_audit(GUILD, "reset", actor_id=OLD_USER, actor_name="x", detail={"user": "2"})
        await self.service.delete_my_data(OLD_USER)
        self.assertIn("Their verified role was removed.", self.log_text())
        self.assertIn("2 staff actions lost their name.", self.log_text())
        self.assertEqual(json.loads((await self.db.one("SELECT detail FROM audit WHERE kind = 'data_deleted'"))["detail"])["staff_actions"], 2)

    async def test_a_role_that_couldnt_be_taken_is_reported_and_not_claimed(self):
        await self.member_with_records()
        self.port.role_refusals[VERIFIED_ROLE] = ROLE_TOO_LOW
        await self.service.delete_my_data(OLD_USER)
        self.assertIn(ROLE_TOO_LOW, self.log_text())
        self.assertIn("a member who deleted their records", self.log_text())
        self.assertNotIn(OLD_USER, self.log_text().replace("<@" + STAFF, ""))
        self.assertNotIn("Their verified role was removed.", self.log_text())

    async def test_someone_with_no_record_here_causes_no_notice(self):
        await self.service.delete_my_data(OTHER_USER)
        self.assertEqual(self.posts(), [])

    async def test_each_server_hears_about_it_separately(self):
        await self.member_with_records()
        await self.db.save_settings("970000000000000888", settings.normalize(self.doc), setup_done=True)
        await self.db.add_attempt("970000000000000888", OLD_USER, "failed", check_id="vpn")
        await self.service.delete_my_data(OLD_USER)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM audit WHERE kind = 'data_deleted'"), 2)

    async def test_a_deleted_moderator_keeps_one_stable_pseudonym_per_server(self):
        await self.db.add_audit(GUILD, "manual_verify", actor_id=STAFF, actor_name="mod", detail={"user": "1"})
        await self.db.add_audit(GUILD, "reset", actor_id=STAFF, actor_name="mod", detail={"user": "2"})
        await self.db.add_audit("970000000000000888", "reset", actor_id=STAFF, actor_name="mod", detail={"user": "3"})
        await self.db.add_audit(GUILD, "reset", actor_id=OTHER_USER, actor_name="other", detail={"user": "4"})
        await self.service.delete_my_data(STAFF)
        names = [row["actor_name"] for row in await self.db.all("SELECT actor_name FROM audit WHERE actor_id IS NULL AND kind != 'data_deleted' AND guild_id = ?", (GUILD,))]
        self.assertEqual(len(names), 2)
        self.assertEqual(names[0], names[1])
        self.assertRegex(names[0], r"^Deleted account [0-9a-f]{8}$")
        other_server = (await self.db.one("SELECT actor_name FROM audit WHERE guild_id = '970000000000000888'"))["actor_name"]
        self.assertNotEqual(other_server, names[0])
        await self.service.delete_my_data(OTHER_USER)
        second = (await self.db.one("SELECT actor_name FROM audit WHERE guild_id = ? AND detail LIKE ?", (GUILD, '%"4"%')))["actor_name"]
        self.assertNotEqual(second, names[0])
        self.assertNotIn(STAFF, self.database_dump())


class MyData(Prepared):
    async def test_every_member_field_comes_back(self):
        await self.db.touch_member(GUILD, OLD_USER, username="someone", avatar="pic")
        await self.db.update_member(GUILD, OLD_USER, joined_at=5.0, kick_at=6.0, fails=2, last_fail_at=7.0, limit_reached_at=8.0, help_thread_id="9", first_verified_at=10.0)
        record = (await self.service.my_data(OLD_USER))[0]
        self.assertEqual({key: record[key] for key in ("username", "avatar", "joined_at", "kick_at", "fails", "last_fail_at", "limit_reached_at", "help_thread_id", "first_verified_at")},
                         {"username": "someone", "avatar": "pic", "joined_at": 5.0, "kick_at": 6.0, "fails": 2, "last_fail_at": 7.0, "limit_reached_at": 8.0, "help_thread_id": "9", "first_verified_at": 10.0})

    async def test_the_true_attempt_count_comes_back_past_the_list_limit(self):
        await self.db.touch_member(GUILD, OLD_USER)
        for _ in range(205):
            await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn")
        record = (await self.service.my_data(OLD_USER))[0]
        self.assertEqual((record["attempt_count"], len(record["attempts"])), (205, 200))

    async def test_attempts_carry_their_labels_without_the_other_account(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="alt_account", seconds=12.0, detail={"findings": [
            {"check": "alt_account", "action": "deny", "detail": {"account": OTHER_USER, "confidence": "likely", "methods": ["ip"]}}], "bypassed": []})
        attempt = (await self.service.my_data(OLD_USER))[0]["attempts"][0]
        self.assertEqual(attempt["seconds"], 12.0)
        self.assertEqual(attempt["detail"], {"findings": [{"check": "alt_account", "action": "deny", "detail": {"confidence": "likely", "methods": ["ip"]}}], "bypassed": []})
        self.assertNotIn(OTHER_USER, json.dumps(attempt))

    async def test_a_staff_verification_doesnt_name_the_staff_member(self):
        await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff")
        attempt = (await self.service.my_data(OLD_USER))[0]["attempts"][0]
        self.assertEqual(attempt["outcome"], "manual")
        self.assertNotIn(STAFF, json.dumps(attempt))

    async def test_trusted_pairs_audit_rows_and_the_ban_date_come_back(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.trust_pair(GUILD, OLD_USER, OTHER_USER, STAFF)
        await self.db.add_audit(GUILD, "manual_verify", actor_id=STAFF, actor_name="s", detail={"user": OLD_USER})
        await self.db.record_ban(GUILD, OLD_USER)
        record = (await self.service.my_data(OLD_USER))[0]
        self.assertEqual((record["trusted_pairs"], record["audit_about"]), (1, 1))
        self.assertAlmostEqual(record["banned_at"], time.time(), delta=30)
        self.assertTrue(record["banned"])
        self.assertNotIn(OTHER_USER, json.dumps(record))

    async def test_a_live_link_is_counted_and_never_shown(self):
        await self.db.touch_member(GUILD, OLD_USER)
        url, _ = await self.service.new_link(GUILD, OLD_USER, await self.service.get_settings(GUILD))
        record = (await self.service.my_data(OLD_USER))[0]
        self.assertEqual(record["live_links"], 1)
        self.assertNotIn(url.rsplit("/", 1)[1], json.dumps(record))


class SmallThings(Prepared):
    async def test_a_verified_member_with_no_role_gets_it_by_pressing_verify(self):
        for mode in ("web", "button"):
            await self.edit(lambda doc, mode=mode: doc["core"].update(mode=mode))
            user = OTHER_USER if mode == "web" else THIRD_USER
            member = self.port.add_member(user)
            await self.db.touch_member(GUILD, user)
            await self.db.mark_verified(GUILD, user, service_module.IMPORTED_WITHOUT_ROLE)
            result = await self.service.press_verify(member)
            self.assertEqual(result.status, "already", mode)
            self.assertIn(("add_role", user, VERIFIED_ROLE), self.port.calls)
            self.assertEqual(self.port.dms, [])

    async def test_a_verified_member_whose_role_cant_be_given_hears_why(self):
        member = self.port.add_member(OTHER_USER)
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.mark_verified(GUILD, OTHER_USER, service_module.IMPORTED_WITHOUT_ROLE)
        self.port.role_problem = ROLE_TOO_LOW
        result = await self.service.press_verify(member)
        self.assertEqual((result.status, result.reason), ("problem", "role_problem"))
        self.assertIn("Staff have been told", result.message)
        self.assertIn(ROLE_TOO_LOW, self.log_text())

    async def test_a_pending_member_still_gets_a_link(self):
        self.assertIsInstance(await self.service.press_verify(self.port.add_member(OTHER_USER)), str)

    async def test_an_import_clears_what_a_failed_try_left_behind(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.update_member(GUILD, OTHER_USER, fails=3, last_fail_at=5.0, limit_reached_at=6.0)
        await self.service.import_members(GUILD, [OTHER_USER], STAFF, "staff")
        record = await self.db.member(GUILD, OTHER_USER)
        self.assertEqual((record["fails"], record["last_fail_at"], record["limit_reached_at"]), (0, None, None))

    def test_a_duration_of_one_reads_right(self):
        self.assertEqual(notices._duration(1), "1 minute")
        self.assertEqual(notices._duration(2), "2 minutes")
        self.assertEqual(notices._duration(60), "1 hour")
        self.assertEqual(notices._duration(1440), "1 day")

    def test_no_notice_prints_a_channel_that_isnt_set(self):
        for notice in (notices.go_to_channel_notice("S", None), notices.reset_notice("S", None, None)):
            self.assertNotIn("<#None>", json.dumps(notice.embeds))
            self.assertIn("verification channel", json.dumps(notice.embeds))
        self.assertIn("<#123>", json.dumps(notices.go_to_channel_notice("S", "123").embeds))
        self.assertIn("<#123>", json.dumps(notices.reset_notice("S", None, "123").embeds))

    async def test_a_bypass_notice_never_prints_a_channel_that_isnt_set(self):
        await self.edit(lambda doc: doc["core"].update(channel=None))
        await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 1, "channel", STAFF, "staff", LOG_CHANNEL)
        self.assertNotIn("<#None>", self.posts(LOG_CHANNEL)[-2].content + self.posts(LOG_CHANNEL)[-1].content)

    def test_a_failure_dm_has_no_try_again_link(self):
        notice = notices.failed_notice("S", "vpn", "text", "deny", "https://x.test", "https://x.test/appeal", True)
        self.assertEqual([button.label for button in notice.buttons], ["What to do", "Appeal"])


class BansAndLinks(Prepared):
    async def verified_earlier_account(self, user=OTHER_USER):
        await self.submit_directly(await self.signed_in(user))

    def count_ban_lookups(self):
        asked = []
        real = self.port.is_banned

        async def spy(guild_id, user_id):
            asked.append(user_id)
            return await real(guild_id, user_id)
        self.port.is_banned = spy
        return asked

    async def test_a_ban_lifted_while_the_bot_was_away_isnt_held_against_a_new_account(self):
        await self.turn_on_alts()
        await self.verified_earlier_account()
        await self.db.record_ban(GUILD, OTHER_USER)
        result = await self.submit_directly(await self.signed_in(THIRD_USER))
        self.assertEqual(result.action, "kick", "the alt action, because the earlier account isn't banned any more")
        self.assertFalse(await self.db.is_banned(GUILD, OTHER_USER))
        self.assertEqual(self.port.did("ban"), [])

    async def test_a_ban_discord_still_has_stays_a_ban(self):
        await self.turn_on_alts()
        await self.verified_earlier_account()
        await self.db.record_ban(GUILD, OTHER_USER)
        self.port.banned.add(OTHER_USER)
        result = await self.submit_directly(await self.signed_in(THIRD_USER))
        self.assertEqual(result.action, "ban")
        self.assertTrue(await self.db.is_banned(GUILD, OTHER_USER))

    async def test_discord_not_answering_keeps_the_ban(self):
        await self.turn_on_alts()
        await self.verified_earlier_account()
        await self.db.record_ban(GUILD, OTHER_USER)

        async def down(*args):
            raise DiscordUnavailable("down")
        self.port.is_banned = down
        result = await self.submit_directly(await self.signed_in(THIRD_USER))
        self.assertEqual(result.action, "ban")
        self.assertTrue(await self.db.is_banned(GUILD, OTHER_USER))

    async def test_a_link_too_weak_to_count_even_for_a_banned_account_costs_no_call_to_discord(self):
        await self.turn_on_alts(min_confidence="confirmed")
        await self.verified_earlier_account()
        asked = self.count_ban_lookups()
        # The same machine on a reserved address scores 30, which is under the 60 a link to a banned account counts from.
        await self.submit_directly(await self.signed_in(THIRD_USER), device="device-2", report=clean_report(fp={"id": "e" * 32, "confidence": 0.9}))
        self.assertEqual(asked, [])

    async def test_a_link_that_would_count_if_the_account_is_banned_is_asked_about(self):
        await self.turn_on_alts(min_confidence="confirmed")
        await self.verified_earlier_account()
        asked = self.count_ban_lookups()
        await self.submit_directly(await self.signed_in(THIRD_USER), device="device-2")
        self.assertEqual(asked, [OTHER_USER])

    async def test_a_link_at_the_floor_is_asked_about(self):
        await self.turn_on_alts()
        await self.verified_earlier_account()
        asked = self.count_ban_lookups()
        await self.submit_directly(await self.signed_in(THIRD_USER))
        self.assertEqual(asked, [OTHER_USER])

    async def test_with_the_alt_check_off_nothing_is_looked_up(self):
        await self.verified_earlier_account()
        await self.change(alt_account={"enabled": False})
        asked = self.count_ban_lookups()
        with patch("altwarden.altmatch.find_links", side_effect=AssertionError("no reason to look")):
            await self.submit_directly(await self.signed_in(THIRD_USER))
        self.assertEqual(asked, [])

    async def test_a_member_bypassing_the_alt_check_costs_no_lookup_but_still_queues(self):
        await self.turn_on_alts()
        await self.verified_earlier_account()
        token = await self.signed_in(THIRD_USER)
        await self.db.run("UPDATE sessions SET bypass = '[\"alt_account\"]' WHERE token_hash = ?", (crypto.token_hash(token),))
        seen = []
        real = self.service._evidence_held

        def spying(guild_id, digests):
            seen.append(sorted(digests))
            return real(guild_id, digests)
        asked = self.count_ban_lookups()
        with patch.object(self.service, "_evidence_held", spying):
            result = await self.submit_directly(token)
        self.assertEqual(result.status, "verified")
        self.assertEqual(asked, [])
        self.assertIn("cookie", seen[0])


class TalkingToStaff(Prepared):
    async def desk(self):
        await self.edit(lambda doc: doc["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, redirect=True))

    async def test_the_button_is_offered_to_someone_denied(self):
        await self.desk()
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.assertTrue((await self.verify_through(ip="45.33.32.7"))["staff_help"])

    async def test_it_isnt_offered_after_a_kick_or_a_ban(self):
        await self.desk()
        for action in ("kick", "ban"):
            await self.change(vpn={"enabled": True, "action": action})
            self.assertFalse((await self.verify_through(ip="45.33.32.7"))["staff_help"], action)

    async def test_it_is_offered_when_the_kick_failed_and_they_are_still_here(self):
        await self.desk()
        self.port.kick_works = False
        await self.change(vpn={"enabled": True, "action": "kick"})
        self.assertTrue((await self.verify_through(ip="45.33.32.7"))["staff_help"])

    async def test_it_isnt_offered_with_the_redirect_off(self):
        await self.edit(lambda doc: doc["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, redirect=False))
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.assertFalse((await self.verify_through(ip="45.33.32.7"))["staff_help"])


if __name__ == "__main__":
    unittest.main()
