"""Data and rules: how evidence scores, what presets set, what the database keeps and what imports carry."""
import asyncio
import base64
import copy
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import access, altmatch, analytics, catalog, crypto, db as db_module, engine, notices, settings, signals
from altwarden.netintel import NetInfo
from fakes import DB_KEY, GUILD, OLD_USER, OTHER_USER
from test_detection import clean_report
from test_flow import Base as FlowBase

OLD_ACCOUNT = "175928847299117063"
FAR = time.time() + 86400


def attempt(document, *, links=(), net=None, account=None):
    return engine.Attempt(document, engine.WEB, account or engine.Account(OLD_ACCOUNT, avatar="a", mfa=True, email_verified=True, email_disposable=False),
                          net=net, links=list(links))


def alt_rules(**options):
    document = settings.defaults()
    document["checks"]["alt_account"].update(enabled=True, alt_action="kick", main_action="watch", banned_alt_action="ban", min_confidence="likely")
    document["checks"]["alt_account"].update(options)
    return document


class DatabaseCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.db = db_module.Database(Path(self.folder.name) / "t.db", DB_KEY)
        await self.db.open()

    async def asyncTearDown(self):
        await self.db.close()
        self.folder.cleanup()

    async def seed(self, user, *, verified=True, **digests):
        await self.db.touch_member("1", user)
        if verified:
            await self.db.mark_verified("1", user, "web")
        for kind, digest in digests.items():
            await self.db.store_identifier("1", user, kind, digest, FAR)

    async def links(self, digests, *, weak_fingerprint=False, weak_ip=False, methods=None, user="99"):
        return await altmatch.find_links(self.db, "1", user, digests, methods=methods or {"cookie": True, "fingerprint": True, "ip": True},
                                         weak_fingerprint=weak_fingerprint, weak_ip=weak_ip)


class EvidenceScore(DatabaseCase):
    async def test_no_evidence_without_the_cookie_reaches_confirmed(self):
        await self.seed("10", fingerprint="f", ip="i", device="d")
        link = (await self.links({"fingerprint": "f", "ip": "i", "device": "d"}))[0]
        self.assertEqual((link.score, link.confidence), (99, "likely"))

    async def test_the_cookie_alone_is_confirmed(self):
        await self.seed("10", cookie="c")
        self.assertEqual((await self.links({"cookie": "c"}))[0].confidence, "confirmed")

    async def test_a_second_browser_on_one_pc_and_connection_is_likely(self):
        await self.seed("10", ip="i", device="d")
        link = (await self.links({"ip": "i", "device": "d"}))[0]
        self.assertEqual((link.score, link.confidence), (99, "likely"))

    async def test_one_kind_of_machine_from_another_address_stays_weak(self):
        await self.seed("10", ip="other", device="d")
        self.assertEqual(await self.links({"ip": "i", "device": "d"}), [])

    async def test_the_pair_bonus_skips_a_weak_address_and_a_weak_fingerprint(self):
        await self.seed("10", ip="i", device="d")
        self.assertEqual((await self.links({"ip": "i", "device": "d"}, weak_ip=True))[0].score, 30)
        self.assertEqual((await self.links({"ip": "i", "device": "d"}, weak_fingerprint=True))[0].score, 90)

class AltJudgment(unittest.TestCase):
    def link(self, other, score, confidence, methods, **options):
        options.setdefault("verified", True)
        return altmatch.Link(other, score, confidence, methods, **options)

    def test_every_link_at_the_floor_is_judged_so_the_middle_account_is_stopped(self):
        as_alt = self.link("1", 100, "confirmed", ["cookie"], other_is_main=True)
        as_main = self.link("3", 120, "confirmed", ["cookie", "ip"], other_is_main=False)
        decision = engine.run_checks(attempt(alt_rules(), links=[as_main, as_alt]))
        self.assertEqual((decision.action, decision.alt_link.other_id), ("kick", "1"))

    def test_a_softer_banned_action_cant_shadow_a_harder_one(self):
        banned = self.link("1", 100, "confirmed", ["cookie"], banned=True)
        good = self.link("2", 100, "confirmed", ["cookie"])
        decision = engine.run_checks(attempt(alt_rules(banned_alt_action="deny"), links=[banned, good]))
        self.assertEqual((decision.action, decision.alt_link.other_id), ("kick", "2"))

    def test_a_tie_goes_to_the_banned_account_then_the_score(self):
        plain = self.link("1", 130, "confirmed", ["cookie"])
        banned = self.link("2", 100, "confirmed", ["cookie"], banned=True)
        stronger = self.link("3", 100, "confirmed", ["cookie"])
        decision = engine.run_checks(attempt(alt_rules(banned_alt_action="kick"), links=[stronger, plain, banned]))
        self.assertEqual(decision.alt_link.other_id, "2")
        decision = engine.run_checks(attempt(alt_rules(), links=[stronger, plain]))
        self.assertEqual(decision.alt_link.other_id, "1")

    def test_a_link_below_confirmed_gets_the_chosen_actions(self):
        likely = self.link("1", 80, "likely", ["fingerprint", "ip"])
        decision = engine.run_checks(attempt(alt_rules(alt_action="kick", main_action="ban"), links=[likely]))
        self.assertEqual((decision.action, decision.main_action), ("kick", "ban"))

    def test_a_banned_account_below_confirmed_gets_the_banned_action(self):
        likely = self.link("1", 80, "likely", ["fingerprint", "ip"], banned=True)
        decision = engine.run_checks(attempt(alt_rules(banned_alt_action="ban"), links=[likely]))
        self.assertEqual(decision.action, "ban")

    def test_the_earlier_account_verifying_gets_the_main_action(self):
        likely = self.link("1", 80, "likely", ["fingerprint", "ip"], other_is_main=False)
        decision = engine.run_checks(attempt(alt_rules(main_action="kick"), links=[likely]))
        self.assertEqual(decision.action, "kick")

    def test_a_confirmed_link_keeps_every_action_and_no_note(self):
        confirmed = self.link("1", 100, "confirmed", ["cookie"])
        decision = engine.run_checks(attempt(alt_rules(main_action="ban"), links=[confirmed]))
        self.assertEqual((decision.action, decision.main_action), ("kick", "ban"))
        self.assertNotIn("capped", decision.primary.detail)

    def test_watch_stays_watch_with_no_note(self):
        likely = self.link("1", 80, "likely", ["fingerprint", "ip"])
        decision = engine.run_checks(attempt(alt_rules(alt_action="watch"), links=[likely]))
        self.assertTrue(decision.passed)
        self.assertNotIn("capped", decision.findings[0].detail)

    def test_the_log_names_the_strength_of_the_match(self):
        likely = self.link("1", 80, "likely", ["fingerprint", "ip"])
        finding = engine.run_checks(attempt(alt_rules(), links=[likely])).primary
        self.assertEqual(notices._detail_text(finding), "Likely match, score 80")

    def test_a_link_under_the_floor_is_watched_and_recorded(self):
        possible = self.link("1", 55, "possible", ["ip", "device"])
        decision = engine.run_checks(attempt(alt_rules(), links=[possible]))
        self.assertTrue(decision.passed)
        self.assertEqual(decision.alt_link.other_id, "1")
        self.assertEqual(decision.main_action, "watch")
        self.assertEqual([(finding.check_id, finding.action) for finding in decision.findings], [("alt_account", "watch")])

    def test_a_link_under_the_floor_to_a_banned_account_is_watched_too(self):
        possible = self.link("1", 35, "possible", ["ip"], banned=True, verified=False)
        decision = engine.run_checks(attempt(alt_rules(), links=[possible]))
        self.assertTrue(decision.passed)
        self.assertEqual(decision.findings[0].action, "watch")

    def test_someone_who_never_got_in_leaves_no_finding(self):
        possible = self.link("1", 55, "possible", ["ip", "device"], verified=False)
        decision = engine.run_checks(attempt(alt_rules(), links=[possible]))
        self.assertEqual((decision.findings, decision.alt_link), ([], None))

    def test_a_link_at_the_floor_outranks_a_stronger_watch_under_it(self):
        strong = self.link("1", 100, "confirmed", ["cookie"], other_is_main=True)
        decision = engine.run_checks(attempt(alt_rules(min_confidence="confirmed"), links=[
            self.link("2", 99, "likely", ["fingerprint", "ip", "device"]), strong]))
        self.assertEqual((decision.action, decision.alt_link.other_id), ("kick", "1"))

    def test_a_bypassed_alt_check_records_nothing(self):
        possible = self.link("1", 55, "possible", ["ip", "device"])
        run = attempt(alt_rules(), links=[possible])
        run.bypass = frozenset({"alt_account"})
        self.assertEqual(engine.run_checks(run).findings, [])


PRESET_TABLE = {
    #                  gentle                    standard                 strict
    "account_age":      ((False, "deny", {"days": 7}), (True, "deny", {"days": 7}), (True, "kick", {"days": 30})),
    "avatar":           ((False, "deny", {}), (False, "deny", {}), (True, "kick", {})),
    "disposable_email": ((True, "deny", {}), (True, "deny", {}), (True, "kick", {})),
    "alt_account":      ((True, "deny", {"alt_action": "deny", "main_action": "watch", "banned_alt_action": "deny", "min_confidence": "possible"}),
                         (True, "kick", {"alt_action": "kick", "main_action": "watch", "banned_alt_action": "ban", "min_confidence": "possible"}),
                         (True, "ban", {"alt_action": "ban", "main_action": "kick", "banned_alt_action": "ban", "min_confidence": "possible"})),
    "max_attempts":     ((False, "deny", {"attempts": 5, "reset_minutes": 1440}), (True, "deny", {"attempts": 5, "reset_minutes": 1440}),
                         (True, "kick", {"attempts": 3, "reset_minutes": 0})),
    "vpn":              ((False, "deny", {}), (True, "deny", {}), (True, "kick", {})),
    "mobile_data":      ((False, "deny", {}), (False, "deny", {}), (True, "deny", {})),
    "automation":       ((False, "deny", {}), (True, "deny", {}), (True, "kick", {})),
    "antidetect":       ((False, "deny", {}), (True, "deny", {}), (True, "kick", {})),
    "tampering":        ((False, "deny", {"anomaly_score": 50}), (True, "deny", {"anomaly_score": 50}), (True, "kick", {"anomaly_score": 40})),
    "fake_ua":          ((True, "deny", {}), (True, "kick", {}), (True, "kick", {})),
    "devtools":         ((False, "deny", {}), (True, "deny", {}), (True, "deny", {})),
    "incognito":        ((False, "deny", {}), (True, "deny", {}), (True, "kick", {})),
    "privacy":          ((False, "deny", {}), (True, "deny", {}), (True, "deny", {})),
    "threat":           ((False, "deny", {"bot_score": 80, "suspect_score": 70}), (True, "deny", {"bot_score": 80, "suspect_score": 70}),
                         (True, "kick", {"bot_score": 70, "suspect_score": 50})),
    "vm":               ((False, "deny", {}), (True, "deny", {}), (True, "kick", {})),
    "rooted":           ((False, "deny", {}), (True, "deny", {}), (True, "kick", {})),
}
PRESET_NAMES = ("gentle", "standard", "strict")


class Presets(unittest.TestCase):
    def changed(self, **core):
        document = settings.defaults()
        document["core"].update(core)
        return document

    def test_each_preset_matches_the_table_row_by_row(self):
        for index, name in enumerate(PRESET_NAMES):
            document = settings.apply_preset(settings.defaults(), name)
            for check_id, row in PRESET_TABLE.items():
                enabled, action, extras = row[index]
                check = document["checks"][check_id]
                self.assertEqual((check["enabled"], check["action"]), (enabled, action), (name, check_id))
                for key, value in extras.items():
                    self.assertEqual(check[key], value, (name, check_id, key))

    def test_the_table_covers_every_check_but_two_factor_and_countries(self):
        self.assertEqual(set(PRESET_TABLE) | {"mfa", "geogate"}, set(catalog.CHECK_IDS))
        for name in PRESET_NAMES:
            self.assertEqual(set(catalog.PRESETS[name]["checks"]), set(PRESET_TABLE), name)

    def test_the_result_never_depends_on_the_preset_before_it(self):
        for first in PRESET_NAMES:
            for second in PRESET_NAMES:
                direct = settings.apply_preset(settings.defaults(), second)
                after = settings.apply_preset(settings.apply_preset(settings.defaults(), first), second)
                if second != "strict":  # Gentle and Standard leave Auto Kick's minutes alone, by design
                    after["core"]["auto_kick"]["minutes"] = direct["core"]["auto_kick"]["minutes"]
                self.assertEqual(after, direct, (first, second))

    def test_switching_on_any_check_left_off_starts_at_deny(self):
        for name in PRESET_NAMES:
            document = settings.apply_preset(settings.defaults(), name)
            for check_id, check in document["checks"].items():
                if not check["enabled"]:
                    self.assertEqual(check["action"], "deny", (name, check_id))

    def test_every_preset_resets_auto_dm_and_the_closed_dm_notice(self):
        document = self.changed(auto_dm=False, notify_closed_dms={"enabled": False, "seconds": 200})
        for name in PRESET_NAMES:
            core = settings.apply_preset(document, name)["core"]
            self.assertIs(core["auto_dm"], True, name)
            self.assertEqual(core["notify_closed_dms"], {"enabled": True, "seconds": 30}, name)

    def test_strict_sets_auto_kick_to_ten_minutes(self):
        document = self.changed(auto_kick={"enabled": False, "minutes": 10080})
        self.assertEqual(settings.apply_preset(document, "strict")["core"]["auto_kick"], {"enabled": True, "minutes": 10})

    def test_gentle_and_standard_turn_auto_kick_off_and_keep_its_minutes(self):
        document = self.changed(auto_kick={"enabled": True, "minutes": 45})
        for name in ("gentle", "standard"):
            self.assertEqual(settings.apply_preset(document, name)["core"]["auto_kick"], {"enabled": False, "minutes": 45}, name)
            self.assertEqual(settings.detect_preset(settings.apply_preset(document, name)), name)

    def test_presets_keep_two_factor_country_rules_and_the_limit_role(self):
        document = settings.defaults()
        document["checks"]["mfa"].update(enabled=False, action="ban")
        document["checks"]["geogate"].update(enabled=True, action="kick", countries=["RU"])
        document["checks"]["max_attempts"]["role"] = "970000000000000111"
        for name in PRESET_NAMES:
            result = settings.apply_preset(document, name)["checks"]
            self.assertEqual(result["mfa"], document["checks"]["mfa"], name)
            self.assertEqual(result["geogate"], document["checks"]["geogate"], name)
            self.assertEqual(result["max_attempts"]["role"], "970000000000000111", name)

    def test_applying_a_preset_doesnt_share_its_table(self):
        document = settings.apply_preset(settings.defaults(), "standard")
        document["checks"]["alt_account"]["methods"]["ip"] = False
        document["core"]["notify_closed_dms"]["seconds"] = 99
        self.assertTrue(catalog.PRESETS["standard"]["checks"]["alt_account"][2]["methods"]["ip"])
        self.assertEqual(catalog.PRESETS["standard"]["core"]["notify_closed_dms"]["seconds"], 30)

    def test_detection_compares_rows_that_are_off(self):
        document = settings.apply_preset(settings.defaults(), "gentle")
        self.assertEqual(settings.detect_preset(document), "gentle")
        document["checks"]["vpn"]["action"] = "watch"
        self.assertEqual(settings.detect_preset(document), "custom")
        document = settings.apply_preset(settings.defaults(), "gentle")
        document["checks"]["threat"]["bot_score"] = 11
        self.assertEqual(settings.detect_preset(document), "custom")

    def test_detection_compares_every_core_setting_a_preset_sets(self):
        for change in ({"auto_dm": False}, {"notify_closed_dms": {"enabled": False, "seconds": 30}}, {"notify_closed_dms": {"enabled": True, "seconds": 60}}):
            self.assertEqual(settings.detect_preset(self.changed(**change)), "custom", change)
        strict = settings.apply_preset(settings.defaults(), "strict")
        strict["core"]["auto_kick"]["minutes"] = 11
        self.assertEqual(settings.detect_preset(strict), "custom")

    def test_detection_compares_the_evidence_switches(self):
        document = settings.defaults()
        document["checks"]["alt_account"]["methods"]["ip"] = False
        self.assertEqual(settings.detect_preset(document), "custom")

    def test_a_new_server_is_standard_and_survives_normalizing(self):
        self.assertEqual(settings.defaults()["preset"], "standard")
        self.assertEqual(settings.normalize(settings.defaults())["preset"], "standard")
        for name in PRESET_NAMES:
            self.assertEqual(settings.normalize(settings.apply_preset(settings.defaults(), name))["preset"], name)

    def test_the_blurbs_say_what_each_preset_does(self):
        self.assertEqual(catalog.PRESETS["gentle"]["blurb"], "Stops throwaway emails, fake browser identities and alt accounts. Everything else stays off. Two-factor login keeps its own setting.")
        self.assertEqual(catalog.PRESETS["standard"]["blurb"], "Stops anyone who fails a check. Kicks fake browser identities and alt accounts.")
        self.assertEqual(catalog.PRESETS["strict"]["blurb"], "For servers under attack. Kicks or bans on most failures, and removes anyone who doesn't verify within 10 minutes.")

    def test_no_preset_uses_watch_except_for_the_earlier_account(self):
        for name in PRESET_NAMES:
            for check_id, (_, action, extras) in catalog.PRESETS[name]["checks"].items():
                self.assertNotEqual(action, "watch", (name, check_id))
                self.assertNotIn("watch", {extras.get("alt_action"), extras.get("banned_alt_action")}, (name, check_id))

    def test_strict_is_never_softer_than_standard(self):
        strict, standard = catalog.PRESETS["strict"]["checks"], catalog.PRESETS["standard"]["checks"]
        for check_id in strict:
            self.assertGreaterEqual(strict[check_id][0], standard[check_id][0], check_id)
            self.assertGreaterEqual(catalog.SEVERITY[strict[check_id][1]], catalog.SEVERITY[standard[check_id][1]], check_id)


class EarlierAccountOptions(unittest.TestCase):
    def main_action(self, value):
        return settings.normalize({"checks": {"alt_account": {"main_action": value}}})["checks"]["alt_account"]["main_action"]

    def test_a_stored_deny_on_the_earlier_account_becomes_watch(self):
        self.assertEqual(self.main_action("deny"), "watch")

    def test_watch_kick_and_ban_stay(self):
        for action in ("watch", "kick", "ban"):
            self.assertEqual(self.main_action(action), action)

    def test_anything_else_falls_back_to_the_default(self):
        self.assertEqual(self.main_action("nonsense"), "watch")


class ResetMinutes(unittest.TestCase):
    def reset(self, value):
        return settings.normalize({"checks": {"max_attempts": {"reset_minutes": value}}})["checks"]["max_attempts"]["reset_minutes"]

    def test_zero_or_five_up_to_thirty_days(self):
        self.assertEqual([self.reset(value) for value in (0, 1, 4, 5, 6, 43200, 43201)], [0, 5, 5, 5, 6, 43200, 43200])


class FailOpen(unittest.TestCase):
    def test_a_new_server_doesnt_pass_people_when_the_check_cant_run(self):
        self.assertIs(settings.defaults()["core"]["fail_open"], False)
        self.assertIs(settings.normalize({})["core"]["fail_open"], False)

    def test_a_saved_server_keeps_what_it_stored(self):
        self.assertIs(settings.normalize({"core": {"fail_open": True}})["core"]["fail_open"], True)


class ConnectionCheckUnavailable(FlowBase):
    async def test_a_new_server_with_no_lists_asks_the_member_to_retry(self):
        self.net.lists = type(self.net.lists)()
        result = await self.verify_through()
        self.assertEqual((result["status"], result["reason"]), ("problem", "connection_check"))
        self.assertFalse(self.port.did("add_role"))


def code_holding(value) -> str:
    return "AW1." + base64.urlsafe_b64encode(zlib.compress(json.dumps(value).encode())).decode()


class SettingsCodes(unittest.TestCase):
    ROLE = "970000000000000111"

    def source(self):
        document = settings.apply_preset(settings.defaults(), "strict")
        document["appeals"]["enabled"] = False
        document["core"]["logs"]["enabled"] = True
        document["core"]["alerts"]["enabled"] = True
        document["core"]["help_desk"].update(enabled=True, require_attempt=False, redirect=True, auto_close=True, member_close=True)
        return document

    def target(self):
        document = settings.defaults()
        document["core"].update(verified_role=self.ROLE, channel=self.ROLE)
        document["core"]["logs"]["modules"] = {"general": self.ROLE}
        document["core"]["alerts"]["roles"] = {"general": self.ROLE}
        document["core"]["help_desk"]["support_role"] = self.ROLE
        document["appeals"].update(channel=self.ROLE, role=self.ROLE)
        return settings.normalize(document)

    def test_a_code_that_isnt_an_object_is_refused_as_damaged(self):
        for value in ([], ["checks"], "checks", 5, None):
            with self.assertRaises(ValueError, msg=value):
                settings.import_code(settings.defaults(), code_holding(value))

    def test_a_preset_name_of_the_wrong_type_is_refused(self):
        for value in ([], {}, 5, None):
            with self.assertRaises(ValueError, msg=value):
                settings.apply_preset(settings.defaults(), value)

    def test_what_an_export_carries_comes_back_from_an_import(self):
        source, target = self.source(), self.target()
        merged = settings.import_code(target, settings.export_code(source))
        for path in ("appeals", "core"):
            self.assertIn(path, json.loads(zlib.decompress(base64.urlsafe_b64decode(settings.export_code(source)[4:]))))
        self.assertIs(merged["appeals"]["enabled"], False)
        self.assertIs(merged["core"]["logs"]["enabled"], True)
        self.assertIs(merged["core"]["alerts"]["enabled"], True)
        desk = merged["core"]["help_desk"]
        self.assertEqual((desk["enabled"], desk["require_attempt"], desk["redirect"], desk["auto_close"], desk["member_close"]), (True, False, True, True, True))
        self.assertEqual(merged["checks"], {**source["checks"], "max_attempts": {**source["checks"]["max_attempts"], "role": None}})

    def test_a_code_cant_replace_the_appeal_channel_or_limit_role(self):
        target = self.target()
        target["checks"]["max_attempts"]["role"] = self.ROLE
        target["honeypot"].update(channel=self.ROLE, whitelist_roles=[self.ROLE])
        target["raid"]["alert_role"] = self.ROLE
        merged = settings.import_code(target, settings.export_code(settings.defaults()))
        self.assertEqual(merged["checks"]["max_attempts"]["role"], self.ROLE)
        self.assertEqual((merged["honeypot"]["channel"], merged["honeypot"]["whitelist_roles"], merged["raid"]["alert_role"]), (self.ROLE, [self.ROLE], self.ROLE))

    def test_an_import_keeps_this_servers_channels_and_roles(self):
        merged = settings.import_code(self.target(), settings.export_code(self.source()))
        self.assertEqual(merged["core"]["logs"]["modules"], {"general": self.ROLE})
        self.assertEqual(merged["core"]["alerts"]["roles"], {"general": self.ROLE})
        self.assertEqual(merged["core"]["help_desk"]["support_role"], self.ROLE)
        self.assertEqual((merged["appeals"]["channel"], merged["appeals"]["role"]), (self.ROLE, self.ROLE))

    def test_a_round_trip_changes_nothing(self):
        target = self.target()
        self.assertEqual(settings.diff(target, settings.import_code(target, settings.export_code(target))), [])

    def test_a_damaged_section_leaves_the_current_one_alone(self):
        target = self.target()
        target["privacy"]["ip_days"] = 7
        merged = settings.import_code(target, code_holding({"privacy": 5, "checks": [], "core": {"logs": 5, "help_desk": []}}))
        self.assertEqual(merged, target)

    def test_a_code_cant_set_a_channel_or_role(self):
        code = code_holding({"core": {"logs": {"modules": {"general": "1" * 18}}, "alerts": {"roles": {"general": "1" * 18}}, "help_desk": {"support_role": "1" * 18}},
                             "appeals": {"channel": "1" * 18, "role": "1" * 18}})
        merged = settings.import_code(self.target(), code)
        self.assertNotIn("1" * 18, json.dumps(merged))

    def test_the_changes_an_import_makes_can_be_listed(self):
        target = self.target()
        source = settings.defaults()
        source["privacy"]["banned_days"] = 0
        source["core"]["external_vpn_lookup"] = True
        changes = settings.diff(target, settings.import_code(target, settings.export_code(source)))
        self.assertEqual({change["path"]: (change["before"], change["after"]) for change in changes},
                         {"privacy.banned_days": (730, 0), "core.external_vpn_lookup": (False, True)})


class Normalizing(unittest.TestCase):
    def test_an_empty_document_is_exactly_a_new_server(self):
        self.assertEqual(settings.normalize({}), settings.defaults())

    def test_ids_take_ascii_digits_only(self):
        for value in ("١" * 18, "１" * 18, "1" * 14, "1" * 22, "abc", True):
            self.assertIsNone(settings._snowflake(value), value)
        self.assertEqual(settings._snowflake(" 123456789012345678 "), "123456789012345678")
        self.assertEqual(settings._snowflake(123456789012345678), "123456789012345678")

    def test_a_custom_emoji_takes_ascii_digits_only(self):
        self.assertEqual(settings._emoji("<:ab:" + "١" * 18 + ">"), "")
        self.assertEqual(settings._emoji("<:ab:123456789012345678>"), "<:ab:123456789012345678>")

    def test_what_discord_would_refuse_isnt_an_emoji(self):
        for value in ("!", "...", "é", "中", "\u200b", "😀😀", "✅✅", "\ufe0f", "°", "\u200d", "😀\u200d", "   ", "-"):
            self.assertEqual(settings._emoji(value), "", repr(value))

    def test_one_emoji_of_every_shape_survives(self):
        for value in ("😀", "✅", "❤", "❤\ufe0f", "👍🏽", "👨\u200d👩\u200d👧", "🏳\ufe0f\u200d🌈", "🇺🇸", "1\ufe0f⃣", "#⃣", "‼\ufe0f", "ℹ\ufe0f", "↔\ufe0f", "〰\ufe0f", "©\ufe0f", "🏴\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f"):
            self.assertEqual(settings._emoji(value), value, repr(value))

    def test_an_image_address_needs_a_host_and_no_spaces(self):
        for value in ("https://", "https:// x", "https://a.example/a b", "http://a.example/x", "https://[x/", "https://a.example/\x00", "https://a\u200bb.example/", 5, None, "https://a.example/" + "x" * 2000):
            self.assertEqual(settings._https_url(value), "", repr(value))
        self.assertEqual(settings._https_url("https://a.example/x.png"), "https://a.example/x.png")
        self.assertEqual(settings._https_url("https://a.example/x.png\n"), "https://a.example/x.png")

    def test_a_button_label_of_only_spaces_falls_back(self):
        document = settings.defaults()
        document["messages"]["verification"].update(verify_label="   ", help_label=" Help ")
        message = settings.normalize(document)["messages"]["verification"]
        self.assertEqual((message["verify_label"], message["help_label"]), ("Verify", "Help"))

    def test_country_rules_name_only_what_the_table_holds(self):
        overrides = {"<img src=x>": "deny", "us": "deny", "region:<b>": "deny", "continent:Atlantis": "deny", "US": "kick", "region:Southern Asia": "ban", "continent:Europe": "watch", "FR": "nonsense", "DE": ["kick"]}
        document = settings.normalize({"checks": {"geogate": {"overrides": overrides}}})
        self.assertEqual(document["checks"]["geogate"]["overrides"], {"US": "kick", "region:Southern Asia": "ban", "continent:Europe": "watch"})

    def test_a_malformed_override_grants_nothing(self):
        rule = settings._normalize_rule({"overrides": [{"type": "user", "id": "1" * 18}, {"type": "role", "id": "2" * 18, "allow": "yes"},
                                                       {"type": "everyone", "allow": 1}, {"type": "user", "id": "3" * 18, "allow": True}]}, ["manage_guild"])
        self.assertEqual([entry["allow"] for entry in rule["overrides"]], [False, False, False, True])


class SettingsRevision(unittest.TestCase):
    def test_a_revision_is_stable_across_key_order(self):
        document = settings.defaults()
        reordered = json.loads(json.dumps(document, sort_keys=True))
        for section in ("rules", "access", "look"):
            self.assertEqual(settings.revision(document, section), settings.revision(reordered, section))

    def test_each_section_sees_only_its_own_changes(self):
        changes = {"rules": lambda d: d["checks"]["vpn"].update(action="ban"),
                   "access": lambda d: d["permissions"]["pages"].update(audit={}),
                   "look": lambda d: d["messages"]["verification"].update(title="New")}
        look_too = lambda d: d["appearance"].update(bio="New")
        core_too = lambda d: d["core"].update(mode="button")
        base = settings.defaults()
        for changed, change in [*changes.items(), ("look", look_too), ("rules", core_too)]:
            document = copy.deepcopy(base)
            change(document)
            for section in ("rules", "access", "look"):
                same = settings.revision(document, section) == settings.revision(base, section)
                self.assertEqual(same, section != changed, (changed, section))

    def test_an_unknown_section_is_refused(self):
        with self.assertRaises(ValueError):
            settings.revision(settings.defaults(), "everything")

    def test_a_conflict_is_its_own_kind_of_error(self):
        self.assertTrue(issubclass(settings.Conflict, Exception))
        self.assertFalse(issubclass(settings.Conflict, ValueError), "the routes treat ValueError as a bad request")


class CommandDefaults(unittest.TestCase):
    def test_uninstall_takes_administrator_and_raid_takes_kick_members(self):
        self.assertEqual(settings.COMMAND_DEFAULTS["uninstall"], ["administrator"])
        self.assertEqual(settings.COMMAND_DEFAULTS["raid"], ["manage_guild", "kick_members"])

    def test_the_rest_stay_where_they_were(self):
        self.assertEqual(settings.COMMAND_DEFAULTS["lookup"], ["manage_roles"])
        self.assertEqual(settings.COMMAND_DEFAULTS["setup"], ["manage_guild"])
        self.assertEqual(settings.COMMAND_DEFAULTS["post-message"], ["manage_guild"])

    def test_a_manage_server_viewer_cant_uninstall(self):
        rule = settings.command_rule(settings.defaults(), "uninstall")
        manager = access.Viewer("1", frozenset(), frozenset({"manage_guild"}))
        admin = access.Viewer("1", frozenset(), frozenset({"administrator"}))
        self.assertEqual((access.allowed(rule, manager), access.allowed(rule, admin)), (False, True))


I18N = Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static" / "i18n"
LANGUAGES = ("de", "es", "fr", "ja", "ko", "pt", "ru", "zh")


class FailureTexts(unittest.TestCase):
    def test_the_texts_tell_a_member_what_to_do(self):
        self.assertEqual(catalog.FAILURE_TEXT["privacy"], "Your browser is blocking the details this server needs. Turn off fingerprint protection or Brave Shields for this site, or use a browser with default settings.")
        self.assertEqual(catalog.FAILURE_TEXT["antidetect"], "Your browser is hiding what device it's on. Turn off extensions that change this, or use a normal browser.")
        self.assertEqual(catalog.FAILURE_TEXT["fake_ua"], "Your browser is reporting a different browser or system than it is. Turn off user agent switchers and try again.")
        self.assertEqual(catalog.FAILURE_TEXT["vm"], "Open the link on your own device, not inside a virtual machine. If this is your own computer, turn on hardware acceleration in your browser or update your graphics driver.")
        self.assertEqual(catalog.FAILURE_TEXT["max_attempts"], "You have used all your verification attempts for this server.")

    def test_every_language_holds_the_same_strings_with_the_same_placeholders(self):
        english = json.loads((I18N / "en.json").read_text(encoding="utf-8"))
        for text in catalog.FAILURE_TEXT.values():
            self.assertIn(text, english)
        for language in LANGUAGES:
            table = json.loads((I18N / f"{language}.json").read_text(encoding="utf-8"))
            self.assertEqual(set(table), set(english), language)
            for key, value in table.items():
                self.assertEqual(sorted(re.findall(r"\{\w+\}", key)), sorted(re.findall(r"\{\w+\}", value)), (language, key))

    def test_the_new_strings_are_really_translated(self):
        for text in ("privacy", "antidetect", "fake_ua", "vm", "account_age_one"):
            for language in LANGUAGES:
                table = json.loads((I18N / f"{language}.json").read_text(encoding="utf-8"))
                self.assertNotEqual(table[catalog.FAILURE_TEXT[text]], catalog.FAILURE_TEXT[text], (language, text))

    def test_a_one_day_minimum_reads_as_one_day(self):
        document = settings.defaults()
        document["checks"]["account_age"].update(enabled=True, days=1)
        new_account = engine.Account(str(((int(time.time() * 1000) - engine.DISCORD_EPOCH_MS) << 22)), avatar="a", mfa=True, email_verified=True, email_disposable=False)
        finding = engine.run_checks(attempt(document, account=new_account)).primary
        self.assertEqual(finding.message, "This server only accepts Discord accounts older than 1 day.")
        self.assertEqual(finding.check_id, "account_age")
        self.assertEqual(catalog.HELP_SLUG[finding.reason], "account-age")
        document["checks"]["account_age"]["days"] = 2
        self.assertIn("older than 2 days", engine.run_checks(attempt(document, account=new_account)).primary.message)

    def test_labels_state_what_the_check_covers(self):
        self.assertIn("Pixel", catalog.BY_ID["rooted"].blurb)
        self.assertIn("iCloud Private Relay", catalog.BY_ID["vpn"].blurb)
        self.assertIn("no verified email", catalog.BY_ID["disposable_email"].blurb)
        self.assertIn("banned", catalog.BY_ID["alt_account"].blurb)
        for check in catalog.CHECKS:
            self.assertNotRegex(check.blurb, r"^(Flags|Notices)\b", check.id)
        self.assertNotIn("why", catalog.ACTION_BLURB["kick"] + catalog.ACTION_BLURB["ban"])


class RaidAccountAge(unittest.TestCase):
    def tightened(self, *, enabled, days=30, minimum, action="deny"):
        document = settings.defaults()
        document["checks"]["account_age"].update(enabled=enabled, days=days, action=action)
        document["raid"]["min_account_days"] = minimum
        return engine.effective_settings(document, True)["checks"]["account_age"]

    def test_a_minimum_of_zero_leaves_a_check_that_was_off_off(self):
        self.assertFalse(self.tightened(enabled=False, minimum=0)["enabled"])

    def test_a_check_that_was_off_uses_the_raid_minimum_alone(self):
        age = self.tightened(enabled=False, days=30, minimum=7)
        self.assertEqual((age["enabled"], age["days"], age["action"]), (True, 7, "kick"))

    def test_a_check_that_was_on_keeps_the_longer_age(self):
        self.assertEqual(self.tightened(enabled=True, days=30, minimum=7)["days"], 30)
        self.assertEqual(self.tightened(enabled=True, days=3, minimum=7)["days"], 7)
        self.assertEqual(self.tightened(enabled=True, days=3, minimum=0)["action"], "kick")

    def test_a_raid_never_softens_a_ban(self):
        self.assertEqual(self.tightened(enabled=False, minimum=7, action="ban")["action"], "ban")


class CountryAllowList(unittest.TestCase):
    def decision(self, net, *, kind="allow"):
        document = settings.defaults()
        document["checks"]["geogate"].update(enabled=True, action="kick", list=kind, countries=["US"])
        return engine.run_checks(attempt(document, net=net))

    def test_an_address_the_loaded_lists_cant_place_isnt_on_the_list(self):
        decision = self.decision(NetInfo(country=None, known=True))
        self.assertEqual((decision.action, decision.primary.check_id), ("kick", "geogate"))
        self.assertEqual(decision.primary.detail, {"list": "allow"})

    def test_a_listed_country_still_passes(self):
        self.assertTrue(self.decision(NetInfo(country="US", known=True)).passed)

    def test_with_no_lists_loaded_it_logs_and_finds_nothing(self):
        with self.assertLogs("altwarden.engine", "WARNING"):
            decision = self.decision(NetInfo(country=None, known=False))
        self.assertEqual(decision.findings, [])

    def test_a_block_list_passes_an_unknown_country(self):
        self.assertTrue(self.decision(NetInfo(country=None, known=True), kind="block").passed)


class StaffCards(unittest.TestCase):
    def card(self, username="someone", text="Please look at this again."):
        return notices.appeal_card(1, OLD_ACCOUNT, username, "vpn", text).embeds[0]

    def test_appeal_text_cant_pass_for_links_mentions_or_formatting(self):
        description = self.card(text="**URGENT** [Approve here](https://evil.example) <@&1> @everyone `x` ~~y~~ __z__ ||s||")["description"]
        for live in ("**URGENT**", "[Approve here](", "<@&1>", "@everyone", "`x`", "~~y~~", "__z__", "||s||"):
            self.assertNotRegex(description, r"(?<!\\)" + re.escape(live), live)

    def test_line_starts_that_would_format_are_escaped(self):
        description = self.card(text="# big\n> quote\n- item")["description"]
        self.assertEqual(description, "\\# big\n\\> quote\n\\- item")

    def test_a_bare_address_stays_usable(self):
        self.assertEqual(self.card(text="See https://a.example/x_y_z.png please")["description"], "See https://a.example/x_y_z.png please")

    def test_plain_words_read_as_typed(self):
        self.assertEqual(self.card(text="I share a home connection, sorry!")["description"], "I share a home connection, sorry!")

    def test_a_long_appeal_stays_under_discords_limit(self):
        self.assertLessEqual(len(self.card(text="*" * 5000)["description"]), notices.DESCRIPTION_LIMIT)

    def test_a_name_cant_break_out_of_its_code_span(self):
        value = self.card(username="x` [Approve here](https://evil.example) `\ny")["fields"][0]["value"]
        self.assertEqual(value, f"<@{OLD_ACCOUNT}>\n`x [Approve here](https://evil.example) y`")

    def test_a_name_of_only_backticks_falls_back_to_the_id(self):
        self.assertEqual(self.card(username="```")["fields"][0]["value"], f"<@{OLD_ACCOUNT}>\n`{OLD_ACCOUNT}`")


class SealedValues(unittest.TestCase):
    keys = crypto.Keyring(b"k" * 32)

    def test_a_sealed_value_opens_again_and_holds_nothing_readable(self):
        sealed = self.keys.seal("lookup-key", "970000000000000001", "secret-key-value")
        self.assertTrue(sealed.startswith("v1."))
        self.assertTrue(crypto.is_sealed(sealed))
        self.assertNotIn("secret-key-value", sealed)
        self.assertEqual(self.keys.unseal("lookup-key", "970000000000000001", sealed), "secret-key-value")

    def test_a_sealed_value_is_base64_of_a_nonce_and_ciphertext(self):
        raw = base64.b64decode(self.keys.seal("p", "1", "abc")[3:], validate=True)
        self.assertEqual(len(raw), 12 + 3 + 16)

    def test_two_seals_of_one_value_look_unrelated(self):
        self.assertNotEqual(self.keys.seal("p", "1", "same"), self.keys.seal("p", "1", "same"))

    def test_it_only_opens_for_its_own_purpose_server_and_key(self):
        sealed = self.keys.seal("webhook-secret", "1", "value")
        for keys, purpose, scope in ((self.keys, "webhook-url", "1"), (self.keys, "webhook-secret", "2"), (crypto.Keyring(b"o" * 32), "webhook-secret", "1")):
            with self.assertRaises(ValueError):
                keys.unseal(purpose, scope, sealed)

    def test_a_changed_or_plain_value_is_refused(self):
        sealed = self.keys.seal("p", "1", "value")
        flipped = sealed[:-3] + ("A" if sealed[-3] != "A" else "B") + sealed[-2:]
        for value in (flipped, "plain", "v1.", "v1.!!!", "v1.AAAA", "v2." + sealed[3:], "abc" + sealed[3:]):
            with self.assertRaises(ValueError, msg=value):
                self.keys.unseal("p", "1", value)

    def test_a_scope_can_be_a_number_or_its_text(self):
        self.assertEqual(self.keys.unseal("p", "12", self.keys.seal("p", 12, "value")), "value")

    def test_text_survives_every_character(self):
        for text in ("", "é中😀", "\ud800"):
            self.assertEqual(self.keys.unseal("p", "1", self.keys.seal("p", "1", text)), text)

    def test_the_master_key_never_appears_in_a_repr(self):
        keys = crypto.Keyring(b"SECRET-MASTER-KEY-BYTES-32-LONG!")
        self.assertNotIn("SECRET", repr(keys))
        self.assertNotIn("master", repr(keys))
        self.assertEqual(keys.master, b"SECRET-MASTER-KEY-BYTES-32-LONG!")

    def test_the_cipher_is_pinned(self):
        requirements = (Path(__file__).resolve().parent.parent / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("cryptography==50.0.0", requirements.splitlines())


class SealingStoredSecrets(DatabaseCase):
    keys = crypto.Keyring(b"k" * 32)

    async def hook(self, url="https://a.example/hook", secret="plain-secret"):
        return await self.db.insert("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES ('1', ?, ?, '[]', 1)", (url, secret))

    async def test_plain_secrets_are_listed_with_where_they_live(self):
        await self.db.set_lookup_key("1", "plain-key")
        hook = await self.hook()
        found = {(row["table"], row["column"], row["row_key"], row["guild_id"], row["value"]) for row in await self.db.unsealed_secrets()}
        self.assertEqual(found, {("lookup_keys", "lookup_key", "1", "1", "plain-key"), ("webhooks", "secret", hook, "1", "plain-secret"),
                                 ("webhooks", "url", hook, "1", "https://a.example/hook")})

    async def test_sealed_secrets_arent_listed_again(self):
        await self.db.set_lookup_key("1", "plain-key")
        for row in await self.db.unsealed_secrets():
            sealed = self.keys.seal(row["column"], row["guild_id"], row["value"])
            self.assertTrue(await self.db.store_sealed(row["table"], row["column"], row["row_key"], sealed, plain=row["value"]))
        self.assertEqual(await self.db.unsealed_secrets(), [])
        self.assertEqual(self.keys.unseal("lookup_key", "1", await self.db.lookup_key("1")), "plain-key")

    async def test_a_value_changed_since_it_was_read_isnt_overwritten(self):
        await self.db.set_lookup_key("1", "newer-key")
        self.assertFalse(await self.db.store_sealed("lookup_keys", "lookup_key", "1", self.keys.seal("k", "1", "older-key"), plain="older-key"))
        self.assertEqual(await self.db.lookup_key("1"), "newer-key")

    async def test_only_sealed_values_and_sealed_columns_get_through(self):
        with self.assertRaises(ValueError):
            await self.db.store_sealed("lookup_keys", "lookup_key", "1", "plain", plain="x")
        with self.assertRaises(ValueError):
            await self.db.store_sealed("guilds", "settings", "1", "v1.abc", plain="x")


# The schema as released in 1.1.3, for proving an existing database opens under the current code.
PREVIOUS_SCHEMA = """
CREATE TABLE IF NOT EXISTS guilds (
    guild_id TEXT PRIMARY KEY,
    settings TEXT NOT NULL,
    setup_done INTEGER NOT NULL DEFAULT 0,
    raid_until REAL NOT NULL DEFAULT 0,
    left_at REAL,
    verify_message_id TEXT,
    honeypot_message_id TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',
    bypass TEXT NOT NULL DEFAULT '[]',
    bypass_by TEXT,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    opened_at REAL,
    finished_at REAL,
    auth_state_hash TEXT,
    browser_hash TEXT,
    signed_in_at REAL,
    account TEXT,
    nonce TEXT,
    pow_salt TEXT,
    pow_bits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_member ON sessions (guild_id, user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS sessions_auth_state ON sessions (auth_state_hash);

CREATE TABLE IF NOT EXISTS members (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    avatar TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    method TEXT,
    verified_at REAL,
    first_verified_at REAL,
    joined_at REAL,
    kick_at REAL,
    fails INTEGER NOT NULL DEFAULT 0,
    last_fail_at REAL,
    limit_reached_at REAL,
    help_thread_id TEXT,
    forget_on_unban INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (guild_id, user_id)
);
CREATE INDEX IF NOT EXISTS members_status ON members (guild_id, status);
CREATE INDEX IF NOT EXISTS members_user ON members (user_id);
CREATE INDEX IF NOT EXISTS members_kick ON members (kick_at);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    at REAL NOT NULL,
    outcome TEXT NOT NULL,
    check_id TEXT,
    action TEXT,
    mode TEXT,
    seconds REAL,
    bypassed INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS attempts_guild_time ON attempts (guild_id, at);
CREATE INDEX IF NOT EXISTS attempts_member ON attempts (guild_id, user_id, at);
CREATE INDEX IF NOT EXISTS attempts_user ON attempts (user_id);

CREATE TABLE IF NOT EXISTS identifiers (
    guild_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    user_id TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (guild_id, kind, digest, user_id)
);
CREATE INDEX IF NOT EXISTS identifiers_member ON identifiers (guild_id, user_id);
CREATE INDEX IF NOT EXISTS identifiers_expiry ON identifiers (expires_at);

CREATE TABLE IF NOT EXISTS links (
    guild_id TEXT NOT NULL,
    main_id TEXT NOT NULL,
    alt_id TEXT NOT NULL,
    confidence TEXT NOT NULL,
    score INTEGER NOT NULL,
    methods TEXT NOT NULL,
    at REAL NOT NULL,
    PRIMARY KEY (guild_id, main_id, alt_id)
);
CREATE TABLE IF NOT EXISTS trusted_pairs (
    guild_id TEXT NOT NULL,
    first_id TEXT NOT NULL,
    second_id TEXT NOT NULL,
    by_id TEXT NOT NULL,
    at REAL NOT NULL,
    PRIMARY KEY (guild_id, first_id, second_id)
);
CREATE TABLE IF NOT EXISTS bans (
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    at REAL NOT NULL,
    by_altwarden INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (guild_id, user_id)
);
CREATE TABLE IF NOT EXISTS appeals (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    check_id TEXT,
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at REAL NOT NULL,
    decided_by TEXT,
    decided_at REAL,
    note TEXT,
    channel_id TEXT,
    message_id TEXT
);
CREATE INDEX IF NOT EXISTS appeals_guild ON appeals (guild_id, status, created_at);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    at REAL NOT NULL,
    actor_id TEXT,
    actor_name TEXT,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_guild ON audit (guild_id, at);

CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    avatar TEXT,
    guilds TEXT NOT NULL DEFAULT '[]',
    csrf TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'dashboard',
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS login_states (
    state_hash TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    next_path TEXT NOT NULL DEFAULT '/',
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS command_syncs (
    state_hash TEXT PRIMARY KEY,
    guild_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    changes TEXT NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY,
    guild_id TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL,
    last_status INTEGER,
    last_sent_at REAL
);
CREATE TABLE IF NOT EXISTS lookup_keys (
    guild_id TEXT PRIMARY KEY,
    lookup_key TEXT NOT NULL,
    saved_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash TEXT PRIMARY KEY,
    guild_id TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_used_at REAL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value REAL NOT NULL
);
"""


def previous_database(path):
    """A database from the last release with a row in every table."""
    connection = db_module.open_encrypted(str(path), DB_KEY)
    connection.executescript(PREVIOUS_SCHEMA)
    now = time.time()
    connection.execute("INSERT INTO guilds (guild_id, settings, created_at, updated_at) VALUES ('1', '{}', 1, 1)")
    connection.execute("INSERT INTO sessions (token_hash, guild_id, user_id, state, created_at, expires_at) VALUES ('t', '1', '10', 'checking', ?, ?)", (now, now + 999))
    connection.execute("INSERT INTO members (guild_id, user_id, username, status, verified_at, joined_at, kick_at) VALUES ('1', '10', 'kept', 'verified', 5, 4, ?)", (now + 999,))
    connection.execute("INSERT INTO attempts (guild_id, user_id, at, outcome) VALUES ('1', '10', ?, 'passed')", (now,))
    connection.execute("INSERT INTO identifiers VALUES ('1', 'cookie', 'c', '10', ?, ?, ?)", (now, now, now + 999))
    connection.execute("INSERT INTO links VALUES ('1', '10', '11', 'likely', 70, '[]', ?)", (now,))
    connection.execute("INSERT INTO trusted_pairs VALUES ('1', '10', '11', '5', ?)", (now,))
    connection.execute("INSERT INTO bans VALUES ('1', '12', ?, 1)", (now,))
    for user, status in (("10", "open"), ("10", "open"), ("10", "deciding"), ("10", "denied"), ("10", "denied"), ("11", "open")):
        connection.execute("INSERT INTO appeals (guild_id, user_id, text, status, created_at) VALUES ('1', ?, 'please', ?, ?)", (user, status, now))
    connection.execute("INSERT INTO audit (guild_id, at, kind) VALUES ('1', ?, 'reset')", (now,))
    connection.execute("INSERT INTO web_sessions (token_hash, user_id, username, csrf, created_at, expires_at) VALUES ('w', '10', 'n', 'c', 1, ?)", (now + 999,))
    connection.execute("INSERT INTO login_states VALUES ('s', 'login', '/', ?)", (now + 999,))
    connection.execute("INSERT INTO command_syncs VALUES ('s', '1', '10', '[]', ?)", (now + 999,))
    connection.execute("INSERT INTO webhooks (guild_id, url, secret, created_at) VALUES ('1', 'https://a.example', 's', 1)")
    connection.execute("INSERT INTO lookup_keys VALUES ('1', 'k', 1)")
    connection.execute("INSERT INTO api_keys VALUES ('h', '1', 'l', 1, NULL)")
    connection.execute("INSERT INTO meta VALUES ('last_online', 1)")
    connection.commit()
    connection.close()


class OlderDatabase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "old.db"
        previous_database(self.path)
        self.db = db_module.Database(self.path, DB_KEY)
        await self.db.open()

    async def asyncTearDown(self):
        await self.db.close()
        self.folder.cleanup()

    async def test_a_populated_database_opens_and_keeps_its_rows(self):
        self.assertEqual(await self.db.scalar("PRAGMA integrity_check"), "ok")
        self.assertEqual((await self.db.member("1", "10"))["username"], "kept")
        for table in ("guilds", "sessions", "members", "attempts", "identifiers", "links", "trusted_pairs", "bans", "audit", "web_sessions",
                      "login_states", "command_syncs", "webhooks", "lookup_keys", "api_keys", "meta"):
            self.assertEqual(await self.db.scalar(f"SELECT COUNT(*) FROM {table}"), 1, table)

    async def test_it_gains_what_the_schema_has_added(self):
        record = await self.db.member("1", "10")
        self.assertIsNone(record["kick_warn_at"])
        await self.db.update_member("1", "10", kick_warn_at=123.0)
        self.assertEqual((await self.db.member("1", "10"))["kick_warn_at"], 123.0)

    async def test_it_has_the_same_columns_and_indexes_as_a_new_database(self):
        fresh = db_module.Database(Path(self.folder.name) / "new.db", DB_KEY)
        await fresh.open()
        try:
            for question in ("SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'", "SELECT name FROM sqlite_master WHERE type = 'table'"):
                self.assertEqual({row["name"] for row in await self.db.all(question)}, {row["name"] for row in await fresh.all(question)})
            for row in await fresh.all("SELECT name FROM sqlite_master WHERE type = 'table'"):
                ours = await self.db.all(f"PRAGMA table_info({row['name']})")
                theirs = await fresh.all(f"PRAGMA table_info({row['name']})")
                self.assertEqual(sorted(entry["name"] for entry in ours), sorted(entry["name"] for entry in theirs), row["name"])
        finally:
            await fresh.close()

    async def test_the_writes_that_used_to_rely_on_column_order_still_land(self):
        await self.db.set_meta("last_online", 2.0)
        self.assertEqual(await self.db.get_meta("last_online"), 2.0)
        await self.db.trust_pair("1", "20", "21", "5")
        self.assertTrue((await self.db.link_facts("1", "21", ["20"]))["20"]["trusted"])
        await self.db.record_ban("1", "30")
        self.assertTrue(await self.db.is_banned("1", "30"))

    async def test_the_index_nothing_used_is_gone(self):
        self.assertIsNone(await self.db.scalar("SELECT 1 FROM sqlite_master WHERE name = 'sessions_auth_state'"))

    async def test_duplicate_waiting_appeals_collapse_to_the_first(self):
        rows = await self.db.all("SELECT id, user_id, status FROM appeals ORDER BY id")
        self.assertEqual([(row["id"], row["user_id"], row["status"]) for row in rows], [(1, "10", "open"), (4, "10", "denied"), (5, "10", "denied"), (6, "11", "open")])

    async def test_a_second_open_finishes_with_nothing_changed(self):
        await self.db.close()
        await self.db.open()
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM appeals"), 4)

    async def test_a_check_interrupted_by_the_restart_hands_its_link_back(self):
        self.assertEqual(await self.db.scalar("SELECT state FROM sessions"), "signed_in")


class SchemaGrowth(unittest.TestCase):
    """SQLite refuses to add a NOT NULL column with no default to a table that has rows, so a new one would stop the bot from starting."""

    def columns(self, schema):
        model = sqlite3.connect(":memory:")
        model.executescript(schema)
        found = {}
        for (table,) in model.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
            for _, name, _, not_null, default, _ in model.execute(f"PRAGMA table_info({table})"):
                found[table, name] = (not_null, default)
        model.close()
        return found

    def test_every_column_added_since_the_last_release_can_be_added_to_a_populated_table(self):
        before = self.columns(PREVIOUS_SCHEMA)
        for key, (not_null, default) in self.columns(db_module.SCHEMA).items():
            if key not in before:
                self.assertFalse(not_null and default is None, key)


class Indexes(DatabaseCase):
    async def test_the_timers_tick_reads_have_their_own_indexes(self):
        now = time.time()
        for sql, name in (("SELECT user_id FROM members WHERE limit_reached_at IS NOT NULL AND limit_reached_at <= ?", "members_limit_reached"),
                          ("SELECT user_id FROM members WHERE kick_warn_at IS NOT NULL AND kick_warn_at <= ?", "members_kick_warn")):
            plan = " ".join(row["detail"] for row in await self.db.all(f"EXPLAIN QUERY PLAN {sql}", (now,)))
            self.assertIn(name, plan)

    async def test_a_new_database_has_no_index_on_the_old_flow_state(self):
        self.assertIsNone(await self.db.scalar("SELECT 1 FROM sqlite_master WHERE name = 'sessions_auth_state'"))


class KickWarning(DatabaseCase):
    async def test_a_member_getting_in_clears_both_timers(self):
        await self.seed("10", verified=False)
        await self.db.update_member("1", "10", kick_at=5.0, kick_warn_at=4.0)
        await self.db.mark_verified("1", "10", "web")
        record = await self.db.member("1", "10")
        self.assertEqual((record["kick_at"], record["kick_warn_at"]), (None, None))


class OneWaitingAppeal(DatabaseCase):
    async def test_a_second_appeal_while_one_waits_opens_nothing(self):
        first = await self.db.open_appeal("1", "10", "vpn", "please")
        self.assertIsInstance(first, int)
        self.assertIsNone(await self.db.open_appeal("1", "10", "vpn", "again"))
        await self.db.run("UPDATE appeals SET status = 'deciding'")
        self.assertIsNone(await self.db.open_appeal("1", "10", "vpn", "again"))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM appeals"), 1)

    async def test_a_decided_appeal_doesnt_block_the_next(self):
        await self.db.open_appeal("1", "10", "vpn", "please")
        await self.db.run("UPDATE appeals SET status = 'denied'")
        self.assertIsInstance(await self.db.open_appeal("1", "10", "vpn", "again"), int)

    async def test_other_members_and_servers_arent_held_up(self):
        await self.db.open_appeal("1", "10", "vpn", "please")
        self.assertIsInstance(await self.db.open_appeal("1", "11", "vpn", "please"), int)
        self.assertIsInstance(await self.db.open_appeal("2", "10", "vpn", "please"), int)


class ConcurrentAppeals(FlowBase):
    async def test_two_submits_at_once_open_one_appeal(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny")
        answers = await asyncio.gather(*(self.service.submit_appeal(GUILD, OLD_USER, "someone", "This was my home connection.") for _ in range(4)))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM appeals"), 1)
        self.assertEqual(sum(answer is None for answer in answers), 1)
        self.assertEqual(sum(answer == "You already have an appeal waiting." for answer in answers), 3)


class DeletedValuesLeaveTheLog(DatabaseCase):
    MARKER = "MARKER-VALUE-" + "x" * 40

    def log_size(self):
        """The bytes in the write-ahead log. What's deleted stays in the log until a checkpoint empties it, and the log is encrypted either way."""
        log = Path(self.folder.name) / "t.db-wal"
        return log.stat().st_size if log.exists() else 0

    async def test_removing_a_lookup_key_empties_the_log(self):
        await self.db.set_lookup_key("1", self.MARKER)
        self.assertGreater(self.log_size(), 0)
        await self.db.set_lookup_key("1", None)
        self.assertEqual(self.log_size(), 0)

    async def test_forgetting_a_server_empties_the_log(self):
        await self.db.save_settings("1", {"privacy": {}})
        await self.db.touch_member("1", "10", username=self.MARKER)
        self.assertGreater(self.log_size(), 0)
        await self.db.forget_guild("1")
        self.assertEqual(self.log_size(), 0)

    async def test_the_hourly_purge_empties_the_log(self):
        await self.db.touch_member("1", "10", username=self.MARKER)
        await self.db.run("DELETE FROM members")
        self.assertGreater(self.log_size(), 0, "a plain delete leaves the old value in the log, which is why the purge checkpoints")
        await self.db.purge_expired({})
        self.assertEqual(self.log_size(), 0)

    async def test_a_departed_server_is_cleared_too(self):
        await self.db.save_settings("1", settings.defaults())
        await self.db.touch_member("1", "10", username=self.MARKER)
        await self.db.set_guild_field("1", "left_at", 1)
        await self.db.purge_expired({})
        self.assertEqual(self.log_size(), 0)
        self.assertIsNone(await self.db.member("1", "10"))

    async def test_deleted_pages_are_zeroed_before_they_are_encrypted(self):
        self.assertEqual(await self.db.scalar("PRAGMA secure_delete"), 1)

    async def test_the_log_has_a_size_limit(self):
        self.assertEqual(await self.db.scalar("PRAGMA journal_size_limit"), db_module.WAL_LIMIT_BYTES)

    async def test_a_checkpoint_says_when_it_was_held_up(self):
        self.assertTrue(await self.db.checkpoint())
        reader = self.db.reader()
        try:
            reader.execute("BEGIN")
            reader.execute("SELECT * FROM meta").fetchall()
            await self.db.set_meta("a", 1.0)
            await self.db.conn.execute("PRAGMA busy_timeout=0")
            self.assertFalse(await self.db.checkpoint())
        finally:
            reader.close()
        self.assertTrue(await self.db.checkpoint())


class Retention(DatabaseCase):
    OLD = time.time() - 2000 * 86400

    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.db.save_settings("1", settings.defaults())

    async def test_someone_who_once_verified_is_never_purged(self):
        await self.db.touch_member("1", "10")
        await self.db.update_member("1", "10", status="pending", first_verified_at=self.OLD, joined_at=self.OLD)
        await self.db.touch_member("1", "11")
        await self.db.update_member("1", "11", status="pending", verified_at=self.OLD, joined_at=self.OLD)
        await self.db.touch_member("1", "12")
        await self.db.update_member("1", "12", status="pending", joined_at=self.OLD)
        removed = await self.db.purge_expired({"1": settings.defaults()})
        self.assertEqual(removed["members"], 1)
        self.assertIsNotNone(await self.db.member("1", "10"))
        self.assertIsNotNone(await self.db.member("1", "11"))
        self.assertIsNone(await self.db.member("1", "12"))

    async def test_an_old_open_appeal_goes_with_the_attempts_it_is_about(self):
        await self.db.insert("INSERT INTO appeals (guild_id, user_id, text, created_at) VALUES ('1', '10', 'old', ?)", (self.OLD,))
        await self.db.insert("INSERT INTO appeals (guild_id, user_id, text, created_at) VALUES ('1', '11', 'new', ?)", (time.time(),))
        await self.db.insert("INSERT INTO appeals (guild_id, user_id, text, status, created_at) VALUES ('1', '12', 'busy', 'deciding', ?)", (self.OLD,))
        removed = await self.db.purge_expired({"1": settings.defaults()})
        self.assertEqual(removed["appeals"], 1)
        self.assertEqual({row["text"] for row in await self.db.all("SELECT text FROM appeals")}, {"new", "busy"})

    async def orphans(self, guild, at):
        await self.db.touch_member(guild, "10")
        await self.db.update_member(guild, "10", joined_at=at)
        await self.db.run("INSERT INTO attempts (guild_id, user_id, at, outcome) VALUES (?, '10', ?, 'passed')", (guild, at))
        await self.db.run("INSERT INTO audit (guild_id, at, kind) VALUES (?, ?, 'reset')", (guild, at))
        await self.db.run("INSERT INTO identifiers VALUES (?, 'cookie', 'c', '10', ?, ?, ?)", (guild, at, at, time.time() + 999))
        await self.db.run("INSERT INTO links VALUES (?, '10', '11', 'likely', 70, '[]', ?)", (guild, at))
        await self.db.run("INSERT INTO trusted_pairs VALUES (?, '10', '11', '5', ?)", (guild, at))
        await self.db.run("INSERT INTO bans VALUES (?, '12', ?, 1)", (guild, at))
        await self.db.run("INSERT INTO appeals (guild_id, user_id, text, status, created_at) VALUES (?, '10', 'x', 'denied', ?)", (guild, at))
        await self.db.run("INSERT INTO sessions (token_hash, guild_id, user_id, created_at, expires_at) VALUES (?, ?, '10', ?, ?)", (guild, guild, at, time.time() + 999))
        await self.db.run("INSERT INTO webhooks (guild_id, url, secret, created_at) VALUES (?, 'https://a.example', 's', ?)", (guild, at))
        await self.db.run("INSERT INTO lookup_keys (guild_id, lookup_key, saved_at) VALUES (?, 'k', ?)", (guild, at))
        await self.db.run("INSERT INTO api_keys (key_hash, guild_id, label, created_at) VALUES (?, ?, 'l', ?)", (guild, guild, at))

    TABLES = tuple(db_module.ORPHAN_AGE)

    async def count(self, table, guild):
        return await self.db.scalar(f"SELECT COUNT(*) FROM {table} WHERE guild_id = ?", (guild,))

    async def test_old_rows_for_a_server_with_no_record_are_swept(self):
        await self.orphans("gone", self.OLD)
        removed = await self.db.purge_expired({})
        for table in self.TABLES:
            self.assertEqual(await self.count(table, "gone"), 0, table)
        self.assertEqual(removed["orphans"], len(self.TABLES))

    async def test_recent_rows_get_the_same_grace_as_a_departed_server(self):
        await self.orphans("gone", time.time() - (db_module.DEPARTED_DAYS - 1) * 86400)
        await self.db.purge_expired({})
        for table in self.TABLES:
            self.assertEqual(await self.count(table, "gone"), 1, table)

    async def test_a_server_with_a_record_keeps_its_rows_to_the_sweep(self):
        await self.db.save_settings("kept", settings.defaults())
        await self.orphans("kept", self.OLD)
        await self.db.purge_expired({})  # no retention rules passed, so only the sweep could remove these
        for table in self.TABLES:
            self.assertEqual(await self.count(table, "kept"), 1, table)


class BanRecords(DatabaseCase):
    async def test_the_ban_event_after_our_own_ban_keeps_who_did_it_and_when(self):
        await self.db.record_ban("1", "10", by_altwarden=True)
        await self.db.run("UPDATE bans SET at = 5")
        await self.db.record_ban("1", "10")
        row = await self.db.one("SELECT at, by_altwarden FROM bans")
        self.assertEqual((row["at"], row["by_altwarden"]), (5, 1))

    async def test_our_ban_after_seeing_one_marks_it_ours(self):
        await self.db.record_ban("1", "10")
        await self.db.record_ban("1", "10", by_altwarden=True)
        self.assertEqual(await self.db.scalar("SELECT by_altwarden FROM bans"), 1)

    async def test_a_ban_after_an_unban_starts_again(self):
        await self.db.record_ban("1", "10", by_altwarden=True)
        await self.db.run("UPDATE bans SET at = 5")
        await self.db.clear_ban("1", "10")
        await self.db.record_ban("1", "10")
        row = await self.db.one("SELECT at, by_altwarden FROM bans")
        self.assertEqual(row["by_altwarden"], 0)
        self.assertGreater(row["at"], 5)

    async def test_keeping_hashes_for_a_ban_still_works_on_a_repeat(self):
        await self.db.store_identifier("1", "10", "cookie", "c", time.time() + 5)
        await self.db.record_ban("1", "10", keep_days=30)
        await self.db.record_ban("1", "10", keep_days=30)
        self.assertGreater(await self.db.scalar("SELECT expires_at FROM identifiers"), time.time() + 29 * 86400)


class ProfilePictures(DatabaseCase):
    async def picture(self):
        return (await self.db.member("1", "10"))["avatar"]

    async def test_a_removed_picture_clears_the_old_one(self):
        await self.db.touch_member("1", "10", username="a", avatar="old")
        await self.db.touch_member("1", "10", username="a", avatar=None)
        self.assertIsNone(await self.picture())

    async def test_a_touch_that_doesnt_know_keeps_it(self):
        await self.db.touch_member("1", "10", username="a", avatar="old")
        await self.db.touch_member("1", "10")
        await self.db.touch_member("1", "10", username="b")
        self.assertEqual(await self.picture(), "old")

    async def test_a_new_picture_replaces_it(self):
        await self.db.touch_member("1", "10", avatar="old")
        await self.db.touch_member("1", "10", avatar="new")
        self.assertEqual(await self.picture(), "new")


class IdentifierCaps(DatabaseCase):
    async def kinds(self, kind):
        return await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE kind = ?", (kind,))

    async def test_each_kind_keeps_only_the_newest(self):
        for kind, cap in (("ip", 20), ("cookie", 10), ("fingerprint", 10), ("device", 3), ("os", 5), ("browser", 5)):
            for index in range(cap + 5):
                await self.db.store_identifier("1", "10", kind, f"{kind}{index}", FAR)
            self.assertEqual(await self.kinds(kind), cap, kind)
            self.assertIsNotNone(await self.db.scalar("SELECT 1 FROM identifiers WHERE digest = ?", (f"{kind}{cap + 4}",)), kind)
            self.assertIsNone(await self.db.scalar("SELECT 1 FROM identifiers WHERE digest = ?", (f"{kind}0",)), kind)

    async def test_seeing_an_old_value_again_keeps_it(self):
        await self.db.store_identifier("1", "10", "os", "first", FAR)
        await self.db.run("UPDATE identifiers SET last_seen = 1")
        for index in range(4):
            await self.db.store_identifier("1", "10", "os", f"other{index}", FAR)
        await self.db.store_identifier("1", "10", "os", "first", FAR)
        await self.db.store_identifier("1", "10", "os", "newest", FAR)
        self.assertIsNotNone(await self.db.scalar("SELECT 1 FROM identifiers WHERE digest = 'first'"))

    async def test_one_member_flooding_doesnt_touch_another(self):
        await self.db.store_identifier("1", "11", "os", "theirs", FAR)
        await self.db.store_identifier("2", "10", "os", "elsewhere", FAR)
        for index in range(9):
            await self.db.store_identifier("1", "10", "os", f"mine{index}", FAR)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE digest IN ('theirs', 'elsewhere')"), 2)


class ManyAccountsOnOneAddress(DatabaseCase):
    async def many(self, count, *, verified=False):
        now = time.time()
        rows = [("1", "ip", "shared", str(1000 + index), now, now, FAR) for index in range(count)]
        await self.db.run_many("INSERT INTO identifiers (guild_id, kind, digest, user_id, first_seen, last_seen, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
        if verified:
            await self.db.run_many("INSERT INTO members (guild_id, user_id, status, first_verified_at) VALUES (?, ?, 'verified', 1)", [("1", str(1000 + index)) for index in range(count)])

    async def queries_for_one_lookup(self):
        count = 0
        real_all, real_one = self.db.all, self.db.one

        async def counted_all(*args):
            nonlocal count
            count += 1
            return await real_all(*args)

        async def counted_one(*args):
            nonlocal count
            count += 1
            return await real_one(*args)
        with patch.object(self.db, "all", counted_all), patch.object(self.db, "one", counted_one):
            links = await self.links({"ip": "shared"})
        return count, links

    async def test_the_query_count_doesnt_grow_with_the_accounts(self):
        await self.many(3, verified=True)
        few, links = await self.queries_for_one_lookup()
        self.assertEqual(len(links), 3)
        await self.db.run("DELETE FROM identifiers")
        await self.many(1000, verified=False)
        many, links = await self.queries_for_one_lookup()
        self.assertEqual(few, many)
        self.assertLessEqual(len(links), db_module.MATCH_LIMIT)

    async def test_who_got_in_or_was_banned_outranks_a_pile_of_failed_attempts(self):
        await self.many(500)
        old = time.time() - 9000
        for user, setup in (("verified", self.db.mark_verified("1", "verified", "web")), ("banned", self.db.record_ban("1", "banned"))):
            await self.db.touch_member("1", user)
            await setup
            await self.db.run("INSERT INTO identifiers (guild_id, kind, digest, user_id, first_seen, last_seen, expires_at) VALUES ('1', 'ip', 'shared', ?, ?, ?, ?)", (user, old, old, FAR))
        links = await self.links({"ip": "shared"})
        self.assertEqual([link.other_id for link in links[:2]], ["banned", "verified"])
        self.assertTrue(links[0].banned)
        self.assertTrue(links[1].verified)

    async def test_an_approved_member_counts_as_someone_who_got_in(self):
        await self.db.touch_member("1", "10")
        await self.db.update_member("1", "10", status="approved")
        await self.db.store_identifier("1", "10", "cookie", "c", FAR)
        self.assertTrue((await self.links({"cookie": "c"}))[0].verified)

    async def test_trusted_pairs_drop_out_in_either_order(self):
        await self.seed("10", cookie="c")
        await self.seed("100", cookie="c")
        await self.db.trust_pair("1", "99", "10", "5")
        await self.db.trust_pair("1", "99", "100", "5")
        await self.seed("101", cookie="c")
        self.assertEqual([link.other_id for link in await self.links({"cookie": "c"})], ["101"])

    async def test_nothing_crosses_to_another_server(self):
        await self.seed("10", cookie="c")
        await self.db.touch_member("2", "11")
        await self.db.mark_verified("2", "11", "web")
        await self.db.record_ban("2", "10")
        await self.db.trust_pair("2", "99", "10", "5")
        await self.db.store_identifier("2", "11", "cookie", "c", FAR)
        links = await self.links({"cookie": "c"})
        self.assertEqual([(link.other_id, link.banned) for link in links], [("10", False)])

    async def test_the_lookup_batches_more_ids_than_one_query_holds(self):
        others = [str(index) for index in range(db_module.LOOKUP_CHUNK + 5)]
        await self.db.record_ban("1", others[1])
        await self.db.record_ban("1", others[-1])
        facts = await self.db.link_facts("1", "99", others)
        self.assertEqual(len(facts), db_module.LOOKUP_CHUNK + 5)
        self.assertEqual([other for other in others if facts[other]["banned"]], [others[1], others[-1]])


class ReportedConnectionType(FlowBase):
    async def seed_home_connection(self):
        self.port.add_member(OTHER_USER)
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.mark_verified(GUILD, OTHER_USER, "web")
        for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4")):
            await self.db.store_identifier(GUILD, OTHER_USER, kind, self.keys.digest(int(GUILD), kind, value), FAR)

    async def test_a_browser_claiming_cellular_doesnt_lower_the_address_weight(self):
        await self.seed_home_connection()
        await self.change(alt_account={"enabled": True, "alt_action": "deny"})
        result = await self.verify_through(report=clean_report(conn={"type": "cellular"}), ip="8.8.4.4")
        self.assertEqual((result["status"], result["reason"]), ("failed", "alt_account"))

    async def test_a_browser_claiming_cellular_still_counts_for_mobile_data(self):
        await self.change(mobile_data={"enabled": True, "action": "deny"})
        result = await self.verify_through(report=clean_report(conn={"type": "cellular"}), ip="8.8.4.4")
        self.assertEqual(result["reason"], "mobile_data")


def replay_row(finding, outcome="failed"):
    return {"user_id": "1", "outcome": outcome, "detail": json.dumps({"findings": [finding]})}


class PreviewAgreesWithTheEngine(unittest.TestCase):
    def replay(self, rules, finding, outcome="failed"):
        return analytics._replay([replay_row(finding, outcome)], rules, 30)

    def test_a_replayed_link_acts_like_a_real_one(self):
        finding = {"check": "alt_account", "action": "kick", "detail": {"confidence": "likely", "score": 80, "methods": ["fingerprint", "ip"],
                                                                         "banned": False, "other_is_main": False}}
        self.assertEqual(self.replay(alt_rules(main_action="kick"), finding, "passed")["blocked_now"], 1)

    def test_every_evidence_switch_off_means_the_link_doesnt_fire(self):
        finding = {"check": "alt_account", "action": "kick", "detail": {"confidence": "confirmed", "score": 100, "methods": ["cookie"], "banned": False, "other_is_main": True}}
        rules = alt_rules(methods={"cookie": False, "fingerprint": True, "ip": True})
        self.assertEqual(self.replay(rules, finding)["blocked_now"], 0)
        self.assertEqual(self.replay(alt_rules(), finding)["blocked_now"], 1)

    def test_a_link_is_rescored_from_the_evidence_still_on(self):
        finding = {"check": "alt_account", "action": "kick", "detail": {"confidence": "likely", "score": 80, "methods": ["fingerprint", "ip"], "banned": False, "other_is_main": True}}
        rules = alt_rules(methods={"cookie": True, "fingerprint": True, "ip": False})
        self.assertEqual(self.replay(rules, finding)["blocked_now"], 0, "a fingerprint alone is under the floor")
        self.assertEqual(self.replay(alt_rules(), finding)["blocked_now"], 1)

    def test_rescoring_honors_the_weak_kinds_on_record(self):
        finding = {"check": "alt_account", "action": "kick", "detail": {"confidence": "confirmed", "score": 110, "methods": ["cookie", "ip"], "weak": ["ip"], "banned": False, "other_is_main": True}}
        rules = alt_rules(min_confidence="possible", methods={"cookie": False, "fingerprint": True, "ip": True})
        self.assertEqual(self.replay(rules, finding)["blocked_now"], 0, "a mobile address alone scores 10, under possible")

    def test_an_older_row_keeps_its_recorded_score_as_a_ceiling(self):
        finding = {"check": "alt_account", "action": "deny", "detail": {"confidence": "possible", "score": 30, "methods": ["ip", "device"], "banned": False, "other_is_main": True}}
        self.assertEqual(self.replay(alt_rules(), finding)["blocked_now"], 0)

    def test_an_old_link_with_no_cookie_no_longer_replays_as_confirmed(self):
        finding = {"check": "alt_account", "action": "kick", "detail": {"confidence": "confirmed", "score": 100, "methods": ["fingerprint", "ip", "device"], "banned": False, "other_is_main": True}}
        self.assertEqual(self.replay(alt_rules(min_confidence="confirmed"), finding)["blocked_now"], 0)

    def test_a_raised_attempt_limit_no_longer_fires(self):
        finding = {"check": "max_attempts", "action": "deny", "detail": {"attempts": 5}}
        rules = settings.defaults()
        rules["checks"]["max_attempts"]["attempts"] = 100
        self.assertEqual(self.replay(rules, finding)["blocked_now"], 0)
        rules["checks"]["max_attempts"]["attempts"] = 5
        self.assertEqual(self.replay(rules, finding)["blocked_now"], 1)
        rules["checks"]["max_attempts"]["attempts"] = 3
        self.assertEqual(self.replay(rules, finding)["blocked_now"], 1)

    def geogate(self, **options):
        rules = settings.defaults()
        rules["checks"]["geogate"].update(enabled=True, action="deny", **options)
        return self.replay(rules, {"check": "geogate", "action": "deny", "detail": {"list": "block"}})

    def test_an_empty_block_list_stops_nobody(self):
        result = self.geogate(list="block", countries=[])
        self.assertEqual((result["blocked_now"], result["newly_passed"], result["not_replayed"]), (0, 1, 0))

    def test_a_country_rule_that_could_fire_is_counted_apart(self):
        for options in ({"list": "block", "countries": ["RU"]}, {"list": "allow", "countries": ["US"]}, {"list": "allow", "countries": []}):
            result = self.geogate(**options)
            self.assertEqual((result["attempts"], result["not_replayed"], result["blocked_then"], result["blocked_now"], result["newly_passed"], result["by_check"]),
                             (1, 1, 0, 0, 0, []), options)

    def test_a_country_rule_switched_off_lets_it_through(self):
        rules = settings.defaults()
        rules["checks"]["geogate"]["enabled"] = False
        result = self.replay(rules, {"check": "geogate", "action": "deny", "detail": {"list": "block"}})
        self.assertEqual((result["not_replayed"], result["newly_passed"]), (0, 1))

    def test_rows_can_arrive_one_at_a_time(self):
        rows = (replay_row({"check": "vpn", "action": "deny", "detail": {}}) for _ in range(3))
        self.assertEqual(analytics._replay(rows, settings.defaults(), 30)["attempts"], 3)


class SlowReads(DatabaseCase):
    async def test_a_preview_never_loads_every_row_at_once(self):
        await self.db.add_attempt("1", "10", "failed", check_id="vpn", action="deny", detail={"findings": [{"check": "vpn", "action": "deny", "detail": {}}]})
        with patch.object(self.db, "read_all", side_effect=AssertionError("loads the whole result")):
            result = await analytics.preview(self.db, "1", settings.defaults())
        self.assertEqual((result["attempts"], result["blocked_now"]), (1, 1))

    async def overlap(self, *guilds):
        running = peak = 0
        guard = threading.Lock()

        def slow(rows, rules, days):
            nonlocal running, peak
            with guard:
                running += 1
                peak = max(peak, running)
            time.sleep(0.05)
            with guard:
                running -= 1
            return {}
        with patch.object(analytics, "_replay", slow):
            await asyncio.gather(*(analytics.preview(self.db, guild, settings.defaults()) for guild in guilds))
        return peak

    async def test_one_preview_runs_per_server_at_a_time(self):
        self.assertEqual(await self.overlap("1", "1", "1", "1"), 1)

    async def test_another_server_doesnt_wait(self):
        self.assertEqual(await self.overlap("1", "2"), 2)

    async def test_a_report_waits_its_turn_too(self):
        lock = analytics._job("1")
        await lock.acquire()
        report = asyncio.ensure_future(analytics.report(self.db, "1", 0, time.time()))
        await asyncio.sleep(0.05)
        self.assertFalse(report.done())
        lock.release()
        await report


class ReportNumbers(DatabaseCase):
    async def test_a_manual_verify_counts_as_finished(self):
        await self.db.add_attempt("1", "10", "started")
        await self.db.add_attempt("1", "10", "manual")
        funnel = (await analytics.report(self.db, "1", time.time() - 60, time.time() + 60))["funnel"]
        self.assertEqual((funnel["started"], funnel["finished"], funnel["verified"], funnel["unfinished"]), (1, 1, 1, 0))

    async def test_a_cut_period_says_so(self):
        end = time.time()
        cut = (await analytics.report(self.db, "1", end - 730 * 86400, end))["range"]
        self.assertEqual((cut["clamped"], cut["start"], cut["end"]), (True, end - analytics.MAX_RANGE_DAYS * 86400, end))
        whole = (await analytics.report(self.db, "1", end - 30 * 86400, end))["range"]
        self.assertEqual((whole["clamped"], whole["start"]), (False, end - 30 * 86400))
