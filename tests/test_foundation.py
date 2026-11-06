import asyncio
import base64
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from altwarden import access, catalog, crypto, db, settings
from fakes import DB_KEY


class HkdfVectors(unittest.TestCase):
    """RFC 5869 appendix A, test cases 1 and 3."""

    def test_case_1(self):
        okm = crypto.hkdf_sha256(bytes.fromhex("0b" * 22), salt=bytes.fromhex("000102030405060708090a0b0c"),
                                 info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), length=42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_case_3_no_salt_or_info(self):
        okm = crypto.hkdf_sha256(bytes.fromhex("0b" * 22), length=42)
        self.assertEqual(okm.hex(), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")


class Keys(unittest.TestCase):
    def setUp(self):
        self.ring = crypto.Keyring(b"k" * 32)

    def test_same_value_differs_between_servers(self):
        self.assertNotEqual(self.ring.digest(1, "ip", "203.0.113.9"), self.ring.digest(2, "ip", "203.0.113.9"))

    def test_same_value_differs_between_kinds(self):
        self.assertNotEqual(self.ring.digest(1, "ip", "x"), self.ring.digest(1, "cookie", "x"))

    def test_digest_is_stable_and_reveals_nothing(self):
        first = self.ring.digest(1, "ip", "203.0.113.9")
        self.assertEqual(first, self.ring.digest(1, "ip", "203.0.113.9"))
        self.assertNotIn("203.0.113.9", first)
        int(first, 16)
        self.assertEqual(len(first), crypto.DIGEST_BYTES * 2)

    def test_another_master_key_cannot_reproduce_a_digest(self):
        other = crypto.Keyring(b"j" * 32)
        self.assertNotEqual(self.ring.digest(1, "ip", "203.0.113.9"), other.digest(1, "ip", "203.0.113.9"))

    def test_device_cookie_round_trip_and_forgery(self):
        cookie = self.ring.new_device_cookie()
        self.assertIsNotNone(self.ring.read_device_cookie(cookie))
        value = cookie.split(".")[0]
        self.assertIsNone(self.ring.read_device_cookie(f"{value}.forged"))
        self.assertIsNone(self.ring.read_device_cookie("no-dot"))
        self.assertIsNone(self.ring.read_device_cookie(None))
        self.assertIsNone(crypto.Keyring(b"j" * 32).read_device_cookie(cookie))

    def test_master_key_rules(self):
        good = crypto.new_master_key()
        self.assertEqual(len(crypto.decode_master_key(good)), 32)
        with self.assertRaises(ValueError):
            crypto.decode_master_key(base64.b64encode(b"short").decode())
        with self.assertRaises(ValueError):
            crypto.decode_master_key("not base64 at all!")

    def test_token_hash_is_sha256(self):
        self.assertEqual(crypto.token_hash("abc"), hashlib.sha256(b"abc").hexdigest())


class NetworkKeying(unittest.TestCase):
    def test_ipv4_stays_exact(self):
        self.assertEqual(crypto.network_of("203.0.113.9"), "203.0.113.9")

    def test_ipv6_collapses_to_its_64(self):
        self.assertEqual(crypto.network_of("2001:db8:1:2:aaaa::1"), crypto.network_of("2001:db8:1:2:bbbb::2"))
        self.assertNotEqual(crypto.network_of("2001:db8:1:2::1"), crypto.network_of("2001:db8:1:3::1"))

    def test_mapped_ipv4(self):
        self.assertEqual(crypto.network_of("::ffff:203.0.113.9"), "203.0.113.9")


class ProofOfWork(unittest.TestCase):
    def test_leading_zero_bits(self):
        self.assertEqual(crypto.leading_zero_bits(b"\x00\x00\xff"), 16)
        self.assertEqual(crypto.leading_zero_bits(b"\x00\x0f"), 12)
        self.assertEqual(crypto.leading_zero_bits(b"\x80"), 0)

    def test_solution_found_and_checked(self):
        salt = "abc"
        counter = next(n for n in range(1 << 20) if crypto.pow_solved(salt, n, 8))
        self.assertTrue(crypto.pow_solved(salt, counter, 8))
        self.assertFalse(crypto.pow_solved(salt, -1, 0))


class SettingsDocument(unittest.TestCase):
    def test_defaults_survive_normalize_unchanged(self):
        base = settings.defaults()
        self.assertEqual(settings.normalize(base), base)

    def test_junk_becomes_a_complete_document(self):
        for junk in (None, 7, "x", [], {"core": "nope", "checks": 3, "messages": []}):
            result = settings.normalize(junk)
            self.assertEqual(set(result["checks"]), set(catalog.CHECK_IDS))

    def test_numbers_are_clamped(self):
        doc = settings.defaults()
        doc["checks"]["account_age"]["days"] = 999999
        doc["core"]["auto_kick"]["minutes"] = 1
        doc["checks"]["threat"]["bot_score"] = 0
        result = settings.normalize(doc)
        self.assertEqual(result["checks"]["account_age"]["days"], 3650)
        self.assertEqual(result["core"]["auto_kick"]["minutes"], 5)
        self.assertEqual(result["checks"]["threat"]["bot_score"], 1)

    def test_unknown_action_is_refused(self):
        doc = settings.defaults()
        doc["checks"]["vpn"]["action"] = "nuke"
        self.assertEqual(settings.normalize(doc)["checks"]["vpn"]["action"], settings.defaults()["checks"]["vpn"]["action"])

    def test_snowflake_rules(self):
        doc = settings.defaults()
        doc["core"]["verified_role"] = "123"
        doc["core"]["channel"] = "970000000000000111"
        result = settings.normalize(doc)
        self.assertIsNone(result["core"]["verified_role"])
        self.assertEqual(result["core"]["channel"], "970000000000000111")

    def test_image_links_must_be_https(self):
        doc = settings.defaults()
        doc["messages"]["verification"]["image"] = "http://example.com/a.png"
        self.assertEqual(settings.normalize(doc)["messages"]["verification"]["image"], "")

    def test_every_preset_is_recognized_after_applying_it(self):
        for name in catalog.PRESETS:
            doc = settings.apply_preset(settings.defaults(), name)
            self.assertEqual(settings.detect_preset(doc), name)

    def test_changing_one_check_makes_it_custom(self):
        doc = settings.apply_preset(settings.defaults(), "standard")
        doc["checks"]["vpn"]["action"] = "ban"
        self.assertEqual(settings.detect_preset(doc), "custom")

    def test_preset_leaves_server_values_alone(self):
        doc = settings.defaults()
        doc["core"]["verified_role"] = "970000000000000111"
        doc["checks"]["geogate"]["countries"] = ["RU"]
        result = settings.apply_preset(doc, "strict")
        self.assertEqual(result["core"]["verified_role"], "970000000000000111")
        self.assertEqual(result["checks"]["geogate"]["countries"], ["RU"])

    def test_gentle_preset_stops_only_what_its_blurb_names(self):
        doc = settings.apply_preset(settings.defaults(), "gentle")
        on = {check_id for check_id, check in doc["checks"].items() if check["enabled"]}
        self.assertEqual(on, {"mfa", "disposable_email", "alt_account", "fake_ua"})
        self.assertEqual(doc["checks"]["mfa"]["action"], "deny", "no preset changes this check")

    def test_problems_list(self):
        self.assertEqual(len(settings.problems(settings.defaults())), 2)

    def test_paused_checks_follow_mode(self):
        doc = settings.defaults()
        doc["core"]["mode"] = "button"
        paused = settings.paused_checks(doc)
        self.assertIn("vpn", paused)
        self.assertNotIn("account_age", paused)

    def test_export_round_trip_keeps_server_specifics(self):
        source = settings.apply_preset(settings.defaults(), "strict")
        source["core"]["verified_role"] = "111111111111111111"
        source["core"]["cooldown"]["seconds"] = 120
        target = settings.defaults()
        target["core"]["verified_role"] = "222222222222222222"
        target["core"]["channel"] = "333333333333333333"
        target["messages"]["verification"]["title"] = "Ours"
        merged = settings.import_code(settings.normalize(target), settings.export_code(source))
        self.assertEqual(merged["core"]["verified_role"], "222222222222222222")
        self.assertEqual(merged["core"]["channel"], "333333333333333333")
        self.assertEqual(merged["messages"]["verification"]["title"], "Ours")
        self.assertEqual(merged["core"]["cooldown"]["seconds"], 120)
        self.assertEqual(merged["preset"], "strict")

    def test_export_holds_no_ids(self):
        doc = settings.defaults()
        doc["core"]["verified_role"] = "111111111111111111"
        doc["core"]["logs"]["modules"]["general"] = "222222222222222222"
        code = settings.export_code(doc)
        text = __import__("zlib").decompress(base64.urlsafe_b64decode(code[4:])).decode()
        self.assertNotIn("111111111111111111", text)
        self.assertNotIn("222222222222222222", text)

    def test_bad_codes_are_refused(self):
        for bad in ("hello", "AW1.!!!", "AW1." + base64.urlsafe_b64encode(b"not zlib").decode()):
            with self.assertRaises(ValueError):
                settings.import_code(settings.defaults(), bad)

    def test_compression_bomb_is_refused(self):
        bomb = __import__("zlib").compress(b"0" * (settings.MAX_EXPORT_BYTES * 4), 9)
        with self.assertRaises(ValueError):
            settings.import_code(settings.defaults(), "AW1." + base64.urlsafe_b64encode(bomb).decode())

    def test_diff_lists_changes(self):
        before = settings.defaults()
        after = settings.normalize(before)
        after["checks"]["vpn"]["action"] = "ban"
        self.assertEqual(settings.diff(before, after)[0]["path"], "checks.vpn.action")


class AccessRules(unittest.TestCase):
    def viewer(self, roles=(), perms=(), owner=False, user="5"):
        return access.Viewer(user, frozenset(roles), frozenset(perms), owner)

    def test_owner_and_admin_always_pass(self):
        rule = {"required": ["manage_guild"], "overrides": [{"type": "everyone", "id": None, "allow": False}]}
        self.assertTrue(access.allowed(rule, self.viewer(owner=True)))
        self.assertTrue(access.allowed(rule, self.viewer(perms=["administrator"])))

    def test_required_permissions_all_needed(self):
        rule = {"required": ["manage_guild", "manage_roles"], "overrides": []}
        self.assertFalse(access.allowed(rule, self.viewer(perms=["manage_guild"])))
        self.assertTrue(access.allowed(rule, self.viewer(perms=["manage_guild", "manage_roles"])))

    def test_member_override_wins_over_roles(self):
        rule = {"required": ["manage_guild"], "overrides": [
            {"type": "role", "id": "9", "allow": True}, {"type": "user", "id": "5", "allow": False}]}
        self.assertFalse(access.allowed(rule, self.viewer(roles=["9"])))

    def test_allowed_role_beats_blocked_role(self):
        rule = {"required": [], "overrides": [
            {"type": "role", "id": "1", "allow": False}, {"type": "role", "id": "2", "allow": True}]}
        self.assertTrue(access.allowed(rule, self.viewer(roles=["1", "2"])))
        self.assertFalse(access.allowed(rule, self.viewer(roles=["1"])))

    def test_everyone_override_before_required(self):
        rule = {"required": ["manage_guild"], "overrides": [{"type": "everyone", "id": None, "allow": True}]}
        self.assertTrue(access.allowed(rule, self.viewer()))

    def test_no_required_and_no_override_means_owner_only(self):
        self.assertFalse(access.allowed({"required": [], "overrides": []}, self.viewer(perms=["manage_guild"])))

    def test_stored_rules_round_trip_through_normalize(self):
        doc = settings.defaults()
        doc["permissions"]["pages"]["settings"] = {"edit": {"required": ["manage_guild", "bogus"], "overrides": [
            {"type": "role", "id": "970000000000000111", "allow": True}, {"type": "alien", "id": "1"}]}}
        rule = settings.page_rule(settings.normalize(doc), "settings", "edit")
        self.assertEqual(rule["required"], ["manage_guild"])
        self.assertEqual(len(rule["overrides"]), 1)


class Storage(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.db = db.Database(os.path.join(self.dir.name, "t.db"), DB_KEY)
        await self.db.open()

    async def asyncTearDown(self):
        await self.db.close()
        self.dir.cleanup()

    async def test_no_column_can_hold_a_raw_identifier(self):
        rows = await self.db.all("SELECT name FROM sqlite_master WHERE type = 'table'")
        for row in rows:
            for column in await self.db.all(f"PRAGMA table_info({row['name']})"):
                self.assertNotIn(column["name"].lower(), ("ip", "ip_address", "email", "refresh_token", "access_token", "fingerprint", "cookie"))

    async def test_settings_round_trip(self):
        await self.db.save_settings("1", settings.defaults(), setup_done=True)
        row = await self.db.guild("1")
        self.assertEqual(row["settings"]["preset"], "standard")
        self.assertEqual(row["setup_done"], 1)

    async def test_match_ignores_self_and_expired(self):
        future, past = time.time() + 100, time.time() - 100
        await self.db.store_identifier("1", "10", "cookie", "aa", future)
        await self.db.store_identifier("1", "11", "cookie", "aa", past)
        await self.db.store_identifier("2", "12", "cookie", "aa", future)
        self.assertEqual(await self.db.matches("1", "99", "cookie", "aa"), ["10"])
        self.assertEqual(await self.db.matches("1", "10", "cookie", "aa"), [])

    async def test_ban_extends_identifier_life(self):
        soon = time.time() + 10
        await self.db.store_identifier("1", "10", "cookie", "aa", soon)
        await self.db.record_ban("1", "10", keep_days=30)
        row = await self.db.one("SELECT expires_at FROM identifiers")
        self.assertGreater(row["expires_at"], soon + 86400)
        self.assertTrue(await self.db.is_banned("1", "10"))

    async def test_purge_removes_expired_rows(self):
        await self.db.store_identifier("1", "10", "ip", "aa", time.time() - 1)
        await self.db.store_identifier("1", "10", "cookie", "bb", time.time() + 100)
        doc = settings.defaults()
        await self.db.conn.execute("INSERT INTO attempts (guild_id, user_id, at, outcome) VALUES ('1', '10', 1, 'failed')")
        await self.db.conn.commit()
        removed = await self.db.purge_expired({"1": doc})
        self.assertEqual(removed["identifiers"], 1)
        self.assertEqual(removed["attempts"], 1)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 1)

    async def test_trusted_pair_is_order_free(self):
        await self.db.trust_pair("1", "20", "10", "5")
        self.assertTrue(await self.db.is_trusted_pair("1", "10", "20"))
        self.assertFalse(await self.db.is_trusted_pair("1", "10", "30"))

    async def test_forget_guild_clears_everything(self):
        await self.db.save_settings("1", settings.defaults())
        await self.db.store_identifier("1", "10", "ip", "aa", time.time() + 100)
        await self.db.add_attempt("1", "10", "passed")
        await self.db.forget_guild("1")
        self.assertIsNone(await self.db.guild("1"))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts"), 0)


if __name__ == "__main__":
    unittest.main()
