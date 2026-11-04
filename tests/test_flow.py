"""The whole journey, run through the real service and web code against a fake Discord."""
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from altwarden import crypto, db, notices, settings
from altwarden.netintel import NetIntel, load_lists
from altwarden.service import Service
from altwarden.web.app import BROWSER_COOKIE, DEVICE_COOKIE, FLOW_COOKIE, SESSION_COOKIE, build_app
from altwarden.web.oauth import DiscordOAuth
from fakes import (CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, UNVERIFIED_ROLE, VERIFIED_ROLE, FakeDiscordApi,
                   FakePort)
from test_detection import clean_report

PUBLIC = "https://altwarden.test"


def solve(salt: str, bits: int) -> int:
    return next(n for n in range(1 << 24) if crypto.pow_solved(salt, n, bits))


class Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.TemporaryDirectory()
        folder = Path(self.dir.name)
        (folder / "lists").mkdir()
        (folder / "lists" / "vpn-x4b-ipv4.txt").write_text("45.33.32.0/24\n")
        (folder / "lists" / "disposable.txt").write_text("mailinator.com\n")
        (folder / "lists" / "country-ipv4.csv").write_text("3221225984,3221226239,US\n")
        self.db = db.Database(folder / "t.db")
        await self.db.open()
        self.keys = crypto.Keyring(b"k" * 32)
        self.net = NetIntel(folder / "lists")
        self.net.lists = load_lists(folder / "lists")
        self.port = FakePort()
        self.service = Service(self.db, self.keys, self.net, self.port, PUBLIC)
        self.service_pow(4)
        self.doc = settings.defaults()
        self.doc["core"].update(verified_role=VERIFIED_ROLE, channel=CHANNEL)
        self.doc["core"]["logs"] = {"enabled": True, "modules": {name: LOG_CHANNEL for name in ("general", "success", "vpn", "alt_account", "incognito", "raid", "settings", "automation")}}
        await self.db.save_settings(GUILD, settings.normalize(self.doc), setup_done=True)
        self.port.add_member(OLD_USER)

        self.discord = FakeDiscordApi()
        self.discord_server = TestServer(self.discord.app())
        await self.discord_server.start_server()
        self.http = aiohttp.ClientSession()
        self.oauth = DiscordOAuth(self.http, "123", "client-secret", api=str(self.discord_server.make_url("")).rstrip("/"))
        self.app = build_app(self.service, self.keys, self.oauth, trust_proxy=True)
        self.app["http"] = self.http
        self.posted = []

        async def post_message(guild_id, which):
            self.posted.append(which)
        self.app["post_message"] = post_message
        self.client = TestClient(TestServer(self.app), cookie_jar=aiohttp.CookieJar(unsafe=True))
        await self.client.start_server()

    def database_dump(self) -> str:
        connection = sqlite3.connect(self.db.path)
        try:
            return "\n".join(connection.iterdump())
        finally:
            connection.close()

    def service_pow(self, bits):
        import altwarden.service as module
        module.POW_BITS = bits

    async def asyncTearDown(self):
        await self.client.close()
        await self.discord_server.close()
        await self.http.close()
        await self.db.close()
        self.dir.cleanup()

    async def change(self, **checks):
        document = await self.service.get_settings(GUILD)
        for check_id, options in checks.items():
            document["checks"][check_id].update(options)
        await self.service.save_settings(GUILD, document)

    def cookie_header(self, *names):
        return {"Cookie": "; ".join(f"{name}={value}" for name, value in self.jar.items() if name in names)}

    async def sign_in(self, token, user=OLD_USER, ip="203.0.113.9"):
        """Walk the sign-in the way a browser does. Cookies are carried by hand, since __Host- needs https."""
        self.jar = getattr(self, "jar", {})
        response = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        self.assertEqual(response.status, 302)
        location = response.headers["Location"]
        state = parse_qs(urlsplit(location).query)["state"][0]
        self.jar[FLOW_COOKIE] = response.cookies[FLOW_COOKIE].value
        self.discord.user["id"] = user
        response = await self.client.get("/verify/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers=self.cookie_header(FLOW_COOKIE, BROWSER_COOKIE))
        if BROWSER_COOKIE in response.cookies:
            self.jar[BROWSER_COOKIE] = response.cookies[BROWSER_COOKIE].value
        return response

    async def attempt(self, token, report=None, ip="203.0.113.9", ua=None):
        headers = {"X-Forwarded-For": ip, "User-Agent": ua or clean_report()["nav"]["ua"]}
        headers.update(self.cookie_header(DEVICE_COOKIE, BROWSER_COOKIE))
        response = await self.client.post(f"/api/verify/{token}/challenge", headers=headers)
        self.assertEqual(response.status, 200, await response.text())
        challenge = await response.json()
        if DEVICE_COOKIE in response.cookies:
            self.jar[DEVICE_COOKIE] = response.cookies[DEVICE_COOKIE].value
            headers.update(self.cookie_header(DEVICE_COOKIE, BROWSER_COOKIE))
        body = {"nonce": challenge["nonce"], "counter": solve(challenge["salt"], challenge["bits"]), "report": report or clean_report()}
        return await self.client.post(f"/api/verify/{token}/submit", json=body, headers=headers)

    async def link_for(self, user=OLD_USER):
        document = await self.service.get_settings(GUILD)
        url, _ = await self.service.new_link(GUILD, user, document)
        return url.rsplit("/", 1)[1]

    async def verify_through(self, user=OLD_USER, report=None, ip="203.0.113.9"):
        token = await self.link_for(user)
        response = await self.sign_in(token, user=user)
        self.assertIn(f"/v/{token}", response.headers["Location"])
        result = await self.attempt(token, report, ip)
        self.assertEqual(result.status, 200, await result.text())
        return await result.json()


class HappyPath(Base):
    async def test_join_sends_a_private_link(self):
        member = self.port.add_member(OTHER_USER)
        await self.service.on_join(member)
        user, notice = self.port.dms[0]
        self.assertEqual(user, OTHER_USER)
        self.assertTrue(notice.buttons[0].url.startswith(f"{PUBLIC}/v/"))

    async def test_closed_dms_ping_in_the_channel(self):
        self.port.dm_open = False
        await self.service.on_join(self.port.add_member(OTHER_USER))
        channel, notice = self.port.sent[-1]
        self.assertEqual(channel, CHANNEL)
        self.assertIn(OTHER_USER, notice.content)
        self.assertEqual(notice.delete_after, 30)

    async def test_full_verification(self):
        result = await self.verify_through()
        self.assertEqual(result["status"], "verified")
        self.assertIn(("add_role", OLD_USER, VERIFIED_ROLE), self.port.calls)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "verified")
        self.assertEqual(self.port.dms[-1][0], OLD_USER)
        titles = [notice.embeds[0]["title"] for channel, notice in self.port.sent if channel == LOG_CHANNEL]
        self.assertIn("Member verified", titles)

    async def test_oauth_token_is_revoked_and_never_stored(self):
        await self.verify_through()
        self.assertEqual(self.discord.revoked, ["fake-access"])
        dump = self.database_dump()
        self.assertNotIn("fake-access", dump)
        self.assertNotIn("fake-refresh", dump)

    async def test_no_raw_identifier_reaches_the_database(self):
        self.doc = await self.service.get_settings(GUILD)
        await self.change(disposable_email={"enabled": True, "action": "deny"})
        await self.verify_through(ip="203.0.113.77")
        dump = self.database_dump()
        self.assertNotIn("203.0.113.77", dump)
        self.assertNotIn("someone@example.org", dump)
        self.assertNotIn("example.org", dump)
        self.assertNotIn(clean_report()["fp"]["id"], dump)
        self.assertNotIn(self.jar[DEVICE_COOKIE].split(".")[0], dump)

    async def test_email_scope_only_when_the_check_is_on(self):
        token = await self.link_for()
        await self.change(disposable_email={"enabled": False})
        response = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        self.assertEqual(parse_qs(urlsplit(response.headers["Location"]).query)["scope"], ["identify"])
        await self.change(disposable_email={"enabled": True})
        response = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        self.assertEqual(parse_qs(urlsplit(response.headers["Location"]).query)["scope"], ["identify email"])

    async def test_digests_expire_on_schedule(self):
        await self.verify_through()
        rows = await self.db.all("SELECT kind, expires_at FROM identifiers")
        by_kind = {row["kind"]: row["expires_at"] for row in rows}
        self.assertLess(by_kind["ip"], time.time() + 31 * 86400)
        self.assertGreater(by_kind["fingerprint"], time.time() + 300 * 86400)


class SignInGuards(Base):
    async def test_callback_needs_the_browser_that_started(self):
        token = await self.link_for()
        response = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        response = await self.client.get("/verify/callback", params={"code": "abc", "state": state}, allow_redirects=False)
        self.assertEqual(response.headers["Location"], "/help/link-expired")
        self.assertEqual(self.discord.exchanged, [])

    async def test_state_is_single_use(self):
        token = await self.link_for()
        await self.sign_in(token)
        flow = self.jar[FLOW_COOKIE]
        state = flow.split(".")[0]
        response = await self.client.get("/verify/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={flow}"})
        self.assertEqual(response.headers["Location"], "/help/link-expired")

    async def test_wrong_account(self):
        token = await self.link_for(OLD_USER)
        response = await self.sign_in(token, user=OTHER_USER)
        self.assertIn("signin=wrong", response.headers["Location"])
        self.assertIsNone((await self.service.session(token))["account"])

    async def test_declined_sign_in(self):
        token = await self.link_for()
        response = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        flow = response.cookies[FLOW_COOKIE].value
        response = await self.client.get("/verify/callback", params={"error": "access_denied", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={flow}"})
        self.assertIn("signin=declined", response.headers["Location"])

    async def test_discord_failure_is_reported(self):
        self.discord.fail_exchange = True
        response = await self.sign_in(await self.link_for())
        self.assertIn("signin=failed", response.headers["Location"])

    async def test_expired_link(self):
        token = await self.link_for()
        await self.db.run("UPDATE sessions SET expires_at = 1")
        data = await (await self.client.get(f"/api/verify/{token}")).json()
        self.assertEqual(data["step"], "expired")

    async def test_unknown_link(self):
        data = await (await self.client.get("/api/verify/" + "a" * 43)).json()
        self.assertEqual(data["step"], "expired")

    async def test_new_link_kills_the_old_one(self):
        first = await self.link_for()
        await self.link_for()
        self.assertIsNone(await self.service.session(first))


class SubmissionGuards(Base):
    async def signed_in(self):
        token = await self.link_for()
        await self.sign_in(token)
        return token

    async def test_nonce_cannot_be_replayed(self):
        token = await self.signed_in()
        cookies = self.cookie_header(BROWSER_COOKIE)
        response = await self.client.post(f"/api/verify/{token}/challenge", headers=cookies)
        challenge = await response.json()
        body = {"nonce": challenge["nonce"], "counter": solve(challenge["salt"], challenge["bits"]), "report": clean_report()}
        first = await self.client.post(f"/api/verify/{token}/submit", json=body, headers=cookies)
        self.assertEqual(first.status, 200)
        second = await self.client.post(f"/api/verify/{token}/submit", json=body, headers=cookies)
        self.assertEqual(second.status, 409)

    async def test_unsolved_puzzle_is_refused(self):
        token = await self.signed_in()
        cookies = self.cookie_header(BROWSER_COOKIE)
        challenge = await (await self.client.post(f"/api/verify/{token}/challenge", headers=cookies)).json()
        wrong = next(n for n in range(1 << 20) if not crypto.pow_solved(challenge["salt"], n, challenge["bits"]))
        response = await self.client.post(f"/api/verify/{token}/submit", json={"nonce": challenge["nonce"], "counter": wrong, "report": {}}, headers=cookies)
        self.assertEqual(response.status, 400)

    async def test_check_cannot_run_before_sign_in(self):
        token = await self.link_for()
        self.assertEqual((await self.client.post(f"/api/verify/{token}/challenge")).status, 409)

    async def test_oversized_report_is_refused(self):
        token = await self.signed_in()
        await self.client.post(f"/api/verify/{token}/challenge")
        response = await self.client.post(f"/api/verify/{token}/submit", data=b"x" * (70 * 1024), headers={"Content-Type": "application/json"})
        self.assertEqual(response.status, 413)

    async def test_junk_body_is_refused(self):
        token = await self.signed_in()
        await self.client.post(f"/api/verify/{token}/challenge")
        response = await self.client.post(f"/api/verify/{token}/submit", data=b"not json", headers={"Content-Type": "application/json"})
        self.assertEqual(response.status, 400)

    async def test_forged_device_cookie_is_ignored(self):
        token = await self.signed_in()
        self.jar[DEVICE_COOKIE] = "forged.value"
        result = await self.attempt(token)
        self.assertEqual(result.status, 200)
        self.assertIsNone(await self.db.scalar("SELECT 1 FROM identifiers WHERE kind = 'cookie' AND digest = ?",
                                               (self.keys.digest(int(GUILD), "cookie", "forged"),)))


class Outcomes(Base):
    async def test_watch_lets_the_member_in_and_logs_it(self):
        await self.change(incognito={"enabled": True, "action": "watch"})
        report = clean_report(private={"isPrivate": True})
        result = await self.verify_through(report=report)
        self.assertEqual(result["status"], "verified")
        titles = [notice.embeds[0]["title"] for _, notice in self.port.sent]
        self.assertIn("Member verified, checks watched", titles)

    async def test_deny_keeps_the_link_for_a_retry(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        first = await (await self.attempt(token, ip="45.33.32.7")).json()
        self.assertEqual((first["status"], first["action"], first["retry"]), ("failed", "deny", True))
        second = await (await self.attempt(token, ip="203.0.113.9")).json()
        self.assertEqual(second["status"], "verified")

    async def test_kick_tells_them_first(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        result = await self.verify_through(ip="45.33.32.7")
        self.assertEqual(result["action"], "kick")
        self.assertTrue(self.port.did("kick"))
        self.assertEqual(self.port.dms[-1][1].embeds[0]["title"], "You weren't verified in Test Server")

    async def test_ban_is_recorded(self):
        await self.change(vpn={"enabled": True, "action": "ban"})
        await self.verify_through(ip="45.33.32.7")
        self.assertTrue(await self.db.is_banned(GUILD, OLD_USER))

    async def test_failed_kick_is_reported_in_the_log(self):
        self.port.kick_works = False
        await self.change(vpn={"enabled": True, "action": "kick"})
        await self.verify_through(ip="45.33.32.7")
        last = self.port.sent[-1][1].embeds[0]
        self.assertIn("failed, usually a missing permission", last["fields"][1]["value"])

    async def test_role_problem_reaches_staff_not_a_false_success(self):
        self.port.role_problem = "AltWarden needs Manage Roles"
        result = await self.verify_through()
        self.assertEqual(result["status"], "problem")
        self.assertNotEqual((await self.db.member(GUILD, OLD_USER))["status"], "verified")

    async def test_hidden_reason_setting(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["show_reason"] = False
        await self.service.save_settings(GUILD, document)
        await self.change(vpn={"enabled": True, "action": "deny"})
        result = await self.verify_through(ip="45.33.32.7")
        self.assertNotIn("VPN", result["message"])

    async def test_attempt_limit_with_role_and_reset(self):
        await self.change(vpn={"enabled": True, "action": "deny"},
                          max_attempts={"enabled": True, "action": "deny", "attempts": 2, "role": UNVERIFIED_ROLE, "reset_minutes": 5})
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token, ip="45.33.32.7")
        await self.attempt(token, ip="45.33.32.7")
        self.assertIn(("add_role", OLD_USER, UNVERIFIED_ROLE), self.port.calls)
        result = await (await self.attempt(token, ip="203.0.113.9")).json()
        self.assertEqual(result["reason"], "max_attempts")
        await self.db.run("UPDATE members SET limit_reached_at = 1")
        result = await (await self.attempt(token, ip="203.0.113.9")).json()
        self.assertEqual(result["status"], "verified")

    async def test_cooldown_blocks_without_counting(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["cooldown"].update(enabled=True, seconds=300)
        await self.service.save_settings(GUILD, document)
        await self.change(vpn={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token, ip="45.33.32.7")
        result = await (await self.attempt(token, ip="203.0.113.9")).json()
        self.assertEqual(result["status"], "cooldown")
        self.assertGreater(result["seconds_left"], 200)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], 1)


class AltFlow(Base):
    async def test_same_browser_second_account_is_caught(self):
        await self.change(alt_account={"enabled": True, "alt_action": "deny", "action": "deny"})
        self.assertEqual((await self.verify_through(OLD_USER))["status"], "verified")
        self.port.add_member(OTHER_USER)
        result = await self.verify_through(OTHER_USER)
        self.assertEqual((result["status"], result["reason"]), ("failed", "alt_account"))
        link = await self.db.one("SELECT * FROM links")
        self.assertEqual((link["main_id"], link["alt_id"]), (OLD_USER, OTHER_USER))
        self.assertEqual(link["confidence"], "confirmed")

    async def test_sibling_on_the_same_connection_passes(self):
        await self.change(alt_account={"enabled": True, "alt_action": "ban", "action": "ban"})
        await self.verify_through(OLD_USER)
        self.port.add_member(OTHER_USER)
        self.jar.pop(DEVICE_COOKIE)
        report = clean_report(fp={"id": "b" * 32}, gpu={"renderer": "Intel Iris"}, worker={})
        result = await self.verify_through(OTHER_USER, report=report)
        self.assertEqual(result["status"], "verified")

    async def test_alt_of_a_banned_account_is_banned(self):
        await self.change(alt_account={"enabled": True, "alt_action": "deny", "action": "deny", "banned_alt_action": "ban"})
        await self.verify_through(OLD_USER)
        await self.service.on_ban(GUILD, OLD_USER)
        self.port.add_member(OTHER_USER)
        result = await self.verify_through(OTHER_USER)
        self.assertEqual(result["action"], "ban")
        self.assertIn(OTHER_USER, self.port.banned)

    async def test_ban_only_known_to_discord_is_picked_up(self):
        await self.change(alt_account={"enabled": True, "alt_action": "deny", "action": "deny", "banned_alt_action": "ban"})
        await self.verify_through(OLD_USER)
        self.port.banned.add(OLD_USER)
        self.port.add_member(OTHER_USER)
        self.assertEqual((await self.verify_through(OTHER_USER))["action"], "ban")

    async def test_trusted_pair_stays_clear(self):
        await self.change(alt_account={"enabled": True, "alt_action": "ban", "action": "ban"})
        await self.verify_through(OLD_USER)
        await self.db.trust_pair(GUILD, OLD_USER, OTHER_USER, STAFF)
        self.port.add_member(OTHER_USER)
        self.assertEqual((await self.verify_through(OTHER_USER))["status"], "verified")

    async def test_two_servers_cannot_be_linked(self):
        first = self.keys.digest(1, "cookie", "same")
        second = self.keys.digest(2, "cookie", "same")
        self.assertNotEqual(first, second)


class StaffTools(Base):
    async def test_manual_verify(self):
        self.assertIsNone(await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff"))
        self.assertIn(("add_role", OLD_USER, VERIFIED_ROLE), self.port.calls)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["method"], "staff")

    async def test_reset_clears_records_and_tells_the_member(self):
        await self.verify_through()
        told = await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertTrue(told)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts"), 0)
        self.assertIn(("remove_role", OLD_USER, VERIFIED_ROLE), self.port.calls)

    async def test_bypass_skips_only_chosen_checks_and_hides_the_link_from_logs(self):
        await self.change(vpn={"enabled": True, "action": "deny"}, incognito={"enabled": True, "action": "deny"})
        url, delivered = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 2, "dm", STAFF, "staff")
        self.assertTrue(delivered)
        token = url.rsplit("/", 1)[1]
        for _, notice in self.port.sent:
            self.assertNotIn(token, json.dumps(notice.embeds))
        await self.sign_in(token)
        passed = await (await self.attempt(token, ip="45.33.32.7")).json()
        self.assertEqual(passed["status"], "verified")

    async def test_bypass_still_runs_the_rest(self):
        await self.change(vpn={"enabled": True, "action": "deny"}, incognito={"enabled": True, "action": "deny"})
        url, _ = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 2, "dm", STAFF, "staff")
        token = url.rsplit("/", 1)[1]
        await self.sign_in(token)
        result = await (await self.attempt(token, clean_report(private={"isPrivate": True}), ip="45.33.32.7")).json()
        self.assertEqual(result["reason"], "incognito")

    async def test_auto_kick_survives_restart_and_skips_the_verified(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["auto_kick"].update(enabled=True, minutes=5)
        await self.service.save_settings(GUILD, document)
        await self.service.on_join(self.port.add_member(OTHER_USER))
        await self.db.run("UPDATE members SET kick_at = 1 WHERE user_id = ?", (OTHER_USER,))
        fresh = Service(self.db, self.keys, self.net, self.port, PUBLIC)
        await fresh.tick()
        self.assertTrue(self.port.did("kick"))
        self.port.calls.clear()
        await self.db.run("UPDATE members SET kick_at = 1, status = 'verified' WHERE user_id = ?", (OTHER_USER,))
        await fresh.tick()
        self.assertFalse(self.port.did("kick"))

    async def test_a_verified_member_who_rejoins_verifies_again(self):
        await self.verify_through()
        self.port.calls.clear()
        self.port.dms.clear()
        await self.service.on_join(self.port.add_member(OLD_USER))
        self.assertNotIn(("add_role", OLD_USER, VERIFIED_ROLE), self.port.calls)
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual(record["status"], "pending")
        self.assertTrue(self.port.dms, "they get a new link, like any new member")
        self.assertIsNotNone(record["first_verified_at"], "they still count as the account that verified first")

    async def test_an_imported_member_who_rejoins_verifies_again(self):
        await self.service.import_members(GUILD, [OTHER_USER], STAFF, "staff")
        self.port.calls.clear()
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertNotIn(("add_role", OTHER_USER, VERIFIED_ROLE), self.port.calls)
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["status"], "pending")

    async def test_rejoin_is_remembered_when_a_server_turns_that_on(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["remember_rejoin"] = True
        await self.service.save_settings(GUILD, document)
        await self.verify_through()
        self.port.calls.clear()
        self.port.dms.clear()
        await self.service.on_join(self.port.add_member(OLD_USER))
        self.assertIn(("add_role", OLD_USER, VERIFIED_ROLE), self.port.calls)
        self.assertEqual(self.port.dms, [])

    async def test_import_members(self):
        count = await self.service.import_members(GUILD, [OLD_USER, OTHER_USER], STAFF, "staff")
        self.assertEqual(count, 2)
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["status"], "verified")
        self.assertEqual(await self.service.import_members(GUILD, [OLD_USER], STAFF, "staff"), 0)

    async def test_button_mode(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["mode"] = "button"
        await self.service.save_settings(GUILD, document)
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(result.status, "verified")

    async def test_instant_mode(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["mode"] = "instant"
        await self.service.save_settings(GUILD, document)
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn(("add_role", OTHER_USER, VERIFIED_ROLE), self.port.calls)

    async def test_press_verify_gives_a_link_in_web_mode(self):
        outcome = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertTrue(outcome.startswith(f"{PUBLIC}/v/"))

    async def test_press_verify_when_already_verified(self):
        member = self.port.add_member(OLD_USER, roles=(VERIFIED_ROLE,))
        self.assertEqual((await self.service.press_verify(member)).status, "already")


class Honeypot(Base):
    async def turn_on(self, action="ban", roles=()):
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=LOG_CHANNEL, action=action, whitelist_roles=list(roles))
        document["core"]["logs"]["modules"]["honeypot"] = LOG_CHANNEL
        await self.service.save_settings(GUILD, document)

    async def test_post_is_deleted_and_acted_on(self):
        await self.turn_on("ban")
        await self.service.honeypot_hit(GUILD, OLD_USER, "x", LOG_CHANNEL, "55", role_ids=())
        self.assertTrue(self.port.did("delete_message"))
        self.assertEqual(self.port.did("ban")[0][3], 3600)

    async def test_softban_unbans_again(self):
        await self.turn_on("softban")
        await self.service.honeypot_hit(GUILD, OLD_USER, "x", LOG_CHANNEL, "55", role_ids=())
        self.assertTrue(self.port.did("ban") and self.port.did("unban"))

    async def test_whitelisted_role_is_ignored(self):
        await self.turn_on("ban", roles=[VERIFIED_ROLE])
        await self.service.honeypot_hit(GUILD, OLD_USER, "x", LOG_CHANNEL, "55", role_ids=(VERIFIED_ROLE,))
        self.assertFalse(self.port.did("delete_message"))

    async def test_webhook_is_only_logged(self):
        await self.turn_on("ban")
        await self.service.honeypot_hit(GUILD, "1", "hook", LOG_CHANNEL, "55", role_ids=(), is_webhook=True)
        self.assertFalse(self.port.did("ban"))
        self.assertTrue(self.port.did("delete_message"))


class Raid(Base):
    async def test_join_spike_turns_raid_mode_on_and_tightens_rules(self):
        document = await self.service.get_settings(GUILD)
        document["raid"].update(joins=3, seconds=60, min_account_days=99999 if False else 365)
        await self.service.save_settings(GUILD, document)
        young = str((int(time.time() * 1000) - 1420070400000) << 22)
        for index in range(3):
            await self.service.on_join(self.port.add_member(str(int(young) + index)))
        self.assertTrue(await self.service.raid_active(GUILD))
        rules = await self.service.effective(GUILD, document)
        self.assertEqual(rules["checks"]["account_age"]["action"], "kick")
        self.assertIn("Raid mode on", [notice.embeds[0]["title"] for _, notice in self.port.sent if notice.embeds])

    async def test_raid_ends_by_itself(self):
        document = await self.service.get_settings(GUILD)
        await self.service.start_raid(GUILD, document, "test")
        await self.db.set_guild_field(GUILD, "raid_until", time.time() - 1)
        await self.service.tick()
        self.assertFalse(await self.service.raid_active(GUILD))


class Appeals(Base):
    async def failed_member(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        await self.verify_through(ip="45.33.32.7")

    async def test_appeal_reaches_staff_with_buttons(self):
        await self.failed_member()
        self.assertIsNone(await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN."))
        card = self.port.sent[-1][1]
        self.assertEqual(card.embeds[0]["title"], "New appeal")
        self.assertEqual(len(card.buttons), 3)

    async def test_no_failed_attempt_no_appeal(self):
        self.assertIsNotNone(await self.service.submit_appeal(GUILD, OLD_USER, "someone", "Please let me in right now."))

    async def test_only_one_open_appeal(self):
        await self.failed_member()
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        self.assertIn("already", await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection again."))

    async def test_approval_verifies_and_tells_them(self):
        await self.failed_member()
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        appeal = await self.db.one("SELECT id FROM appeals")
        self.assertIsNone(await self.service.decide_appeal(GUILD, appeal["id"], "approve", STAFF, "staff"))
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "verified")
        self.assertEqual(self.port.dms[-1][1].embeds[0]["title"], "Your appeal was approved")

    async def test_approval_after_kick_is_honored_at_rejoin(self):
        await self.failed_member()
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        self.port.members.pop((GUILD, OLD_USER))
        appeal = await self.db.one("SELECT id FROM appeals")
        await self.service.decide_appeal(GUILD, appeal["id"], "approve", STAFF, "staff")
        self.port.calls.clear()
        await self.service.on_join(self.port.add_member(OLD_USER))
        self.assertIn(("add_role", OLD_USER, VERIFIED_ROLE), self.port.calls)

    async def test_trust_decision_clears_the_link_for_good(self):
        await self.change(alt_account={"enabled": True, "alt_action": "kick", "action": "kick"})
        await self.verify_through(OLD_USER)
        self.port.add_member(OTHER_USER)
        await self.verify_through(OTHER_USER)
        await self.service.submit_appeal(GUILD, OTHER_USER, "other", "We are brothers sharing one computer at home.")
        appeal = await self.db.one("SELECT id FROM appeals")
        await self.service.decide_appeal(GUILD, appeal["id"], "trust", STAFF, "staff")
        self.assertTrue(await self.db.is_trusted_pair(GUILD, OLD_USER, OTHER_USER))

    async def test_decided_appeal_cannot_be_decided_twice(self):
        await self.failed_member()
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        appeal = await self.db.one("SELECT id FROM appeals")
        await self.service.decide_appeal(GUILD, appeal["id"], "deny", STAFF, "staff")
        self.assertIn("already", await self.service.decide_appeal(GUILD, appeal["id"], "approve", STAFF, "staff"))


class OwnData(Base):
    async def test_my_data_lists_what_is_held(self):
        await self.verify_through()
        records = await self.service.my_data(OLD_USER)
        self.assertEqual(records[0]["status"], "verified")
        self.assertTrue(records[0]["stored_hashes"])

    async def test_delete_removes_everything_and_the_role(self):
        await self.verify_through()
        result = await self.service.delete_my_data(OLD_USER)
        self.assertEqual(result["removed"], [GUILD])
        for table in ("identifiers", "attempts", "members"):
            self.assertEqual(await self.db.scalar(f"SELECT COUNT(*) FROM {table}"), 0, table)
        self.assertIn(("remove_role", OLD_USER, VERIFIED_ROLE), self.port.calls)

    async def test_banned_account_cannot_erase_its_ban_evasion_hashes(self):
        await self.verify_through()
        await self.service.on_ban(GUILD, OLD_USER)
        result = await self.service.delete_my_data(OLD_USER)
        self.assertEqual(result["kept_for_ban"], [GUILD])
        self.assertGreater(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts"), 0)


class WebSecurity(Base):
    async def test_every_page_sends_the_security_headers(self):
        for path in ("/v/" + "a" * 43, "/healthz", "/api/verify/" + "a" * 43):
            response = await self.client.get(path)
            csp = response.headers["Content-Security-Policy"]
            self.assertIn("default-src 'none'", csp)
            self.assertIn("script-src 'self'", csp)
            self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    async def test_verify_page_loads_nothing_from_outside(self):
        html = await (await self.client.get("/v/" + "a" * 43)).text()
        for match in re.findall(r'(?:src|href)="([^"]+)"', html):
            self.assertTrue(match.startswith("/") or match.startswith("https://github.com/"), match)

    async def test_no_static_file_loads_third_party_code(self):
        root = Path(__file__).parent.parent / "altwarden" / "web" / "static"
        for path in root.rglob("*.html"):
            text = path.read_text(encoding="utf-8")
            for bad in ("googletagmanager", "google-analytics", "adsbygoogle", "doubleclick", "translate.google", "cdn.jsdelivr", "cdnjs"):
                self.assertNotIn(bad, text, path.name)

    async def test_client_ip_only_trusts_the_local_proxy(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.change(vpn={"enabled": True, "action": "deny"})
        result = await (await self.attempt(token, ip="45.33.32.7")).json()
        self.assertEqual(result["reason"], "vpn")

    async def test_rate_limit(self):
        token = "a" * 43
        codes = [(await self.client.get(f"/api/verify/{token}")).status for _ in range(40)]
        self.assertIn(429, codes)

    async def test_path_cannot_escape_static(self):
        response = await self.client.get("/static/../service.py")
        self.assertIn(response.status, (403, 404))

    async def test_no_cookie_is_readable_by_scripts(self):
        response = await self.client.get(f"/v/{await self.link_for()}/signin", allow_redirects=False)
        morsel = response.cookies[FLOW_COOKIE]
        self.assertTrue(morsel["httponly"] and morsel["secure"])
        self.assertEqual(morsel["samesite"], "Lax")


class Dashboard(Base):
    async def log_in(self, user=STAFF, owner=True, perms=("manage_guild",)):
        self.port.add_member(user, perms=perms, owner=owner)
        self.discord.user["id"] = user
        self.discord.guilds = [{"id": GUILD, "name": "Test Server", "icon": None, "owner": owner, "permissions": "32"}]
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        flow = response.cookies[FLOW_COOKIE].value
        response = await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={flow}"})
        self.session_cookie = {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE].value}"}
        data = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        self.headers = {**self.session_cookie, "X-CSRF-Token": data["csrf"]}
        return data

    async def test_needs_sign_in(self):
        self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/settings")).status, 401)

    async def test_dashboard_token_is_revoked_too(self):
        await self.log_in()
        self.assertEqual(self.discord.revoked, ["fake-access"])

    async def test_session_lists_the_server(self):
        data = await self.log_in()
        self.assertEqual(data["guilds"][0]["id"], GUILD)

    async def test_a_server_without_the_bot_isnt_offered(self):
        await self.log_in()
        self.discord.guilds = [{"id": GUILD, "name": "Test Server", "icon": None, "owner": True, "permissions": "32"},
                               {"id": "999999999999999999", "name": "Someone Else", "icon": None, "owner": True, "permissions": "8"}]
        data = await self.log_in()
        self.assertEqual([guild["id"] for guild in data["guilds"]], [GUILD])
        self.assertNotIn("invite", data)

    async def test_health_warns_when_the_app_is_public(self):
        await self.log_in()
        url = f"/api/guilds/{GUILD}/health"
        self.assertFalse((await (await self.client.get(url, headers=self.session_cookie)).json())["public_bot"])
        self.client.app["public_bot"] = True
        self.assertTrue((await (await self.client.get(url, headers=self.session_cookie)).json())["public_bot"])

    async def csrf(self):
        session = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        return {**self.session_cookie, "X-CSRF-Token": session["csrf"], "Origin": self.origin} if hasattr(self, "origin") else {**self.session_cookie, "X-CSRF-Token": session["csrf"]}

    async def test_a_lookup_key_is_saved_but_never_shown(self):
        await self.log_in()
        url = f"/api/guilds/{GUILD}/lookup-key"
        key = "111111-222222-333333-444444"
        response = await self.client.put(url, json={"key": key}, headers=await self.csrf())
        self.assertEqual(response.status, 200, await response.text())
        self.assertEqual((await response.json())["lookup_key"], {"saved": True, "ending": "4444"})
        self.assertEqual(await self.db.lookup_key(GUILD), key)
        page = await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)
        text = await page.text()
        self.assertNotIn(key, text)
        self.assertEqual((await page.json())["lookup_key"], {"saved": True, "ending": "4444"})
        audit = await (await self.client.get(f"/api/guilds/{GUILD}/audit", headers=self.session_cookie)).text()
        self.assertNotIn(key, audit)
        self.assertNotIn(key, json.dumps([notice.embeds for _, notice in self.port.sent]))
        exported = await self.client.post(f"/api/guilds/{GUILD}/settings/export", json={}, headers=await self.csrf())
        self.assertNotIn(key, await exported.text())

    async def test_a_lookup_key_can_be_removed_and_goes_with_the_server(self):
        await self.log_in()
        url = f"/api/guilds/{GUILD}/lookup-key"
        await self.client.put(url, json={"key": "abcdef-123456"}, headers=await self.csrf())
        response = await self.client.delete(url, headers=await self.csrf())
        self.assertEqual((await response.json())["lookup_key"], {"saved": False, "ending": None})
        self.assertIsNone(await self.db.lookup_key(GUILD))
        await self.db.set_lookup_key(GUILD, "abcdef-123456")
        await self.db.forget_guild(GUILD)
        self.assertIsNone(await self.db.lookup_key(GUILD))

    async def test_a_bad_lookup_key_is_refused(self):
        await self.log_in()
        for key in ("", "short", "has spaces in it", "x" * 101, "semi;colon-1234"):
            response = await self.client.put(f"/api/guilds/{GUILD}/lookup-key", json={"key": key}, headers=await self.csrf())
            self.assertEqual(response.status, 400, key)
        self.assertIsNone(await self.db.lookup_key(GUILD))

    async def test_a_view_only_member_cant_save_a_lookup_key(self):
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        document["permissions"]["pages"]["settings"] = {"edit": {"required": ["ban_members"], "overrides": []}}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False)
        response = await self.client.put(f"/api/guilds/{GUILD}/lookup-key", json={"key": "abcdef-123456"}, headers=await self.csrf())
        self.assertEqual(response.status, 403)
        self.assertIsNone(await self.db.lookup_key(GUILD))

    async def test_health_says_when_the_lookup_has_no_key(self):
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        document["core"]["external_vpn_lookup"] = True
        await self.service.save_settings(GUILD, document)
        url = f"/api/guilds/{GUILD}/health"
        self.assertTrue((await (await self.client.get(url, headers=self.session_cookie)).json())["lookup_without_key"])
        await self.db.set_lookup_key(GUILD, "abcdef-123456")
        self.assertFalse((await (await self.client.get(url, headers=self.session_cookie)).json())["lookup_without_key"])

    async def test_the_lookup_uses_this_servers_key_and_can_stop_a_member(self):
        asked = []

        async def lookup(ip, key):
            asked.append((ip, key))
            return True

        self.service.proxycheck = lookup
        document = await self.service.get_settings(GUILD)
        document["core"]["external_vpn_lookup"] = True
        document["checks"]["vpn"].update(enabled=True, action="deny")
        await self.service.save_settings(GUILD, document)
        await self.db.set_lookup_key(GUILD, "abcdef-123456")
        result = await self.verify_through()
        self.assertEqual(asked[0][1], "abcdef-123456")
        self.assertEqual(result["status"], "failed", result)

    async def test_the_lookup_isnt_asked_unless_the_server_chose_it(self):
        asked = []

        async def lookup(ip, key):
            asked.append(ip)
            return True

        self.service.proxycheck = lookup
        await self.verify_through()
        self.assertEqual(asked, [])

    async def test_save_settings_writes_the_audit_log(self):
        await self.log_in()
        document = await (await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).json()
        document["settings"]["checks"]["vpn"]["action"] = "ban"
        response = await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": document["settings"]}, headers=self.headers)
        self.assertEqual(response.status, 200, await response.text())
        audit = await (await self.client.get(f"/api/guilds/{GUILD}/audit", headers=self.session_cookie)).json()
        change = audit["entries"][0]["detail"]["changes"][0]
        self.assertEqual((change["path"], change["after"]), ("checks.vpn.action", "ban"))

    async def test_write_without_csrf_is_refused(self):
        await self.log_in()
        response = await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": {}}, headers=self.session_cookie)
        self.assertEqual(response.status, 403)

    async def test_write_from_another_origin_is_refused(self):
        await self.log_in()
        response = await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": {}}, headers={**self.headers, "Origin": "https://evil.test"})
        self.assertEqual(response.status, 403)

    async def test_plain_member_sees_nothing(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=())
        self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).status, 403)
        self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/analytics", headers=self.session_cookie)).status, 403)

    async def test_view_only_member_cannot_save(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild",))
        self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).status, 200)
        response = await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": {}}, headers=self.headers)
        self.assertEqual(response.status, 403)

    async def test_settings_save_cannot_change_permissions(self):
        await self.log_in()
        document = await (await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).json()
        document["settings"]["permissions"] = {"pages": {"settings": {"edit": {"required": []}}}}
        await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": document["settings"]}, headers=self.headers)
        self.assertEqual((await self.service.get_settings(GUILD))["permissions"]["pages"], {})

    async def test_analytics_numbers(self):
        await self.verify_through()
        await self.log_in()
        data = await (await self.client.get(f"/api/guilds/{GUILD}/analytics", headers=self.session_cookie)).json()
        self.assertEqual(data["cards"]["verified"], 1)
        self.assertEqual(data["funnel"]["started"], 1)

    async def test_members_and_history(self):
        await self.verify_through()
        await self.log_in()
        data = await (await self.client.get(f"/api/guilds/{GUILD}/members", headers=self.session_cookie)).json()
        self.assertEqual(data["members"][0]["status"], "verified")
        detail = await (await self.client.get(f"/api/guilds/{GUILD}/members/{OLD_USER}", headers=self.session_cookie)).json()
        self.assertTrue(detail["attempts"])

    async def test_health_report(self):
        await self.log_in()
        data = await (await self.client.get(f"/api/guilds/{GUILD}/health", headers=self.session_cookie)).json()
        self.assertTrue(data["healthy"], data["issues"])
        self.assertFalse(data["has_administrator"])

    async def test_preview_replays_recent_attempts(self):
        await self.change(incognito={"enabled": True, "action": "watch"})
        await self.verify_through(report=clean_report(private={"isPrivate": True}))
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        proposed = json.loads(json.dumps(document))
        proposed["checks"]["incognito"]["action"] = "deny"
        data = await (await self.client.post(f"/api/guilds/{GUILD}/settings/preview", json={"settings": proposed}, headers=self.headers)).json()
        self.assertEqual(data["newly_blocked"], 1)

    async def test_export_and_import(self):
        await self.log_in()
        code = (await (await self.client.post(f"/api/guilds/{GUILD}/settings/export", json={}, headers=self.headers)).json())["code"]
        data = await (await self.client.post(f"/api/guilds/{GUILD}/settings/import", json={"code": code}, headers=self.headers)).json()
        self.assertEqual(data["settings"]["core"]["verified_role"], VERIFIED_ROLE)

    async def test_webhook_rules(self):
        await self.log_in()
        bad = await self.client.post(f"/api/guilds/{GUILD}/webhooks", json={"url": "http://example.com/hook"}, headers=self.headers)
        self.assertEqual(bad.status, 400)
        bad = await self.client.post(f"/api/guilds/{GUILD}/webhooks", json={"url": "https://127.0.0.1/hook"}, headers=self.headers)
        self.assertEqual(bad.status, 400)
        good = await self.client.post(f"/api/guilds/{GUILD}/webhooks", json={"url": "https://example.com/hook"}, headers=self.headers)
        self.assertTrue((await good.json())["secret"])

    async def test_api_key_answers_only_for_its_server(self):
        await self.verify_through()
        await self.log_in()
        key = (await (await self.client.post(f"/api/guilds/{GUILD}/keys", json={"label": "x"}, headers=self.headers)).json())["key"]
        response = await self.client.get(f"/api/v1/guilds/{GUILD}/members/{OLD_USER}", headers={"Authorization": f"Bearer {key}"})
        self.assertTrue((await response.json())["verified"])
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM api_keys WHERE key_hash = ?", (key,)), 0)
        other = await self.client.get(f"/api/v1/guilds/970000000000000999/members/{OLD_USER}", headers={"Authorization": f"Bearer {key}"})
        self.assertEqual(other.status, 401)

    async def test_appeal_decision_through_the_api(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        await self.log_in()
        appeals = await (await self.client.get(f"/api/guilds/{GUILD}/appeals", headers=self.session_cookie)).json()
        response = await self.client.post(f"/api/guilds/{GUILD}/appeals/{appeals['appeals'][0]['id']}", json={"decision": "approve"}, headers=self.headers)
        self.assertEqual(response.status, 200)


class MemberPages(Base):
    async def member_session(self, user=OLD_USER):
        self.discord.user["id"] = user
        response = await self.client.get("/login", params={"for": "member", "next": "/my-data"}, allow_redirects=False)
        url = urlsplit(response.headers["Location"])
        self.assertEqual(parse_qs(url.query)["scope"], ["identify"])
        state = parse_qs(url.query)["state"][0]
        flow = response.cookies[FLOW_COOKIE].value
        response = await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={flow}"})
        cookie = {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE].value}"}
        data = await (await self.client.get("/api/me/data", headers=cookie)).json()
        return cookie, data

    async def test_member_sees_and_deletes_their_data(self):
        await self.verify_through()
        cookie, data = await self.member_session()
        self.assertEqual(data["records"][0]["guild_name"], "Test Server")
        response = await self.client.post("/api/me/delete", json={}, headers={**cookie, "X-CSRF-Token": data["csrf"]})
        self.assertEqual((await response.json())["removed"], [GUILD])

    async def test_member_session_cannot_open_the_dashboard(self):
        cookie, _ = await self.member_session()
        self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/settings", headers=cookie)).status, 401)

    async def test_open_redirect_is_refused(self):
        response = await self.client.get("/login", params={"next": "//evil.test/x"}, allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        row = await self.db.one("SELECT next_path FROM login_states")
        self.assertEqual(row["next_path"], "/dashboard")
        self.assertTrue(state)

    async def test_appeal_through_the_page(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        cookie, data = await self.member_session()
        response = await self.client.post(f"/api/me/appeal/{GUILD}", json={"text": "That was my home connection, not a VPN."},
                                          headers={**cookie, "X-CSRF-Token": data["csrf"]})
        self.assertEqual(response.status, 200, await response.text())


class LogPrivacy(Base):
    async def test_staff_log_holds_no_raw_identifier(self):
        await self.change(vpn={"enabled": True, "action": "deny"}, geogate={"enabled": True, "action": "deny", "list": "block", "countries": ["US"]})
        await self.verify_through(ip="45.33.32.7")
        text = json.dumps([notice.embeds for _, notice in self.port.sent])
        self.assertNotIn("45.33.32.7", text)
        self.assertNotIn(clean_report()["fp"]["id"], text)


if __name__ == "__main__":
    unittest.main()
