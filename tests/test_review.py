"""Each test here reproduces a defect an independent read of the code found, so it can't come back."""
import asyncio
import json
import os
import sqlite3
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from multidict import CIMultiDict

from altwarden import altmatch, analytics, db as database, engine, health, notices, settings, signals
from altwarden.ports import DiscordUnavailable
from altwarden.web.api import webhook_problem
from altwarden.web.app import BROWSER_COOKIE, DEVICE_COOKIE, FLOW_COOKIE, RateLimiter
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, UNVERIFIED_ROLE, VERIFIED_ROLE
from test_detection import CHROME_WIN, clean_report, judge
from test_flow import Base, Dashboard, solve

SAME_PHONE = {"fingerprint": "f1", "device": "d1", "ip": "i1"}
THIRD_USER = "175928847299117066"
OTHER_SERVERS_CHANNEL = "980000000000000001"


class Addresses(Base):
    async def signed_in_submit(self, forwarded_lines):
        token = await self.link_for()
        await self.sign_in(token)
        cookies = self.cookie_header(DEVICE_COOKIE, BROWSER_COOKIE)
        challenge = await (await self.client.post(f"/api/verify/{token}/challenge", headers=cookies)).json()
        headers = CIMultiDict([("User-Agent", CHROME_WIN), *cookies.items()])
        for line in forwarded_lines:
            headers.add("X-Forwarded-For", line)
        headers.add("X-Probe", "1")
        body = {"nonce": challenge["nonce"], "counter": solve(challenge["salt"], challenge["bits"]), "report": clean_report()}
        return await (await self.client.post(f"/api/verify/{token}/submit", json=body, headers=headers)).json()

    async def test_a_forged_line_ahead_of_the_proxys_is_ignored(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        # What the real proxy forwards when a client sends a forged header followed by any other header.
        result = await self.signed_in_submit(["8.8.8.8", "8.8.8.8,45.33.32.7"])
        self.assertEqual(result["reason"], "vpn")

    async def test_the_real_address_passes_through_a_forged_line(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        result = await self.signed_in_submit(["45.33.32.7", "45.33.32.7,203.0.113.9"])
        self.assertEqual(result["status"], "verified")


class RateLimits(Base):
    async def test_one_ipv6_connection_counts_as_one_address(self):
        codes = []
        for number in range(60):
            response = await self.client.get("/api/verify/" + "a" * 43, headers={"X-Forwarded-For": f"2001:db8:1:2::{number + 1:x}"})
            codes.append(response.status)
        self.assertIn(429, codes)

    def test_flooding_the_table_cant_free_a_refused_key(self):
        limits = RateLimiter()
        limits.MAX_KEYS = 50
        while limits.allow("attacker", per_minute=0, burst=2):
            pass
        for number in range(45):
            limits.allow(f"other{number}", per_minute=0, burst=2)
        self.assertFalse(limits.allow("attacker", per_minute=0, burst=2))
        self.assertLessEqual(len(limits.buckets), 50)

    def test_addresses_arent_kept_in_memory(self):
        limits = RateLimiter()
        limits.allow("login:203.0.113.9", per_minute=60, burst=10)
        self.assertNotIn(b"203.0.113.9", b"".join(limits.buckets))


class LinksStayInTheirBrowser(Base):
    async def test_a_link_signed_in_elsewhere_wont_run_here(self):
        token = await self.link_for()
        await self.sign_in(token)
        state = await (await self.client.get(f"/api/verify/{token}")).json()
        self.assertEqual(state["step"], "signin", "another browser is asked to sign in")
        self.assertEqual((await self.client.post(f"/api/verify/{token}/challenge")).status, 409)
        self.assertEqual((await self.client.post(f"/api/verify/{token}/help")).status, 409)

    async def test_the_browser_that_signed_in_can_go_on(self):
        token = await self.link_for()
        await self.sign_in(token)
        state = await (await self.client.get(f"/api/verify/{token}", headers=self.cookie_header(BROWSER_COOKIE))).json()
        self.assertEqual(state["step"], "check")
        self.assertEqual((await self.attempt(token)).status, 200)

    async def test_a_victim_who_opens_the_link_leaves_no_trace_on_it(self):
        token = await self.link_for()
        await self.sign_in(token)
        bound = (await self.db.one("SELECT browser_hash FROM sessions"))["browser_hash"]
        self.assertTrue(bound)
        response = await self.client.post(f"/api/verify/{token}/submit", json={"nonce": "x", "counter": 1, "report": {}}, headers={"Cookie": f"{BROWSER_COOKIE}={'b' * 32}"})
        self.assertEqual(response.status, 409)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)

    async def test_one_browser_leaves_unrelated_values_on_two_links(self):
        first = await self.link_for()
        await self.sign_in(first)
        hash_one = (await self.service.session(first))["browser_hash"]
        second = await self.link_for(OTHER_USER)
        self.port.add_member(OTHER_USER)
        await self.sign_in(second, user=OTHER_USER)
        self.assertNotEqual(hash_one, (await self.service.session(second))["browser_hash"])

    async def test_help_stops_when_the_link_expires(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.db.run("UPDATE sessions SET expires_at = 1")
        self.assertEqual((await self.client.post(f"/api/verify/{token}/help", headers=self.cookie_header(BROWSER_COOKIE))).status, 409)


class OddRequests(Base):
    async def test_a_cookie_of_raw_bytes_isnt_a_500(self):
        token = await self.link_for()
        await self.sign_in(token)
        raw = {"Cookie": f"{BROWSER_COOKIE}=\udcff; {DEVICE_COOKIE}=\udcff.\udcff"}
        from altwarden.web.app import same_text
        self.assertFalse(same_text("\udcff", "abc"))
        from altwarden import crypto
        self.assertIsNone(self.keys.read_device_cookie("\udcff.\udcff"))
        self.assertTrue(crypto.token_hash("\udcff"))
        self.assertIsNotNone(raw)

    async def test_a_huge_number_is_a_bad_request(self):
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.client.post(f"/api/verify/{token}/submit", data='{"nonce": "x", "counter": ' + "9" * 5000 + ', "report": {}}', headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 400)

    async def test_a_lone_surrogate_is_a_bad_request(self):
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.client.post(f"/api/verify/{token}/submit", data='{"nonce": "\\ud800", "counter": 1, "report": {}}', headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 400)


class Loading(Dashboard):
    async def test_dashboard_sign_in_waits_until_discord_is_ready(self):
        self.port.loading = True
        self.assertEqual((await self.client.get("/login", allow_redirects=False)).status, 503)
        self.assertEqual((await self.client.get("/login?for=member", allow_redirects=False)).status, 302, "a member reading their own data has no list to protect")

    async def test_saving_while_discord_loads_the_server_says_so(self):
        await self.log_in()
        document = (await (await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).json())["settings"]
        self.port.absent = True
        self.port.loading = True
        response = await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": document}, headers=self.headers)
        self.assertEqual(response.status, 503)

    async def test_a_failed_lookup_keeps_the_server_on_the_list(self):
        await self.log_in()
        self.port.member = AsyncMock(side_effect=DiscordUnavailable("503"))
        data = await (await self.client.get("/api/session", headers=self.session_cookie)).json()
        self.assertEqual(data["guilds"][0]["id"], GUILD)

    async def test_signing_in_during_startup_keeps_servers_for_staff_without_manage_server(self):
        self.port.add_member(STAFF, perms=(), owner=False)
        self.discord.user["id"] = STAFF
        self.discord.guilds = [{"id": GUILD, "name": "Test Server", "icon": None, "owner": False, "permissions": "0"}]
        from urllib.parse import parse_qs, urlsplit
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        self.port.absent = True
        self.port.loading = True
        await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                              headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})
        self.assertIn(GUILD, (await self.db.one("SELECT guilds FROM web_sessions"))["guilds"])


class Requests(Base):
    async def test_an_empty_report_is_not_a_clean_browser(self):
        await self.change(automation={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.attempt(token, report={"v": 1}, ua="python-requests/2.32")
        self.assertEqual((await response.json())["reason"], "automation")

    async def test_a_chunked_report_is_held_to_the_limit(self):
        token = await self.link_for()
        await self.sign_in(token)

        async def chunks():
            for _ in range(30):
                yield b"x" * 10_000
        response = await self.client.post(f"/api/verify/{token}/submit", data=chunks(), headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 413)

    async def test_deep_json_is_a_bad_request(self):
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.client.post(f"/api/verify/{token}/submit", data="[" * 60000, headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 400)

    async def test_non_ascii_state_is_refused_quietly(self):
        for path in ("/verify/callback", "/dashboard/callback"):
            response = await self.client.get(path, params={"state": "é"}, allow_redirects=False, headers={"Cookie": f"{FLOW_COOKIE}=abc.def"})
            self.assertEqual(response.status, 302, path)

    async def test_a_500_doesnt_log_the_link(self):
        token = await self.link_for()
        await self.sign_in(token)
        self.service.port.guild = AsyncMock(side_effect=RuntimeError("boom"))
        with self.assertLogs("altwarden.web", "ERROR") as logged:
            response = await self.client.get(f"/api/verify/{token}")
        self.assertEqual(response.status, 500)
        self.assertNotIn(token, "\n".join(logged.output))


class PageRules(Dashboard):
    async def deny(self, page, user):
        document = await self.service.get_settings(GUILD)
        document["permissions"]["pages"][page] = {"view": {"required": ["manage_guild"], "overrides": [{"type": "user", "id": user, "allow": False}]}}
        await self.service.save_settings(GUILD, document)

    async def test_a_view_only_page_honors_a_deny_rule(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild",))
        for page, path in (("analytics", "analytics"), ("members", "members"), ("health", "health"), ("audit", "audit")):
            await self.deny(page, OTHER_USER)
            response = await self.client.get(f"/api/guilds/{GUILD}/{path}", headers=self.session_cookie)
            self.assertEqual(response.status, 403, page)

    async def test_a_padded_server_id_doesnt_slip_past_its_rules(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild",))
        await self.deny("analytics", OTHER_USER)
        self.assertEqual((await self.client.get(f"/api/guilds/0{GUILD}/analytics", headers=self.session_cookie)).status, 404)
        self.assertEqual((await self.client.get(f"/appeal/0{GUILD}")).status, 404)

    async def test_the_rules_page_doesnt_hand_out_access_rules(self):
        await self.log_in()
        document = await (await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).json()
        self.assertNotIn("permissions", document["settings"])

    async def test_a_channel_from_another_server_is_refused(self):
        await self.log_in()
        document = (await (await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).json())["settings"]
        document["core"]["logs"]["modules"]["general"] = OTHER_SERVERS_CHANNEL
        response = await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": document}, headers=self.headers)
        self.assertEqual(response.status, 400)
        self.assertIn("isn't in this server", (await response.json())["error"])
        self.assertNotEqual((await self.service.get_settings(GUILD))["core"]["logs"]["modules"]["general"], OTHER_SERVERS_CHANNEL)

    async def test_setup_refuses_another_servers_channel_too(self):
        await self.log_in()
        response = await self.client.post(f"/api/guilds/{GUILD}/setup", json={"verified_role": VERIFIED_ROLE, "channel": OTHER_SERVERS_CHANNEL}, headers=self.headers)
        self.assertEqual(response.status, 400)

    async def test_a_failed_post_is_reported_after_saving(self):
        await self.log_in()
        self.app["post_message"] = AsyncMock(return_value=False)
        document = (await (await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)).json())["settings"]
        document["core"]["channel"] = LOG_CHANNEL
        data = await (await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": document}, headers=self.headers)).json()
        self.assertIn("couldn't post", data["problem"])

    async def test_a_banned_member_isnt_reported_as_verified(self):
        await self.log_in()
        key = (await (await self.client.post(f"/api/guilds/{GUILD}/keys", json={"label": "x"}, headers=self.headers)).json())["key"]
        await self.verify_through()
        await self.service.on_ban(GUILD, OLD_USER)
        answer = await (await self.client.get(f"/api/v1/guilds/{GUILD}/members/{OLD_USER}", headers={"Authorization": f"Bearer {key}"})).json()
        self.assertEqual(answer, {"verified": False, "verified_at": None})

    async def test_strangers_dont_learn_a_servers_name(self):
        await self.log_in(user=THIRD_USER, owner=False, perms=())
        del self.port.members[(GUILD, THIRD_USER)]
        self.port.members.pop((GUILD, THIRD_USER), None)
        data = await (await self.client.get(f"/api/me/appeal/{GUILD}", headers=self.session_cookie)).json()
        self.assertEqual(data["guild"]["name"], "this server")

    async def test_only_servers_the_dashboard_can_show_are_stored(self):
        self.port.add_member(STAFF, perms=("manage_guild",), owner=True)
        self.discord.user["id"] = STAFF
        self.discord.guilds = [{"id": GUILD, "name": "Test Server", "icon": None, "owner": False, "permissions": "0"},
                               {"id": "980000000000000002", "name": "Someone's hobby server", "icon": None, "owner": False, "permissions": "0"},
                               {"id": "980000000000000003", "name": "Mine", "icon": None, "owner": False, "permissions": "32"}]
        from urllib.parse import parse_qs, urlsplit
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                              headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})
        stored = (await self.db.one("SELECT guilds FROM web_sessions"))["guilds"]
        self.assertNotIn("hobby", stored)
        self.assertIn("Mine", stored)
        self.assertIn(GUILD, stored)


class Webhooks(unittest.TestCase):
    def test_every_way_to_write_an_address_is_refused(self):
        for url in ("https://2130706433:8443/", "https://127.1/", "https://0x7f.0.0.1/", "https://0x7f000001/", "https://①②⑦.⓪.⓪.①/", "https://[::1]/", "https://127.0.0.1/"):
            self.assertIsNotNone(webhook_problem(url), url)

    def test_an_ordinary_host_name_is_fine(self):
        self.assertIsNone(webhook_problem("https://hooks.example.com/altwarden"))
        self.assertIsNone(webhook_problem("https://1password.example.com/"))


class Retries(Base):
    async def test_a_failed_account_check_asks_for_a_new_sign_in(self):
        await self.change(avatar={"enabled": True, "action": "deny"})
        self.discord.user["avatar"] = None
        token = await self.link_for()
        await self.sign_in(token)
        self.assertEqual((await (await self.attempt(token)).json())["reason"], "avatar")
        row = await self.service.session(token)
        self.assertEqual((row["state"], row["account"]), ("open", None))
        self.discord.user["avatar"] = "fixed"
        await self.sign_in(token)
        self.assertEqual((await (await self.attempt(token)).json())["status"], "verified")

    async def test_a_reload_after_a_failure_doesnt_spend_an_attempt(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token, ip="45.33.32.7")
        state = await (await self.client.get(f"/api/verify/{token}", headers=self.cookie_header(BROWSER_COOKIE))).json()
        self.assertTrue(state["tried"], "the page waits for Try again")

    async def test_a_failed_account_check_tells_the_page_it_was_tried(self):
        await self.change(avatar={"enabled": True, "action": "deny"})
        self.discord.user["avatar"] = None
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token)
        state = await (await self.client.get(f"/api/verify/{token}", headers=self.cookie_header(BROWSER_COOKIE))).json()
        self.assertEqual((state["step"], state["tried"], state["appeal"]), ("signin", True, True))

    async def test_a_passed_check_with_a_role_problem_can_run_again_by_itself(self):
        self.port.role_problem = "That role no longer exists."
        token = await self.link_for()
        await self.sign_in(token)
        self.assertEqual((await (await self.attempt(token)).json())["status"], "problem")
        state = await (await self.client.get(f"/api/verify/{token}", headers=self.cookie_header(BROWSER_COOKIE))).json()
        self.assertFalse(state["tried"], "nobody was told they failed")

    async def test_a_new_sign_in_clears_the_last_try(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token, ip="45.33.32.7")
        await self.sign_in(token)
        state = await (await self.client.get(f"/api/verify/{token}", headers=self.cookie_header(BROWSER_COOKIE))).json()
        self.assertFalse(state["tried"])

    async def test_an_email_rule_added_after_sign_in_gets_a_new_sign_in(self):
        await self.change(disposable_email={"enabled": False})
        token = await self.link_for()
        await self.sign_in(token)
        await self.change(disposable_email={"enabled": True, "action": "deny"})
        result = await (await self.attempt(token)).json()
        self.assertEqual(result["reason"], "signin_again")
        self.assertEqual((await self.service.session(token))["state"], "open")

    async def test_what_sign_in_read_goes_when_the_attempt_ends(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token)
        self.assertIsNone((await self.db.one("SELECT account FROM sessions"))["account"])


class StaffAndLinks(Base):
    async def test_staff_verification_kills_the_old_link(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff")
        self.assertIsNone(await self.service.session(token))

    async def test_an_old_link_cant_undo_a_role_already_held(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        token = await self.link_for()
        await self.sign_in(token)
        self.port.members[(GUILD, OLD_USER)].role_ids = (VERIFIED_ROLE,)
        result = await (await self.attempt(token, ip="45.33.32.7")).json()
        self.assertEqual(result["status"], "already")
        self.assertFalse(self.port.did("kick"))


class RoleFailures(Base):
    async def test_a_rejoin_that_cant_get_the_role_isnt_recorded_as_done(self):
        await self.verify_through()
        self.port.role_problem = "That role no longer exists."
        await self.service.on_join(self.port.add_member(OLD_USER))
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "pending")
        self.assertIn("Couldn't give the verified role", json.dumps([notice.embeds for _, notice in self.port.sent]))

    async def test_an_approved_member_stays_approved_until_the_role_works(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, status="approved")
        self.port.role_problem = "nope"
        await self.service.on_join(self.port.add_member(OLD_USER))
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "approved")
        self.port.role_problem = None
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(result.status, "already")
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "verified")

    async def test_an_appeal_that_cant_give_the_role_stays_open(self):
        appeal = await self.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, 'vpn', 'please let me in', ?)", (GUILD, OLD_USER, time.time()))
        self.port.role_problem = "That role no longer exists."
        problem = await self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "staff")
        self.assertIn("still open", problem)
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "open")
        self.assertEqual(self.port.dms, [], "nobody is told they were approved")


class FailingEndsAPass(Base):
    async def test_failing_clears_verified_so_a_rejoin_doesnt_restore_the_role(self):
        await self.verify_through()
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        await self.change(vpn={"enabled": True, "action": "kick"})
        await self.verify_through(ip="45.33.32.7")
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["status"], record["verified_at"]), ("pending", None))
        self.port.calls.clear()
        await self.service.on_join(self.port.add_member(OLD_USER))
        self.assertFalse(self.port.did("add_role"))

    async def test_a_discord_ban_ends_a_pass(self):
        await self.verify_through()
        await self.service.on_ban(GUILD, OLD_USER)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "pending")

    async def test_a_honeypot_kick_ends_a_pass(self):
        await self.verify_through()
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=LOG_CHANNEL, action="kick")
        await self.service.save_settings(GUILD, document)
        await self.service.honeypot_hit(GUILD, OLD_USER, "x", LOG_CHANNEL, "1", role_ids=())
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "pending")


class EarlierAccounts(Base):
    async def verified(self, user, when):
        self.port.add_member(user)
        await self.db.touch_member(GUILD, user)
        await self.db.mark_verified(GUILD, user, "web", when=when)

    async def test_the_account_that_verified_first_isnt_treated_as_the_alt(self):
        await self.verified(OLD_USER, time.time() - 1000)
        await self.verified(OTHER_USER, time.time() - 500)
        for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4")):
            await self.db.store_identifier(GUILD, OTHER_USER, kind, self.keys.digest(int(GUILD), kind, value), time.time() + 999)
        await self.change(alt_account={"enabled": True, "alt_action": "kick", "main_action": "watch"})
        result = await self.verify_through(ip="8.8.4.4")
        self.assertEqual(result["status"], "verified")
        self.assertFalse(self.port.did("kick"))
        link = await self.db.one("SELECT main_id, alt_id FROM links")
        self.assertEqual((link["main_id"], link["alt_id"]), (OLD_USER, OTHER_USER))

    async def test_the_account_that_verified_second_is_the_alt(self):
        await self.verified(OTHER_USER, time.time() - 500)
        for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4")):
            await self.db.store_identifier(GUILD, OTHER_USER, kind, self.keys.digest(int(GUILD), kind, value), time.time() + 999)
        await self.change(alt_account={"enabled": True, "alt_action": "kick", "main_action": "watch"})
        self.assertEqual((await self.verify_through(ip="8.8.4.4"))["action"], "kick")

    async def test_someone_who_never_got_in_isnt_an_account_to_match(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.store_identifier(GUILD, OTHER_USER, "cookie", "c1", time.time() + 999)
        links = await altmatch.find_links(self.db, GUILD, OLD_USER, {"cookie": "c1"}, methods={"cookie": True}, weak_fingerprint=False, weak_ip=False)
        self.assertIsNone(altmatch.strongest(links, "likely"))

    async def test_someone_who_got_in_once_still_counts_after_failing_a_later_check(self):
        await self.verified(OTHER_USER, time.time() - 900)
        await self.db.update_member(GUILD, OTHER_USER, status="pending", verified_at=None)
        await self.db.store_identifier(GUILD, OTHER_USER, "cookie", "c1", time.time() + 999)
        links = await altmatch.find_links(self.db, GUILD, OLD_USER, {"cookie": "c1"}, methods={"cookie": True}, weak_fingerprint=False, weak_ip=False)
        self.assertEqual(altmatch.strongest(links, "likely").other_id, OTHER_USER)

    async def test_a_ban_only_discord_knows_about_counts_even_if_they_never_got_in(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4")):
            await self.db.store_identifier(GUILD, OTHER_USER, kind, self.keys.digest(int(GUILD), kind, value), time.time() + 999)
        self.port.banned.add(OTHER_USER)
        await self.change(alt_account={"enabled": True, "alt_action": "deny", "banned_alt_action": "ban"})
        self.assertEqual((await self.verify_through(ip="8.8.4.4"))["action"], "ban")

    async def test_the_first_account_stays_the_main_one_after_passing_again(self):
        await self.verified(OLD_USER, time.time() - 1000)
        await self.verified(OTHER_USER, time.time() - 500)
        await self.db.mark_verified(GUILD, OLD_USER, "web")
        await altmatch.assign_roles(self.db, GUILD, OLD_USER, link := altmatch.Link(OTHER_USER, 80, "likely"))
        self.assertFalse(link.other_is_main)

    async def test_the_first_account_stays_the_main_one_after_failing(self):
        await self.verified(OLD_USER, time.time() - 1000)
        await self.verified(OTHER_USER, time.time() - 500)
        await self.db.update_member(GUILD, OLD_USER, status="pending", verified_at=None)
        await altmatch.assign_roles(self.db, GUILD, OLD_USER, link := altmatch.Link(OTHER_USER, 80, "likely"))
        self.assertFalse(link.other_is_main)

    async def test_a_banned_account_is_still_matched(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.store_identifier(GUILD, OTHER_USER, "cookie", "c1", time.time() + 999)
        await self.db.record_ban(GUILD, OTHER_USER)
        links = await altmatch.find_links(self.db, GUILD, OLD_USER, {"cookie": "c1"}, methods={"cookie": True}, weak_fingerprint=False, weak_ip=False)
        self.assertEqual(links[0].other_id, OTHER_USER)

    async def test_a_banned_earlier_account_can_appeal(self):
        await self.verified(OTHER_USER, time.time() - 500)
        await self.db.store_identifier(GUILD, OTHER_USER, "fingerprint", self.keys.digest(int(GUILD), "fingerprint", "a" * 32), time.time() + 999)
        await self.db.store_identifier(GUILD, OTHER_USER, "ip", self.keys.digest(int(GUILD), "ip", "8.8.4.4"), time.time() + 999)
        await self.change(alt_account={"enabled": True, "alt_action": "watch", "main_action": "ban"})
        await self.verify_through(ip="8.8.4.4")
        self.assertIn(("ban", OTHER_USER, "AltWarden: main account of <" + OLD_USER + ">", 0), self.port.calls)
        self.assertIsNone(await self.service.submit_appeal(GUILD, OTHER_USER, "other", "This really is my brother's account."))
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["status"], "pending")

    async def test_a_ban_only_discord_knows_about_outranks_a_stronger_match(self):
        await self.verified(OTHER_USER, time.time() - 900)
        await self.verified(THIRD_USER, time.time() - 900)
        for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4"), ("device", "not this one")):
            await self.db.store_identifier(GUILD, OTHER_USER, kind, self.keys.digest(int(GUILD), kind, value), time.time() + 999)
        for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4")):
            await self.db.store_identifier(GUILD, THIRD_USER, kind, self.keys.digest(int(GUILD), kind, value), time.time() + 999)
        self.port.banned.add(THIRD_USER)
        await self.change(alt_account={"enabled": True, "alt_action": "deny", "banned_alt_action": "ban"})
        result = await self.verify_through(ip="8.8.4.4")
        self.assertEqual(result["action"], "ban")


class AltEvidence(unittest.IsolatedAsyncioTestCase):
    METHODS = {"cookie": True, "fingerprint": True, "ip": True}

    async def asyncSetUp(self):
        import tempfile
        self.folder = tempfile.TemporaryDirectory()
        self.db = database.Database(os.path.join(self.folder.name, "t.db"))
        await self.db.open()
        await self.db.touch_member("1", "10")
        await self.db.update_member("1", "10", status="verified")
        for kind, digest in SAME_PHONE.items():
            await self.db.store_identifier("1", "10", kind, digest, time.time() + 999)

    async def asyncTearDown(self):
        await self.db.close()
        self.folder.cleanup()

    async def link(self, digests, *, weak_fingerprint=False, weak_ip=False):
        links = await altmatch.find_links(self.db, "1", "99", digests, methods=self.METHODS, weak_fingerprint=weak_fingerprint, weak_ip=weak_ip)
        return links[0] if links else None

    async def test_two_phones_on_one_wifi_arent_acted_on(self):
        link = await self.link(SAME_PHONE, weak_fingerprint=True)
        self.assertEqual((link.score, link.confidence), (65, "possible"))

    async def test_strangers_with_the_same_laptop_arent_acted_on(self):
        link = await self.link({"fingerprint": "f1", "device": "d1"})
        self.assertEqual((link.score, link.confidence), (65, "possible"))

    async def test_the_same_setup_on_the_same_connection_is_acted_on(self):
        link = await self.link({"fingerprint": "f1", "ip": "i1"})
        self.assertEqual((link.score, link.confidence), (80, "likely"))


class Looks(unittest.TestCase):
    def report_for(self, ua, platform, **nav):
        return clean_report(nav={"ua": ua, "platform": platform, "vendor": "Apple Computer, Inc.", "webdriver": False, "cores": 8, **nav}, uad={}, gpu={"renderer": "Apple GPU"},
                            eng={"evalLen": 37}, worker={})

    def test_an_ipad_in_desktop_mode_is_weak_evidence(self):
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
        self.assertTrue(judge(self.report_for(ua, "MacIntel", touch=5), ua).weak_fingerprint)
        self.assertFalse(judge(self.report_for(ua, "MacIntel", touch=0), ua).weak_fingerprint)

    def test_android_and_chromebooks_are_weak_evidence(self):
        android = "Mozilla/5.0 (Linux; Android 14; SM-S921U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
        book = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        for ua in (android, book):
            self.assertTrue(judge(clean_report(nav={"ua": ua, "platform": "Linux x86_64", "vendor": "Google Inc.", "webdriver": False, "cores": 8}, worker={}), ua).weak_fingerprint, ua)
        self.assertFalse(judge().weak_fingerprint)

    def test_an_ipad_worker_saying_ipad_isnt_a_lie(self):
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
        report = self.report_for(ua, "MacIntel", touch=5)
        report["worker"] = {"ua": ua, "platform": "iPad", "cores": 8}
        self.assertFalse(judge(report, ua).antidetect)

    def test_a_worker_on_a_different_system_is_still_a_lie(self):
        report = clean_report()
        report["worker"]["platform"] = "MacIntel"
        self.assertTrue(judge(report).antidetect)


class BrowserVerdicts(unittest.TestCase):
    def test_header_names_are_read_in_any_case(self):
        verdict = signals.evaluate(clean_report(), {"user-agent": "Mozilla/5.0 something else"})
        self.assertTrue(verdict.fake_ua)
        verdict = signals.evaluate(clean_report(), {"user-agent": CHROME_WIN, "sec-ch-ua-platform": '"macOS"'})
        self.assertIn("agent and client hints name different systems", verdict.reasons.get("fake_ua", []))

    def test_brave_padding_its_agent_isnt_a_fake(self):
        report = clean_report()
        report["nav"]["ua"] = CHROME_WIN + "  "
        report["worker"]["ua"] = CHROME_WIN + " "
        self.assertFalse(judge(report).fake_ua)

    def test_a_chromium_browser_can_name_itself(self):
        report = clean_report()
        report["nav"]["vendor"] = "Yandex"
        self.assertFalse(judge(report).fake_ua)
        report["nav"]["vendor"] = "Apple Computer, Inc."
        self.assertTrue(judge(report).fake_ua)

    def test_download_pdfs_alone_isnt_headless(self):
        report = clean_report(bot={"bot": True, "botKind": "headless_chrome", "fired": ["detectPluginsLengthInconsistency"]})
        report["nav"]["pdf"] = False
        self.assertFalse(judge(report).automated)

    def test_that_excuse_doesnt_cover_anything_else(self):
        report = clean_report(bot={"bot": True, "botKind": "headless_chrome", "fired": ["detectPluginsLengthInconsistency", "detectWebDriver"]})
        report["nav"]["pdf"] = False
        self.assertTrue(judge(report).automated)
        report = clean_report(bot={"bot": True, "botKind": "headless_chrome", "fired": ["detectPluginsLengthInconsistency"]})
        report["nav"]["pdf"] = True
        self.assertTrue(judge(report).automated)

    def test_a_removed_webdriver_flag_is_automation(self):
        report = clean_report()
        del report["nav"]["webdriver"]
        report["nav"]["modern"] = True
        self.assertIn("webdriver flag removed", judge(report).reasons["automated"])

    def test_an_old_browser_without_that_flag_isnt_automation(self):
        report = clean_report()
        del report["nav"]["webdriver"]
        report["nav"]["modern"] = False
        self.assertFalse(judge(report).automated)

    def test_an_own_webdriver_property_is_automation(self):
        report = clean_report(lies={"total": 1, "apis": ["Navigator.webdriver"]})
        self.assertIn("webdriver flag hidden", judge(report).reasons["automated"])

    def test_safari_has_no_webdriver_rule_to_trip(self):
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
        report = clean_report(nav={"ua": ua, "platform": "iPhone", "vendor": "Apple Computer, Inc.", "cores": 6}, uad={}, gpu={"renderer": "Apple GPU"}, eng={"evalLen": 37}, worker={})
        self.assertFalse(judge(report, ua).automated)

    def test_a_window_gap_means_nothing_anywhere(self):
        for ua, vendor, length in ((CHROME_WIN, "Google Inc.", 33),
                                   ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0", "", 37),
                                   ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", "Apple Computer, Inc.", 37)):
            report = clean_report(nav={"ua": ua, "platform": "MacIntel", "vendor": vendor, "webdriver": False, "cores": 8}, uad={}, gpu={"renderer": ""}, eng={"evalLen": length}, worker={},
                                  devtools={"size": True, "timing": False})
            self.assertFalse(judge(report, ua).devtools, ua)

    def test_only_a_plain_name_from_botd_reaches_staff(self):
        report = clean_report(bot={"bot": True, "botKind": "<@&1> <script>"})
        self.assertEqual(judge(report).reasons["automated"][0], "BotD: unknown")
        report = clean_report(bot={"bot": True, "botKind": "headless_chrome"})
        self.assertEqual(judge(report).reasons["automated"][0], "BotD: headless_chrome")

    def test_the_standard_preset_only_records_what_could_be_innocent(self):
        document = settings.apply_preset(settings.defaults(), "standard")
        self.assertEqual(document["checks"]["antidetect"]["action"], "watch")
        self.assertEqual(document["checks"]["devtools"]["action"], "deny")


class Outcomes(Base):
    async def test_a_kick_that_fails_isnt_reported_as_done(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        self.port.kick_works = False
        token = await self.link_for()
        await self.sign_in(token)
        result = await (await self.attempt(token, ip="45.33.32.7")).json()
        self.assertEqual((result["action"], result["retry"]), ("deny", True))
        self.assertEqual((await self.service.session(token))["state"], "signed_in", "they're still here, so the link still works")

    async def test_a_member_who_left_during_the_check_is_told_that(self):
        token = await self.link_for()
        await self.sign_in(token)
        from altwarden.ports import MEMBER_GONE
        self.port.role_problem = MEMBER_GONE
        result = await (await self.attempt(token)).json()
        self.assertEqual(result["reason"], "left_server")
        self.assertNotIn("Couldn't give the verified role", json.dumps([notice.embeds for _, notice in self.port.sent]))

    async def test_two_presses_at_once_leave_one_link(self):
        member = self.port.members[(GUILD, OLD_USER)]
        await asyncio.gather(self.service.press_verify(member), self.service.press_verify(member))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM sessions"), 1)

    async def test_a_purged_server_leaves_no_settings_in_memory(self):
        await self.service.get_settings(GUILD)
        await self.db.set_guild_field(GUILD, "left_at", 1)
        await self.service.purge()
        self.assertIsNone(await self.service.get_settings(GUILD))


class Previews(Base):
    async def replay(self, finding, outcome="failed"):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.add_attempt(GUILD, OLD_USER, outcome, check_id="alt_account", action=finding["action"], detail={"findings": [finding]})
        rules = json.loads(json.dumps(await self.service.get_settings(GUILD)))
        rules["checks"]["alt_account"].update(enabled=True, alt_action="kick", main_action="watch", min_confidence="likely")
        return await analytics.preview(self.db, GUILD, rules)

    async def test_a_main_account_verifying_again_isnt_counted_as_stopped(self):
        result = await self.replay({"check": "alt_account", "action": "watch", "detail": {"confidence": "likely", "other_is_main": False}}, "passed")
        self.assertEqual(result["newly_blocked"], 0)

    async def test_a_kicked_earlier_account_follows_the_main_action(self):
        result = await self.replay({"check": "alt_account", "action": "kick", "detail": {"confidence": "likely", "earlier_account": True}})
        self.assertEqual(result["blocked_now"], 0)
        self.assertEqual(result["newly_passed"], 1)


class Races(Base):
    async def test_staff_verification_waits_for_a_running_check(self):
        lock = self.service._lock(GUILD, OLD_USER)
        await lock.acquire()
        verify = asyncio.ensure_future(self.service.manual_verify(GUILD, OLD_USER, STAFF))
        await asyncio.sleep(0.05)
        self.assertFalse(verify.done())
        lock.release()
        self.assertIsNone(await verify)

    async def test_four_presses_at_once_count_as_one(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["mode"] = "button"
        await self.service.save_settings(GUILD, document)
        await self.change(avatar={"enabled": True, "action": "kick"})
        member = self.port.add_member(OLD_USER, avatar=None)
        await asyncio.gather(*(self.service.press_verify(member) for _ in range(4)))
        self.assertEqual(len(self.port.did("kick")), 1)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], 1)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE outcome = 'failed'"), 1)

    async def test_failures_in_a_row_are_all_counted(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=2)
        document = await self.service.get_settings(GUILD)
        document["core"]["mode"] = "button"
        await self.service.save_settings(GUILD, document)
        await self.change(avatar={"enabled": True, "action": "deny"})
        await self.service.press_verify(self.port.add_member(OLD_USER, avatar=None))
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], 3)

    async def test_signing_in_during_a_check_doesnt_reopen_the_session(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.db.run("UPDATE sessions SET state = 'checking'")
        await self.service.attach_account(token, {"id": OLD_USER, "username": "x", "avatar": "a", "mfa": True})
        self.assertEqual((await self.service.session(token))["state"], "checking")

    async def test_two_decisions_at_once_leave_one(self):
        appeal = await self.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, 'vpn', 'please let me in', ?)", (GUILD, OLD_USER, time.time()))
        answers = await asyncio.gather(self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "a"), self.service.decide_appeal(GUILD, appeal, "deny", STAFF, "b"))
        self.assertEqual(sorted(answer is None for answer in answers), [False, True])
        self.assertEqual(len(self.port.dms) >= 1, True)
        titles = [notice.embeds[0]["title"] for _, notice in self.port.dms if "appeal" in notice.embeds[0]["title"]]
        self.assertEqual(len(titles), 1)


class Restarts(Base):
    async def test_a_check_cut_off_by_a_restart_hands_the_link_back(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.db.run("UPDATE sessions SET state = 'checking'")
        await self.db.close()
        await self.db.open()
        self.assertEqual((await self.service.session(token))["state"], "signed_in")

    async def test_pressing_verify_during_a_check_keeps_the_skips(self):
        url, _ = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 2, "none", STAFF, "staff")
        await self.db.run("UPDATE sessions SET state = 'checking'")
        await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        row = await self.db.one("SELECT bypass FROM sessions WHERE state = 'open'")
        self.assertEqual(json.loads(row["bypass"]), ["vpn"])

    async def test_an_older_database_gets_its_new_columns(self):
        path = self.db.path + ".older"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE members (guild_id TEXT NOT NULL, user_id TEXT NOT NULL, username TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY (guild_id, user_id))")
        connection.execute("CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, guild_id TEXT NOT NULL, user_id TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open', created_at REAL NOT NULL, expires_at REAL NOT NULL)")
        connection.execute("INSERT INTO members (guild_id, user_id, username) VALUES ('1', '2', 'kept')")
        connection.execute("INSERT INTO sessions (token_hash, guild_id, user_id, state, created_at, expires_at) VALUES ('t', '1', '2', 'checking', 0, 0)")
        connection.commit()
        connection.close()
        older = database.Database(path)
        await older.open()
        try:
            record = await older.one("SELECT username, forget_on_unban, fails FROM members")
            self.assertEqual((record["username"], record["forget_on_unban"], record["fails"]), ("kept", 0, 0))
            session = await older.one("SELECT state, browser_hash, bypass FROM sessions")
            self.assertEqual((session["state"], session["browser_hash"], session["bypass"]), ("signed_in", None, "[]"))
        finally:
            await older.close()


class Timers(Base):
    async def due(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        self.port.add_member(OTHER_USER)
        await self.db.update_member(GUILD, OTHER_USER, kick_at=time.time() - 1)
        document = await self.service.get_settings(GUILD)
        document["core"]["auto_kick"]["enabled"] = True
        await self.service.save_settings(GUILD, document)

    async def test_discord_failing_keeps_the_timer(self):
        await self.due()
        self.port.member = AsyncMock(side_effect=DiscordUnavailable("503"))
        with self.assertLogs("altwarden.service", "ERROR"):
            await self.service.tick()
        self.assertIsNotNone((await self.db.member(GUILD, OTHER_USER))["kick_at"])
        self.assertFalse(self.port.did("kick"))

    async def test_a_server_still_loading_keeps_the_timer(self):
        await self.due()
        self.port.loading = True
        await self.service.tick()
        self.assertIsNotNone((await self.db.member(GUILD, OTHER_USER))["kick_at"])
        self.assertFalse(self.port.did("kick"))

    async def test_a_timer_that_runs_kicks_and_clears(self):
        await self.due()
        await self.service.tick()
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_at"])
        self.assertTrue(self.port.did("kick"))

    async def test_one_failure_doesnt_hold_up_the_others(self):
        await self.due()
        await self.db.touch_member(GUILD, THIRD_USER)
        self.port.add_member(THIRD_USER)
        await self.db.update_member(GUILD, THIRD_USER, kick_at=time.time() - 1)
        original = self.port.member

        async def picky(guild_id, user_id):
            if user_id == OTHER_USER:
                raise DiscordUnavailable("503")
            return await original(guild_id, user_id)
        self.port.member = picky
        with self.assertLogs("altwarden.service", "ERROR"):
            await self.service.tick()
        self.assertEqual([call[1] for call in self.port.did("kick")], [THIRD_USER])

    async def test_a_raid_that_runs_out_tells_webhooks(self):
        sent = []

        async def sender(guild_id, event, payload):
            sent.append(event)
        self.service.webhook_sender = sender
        await self.db.set_guild_field(GUILD, "raid_until", time.time() - 1)
        await self.service.tick()
        await asyncio.sleep(0)
        self.assertEqual(sent, ["raid.ended"])


class RaidRules(unittest.TestCase):
    def test_a_raid_never_softens_a_rule(self):
        document = settings.defaults()
        document["checks"]["account_age"]["action"] = "ban"
        tightened = engine.effective_settings(document, True)
        self.assertEqual(tightened["checks"]["account_age"]["action"], "ban")

    def test_banned_alts_tighten_along_with_the_rest(self):
        document = settings.apply_preset(settings.defaults(), "gentle")
        tightened = engine.effective_settings(document, True)
        self.assertEqual(tightened["checks"]["alt_account"]["banned_alt_action"], "kick")


class Limits(Base):
    async def test_the_limit_role_goes_when_they_pass(self):
        await self.change(max_attempts={"enabled": True, "role": UNVERIFIED_ROLE})
        await self.verify_through()
        self.assertIn(("remove_role", OLD_USER, UNVERIFIED_ROLE), self.port.calls)

    async def test_the_limit_role_goes_when_staff_verify(self):
        await self.change(max_attempts={"enabled": True, "role": UNVERIFIED_ROLE})
        await self.service.manual_verify(GUILD, OLD_USER, STAFF)
        self.assertIn(("remove_role", OLD_USER, UNVERIFIED_ROLE), self.port.calls)

    def test_the_limit_role_cant_be_the_verified_role(self):
        document = settings.defaults()
        document["core"].update(verified_role=VERIFIED_ROLE, channel=CHANNEL)
        document["checks"]["max_attempts"]["role"] = VERIFIED_ROLE
        self.assertIn("The attempt limit role can't be the verified role.", settings.problems(document))

    def test_the_trap_cant_be_the_verification_channel(self):
        document = settings.defaults()
        document["core"].update(verified_role=VERIFIED_ROLE, channel=CHANNEL)
        document["honeypot"].update(enabled=True, channel=CHANNEL)
        self.assertIn("The honeypot channel can't be the verification channel.", settings.problems(document))

    def test_country_rules_keep_their_whole_names(self):
        rules = {"region:Latin America and the Caribbean": "ban", "region:South-eastern Asia": "kick", "region:Australia and New Zealand": "watch"}
        document = settings.defaults()
        document["checks"]["geogate"]["overrides"] = rules
        self.assertEqual(settings.normalize(document)["checks"]["geogate"]["overrides"], rules)

    def test_every_region_name_fits(self):
        from pathlib import Path
        rows = json.loads((Path(settings.__file__).parent / "web" / "static" / "countries.json").read_text(encoding="utf-8"))
        self.assertLess(max(len(f"region:{row['region']}") for row in rows if row.get("region")), 64)

    def test_an_absurd_number_falls_back(self):
        document = settings.defaults()
        document["raid"]["joins"] = float("inf")
        self.assertEqual(settings.normalize(document)["raid"]["joins"], 15)


class OwnData(Base):
    async def test_deleting_clears_the_date_too(self):
        await self.verify_through()
        await self.db.update_member(GUILD, OLD_USER, fails=2)
        await self.service.delete_my_data(OLD_USER)
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["first_verified_at"])
        await self.db.record_ban(GUILD, OTHER_USER)
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.mark_verified(GUILD, OTHER_USER, "web")
        await self.service.delete_my_data(OTHER_USER)
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["first_verified_at"])

    async def test_the_purge_doesnt_reset_a_recent_limit(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=9, joined_at=time.time() - 9000 * 86400, last_fail_at=time.time() - 60)
        await self.service.purge()
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["fails"], 9)

    async def test_deleting_takes_no_role_from_someone_with_no_member_record(self):
        await self.db.add_audit(GUILD, "manual_verify", actor_id=STAFF, actor_name="x", detail={"user": OLD_USER})
        self.port.add_member(STAFF, roles=(VERIFIED_ROLE,))
        await self.service.delete_my_data(STAFF)
        self.assertFalse([call for call in self.port.calls if call[0] in ("remove_role", "add_role") and call[1] == STAFF])

    async def test_a_reset_with_discord_down_changes_nothing(self):
        await self.verify_through()
        self.port.member = AsyncMock(side_effect=DiscordUnavailable("503"))
        with self.assertRaises(DiscordUnavailable):
            await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertGreater(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "verified")

    async def test_deleting_doesnt_reset_the_attempt_limit(self):
        await self.db.touch_member(GUILD, OLD_USER, username="someone", avatar="abc")
        await self.db.update_member(GUILD, OLD_USER, fails=4, last_fail_at=time.time() - 5, limit_reached_at=time.time() - 5)
        await self.service.delete_my_data(OLD_USER)
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["fails"], record["username"], record["avatar"]), (4, "", None))

    async def test_deleting_doesnt_stop_the_auto_kick_timer(self):
        await self.db.touch_member(GUILD, OLD_USER, username="someone")
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() + 60)
        await self.service.delete_my_data(OLD_USER)
        self.assertIsNotNone((await self.db.member(GUILD, OLD_USER))["kick_at"])

    async def test_with_nothing_to_enforce_the_row_goes(self):
        await self.verify_through()
        await self.service.delete_my_data(OLD_USER)
        self.assertIsNone(await self.db.member(GUILD, OLD_USER))

    async def test_staff_with_no_member_row_can_see_and_delete(self):
        await self.db.add_audit(GUILD, "manual_verify", actor_id=STAFF, actor_name="the staff name", detail={"user": OLD_USER})
        data = await self.service.my_data(STAFF)
        self.assertEqual((data[0]["guild_id"], data[0]["status"], data[0]["staff_actions"]), (GUILD, None, 1))
        await self.service.delete_my_data(STAFF)
        self.assertNotIn(STAFF, self.database_dump())
        self.assertNotIn("the staff name", self.database_dump())

    async def test_a_honeypot_poster_with_no_member_row_is_found(self):
        await self.db.add_attempt(GUILD, OTHER_USER, "honeypot", action="log")
        self.assertEqual(len(await self.service.my_data(OTHER_USER)), 1)
        await self.service.delete_my_data(OTHER_USER)
        self.assertNotIn(OTHER_USER, self.database_dump())

    async def test_a_deleted_id_is_gone_from_other_peoples_records(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.add_attempt(GUILD, OTHER_USER, "failed", check_id="alt_account", detail={"findings": [{"check": "alt_account", "detail": {"account": OLD_USER}}]})
        await self.db.trust_pair(GUILD, OTHER_USER, THIRD_USER, OLD_USER)
        await self.service.delete_my_data(OLD_USER)
        self.assertNotIn(OLD_USER, self.database_dump())

    async def test_a_banned_account_loses_its_name_at_once_and_its_hashes_at_unban(self):
        await self.verify_through()
        await self.db.record_ban(GUILD, OLD_USER, keep_days=730)
        result = await self.service.delete_my_data(OLD_USER)
        self.assertEqual(result["kept_for_ban"], [GUILD])
        record = await self.db.member(GUILD, OLD_USER)
        self.assertEqual((record["username"], record["avatar"]), ("", None))
        self.assertGreater(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,)), 0)
        await self.service.on_unban(GUILD, OLD_USER)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE user_id = ?", (OLD_USER,)), 0)
        self.assertIsNone(await self.db.member(GUILD, OLD_USER))

    async def test_a_banned_account_with_no_member_row_is_found(self):
        await self.db.record_ban(GUILD, OTHER_USER)
        self.assertEqual((await self.service.my_data(OTHER_USER))[0]["banned"], True)


class ManyFailedAlts(Base):
    async def test_failed_accounts_cant_push_the_real_match_out_of_the_list(self):
        self.port.add_member(OTHER_USER)
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.mark_verified(GUILD, OTHER_USER, "web", when=time.time() - 900)
        cookie = "cookie digest"
        await self.db.store_identifier(GUILD, OTHER_USER, "fingerprint", self.keys.digest(int(GUILD), "fingerprint", "a" * 32), time.time() + 999)
        await self.db.store_identifier(GUILD, OTHER_USER, "ip", self.keys.digest(int(GUILD), "ip", "8.8.4.4"), time.time() + 999)
        for number in range(30):
            failed = str(175928847299300000 + number)
            await self.db.touch_member(GUILD, failed)
            for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4"), ("device", cookie)):
                await self.db.store_identifier(GUILD, failed, kind, self.keys.digest(int(GUILD), kind, value), time.time() + 999)
        await self.change(alt_account={"enabled": True, "alt_action": "deny"})
        self.assertEqual((await self.verify_through(ip="8.8.4.4"))["reason"], "alt_account")


class OlderDatabases(Base):
    async def test_a_verified_member_who_rejoined_before_the_date_column_still_counts(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.update_member(GUILD, OTHER_USER, status="pending", verified_at=2000.0)
        await self.db.close()
        await self.db.open()
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["first_verified_at"], 2000.0)

    async def test_verified_members_from_before_the_date_column_still_count(self):
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.update_member(GUILD, OTHER_USER, status="verified", verified_at=1000.0)
        await self.db.close()
        await self.db.open()
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["first_verified_at"], 1000.0)


class BansFoundDuringMatching(Base):
    async def test_a_ban_found_while_matching_ends_that_accounts_pass(self):
        self.port.add_member(OTHER_USER)
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.mark_verified(GUILD, OTHER_USER, "web", when=time.time() - 900)
        for kind, value in (("fingerprint", "a" * 32), ("ip", "8.8.4.4")):
            await self.db.store_identifier(GUILD, OTHER_USER, kind, self.keys.digest(int(GUILD), kind, value), time.time() + 999)
        self.port.banned.add(OTHER_USER)
        await self.verify_through(ip="8.8.4.4")
        self.assertEqual((await self.db.member(GUILD, OTHER_USER))["status"], "pending")
        self.port.banned.discard(OTHER_USER)
        await self.service.on_unban(GUILD, OTHER_USER)
        self.port.calls.clear()
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertFalse(self.port.did("add_role"), "a rejoin doesn't restore the role")

    async def test_deleting_while_banned_ends_the_pass_too(self):
        await self.verify_through()
        await self.db.record_ban(GUILD, OLD_USER)
        await self.service.delete_my_data(OLD_USER)
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "pending")


class BansAndJoins(Base):
    async def test_a_join_that_arrives_with_a_real_ban_keeps_the_ban(self):
        await self.db.record_ban(GUILD, OTHER_USER)
        self.port.banned.add(OTHER_USER)
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertTrue(await self.db.is_banned(GUILD, OTHER_USER))
        self.assertEqual(self.port.dms, [])

    async def test_discord_not_answering_doesnt_erase_a_ban(self):
        await self.db.record_ban(GUILD, OTHER_USER)
        self.port.is_banned = AsyncMock(side_effect=DiscordUnavailable("503"))
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertTrue(await self.db.is_banned(GUILD, OTHER_USER))

    async def test_discord_not_answering_during_an_appeal_changes_nothing(self):
        appeal = await self.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, 'vpn', 'please let me in', ?)", (GUILD, OLD_USER, time.time()))
        self.port.is_banned = AsyncMock(side_effect=DiscordUnavailable("503"))
        self.assertIn("didn't answer", await self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "staff"))
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "open")

    async def test_a_lookup_failing_after_the_unban_still_finishes_the_appeal(self):
        appeal = await self.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, 'vpn', 'please let me in', ?)", (GUILD, OLD_USER, time.time()))
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.record_ban(GUILD, OLD_USER)
        self.port.member = AsyncMock(side_effect=DiscordUnavailable("503"))
        self.assertIsNone(await self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "staff"))
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "approved")
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "approved")


class StaleBans(Base):
    async def test_joining_clears_a_ban_lifted_while_the_bot_was_offline(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.record_ban(GUILD, OLD_USER)
        await self.service.on_join(self.port.add_member(OLD_USER))
        self.assertFalse(await self.db.is_banned(GUILD, OLD_USER))

    async def test_an_appeal_with_a_stale_ban_still_verifies_a_member_who_came_back(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.record_ban(GUILD, OLD_USER)
        appeal = await self.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, 'vpn', 'please let me in', ?)", (GUILD, OLD_USER, time.time()))
        self.assertIsNone(await self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "staff"))
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "verified")


class Appeals(Base):
    async def test_a_decision_in_progress_still_counts_as_waiting(self):
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny")
        appeal = await self.appeal()
        await self.db.run("UPDATE appeals SET status = 'deciding', created_at = 1 WHERE id = ?", (appeal,))
        self.assertIn("already have", await self.service.submit_appeal(GUILD, OLD_USER, "x", "Please look at this again."))
        await self.service.purge()
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM appeals"), 1)

    async def test_a_crash_during_a_decision_hands_it_back(self):
        appeal = await self.appeal()
        await self.db.run("UPDATE appeals SET status = 'deciding' WHERE id = ?", (appeal,))
        await self.db.close()
        await self.db.open()
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "open")

    async def test_a_decision_records_who_made_it(self):
        appeal = await self.appeal()
        self.assertIsNone(await self.service.decide_appeal(GUILD, appeal, "deny", STAFF, "staff", "no"))
        row = await self.db.one("SELECT status, decided_by, note FROM appeals")
        self.assertEqual((row["status"], row["decided_by"], row["note"]), ("denied", STAFF, "no"))

    async def appeal(self):
        return await self.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, 'vpn', 'please let me in', ?)", (GUILD, OLD_USER, time.time()))

    async def test_lifting_a_ban_takes_ban_members(self):
        appeal = await self.appeal()
        await self.db.record_ban(GUILD, OLD_USER)
        problem = await self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "staff", can_unban=False)
        self.assertIn("Ban Members", problem)
        self.assertFalse(self.port.did("unban"))
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "open")

    async def test_a_ban_only_discord_knows_about_gets_lifted(self):
        appeal = await self.appeal()
        self.port.banned.add(OLD_USER)
        self.port.members.pop((GUILD, OLD_USER))  # a banned account isn't in the server
        self.assertIsNone(await self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "staff"))
        self.assertTrue(self.port.did("unban"))
        self.assertEqual((await self.db.member(GUILD, OLD_USER))["status"], "approved")

    async def test_a_ban_that_cant_be_lifted_leaves_it_open(self):
        appeal = await self.appeal()
        await self.db.record_ban(GUILD, OLD_USER)
        self.port.unban = AsyncMock(return_value=False)
        problem = await self.service.decide_appeal(GUILD, appeal, "approve", STAFF, "staff")
        self.assertIn("couldn't lift the ban", problem)
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "open")
        self.assertEqual(self.port.dms, [])


class Retention(Base):
    async def test_lowering_the_connection_setting_applies_to_what_is_stored(self):
        await self.verify_through()
        await self.db.run("UPDATE identifiers SET last_seen = ?", (time.time() - 10 * 86400,))
        document = await self.service.get_settings(GUILD)
        document["privacy"]["ip_days"] = 5
        await self.service.save_settings(GUILD, document)
        await self.service.purge()
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE kind = 'ip'"), 0)
        self.assertGreater(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE kind != 'ip'"), 0)

    async def test_a_softban_doesnt_stretch_the_hashes(self):
        await self.verify_through()
        await self.db.run("UPDATE identifiers SET last_seen = ?", (time.time() - 40 * 86400,))
        await self.service.on_ban(GUILD, OLD_USER)
        await self.service.on_unban(GUILD, OLD_USER)
        await self.service.purge()
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE kind = 'ip'"), 0)

    async def test_an_active_ban_still_keeps_them(self):
        await self.verify_through()
        await self.db.run("UPDATE identifiers SET last_seen = ?", (time.time() - 40 * 86400,))
        await self.service.on_ban(GUILD, OLD_USER)
        await self.service.purge()
        self.assertGreater(await self.db.scalar("SELECT COUNT(*) FROM identifiers WHERE kind = 'ip'"), 0)

    async def test_an_expired_link_goes_at_once(self):
        await self.link_for()
        await self.db.run("UPDATE sessions SET expires_at = ?", (time.time() - 1,))
        await self.service.purge()
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM sessions"), 0)

    async def test_a_server_that_left_while_offline_is_noticed(self):
        await self.db.mark_departed({"980000000000000009"})
        self.assertIsNotNone((await self.db.guild(GUILD))["left_at"])


class Reloads(Base):
    async def test_a_reload_during_a_cooldown_waits_to_be_asked(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["cooldown"].update(enabled=True, seconds=3600)
        await self.service.save_settings(GUILD, document)
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, last_fail_at=time.time())
        token = await self.link_for()
        await self.sign_in(token)
        self.assertEqual((await (await self.attempt(token)).json())["status"], "cooldown")
        state = await (await self.client.get(f"/api/verify/{token}", headers=self.cookie_header(BROWSER_COOKIE))).json()
        self.assertTrue(state["tried"])


class Numbers(Base):
    async def test_someone_who_walked_away_stops_counting(self):
        token = await self.link_for()
        await self.sign_in(token)
        self.assertEqual(await analytics.verifying_now(self.db, GUILD), 1)
        await self.db.run("UPDATE sessions SET signed_in_at = ?", (time.time() - 600,))
        self.assertEqual(await analytics.verifying_now(self.db, GUILD), 0)

    async def test_signing_in_again_counts_as_verifying_again(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.db.run("UPDATE sessions SET opened_at = ?, signed_in_at = ?", (time.time() - 600, time.time() - 600))
        await self.sign_in(token)
        self.assertEqual(await analytics.verifying_now(self.db, GUILD), 1)

    async def test_someone_turned_away_isnt_verifying_now(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        self.assertEqual(await analytics.verifying_now(self.db, GUILD), 1)
        await self.attempt(token, ip="45.33.32.7")
        self.assertEqual(await analytics.verifying_now(self.db, GUILD), 0)

    async def test_a_preview_applies_the_proposed_limits(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="threat", action="deny", detail={"findings": [
            {"check": "threat", "action": "deny", "detail": {"bot_score": 85, "suspect_score": 10}}]})
        rules = await self.service.get_settings(GUILD)
        looser = json.loads(json.dumps(rules))
        looser["checks"]["threat"].update(enabled=True, action="deny", bot_score=90, suspect_score=90)
        self.assertEqual((await analytics.preview(self.db, GUILD, looser))["newly_passed"], 1)
        same = json.loads(json.dumps(rules))
        same["checks"]["threat"].update(enabled=True, action="deny", bot_score=80, suspect_score=90)
        self.assertEqual((await analytics.preview(self.db, GUILD, same))["newly_passed"], 0)

    async def test_a_big_report_doesnt_hold_up_other_queries(self):
        await self.db.run_many("INSERT INTO attempts (guild_id, user_id, at, outcome) VALUES (?, ?, ?, 'passed')",
                               [(GUILD, str(175928847299200000 + number), time.time() - number) for number in range(30000)])
        report = asyncio.ensure_future(analytics.report(self.db, GUILD, time.time() - 86400, time.time() + 1))
        await asyncio.sleep(0)
        started = time.perf_counter()
        await self.db.one("SELECT 1")
        quick = time.perf_counter() - started
        self.assertEqual((await report)["cards"]["verified"], 30000)
        self.assertLess(quick, 0.5)


class Health(unittest.TestCase):
    def test_raid_mode_needs_kick_members(self):
        self.assertIn("Raid mode", health.needed_permissions(settings.defaults())["kick_members"])

    def test_a_country_override_that_bans_needs_ban_members(self):
        document = settings.defaults()
        document["raid"]["enabled"] = False
        document["checks"]["geogate"].update(enabled=True, action="deny", overrides={"RU": "ban"})
        self.assertIn("Country rules", health.needed_permissions(document)["ban_members"])


class Messages(unittest.TestCase):
    def test_hidden_reasons_stay_hidden_in_the_dm(self):
        notice = notices.failed_notice("Server", "vpn", "text", "deny", "https://x.test", None, None, False)
        self.assertEqual(notice.buttons[0].url, "https://x.test/help/verification")

    def test_shown_reasons_link_to_their_guide(self):
        notice = notices.failed_notice("Server", "vpn", "text", "deny", "https://x.test", None, None, True)
        self.assertEqual(notice.buttons[0].url, "https://x.test/help/vpn")

    def test_a_long_server_name_cant_push_an_embed_past_discords_limit(self):
        message = {**settings.DEFAULT_MESSAGES["honeypot"], "title": "t" * 256, "footer": "f" * 2048, "description": "{server} " * 200, "author": "970000000000000011"}
        embed = notices.plain_message(message, "n" * 100, "https://x.test").embeds[0]
        total = len(embed["title"]) + len(embed["description"]) + len(embed["footer"]["text"])
        self.assertLessEqual(total, 6000)
        self.assertIn("Written by", embed["description"])


class BypassNotices(Base):
    async def test_the_ping_goes_where_the_member_can_read_it(self):
        await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 2, "channel", STAFF, "staff", LOG_CHANNEL)
        channel, _ = next(item for item in self.port.sent if item[1].mention_users)
        self.assertEqual(channel, CHANNEL)


class Imports(Base):
    async def test_a_big_import_counts_only_who_changed(self):
        await self.verify_through()
        people = [OLD_USER] + [str(175928847299200000 + number) for number in range(12000)]
        started = time.perf_counter()
        count = await self.service.import_members(GUILD, people, STAFF, "staff")
        self.assertEqual(count, 12000)
        self.assertLess(time.perf_counter() - started, 20)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM members WHERE method = 'imported'"), 12000)


if __name__ == "__main__":
    unittest.main()
