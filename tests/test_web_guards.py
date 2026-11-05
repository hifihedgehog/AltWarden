"""The website: sign-in failures, flow cookies, limits, what each route tells whom, and what each save checks."""
import asyncio
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aiohttp
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from multidict import CIMultiDict

from altwarden import access, crypto, settings
from altwarden.ports import DISCORD_BUSY, DiscordUnavailable
from altwarden.signals import MAX_REPORT_BYTES
from altwarden.web import api as api_module, app as app_module, oauth as oauth_module
from altwarden.web.app import BROWSER_COOKIE, DEVICE_COOKIE, FLOW_COOKIE, SESSION_COOKIE, VERIFY_FLOW_COOKIE, build_app
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, VERIFIED_ROLE
from test_detection import clean_report
from test_flow import PUBLIC, Base as FlowBase, solve

THIRD_USER = "175928847299117066"
ROLE_A = "970000000000000070"
ROLE_B = "970000000000000071"
TRAP = "970000000000000072"


class Base(FlowBase):
    async def log_in(self, user=STAFF, owner=True, perms=("manage_guild",), roles=()):
        self.port.add_member(user, perms=perms, owner=owner, roles=roles)
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

    async def get(self, path):
        response = await self.client.get(f"/api/guilds/{GUILD}{path}", headers=self.session_cookie)
        return response.status, await response.json()

    async def send(self, method, path, body=None):
        response = await self.client.request(method, f"/api/guilds/{GUILD}{path}", json={} if body is None else body, headers=self.headers)
        return response.status, await response.json()

    async def audit_kinds(self):
        return [row["kind"] for row in await self.db.all("SELECT kind FROM audit ORDER BY at, rowid")]


class DiscordOutages(Base):
    """A timeout isn't a ClientError, and a 200 can carry anything. Every path through sign-in has to survive both."""

    def slow_session(self):
        session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=1))
        self.addAsyncCleanup(session.close)
        self.oauth.session = session

    async def test_a_token_exchange_that_times_out_is_a_failed_sign_in(self):
        self.slow_session()
        self.discord.hanging.add("token")
        response = await self.sign_in(await self.link_for())
        self.assertEqual(response.status, 302)
        self.assertIn("signin=failed", response.headers["Location"])

    async def test_a_read_that_times_out_is_a_failed_sign_in_and_the_token_is_still_revoked(self):
        self.slow_session()
        self.discord.hanging.add("me")
        response = await self.sign_in(await self.link_for())
        self.assertIn("signin=failed", response.headers["Location"])
        self.assertEqual(self.discord.revoked, ["fake-access"])

    async def test_a_token_answer_that_isnt_json_is_a_failed_sign_in(self):
        self.discord.token_body = "<html>busy</html>"
        response = await self.sign_in(await self.link_for())
        self.assertIn("signin=failed", response.headers["Location"])

    async def test_a_token_answer_that_isnt_an_object_is_a_failed_sign_in(self):
        self.discord.token_body = "[1, 2]"
        response = await self.sign_in(await self.link_for())
        self.assertIn("signin=failed", response.headers["Location"])

    async def test_an_account_answer_with_no_id_is_a_failed_sign_in(self):
        for body in ('{"username": "x"}', "[]", "not json"):
            self.discord.me_body = body
            response = await self.sign_in(await self.link_for())
            self.assertIn("signin=failed", response.headers["Location"], body)

    async def test_a_server_list_that_isnt_a_list_goes_home_with_no_session(self):
        self.discord.guilds = "not a list"
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        response = await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})
        self.assertEqual((response.status, response.headers["Location"]), (302, "/"))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM web_sessions"), 0)

    async def test_command_writes_that_landed_are_audited_when_something_unexpected_stops_the_rest(self):
        await self.log_in()
        real = self.oauth.edit_command_permissions
        calls = []

        async def second_call_breaks(*args):
            calls.append(args)
            if len(calls) == 2:
                raise RuntimeError("boom")
            return await real(*args)
        self.oauth.edit_command_permissions = second_call_breaks
        override = [{"type": "role", "id": VERIFIED_ROLE, "allow": True}]
        with self.assertLogs("altwarden.web", "ERROR"):
            response = await self.command_sync({"900000000000000001": override, "900000000000000002": override})
        self.assertEqual(response.status, 500)
        row = await self.db.one("SELECT detail FROM audit WHERE kind = 'command_permissions'")
        self.assertEqual(json.loads(row["detail"])["commands"], ["verify-user"])

    async def test_a_dashboard_sign_in_that_times_out_goes_home_with_no_session(self):
        self.slow_session()
        self.discord.hanging.add("token")
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        response = await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})
        self.assertEqual((response.status, response.headers["Location"]), (302, "/"))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM web_sessions"), 0)

    async def test_a_revoke_that_hangs_once_keeps_the_sign_in_and_tries_again(self):
        self.discord.revoke_hangs = 1
        with patch.object(oauth_module, "REVOKE_SECONDS", 0.5):
            response = await self.sign_in(await self.link_for())
        self.assertNotIn("signin=", response.headers["Location"])
        self.assertEqual(self.discord.revoke_calls, 2)
        self.assertEqual(self.discord.revoked, ["fake-access"])

    async def test_a_refused_revoke_is_tried_three_times_and_never_stops_the_sign_in(self):
        self.discord.revoke_status = 500
        with self.assertLogs("altwarden.oauth", "WARNING"):
            response = await self.sign_in(await self.link_for())
        self.assertNotIn("signin=", response.headers["Location"])
        self.assertEqual(self.discord.revoke_calls, 3)

    async def test_a_revoke_that_hangs_every_time_ends_and_keeps_the_sign_in(self):
        self.discord.revoke_hangs = 3
        with patch.object(oauth_module, "REVOKE_SECONDS", 0.5), self.assertLogs("altwarden.oauth", "WARNING"):
            response = await self.sign_in(await self.link_for())
        self.assertNotIn("signin=", response.headers["Location"])
        self.assertEqual(self.discord.revoke_calls, 3)

    async def command_sync(self, changes):
        response = await self.client.post(f"/api/guilds/{GUILD}/permissions/discord", json={"changes": changes}, headers=self.headers)
        self.assertEqual(response.status, 200, await response.text())
        state = parse_qs(urlsplit((await response.json())["authorize"]).query)["state"][0]
        flow = response.cookies[FLOW_COOKIE].value
        return await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                     headers={"Cookie": f"{FLOW_COOKIE}={flow}; {self.session_cookie['Cookie']}"})

    async def test_command_writes_that_landed_are_audited_when_a_later_one_times_out(self):
        await self.log_in()
        self.slow_session()
        self.discord.hanging.add("write")
        override = [{"type": "role", "id": VERIFIED_ROLE, "allow": True}]
        response = await self.command_sync({"900000000000000001": override, "900000000000000002": override})
        self.assertTrue(response.headers["Location"].endswith("discord=refused"), response.headers["Location"])
        self.assertEqual(len(self.discord.command_writes), 1)
        row = await self.db.one("SELECT detail FROM audit WHERE kind = 'command_permissions'")
        self.assertEqual(json.loads(row["detail"])["commands"], ["verify-user"])
        self.assertEqual(self.discord.revoked[-1], "fake-access")

    async def test_a_command_sync_token_answer_that_isnt_json_is_a_failed_sync(self):
        await self.log_in()
        self.discord.token_body = "nope"
        response = await self.command_sync({"900000000000000001": []})
        self.assertTrue(response.headers["Location"].endswith("discord=failed"), response.headers["Location"])

    async def test_a_strange_retry_after_doesnt_break_a_command_write(self):
        class Answer:
            status = 429

            async def json(self, content_type=None):
                return ["not", "an", "object"]

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

        class Session:
            def put(self, *args, **kwargs):
                return Answer()
        client = oauth_module.DiscordOAuth(Session(), "123", "x")
        with patch("asyncio.sleep", AsyncMock()):
            self.assertEqual(await client.edit_command_permissions("t", GUILD, "1", []), 429)


class FlowCookies(Base):
    async def start_verify(self, token):
        response = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        return state, response.cookies[VERIFY_FLOW_COOKIE].value

    async def finish_verify(self, state, flow, code="abc"):
        return await self.client.get("/verify/callback", params={"code": code, "state": state}, allow_redirects=False,
                                     headers={"Cookie": f"{VERIFY_FLOW_COOKIE}={flow}"})

    async def test_someone_else_loading_the_sign_in_cant_break_the_owners(self):
        token = await self.link_for()
        state, flow = await self.start_verify(token)
        await self.start_verify(token)  # the thief, in another browser, with a copy of the link
        response = await self.finish_verify(state, flow)
        self.assertEqual(response.headers["Location"], f"/v/{token}")
        self.assertIsNotNone((await self.service.session(token))["account"])

    async def test_nothing_about_a_sign_in_in_progress_is_stored(self):
        token = await self.link_for()
        await self.start_verify(token)
        self.assertIsNone((await self.service.session(token))["auth_state_hash"])

    async def test_the_flow_cookie_is_signed_and_names_the_link(self):
        token = await self.link_for()
        state, flow = await self.start_verify(token)
        self.assertEqual(flow, f"{state}.{token}.{self.keys.sign('verify-flow', f'{state}.{token}')}")

    async def test_a_flow_cookie_pointing_at_another_link_is_refused(self):
        token = await self.link_for()
        self.port.add_member(OTHER_USER)
        other = await self.link_for(OTHER_USER)
        state, flow = await self.start_verify(token)
        forged = flow.replace(token, other)
        response = await self.finish_verify(state, forged)
        self.assertEqual(response.headers["Location"], "/help/link-expired")
        self.assertEqual(self.discord.exchanged, [])

    async def test_a_state_that_differs_from_the_cookie_is_refused(self):
        token = await self.link_for()
        _, flow = await self.start_verify(token)
        response = await self.finish_verify("another-state", flow)
        self.assertEqual(response.headers["Location"], "/help/link-expired")
        self.assertEqual(self.discord.exchanged, [])

    async def test_a_flow_cookie_with_no_signature_is_refused(self):
        token = await self.link_for()
        state, _ = await self.start_verify(token)
        response = await self.finish_verify(state, f"{state}.{token}")
        self.assertEqual(response.headers["Location"], "/help/link-expired")
        self.assertEqual(self.discord.exchanged, [])

    async def test_a_state_works_once(self):
        token = await self.link_for()
        state, flow = await self.start_verify(token)
        await self.finish_verify(state, flow)
        self.discord.exchanged.clear()
        response = await self.finish_verify(state, flow)
        self.assertEqual(response.headers["Location"], "/help/link-expired")
        self.assertEqual(self.discord.exchanged, [])

    async def test_used_states_are_forgotten_once_their_cookie_has_ended(self):
        used = self.app["used_states"]
        used.update({f"old{number}": 0.0 for number in range(10_000)})
        self.assertTrue(app_module.first_use(self.app, "fresh"))
        self.assertEqual(list(used), ["fresh"])

    async def test_the_flow_cookie_keeps_its_protections(self):
        response = await self.client.get(f"/v/{await self.link_for()}/signin", allow_redirects=False)
        morsel = response.cookies[VERIFY_FLOW_COOKIE]
        self.assertTrue(VERIFY_FLOW_COOKIE.startswith("__Host-"))
        self.assertTrue(morsel["secure"] and morsel["httponly"])
        self.assertEqual((morsel["samesite"], morsel["path"]), ("Lax", "/"))
        self.assertIn("Content-Security-Policy", response.headers)

    async def test_a_dashboard_sign_in_doesnt_touch_a_verification_under_way(self):
        token = await self.link_for()
        state, flow = await self.start_verify(token)
        login = await self.client.get("/login", allow_redirects=False)
        self.assertNotIn(VERIFY_FLOW_COOKIE, login.cookies)
        self.assertIn(FLOW_COOKIE, login.cookies)
        response = await self.finish_verify(state, flow)
        self.assertEqual(response.headers["Location"], f"/v/{token}")

    async def test_every_way_out_of_a_verify_sign_in_but_another_tabs_state_clears_its_cookie(self):
        token = await self.link_for()
        state, flow = await self.start_verify(token)
        # A state that differs is the one way out that leaves the cookie, because it belongs to another tab that can still finish.
        wrong = await self.client.get("/verify/callback", params={"code": "abc", "state": "other"}, allow_redirects=False, headers={"Cookie": f"{VERIFY_FLOW_COOKIE}={flow}"})
        self.assertNotIn(VERIFY_FLOW_COOKIE, wrong.cookies, "state differs")
        declined = await self.client.get("/verify/callback", params={"error": "access_denied", "state": state}, allow_redirects=False, headers={"Cookie": f"{VERIFY_FLOW_COOKIE}={flow}"})
        self.assertEqual(declined.cookies[VERIFY_FLOW_COOKIE].value, "", "declined")
        state, flow = await self.start_verify(token)
        self.discord.fail_exchange = True
        failed = await self.finish_verify(state, flow)
        self.assertEqual(failed.cookies[VERIFY_FLOW_COOKIE].value, "", "failed")
        self.discord.fail_exchange = False
        state, flow = await self.start_verify(token)
        passed = await self.finish_verify(state, flow)
        self.assertEqual(passed.cookies[VERIFY_FLOW_COOKIE].value, "", "signed in")
        await self.db.run("DELETE FROM sessions")
        state, flow = await self.start_verify(await self.link_for())
        await self.db.run("DELETE FROM sessions")
        gone = await self.finish_verify(state, flow)
        self.assertEqual(gone.cookies[VERIFY_FLOW_COOKIE].value, "", "link gone")

    async def login_flow(self):
        response = await self.client.get("/login", allow_redirects=False)
        return parse_qs(urlsplit(response.headers["Location"]).query)["state"][0], response.cookies[FLOW_COOKIE].value

    async def test_every_way_out_of_a_dashboard_sign_in_but_another_tabs_state_clears_its_cookie(self):
        async def callback(state, flow, **params):
            return await self.client.get("/dashboard/callback", params={"state": state, **params}, allow_redirects=False, headers={"Cookie": f"{FLOW_COOKIE}={flow}"})

        state, flow = await self.login_flow()
        # A state that differs leaves the cookie, because it belongs to another tab that can still finish.
        self.assertNotIn(FLOW_COOKIE, (await callback("other", flow, code="x")).cookies, "state differs")
        self.assertEqual((await callback(state, flow)).cookies[FLOW_COOKIE].value, "", "no code")
        self.assertEqual((await callback(state, flow, code="x")).cookies[FLOW_COOKIE].value, "", "state already used")
        state, flow = await self.login_flow()
        await self.db.run("UPDATE login_states SET expires_at = 1")
        self.assertEqual((await callback(state, flow, code="x")).cookies[FLOW_COOKIE].value, "", "expired")
        state, flow = await self.login_flow()
        self.discord.fail_exchange = True
        self.assertEqual((await callback(state, flow, code="x")).cookies[FLOW_COOKIE].value, "", "Discord failed")
        self.discord.fail_exchange = False
        state, flow = await self.login_flow()
        self.assertEqual((await callback(state, flow, code="x")).cookies[FLOW_COOKIE].value, "", "signed in")

    async def test_switching_accounts_asks_discord_to_show_its_screen(self):
        token = await self.link_for()
        plain = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        self.assertEqual(parse_qs(urlsplit(plain.headers["Location"]).query)["prompt"], ["none"])
        switching = await self.client.get(f"/v/{token}/signin?switch=1", allow_redirects=False)
        self.assertEqual(parse_qs(urlsplit(switching.headers["Location"]).query)["prompt"], ["consent"])


class SignInLimits(Base):
    async def test_one_address_cant_keep_starting_sign_ins(self):
        codes = [(await self.client.get(f"/v/{number:043d}/signin", allow_redirects=False)).status for number in range(30)]
        self.assertIn(429, codes)

    async def test_starting_a_sign_in_asks_discord_for_nothing_so_one_link_can_start_many(self):
        # The cap per link sits on the token exchange, or anyone holding a stolen link could spend it and lock the owner out.
        token = await self.link_for()
        codes = [(await self.client.get(f"/v/{token}/signin", allow_redirects=False, headers={"X-Forwarded-For": f"8.8.{number}.1"})).status for number in range(30)]
        self.assertEqual(codes, [302] * 30)
        self.assertEqual(self.discord.exchanged, [])

    async def test_a_flood_of_verify_callbacks_stops_reaching_discord(self):
        token = await self.link_for()
        for _ in range(30):
            start = await self.client.get(f"/v/{token}/signin", allow_redirects=False, headers={"X-Forwarded-For": "8.8.8.8"})
            if start.status != 302:
                break
            state = parse_qs(urlsplit(start.headers["Location"]).query)["state"][0]
            await self.client.get("/verify/callback", params={"code": "junk", "state": state}, allow_redirects=False,
                                  headers={"Cookie": f"{VERIFY_FLOW_COOKIE}={start.cookies[VERIFY_FLOW_COOKIE].value}"})
        self.assertLess(len(self.discord.exchanged), 15)

    async def test_the_verify_callback_has_its_own_limit(self):
        codes = [(await self.client.get("/verify/callback", allow_redirects=False)).status for _ in range(30)]
        self.assertIn(429, codes)

    async def test_the_dashboard_callback_has_its_own_limit(self):
        codes = [(await self.client.get("/dashboard/callback", allow_redirects=False)).status for _ in range(30)]
        self.assertIn(429, codes)

    async def test_a_limit_answer_keeps_the_security_headers(self):
        for _ in range(30):
            response = await self.client.get("/dashboard/callback", allow_redirects=False)
        self.assertEqual(response.status, 429)
        self.assertIn("Content-Security-Policy", response.headers)

    async def test_a_stranger_at_the_dashboard_callback_writes_nothing(self):
        with patch.object(self.db, "run", AsyncMock(wraps=self.db.run)) as run:
            response = await self.client.get("/dashboard/callback", params={"state": "made-up", "code": "x"}, allow_redirects=False,
                                             headers={"Cookie": f"{FLOW_COOKIE}=made-up"})
        self.assertEqual(response.status, 302)
        run.assert_not_called()

    async def test_many_ipv6_networks_in_one_allocation_share_a_larger_limit(self):
        # The clock stands still, so a slow machine can't refill the bucket during the run.
        with patch.object(app_module, "time", SimpleNamespace(monotonic=lambda: 1000.0, time=time.time)):
            codes = [(await self.client.get("/login", allow_redirects=False, headers={"X-Forwarded-For": f"2001:db8:1:{number:x}::1"})).status for number in range(100)]
        wide = 80  # eight times this route's burst of ten
        self.assertEqual(codes, [302] * wide + [429] * (100 - wide))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM login_states"), wide)
        elsewhere = await self.client.get("/login", allow_redirects=False, headers={"X-Forwarded-For": "2001:db8:2:1::1"})
        self.assertEqual(elsewhere.status, 302, "another allocation has its own count")

    async def test_the_size_of_the_wider_limit_follows_the_route(self):
        codes = [(await self.client.get("/login", allow_redirects=False, headers={"X-Forwarded-For": "2001:db8:1:1::1"})).status for _ in range(30)]
        self.assertEqual(codes[:10], [302] * 10)
        self.assertLess(codes.count(302), 15, "one network still has the ordinary limit")

    async def test_an_address_after_a_sign_in_page_is_capped_in_length(self):
        fits = "/" + "a" * 199
        await self.client.get("/login", params={"next": fits}, allow_redirects=False)
        self.assertEqual((await self.db.one("SELECT next_path FROM login_states"))["next_path"], fits)
        await self.db.run("DELETE FROM login_states")
        await self.client.get("/login", params={"next": fits + "a"}, allow_redirects=False)
        self.assertEqual((await self.db.one("SELECT next_path FROM login_states"))["next_path"], "/dashboard")

    async def test_a_new_sign_in_clears_those_that_have_ended(self):
        await self.db.run("INSERT INTO login_states (state_hash, purpose, next_path, expires_at) VALUES ('old', 'dashboard', '/', 1)")
        await self.db.run("INSERT INTO login_states (state_hash, purpose, next_path, expires_at) VALUES ('live', 'dashboard', '/', ?)", (time.time() + 60,))
        await self.client.get("/login", allow_redirects=False)
        names = [row["state_hash"] for row in await self.db.all("SELECT state_hash FROM login_states")]
        self.assertNotIn("old", names)
        self.assertIn("live", names)
        self.assertEqual(len(names), 2)

    async def test_saving_a_sign_in_names_its_columns(self):
        await self.db.run("DROP TABLE login_states")
        await self.db.run("CREATE TABLE login_states (extra TEXT, expires_at REAL NOT NULL, next_path TEXT NOT NULL, purpose TEXT NOT NULL, state_hash TEXT PRIMARY KEY)")
        response = await self.client.get("/login", allow_redirects=False)
        self.assertEqual(response.status, 302)
        row = await self.db.one("SELECT purpose, next_path FROM login_states")
        self.assertEqual((row["purpose"], row["next_path"]), ("dashboard", "/dashboard"))

    async def test_holding_a_command_change_names_its_columns(self):
        await self.log_in()
        await self.db.run("DROP TABLE command_syncs")
        await self.db.run("CREATE TABLE command_syncs (extra TEXT, expires_at REAL NOT NULL, changes TEXT NOT NULL, user_id TEXT NOT NULL, guild_id TEXT NOT NULL, state_hash TEXT PRIMARY KEY)")
        response = await self.client.post(f"/api/guilds/{GUILD}/permissions/discord", json={"changes": {"900000000000000001": []}}, headers=self.headers)
        self.assertEqual(response.status, 200, await response.text())
        row = await self.db.one("SELECT guild_id, user_id FROM command_syncs")
        self.assertEqual((row["guild_id"], row["user_id"]), (GUILD, STAFF))


class WebSessions(Base):
    async def stored_guilds(self):
        return json.loads((await self.db.one("SELECT guilds FROM web_sessions ORDER BY created_at DESC"))["guilds"])

    async def callback(self):
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        return await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                     headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})

    async def test_only_servers_the_bot_is_in_are_kept_whatever_the_person_holds_there(self):
        self.port.add_member(STAFF, perms=("manage_guild",), owner=True)
        self.discord.user["id"] = STAFF
        self.discord.guilds = [{"id": GUILD, "name": "Test Server", "icon": None, "owner": False, "permissions": "0"},
                               {"id": "980000000000000002", "name": "Owned family server", "icon": None, "owner": True, "permissions": "8"},
                               {"id": "980000000000000003", "name": "Managed client server", "icon": None, "owner": False, "permissions": "32"}]
        await self.callback()
        self.assertEqual(await self.stored_guilds(), [{"id": GUILD, "name": "Test Server", "icon": None}])

    async def test_a_server_still_loading_is_kept(self):
        self.port.add_member(STAFF, perms=("manage_guild",), owner=True)
        self.discord.user["id"] = STAFF
        self.discord.guilds = [{"id": "980000000000000002", "name": "Still loading", "icon": None, "owner": False, "permissions": "0"}]
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        self.port.loading = True
        await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                              headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})
        self.assertEqual([guild["name"] for guild in await self.stored_guilds()], ["Still loading"])

    async def test_a_new_sign_in_ends_the_one_this_browser_held(self):
        await self.log_in()
        first = self.session_cookie
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                              headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}; {first['Cookie']}"})
        self.assertEqual((await self.client.get("/api/session", headers=first)).status, 401)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM web_sessions"), 1)

    async def test_a_new_sign_in_leaves_other_browsers_alone(self):
        await self.log_in()
        other_browser = self.session_cookie
        await self.log_in()
        response = await self.client.get("/login", allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                              headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}; {self.session_cookie['Cookie']}"})
        self.assertEqual((await self.client.get("/api/session", headers=other_browser)).status, 200)

    async def test_signing_out_ends_every_device_and_nobody_elses(self):
        await self.log_in(user=OTHER_USER)
        someone_else = self.session_cookie
        await self.log_in()
        other_device = self.session_cookie
        await self.log_in()
        response = await self.client.post("/api/logout", json={}, headers=self.headers)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.cookies[SESSION_COOKIE].value, "")
        self.assertEqual((await self.client.get("/api/session", headers=self.session_cookie)).status, 401)
        self.assertEqual((await self.client.get("/api/session", headers=other_device)).status, 401)
        self.assertEqual((await self.client.get("/api/session", headers=someone_else)).status, 200)

    async def test_the_my_data_sign_in_link_ignores_the_address(self):
        data = await (await self.client.get("/api/me/data?next=//evil.test")).json()
        self.assertEqual(data["login"], "/login?for=member&next=/my-data")


class VerifyPosts(Base):
    async def ready(self):
        token = await self.link_for()
        await self.sign_in(token)
        return token

    def routes(self, token):
        return [f"/api/verify/{token}/{name}" for name in ("challenge", "submit", "help")]

    async def test_a_foreign_origin_is_refused_on_every_verify_post(self):
        token = await self.ready()
        for origin in ("https://evil.test", "null", PUBLIC + ".evil.test", "http://altwarden.test"):
            for route in self.routes(token):
                response = await self.client.post(route, json={}, headers={**self.cookie_header(BROWSER_COOKIE), "Origin": origin})
                self.assertEqual(response.status, 403, (route, origin))
                self.assertIn("Content-Security-Policy", response.headers)

    async def test_a_cross_site_fetch_is_refused_on_every_verify_post(self):
        token = await self.ready()
        for value in ("cross-site", "Cross-Site"):
            for route in self.routes(token):
                response = await self.client.post(route, json={}, headers={**self.cookie_header(BROWSER_COOKIE), "Sec-Fetch-Site": value})
                self.assertEqual(response.status, 403, route)

    async def test_this_sites_own_page_passes(self):
        token = await self.ready()
        response = await self.client.post(f"/api/verify/{token}/challenge", headers={**self.cookie_header(BROWSER_COOKIE), "Origin": PUBLIC, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(response.status, 200, await response.text())

    async def test_a_client_that_sends_neither_header_passes_those_checks(self):
        token = await self.ready()
        self.assertEqual((await self.client.post(f"/api/verify/{token}/challenge", headers=self.cookie_header(BROWSER_COOKIE))).status, 200)

    async def test_a_refused_challenge_changes_nothing(self):
        token = await self.ready()
        await self.client.post(f"/api/verify/{token}/challenge", headers={**self.cookie_header(BROWSER_COOKIE), "Origin": "https://evil.test"})
        self.assertIsNone((await self.service.session(token))["nonce"])

    async def bare_client(self, trust_proxy):
        """Requests with nothing added, which is what the site sees if the proxy stops forwarding addresses."""
        app = build_app(self.service, self.keys, self.oauth, trust_proxy=trust_proxy)
        app["http"] = self.http
        client = TestClient(TestServer(app))
        await client.start_server()
        self.addAsyncCleanup(client.close)
        return client

    async def test_with_a_proxy_expected_a_loopback_address_gets_503_on_every_verify_post(self):
        token = await self.ready()
        client = await self.bare_client(True)
        for route in self.routes(token):
            response = await client.post(route, json={}, headers=self.cookie_header(BROWSER_COOKIE))
            self.assertEqual(response.status, 503, route)
            self.assertEqual((await response.json())["error"], "The connection check isn't available right now.")
            self.assertIn("Content-Security-Policy", response.headers)

    async def test_any_forwarded_value_that_comes_out_loopback_gets_503(self):
        token = await self.ready()
        for value in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "127.8.8.8", "garbage", "1.2.3.4,", ""):
            response = await self.client.post(f"/api/verify/{token}/challenge", headers={**self.cookie_header(BROWSER_COOKIE), "X-Forwarded-For": value})
            self.assertEqual(response.status, 503, value)

    async def test_an_address_that_cant_be_read_gets_503(self):
        token = await self.ready()
        with patch.object(app_module, "client_ip", return_value=""):
            response = await self.client.post(f"/api/verify/{token}/challenge", headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 503)

    async def test_a_real_forwarded_address_passes(self):
        token = await self.ready()
        for value in ("8.8.8.8", "2001:4860:4860::8888"):
            response = await self.client.post(f"/api/verify/{token}/challenge", headers={**self.cookie_header(BROWSER_COOKIE), "X-Forwarded-For": value})
            self.assertEqual(response.status, 200, value)

    async def test_without_a_proxy_expected_a_loopback_address_passes(self):
        token = await self.ready()
        client = await self.bare_client(False)
        response = await client.post(f"/api/verify/{token}/challenge", headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 200, await response.text())

    async def test_a_submit_refused_for_its_address_stores_nothing(self):
        token = await self.ready()
        challenge = await (await self.client.post(f"/api/verify/{token}/challenge", headers=self.cookie_header(BROWSER_COOKIE))).json()
        before = await self.db.scalar("SELECT COUNT(*) FROM attempts")
        client = await self.bare_client(True)
        body = {"nonce": challenge["nonce"], "counter": solve(challenge["salt"], challenge["bits"]), "report": clean_report()}
        response = await client.post(f"/api/verify/{token}/submit", json=body, headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 503)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM identifiers"), 0)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts"), before)
        self.assertEqual((await self.service.session(token))["state"], "signed_in")

    async def test_the_state_read_still_answers_with_no_address(self):
        token = await self.ready()
        client = await self.bare_client(True)
        self.assertEqual((await client.get(f"/api/verify/{token}")).status, 200)

    async def test_a_broken_proxy_is_logged_without_flooding_the_log(self):
        token = await self.ready()
        client = await self.bare_client(True)
        with self.assertLogs("altwarden.web", "WARNING") as logged:
            for _ in range(5):
                await client.post(f"/api/verify/{token}/challenge", headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(len(logged.records), 1)


class DeviceCookies(Base):
    async def challenge(self, token, cookies=None):
        response = await self.client.post(f"/api/verify/{token}/challenge", headers={**self.cookie_header(BROWSER_COOKIE), **(cookies or {})})
        self.assertEqual(response.status, 200, await response.text())
        return response

    async def submit(self, token, response, device=None):
        challenge = await response.json()
        cookie = self.cookie_header(BROWSER_COOKIE)["Cookie"]
        if device:
            cookie += f"; {DEVICE_COOKIE}={device}"
        body = {"nonce": challenge["nonce"], "counter": solve(challenge["salt"], challenge["bits"]), "report": clean_report()}
        return await self.client.post(f"/api/verify/{token}/submit", json=body, headers={"Cookie": cookie, "User-Agent": clean_report()["nav"]["ua"]})

    async def test_a_browser_that_drops_only_the_device_cookie_counts_as_automated(self):
        token = await self.link_for()
        await self.sign_in(token)
        result = await (await self.submit(token, await self.challenge(token))).json()
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(result["reason"], "automation")

    async def test_a_forged_device_cookie_at_submit_counts_the_same(self):
        token = await self.link_for()
        await self.sign_in(token)
        result = await (await self.submit(token, await self.challenge(token), device="forged.value")).json()
        self.assertEqual(result["reason"], "automation")

    async def test_a_browser_that_carries_it_passes(self):
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.challenge(token)
        result = await (await self.submit(token, response, device=response.cookies[DEVICE_COOKIE].value)).json()
        self.assertEqual(result["status"], "verified", result)

    async def test_the_flag_reaches_the_service_from_this_one_place(self):
        token = await self.link_for()
        await self.sign_in(token)
        with patch.object(self.service, "submit_web", AsyncMock(wraps=self.service.submit_web)) as submit:
            response = await self.challenge(token)
            await self.submit(token, response, device=response.cookies[DEVICE_COOKIE].value)
        self.assertIs(submit.call_args.kwargs["cookie_refused"], False)
        token = await self.link_for()
        await self.sign_in(token)
        with patch.object(self.service, "submit_web", AsyncMock(wraps=self.service.submit_web)) as submit:
            await self.submit(token, await self.challenge(token))
        self.assertIs(submit.call_args.kwargs["cookie_refused"], True)

    async def test_the_same_value_gets_a_fresh_life_at_each_challenge(self):
        token = await self.link_for()
        await self.sign_in(token)
        first = await self.challenge(token)
        value = first.cookies[DEVICE_COOKIE].value
        again = await self.challenge(token, {"Cookie": self.cookie_header(BROWSER_COOKIE)["Cookie"] + f"; {DEVICE_COOKIE}={value}"})
        self.assertEqual(again.cookies[DEVICE_COOKIE].value, value)
        self.assertEqual(int(again.cookies[DEVICE_COOKIE]["max-age"]), 365 * 86400)

    async def test_the_life_follows_the_server_doing_the_check_up_to_what_browsers_allow(self):
        token = await self.link_for()
        await self.sign_in(token)
        for days, expected in ((30, 30), (730, 400)):
            document = await self.service.get_settings(GUILD)
            document["privacy"]["identifier_days"] = days
            await self.service.save_settings(GUILD, document)
            response = await self.challenge(token)
            self.assertEqual(int(response.cookies[DEVICE_COOKIE]["max-age"]), expected * 86400, days)

    async def test_a_forged_value_is_replaced_not_renewed(self):
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.challenge(token, {"Cookie": self.cookie_header(BROWSER_COOKIE)["Cookie"] + f"; {DEVICE_COOKIE}=forged.value"})
        fresh = response.cookies[DEVICE_COOKIE].value
        self.assertNotEqual(fresh, "forged.value")
        self.assertIsNotNone(self.keys.read_device_cookie(fresh))

    async def test_the_cookie_keeps_its_protections_when_renewed(self):
        token = await self.link_for()
        await self.sign_in(token)
        morsel = (await self.challenge(token)).cookies[DEVICE_COOKIE]
        self.assertTrue(morsel["secure"] and morsel["httponly"])
        self.assertEqual((morsel["samesite"], morsel["path"]), ("Lax", "/"))


class Submissions(Base):
    async def challenged(self):
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.client.post(f"/api/verify/{token}/challenge", headers=self.cookie_header(BROWSER_COOKIE))
        if DEVICE_COOKIE in response.cookies:
            self.jar[DEVICE_COOKIE] = response.cookies[DEVICE_COOKIE].value
        return token, await response.json()

    def body(self, challenge, **extra):
        return {"nonce": challenge["nonce"], "counter": solve(challenge["salt"], challenge["bits"]), "report": clean_report(), **extra}

    async def test_a_chunked_report_past_the_limit_is_refused(self):
        token, _ = await self.challenged()

        async def chunks():
            for _ in range(20):
                yield b"x" * 8192
        response = await self.client.post(f"/api/verify/{token}/submit", data=chunks(), headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 413)

    async def test_an_announced_length_past_the_limit_is_refused_before_the_body_arrives(self):
        reader, writer = await asyncio.open_connection(self.client.host, self.client.port)
        writer.write(f"POST /api/verify/{'a' * 43}/submit HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.9\r\nContent-Length: 900000\r\n\r\n".encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 3)
        writer.close()
        self.assertIn(b"413", line)

    async def test_a_report_at_the_limit_is_read(self):
        token, _ = await self.challenged()
        raw = b" " * MAX_REPORT_BYTES
        response = await self.client.post(f"/api/verify/{token}/submit", data=raw, headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 400, "read in full, then refused as not being JSON")

    async def test_true_isnt_a_counter(self):
        token, challenge = await self.challenged()
        with patch("altwarden.web.app.pow_solved", return_value=True):
            for counter in (True, False, 1.0, "1", None):
                response = await self.client.post(f"/api/verify/{token}/submit", json=self.body(challenge, counter=counter), headers=self.cookie_header(BROWSER_COOKIE))
                self.assertEqual(response.status, 400, counter)
                self.assertEqual((await response.json())["reason"], "security_check")

    async def test_an_expired_link_doesnt_read_as_a_used_attempt(self):
        token, challenge = await self.challenged()
        await self.db.run("UPDATE sessions SET expires_at = 1")
        response = await self.client.post(f"/api/verify/{token}/submit", json=self.body(challenge), headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 409)
        self.assertEqual((await response.json())["error"], "This link has expired")

    async def test_a_used_attempt_still_says_so(self):
        token, challenge = await self.challenged()
        body = self.body(challenge)
        headers = self.cookie_header(BROWSER_COOKIE, DEVICE_COOKIE)
        await self.client.post(f"/api/verify/{token}/submit", json=body, headers=headers)
        response = await self.client.post(f"/api/verify/{token}/submit", json=body, headers=headers)
        self.assertEqual(response.status, 409)
        self.assertIn("already used", (await response.json())["error"])


class VerifyPage(Base):
    async def state(self, token, headers=None):
        return await (await self.client.get(f"/api/verify/{token}", headers=headers)).json()

    async def test_the_reply_never_carries_the_members_id(self):
        token = await self.link_for()
        data = await self.state(token)
        self.assertEqual(data["member"], {"name": "someone", "avatar": "abc"})
        self.assertNotIn(OLD_USER, json.dumps(data))

    async def test_a_finished_link_names_nobody(self):
        await self.verify_through()
        token = await self.db.one("SELECT token_hash FROM sessions WHERE state = 'done'")
        self.assertIsNotNone(token)
        link = await self.link_for()
        await self.db.run("UPDATE sessions SET state = 'done' WHERE token_hash = ?", (crypto.token_hash(link),))
        data = await self.state(link)
        self.assertEqual(data["step"], "done")
        self.assertNotIn("member", data)

    async def test_an_expired_link_names_nobody(self):
        token = await self.link_for()
        await self.db.run("UPDATE sessions SET expires_at = 1")
        self.assertEqual(await self.state(token), {"step": "expired"})

    async def done_link(self):
        await self.verify_through()
        link = await self.link_for()
        await self.db.run("UPDATE sessions SET state = 'done' WHERE token_hash = ?", (crypto.token_hash(link),))
        return link

    async def test_a_finished_link_reads_as_verified_while_that_is_true(self):
        self.assertEqual((await self.state(await self.done_link()))["step"], "done")

    async def test_a_finished_link_expires_once_the_member_isnt_verified(self):
        link = await self.done_link()
        await self.db.update_member(GUILD, OLD_USER, status="pending")
        self.port.members[(GUILD, OLD_USER)].role_ids = ()
        self.assertEqual(await self.state(link), {"step": "expired"})

    async def test_a_finished_link_stands_for_someone_staff_gave_the_role_to(self):
        link = await self.done_link()
        await self.db.update_member(GUILD, OLD_USER, status="pending")
        self.port.members[(GUILD, OLD_USER)].role_ids = (VERIFIED_ROLE,)
        self.assertEqual((await self.state(link))["step"], "done")

    async def test_a_finished_link_still_answers_when_discord_doesnt(self):
        link = await self.done_link()
        self.port.discord_down = True
        self.assertEqual((await self.state(link))["step"], "done")
        await self.db.update_member(GUILD, OLD_USER, status="pending")
        self.assertEqual(await self.state(link), {"step": "expired"})

    async def test_the_first_view_starts_the_clock_and_later_views_write_nothing(self):
        token = await self.link_for()
        self.assertIsNone((await self.service.session(token))["opened_at"])
        await self.state(token)
        first = (await self.service.session(token))["opened_at"]
        self.assertIsNotNone(first)
        with patch.object(self.service, "mark_opened", AsyncMock()) as mark:
            await self.state(token)
        mark.assert_not_called()

    async def test_a_dead_link_starts_no_clock(self):
        token = await self.link_for()
        await self.db.run("UPDATE sessions SET expires_at = 1")
        await self.state(token)
        self.assertIsNone((await self.service.session(token))["opened_at"])

    async def test_time_to_verify_runs_from_the_first_view(self):
        token = await self.link_for()
        await self.state(token)
        await self.db.run("UPDATE sessions SET opened_at = opened_at - 300")
        await self.sign_in(token)
        await self.attempt(token)
        seconds = await self.db.scalar("SELECT seconds FROM attempts WHERE outcome = 'passed'")
        self.assertGreater(seconds, 290)

    async def desk(self, **options):
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, channel=CHANNEL, support_role=VERIFIED_ROLE, **options)
        await self.service.save_settings(GUILD, document)

    async def test_the_page_learns_whether_to_offer_staff(self):
        token = await self.link_for()
        self.assertFalse((await self.state(token))["staff_help"])
        await self.desk(redirect=False)
        self.assertFalse((await self.state(token))["staff_help"])
        await self.desk(redirect=True)
        self.assertTrue((await self.state(token))["staff_help"])

    async def test_a_server_that_doesnt_offer_staff_opens_no_thread_from_the_page(self):
        await self.desk(redirect=False, require_attempt=False)
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.client.post(f"/api/verify/{token}/help", headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 409)
        self.assertEqual(self.port.threads, [])

    async def test_a_server_that_offers_staff_opens_one(self):
        await self.desk(redirect=True, require_attempt=False)
        token = await self.link_for()
        await self.sign_in(token)
        response = await self.client.post(f"/api/verify/{token}/help", headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 200, await response.text())

    async def test_viewing_a_link_isnt_signing_in(self):
        await self.desk(redirect=True, require_attempt=False)
        token = await self.link_for()
        await self.state(token)
        self.assertEqual((await self.client.post(f"/api/verify/{token}/help")).status, 409)
        self.assertEqual(self.port.threads, [])


class AppealPage(Base):
    async def member_session(self, user=OLD_USER):
        self.discord.user["id"] = user
        response = await self.client.get("/login", params={"for": "member", "next": "/my-data"}, allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        response = await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})
        return {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE].value}"}

    async def page(self, user=OLD_USER):
        cookie = await self.member_session(user)
        response = await self.client.get(f"/api/me/appeal/{GUILD}", headers=cookie)
        self.assertEqual(response.status, 200, await response.text())
        return await response.json()

    async def failed(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")

    async def test_the_page_says_whether_an_appeal_would_go_through_and_never_which_check(self):
        await self.failed()
        data = await self.page()
        self.assertIs(data["check"], True)
        text = json.dumps(data)
        self.assertNotIn("vpn", text)
        self.assertNotIn("VPN", text)

    async def test_a_failure_past_the_window_offers_no_form(self):
        await self.failed()
        await self.db.run("UPDATE attempts SET at = ?", (time.time() - 8 * 86400,))
        data = await self.page()
        self.assertIs(data["check"], False)
        self.assertEqual(data["problem"], "There is no recent failed attempt to appeal.")

    async def test_a_server_with_appeals_off_offers_no_form(self):
        await self.failed()
        document = await self.service.get_settings(GUILD)
        document["appeals"]["enabled"] = False
        await self.service.save_settings(GUILD, document)
        data = await self.page()
        self.assertIs(data["check"], False)
        self.assertIs(data["enabled"], False)

    async def test_a_server_the_bot_left_offers_no_form(self):
        await self.failed()
        self.port.absent = True
        data = await self.page()
        self.assertIs(data["check"], False)
        self.assertIs(data["present"], False)

    async def test_what_else_can_be_appealed_gets_the_form(self):
        for outcome, check_id in (("role_problem", "role_problem"), ("honeypot", "honeypot")):
            await self.db.run("DELETE FROM attempts")
            await self.db.add_attempt(GUILD, OLD_USER, outcome, check_id=check_id, action="kick", mode="web")
            self.assertIs((await self.page())["check"], True, outcome)

    async def test_a_decided_appeal_shows_and_the_same_failure_cant_go_again(self):
        await self.failed()
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        appeal = await self.db.one("SELECT id FROM appeals")
        await self.service.decide_appeal(GUILD, appeal["id"], "deny", STAFF, "staff", "No.")
        data = await self.page()
        self.assertEqual(data["latest"]["status"], "denied")
        self.assertIs(data["check"], False)
        self.assertIs(data["open"], False)

    async def test_a_waiting_appeal_shows(self):
        await self.failed()
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        self.assertIs((await self.page())["open"], True)

    async def test_a_stranger_learns_nothing_about_the_server(self):
        self.port.members.pop((GUILD, THIRD_USER), None)
        data = await self.page(THIRD_USER)
        self.assertEqual(data["guild"]["name"], "this server")
        self.assertIs(data["enabled"], False)
        self.assertIs(data["present"], False)
        self.assertIs(data["check"], False)

    async def test_the_page_still_draws_when_discord_doesnt_answer(self):
        await self.failed()
        cookie = await self.member_session()
        self.port.discord_down = True
        response = await self.client.get(f"/api/me/appeal/{GUILD}", headers=cookie)
        self.assertEqual(response.status, 200)
        self.assertIs((await response.json())["check"], True)


class SiteWideAnswers(Base):
    async def test_a_discord_outage_on_a_dashboard_read_is_a_503_with_one_warning(self):
        await self.log_in()
        self.port.discord_down = True
        for path in (f"/api/guilds/{GUILD}/settings", f"/api/guilds/{GUILD}"):
            with self.assertLogs("altwarden.web", "WARNING") as logged:
                response = await self.client.get(path, headers=self.session_cookie)
            self.assertEqual(response.status, 503, path)
            self.assertEqual(await response.json(), {"error": "Discord didn't answer. Try again in a moment."})
            self.assertEqual(len(logged.records), 1)
            self.assertEqual(logged.records[0].levelname, "WARNING")
            self.assertIsNone(logged.records[0].exc_info, "no traceback")
            self.assertIn("Content-Security-Policy", response.headers)

    async def test_a_discord_outage_on_a_save_is_a_503(self):
        await self.log_in()
        self.port.discord_down = True
        status, data = await self.send("PUT", "/settings", {"settings": {}})
        self.assertEqual((status, data["error"]), (503, DISCORD_BUSY))

    async def test_a_discord_outage_on_the_help_button_is_a_503(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, redirect=True, channel=CHANNEL, support_role=VERIFIED_ROLE)
        await self.service.save_settings(GUILD, document)
        token = await self.link_for()
        await self.sign_in(token)
        self.port.discord_down = True
        response = await self.client.post(f"/api/verify/{token}/help", headers=self.cookie_header(BROWSER_COOKIE))
        self.assertEqual(response.status, 503)
        self.assertEqual((await response.json())["error"], DISCORD_BUSY)

    async def test_an_outage_away_from_the_api_answers_in_plain_text(self):
        app = self.app
        self.assertEqual(app_module.DISCORD_BUSY, DISCORD_BUSY)

        async def handler(request):
            raise DiscordUnavailable("down")
        request = make_mocked_request("GET", "/somewhere")
        response = await app_module.errors(request, handler)
        self.assertEqual((response.status, response.text), (503, DISCORD_BUSY))

    async def test_any_other_failure_stays_a_500_with_its_traceback(self):
        await self.log_in()
        self.port.member = AsyncMock(side_effect=RuntimeError("boom"))
        with self.assertLogs("altwarden.web", "ERROR") as logged:
            response = await self.client.get(f"/api/guilds/{GUILD}/settings", headers=self.session_cookie)
        self.assertEqual(response.status, 500)
        self.assertIsNotNone(logged.records[0].exc_info)

    async def test_the_outage_text_is_translated(self):
        folder = Path(app_module.__file__).parent / "static" / "i18n"
        self.assertIn(DISCORD_BUSY, json.loads((folder / "en.json").read_text(encoding="utf-8")))
        for code in ("de", "es", "fr", "ja", "ko", "pt", "ru", "zh"):
            self.assertIn(DISCORD_BUSY, json.loads((folder / f"{code}.json").read_text(encoding="utf-8")), code)

    async def test_a_missing_library_file_isnt_cached_for_a_year(self):
        response = await self.client.get("/static/vendor/nothing-here.js")
        self.assertEqual(response.status, 404)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("Content-Security-Policy", response.headers)

    async def test_a_missing_page_file_isnt_kept_either(self):
        response = await self.client.get("/static/js/nothing-here.js")
        self.assertEqual((response.status, response.headers["Cache-Control"]), (404, "no-store"))

    async def test_a_library_file_still_caches_for_a_year_and_its_304_too(self):
        name = next(path for path in (Path(app_module.__file__).parent / "static" / "vendor").iterdir() if path.is_file()).name
        response = await self.client.get(f"/static/vendor/{name}")
        self.assertEqual(response.status, 200)
        self.assertIn("immutable", response.headers["Cache-Control"])
        again = await self.client.get(f"/static/vendor/{name}", headers={"If-None-Match": response.headers["ETag"]})
        self.assertEqual(again.status, 304)
        self.assertIn("immutable", again.headers["Cache-Control"])

    async def test_a_page_file_still_asks_first_and_its_304_too(self):
        response = await self.client.get("/static/js/verify.js")
        self.assertEqual((response.status, response.headers["Cache-Control"]), (200, "no-cache"))
        again = await self.client.get("/static/js/verify.js", headers={"If-None-Match": response.headers["ETag"]})
        self.assertEqual((again.status, again.headers["Cache-Control"]), (304, "no-cache"))
        self.assertIn("Content-Security-Policy", again.headers)

    async def test_security_txt_has_a_future_expiry(self):
        text = await (await self.client.get("/.well-known/security.txt")).text()
        line = next(entry for entry in text.splitlines() if entry.startswith("Expires: "))
        when = datetime.strptime(line.removeprefix("Expires: "), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        days = (when - datetime.now(timezone.utc)).days
        self.assertTrue(290 < days <= 300, days)

    async def test_the_health_check_says_only_that_the_site_is_up(self):
        response = await self.client.get("/healthz")
        self.assertEqual(await response.json(), {"ok": True})



class SettingsRevisions(Base):
    async def rules(self):
        return (await self.get("/settings"))[1]

    async def test_a_save_from_a_stale_tab_is_refused_and_changes_nothing(self):
        await self.log_in()
        tab = await self.rules()
        newer = await self.rules()
        newer["settings"]["checks"]["vpn"]["action"] = "ban"
        status, data = await self.send("PUT", "/settings", {"settings": newer["settings"], "base": newer["revision"]})
        self.assertEqual(status, 200, data)
        self.assertNotEqual(data["revision"], tab["revision"])
        tab["settings"]["checks"]["avatar"]["enabled"] = True
        status, data = await self.send("PUT", "/settings", {"settings": tab["settings"], "base": tab["revision"]})
        self.assertEqual(status, 409)
        self.assertEqual(data, {"error": "Someone else changed these settings. Reload to see their changes.", "conflict": True})
        document = await self.service.get_settings(GUILD)
        self.assertEqual(document["checks"]["vpn"]["action"], "ban")
        self.assertFalse(document["checks"]["avatar"]["enabled"])

    async def test_the_revision_a_save_returns_is_the_one_to_save_on_next(self):
        await self.log_in()
        first = await self.rules()
        first["settings"]["checks"]["vpn"]["action"] = "ban"
        _, data = await self.send("PUT", "/settings", {"settings": first["settings"], "base": first["revision"]})
        self.assertEqual(data["revision"], (await self.rules())["revision"])
        data["settings"]["checks"]["vpn"]["action"] = "kick"
        status, _ = await self.send("PUT", "/settings", {"settings": data["settings"], "base": data["revision"]})
        self.assertEqual(status, 200)

    async def test_a_base_that_isnt_text_means_no_check(self):
        await self.log_in()
        document = (await self.rules())["settings"]
        status, _ = await self.send("PUT", "/settings", {"settings": document, "base": 5})
        self.assertEqual(status, 200)

    async def test_no_base_means_no_check(self):
        await self.log_in()
        document = (await self.rules())["settings"]
        await self.service.save_settings(GUILD, {**await self.service.get_settings(GUILD), "preset": "custom"})
        await self.send("PUT", "/settings", {"settings": document})
        status, _ = await self.send("PUT", "/settings", {"settings": document})
        self.assertEqual(status, 200)

    async def test_a_rules_save_keeps_what_another_page_saved_meanwhile(self):
        await self.log_in()
        tab = await self.rules()
        look = (await self.get("/appearance"))[1]
        look["messages"]["verification"]["title"] = "Changed elsewhere"
        await self.send("PUT", "/appearance", {"messages": look["messages"], "base": look["revision"]})
        status, _ = await self.send("PUT", "/settings", {"settings": tab["settings"], "base": tab["revision"]})
        self.assertEqual(status, 200, "another page's save isn't a conflict")
        self.assertEqual((await self.service.get_settings(GUILD))["messages"]["verification"]["title"], "Changed elsewhere")

    async def test_a_permissions_save_from_a_stale_tab_is_refused(self):
        await self.log_in()
        tab = (await self.get("/permissions"))[1]
        rule = {"required": ["manage_guild"], "overrides": [{"type": "everyone", "allow": True}]}
        status, data = await self.send("PUT", "/permissions", {"permissions": {"pages": {"audit": {"view": rule}}, "commands": {}}, "base": tab["revision"]})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["revision"], (await self.get("/permissions"))[1]["revision"])
        status, data = await self.send("PUT", "/permissions", {"permissions": {"pages": {}, "commands": {}}, "base": tab["revision"]})
        self.assertEqual((status, data["conflict"]), (409, True))
        self.assertIn("audit", (await self.service.get_settings(GUILD))["permissions"]["pages"])

    async def test_a_messages_save_from_a_stale_tab_is_refused(self):
        await self.log_in()
        tab = (await self.get("/appearance"))[1]
        first = json.loads(json.dumps(tab["messages"]))
        first["verification"]["title"] = "First"
        status, data = await self.send("PUT", "/appearance", {"messages": first, "base": tab["revision"]})
        self.assertEqual(status, 200, data)
        self.assertEqual(data["revision"], (await self.get("/appearance"))[1]["revision"])
        tab["messages"]["verification"]["title"] = "Second"
        status, data = await self.send("PUT", "/appearance", {"messages": tab["messages"], "base": tab["revision"]})
        self.assertEqual((status, data["conflict"]), (409, True))
        self.assertEqual((await self.service.get_settings(GUILD))["messages"]["verification"]["title"], "First")

    async def test_a_server_with_no_document_yet_accepts_the_revision_it_gave(self):
        await self.log_in()
        await self.db.run("DELETE FROM guilds")
        self.service.forget_cached(GUILD)
        tab = await self.rules()
        status, data = await self.send("PUT", "/permissions", {"permissions": {"pages": {}, "commands": {}}, "base": (await self.get("/permissions"))[1]["revision"]})
        self.assertEqual(status, 200, data)
        self.assertTrue(tab["revision"])

    async def test_a_save_built_on_what_is_stored_now_keeps_permissions_changed_after_the_read(self):
        await self.log_in()
        document = (await self.rules())["settings"]
        original = self.port.guild

        async def changes_meanwhile(guild_id):
            current = json.loads(json.dumps(await self.service.get_settings(GUILD)))
            current["permissions"]["pages"]["audit"] = {"view": {"required": ["administrator"], "overrides": []}}
            self.port.guild = original
            await self.service.save_settings(GUILD, current)
            return await original(guild_id)
        self.port.guild = changes_meanwhile
        status, _ = await self.send("PUT", "/settings", {"settings": document})
        self.assertEqual(status, 200)
        self.assertIn("audit", (await self.service.get_settings(GUILD))["permissions"]["pages"])


class AppearancePage(Base):
    async def only_appearance(self, level="view"):
        document = await self.service.get_settings(GUILD)
        rule = {"required": [], "overrides": [{"type": "role", "id": ROLE_A, "allow": True}]}
        document["permissions"]["pages"]["appearance"] = {level: rule}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=(), roles=(ROLE_A,))

    async def test_a_role_with_only_this_page_can_read_it_and_not_the_rules(self):
        await self.only_appearance()
        status, data = await self.get("/appearance")
        self.assertEqual(status, 200, data)
        self.assertEqual(set(data), {"messages", "appearance", "honeypot_enabled", "can_edit", "revision"})
        self.assertFalse(data["can_edit"])
        self.assertEqual((await self.get("/settings"))[0], 403)

    async def test_an_editor_is_told_they_can_edit(self):
        await self.only_appearance("edit")
        self.assertTrue((await self.get("/appearance"))[1]["can_edit"])

    async def test_someone_without_the_page_cant_read_it(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=())
        self.assertEqual((await self.get("/appearance"))[0], 403)

    async def test_a_failed_repost_after_an_edit_is_reported(self):
        await self.log_in()
        self.app["post_message"] = AsyncMock(return_value=False)
        tab = (await self.get("/appearance"))[1]
        tab["messages"]["verification"]["title"] = "New"
        status, data = await self.send("PUT", "/appearance", {"messages": tab["messages"]})
        self.assertEqual(status, 200)
        self.assertIn("couldn't post", data["problem"])

    async def test_a_failed_honeypot_repost_is_reported_too(self):
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=CHANNEL)
        await self.service.save_settings(GUILD, document)
        self.app["post_message"] = AsyncMock(return_value=False)
        tab = (await self.get("/appearance"))[1]
        tab["messages"]["honeypot"]["title"] = "New"
        _, data = await self.send("PUT", "/appearance", {"messages": tab["messages"]})
        self.assertIn("couldn't post", data["problem"])

    async def test_a_verification_failure_stays_reported_when_the_honeypot_post_works(self):
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=CHANNEL)
        await self.service.save_settings(GUILD, document)
        self.app["post_message"] = AsyncMock(side_effect=lambda guild, which: False if which == "verification" else True)
        tab = (await self.get("/appearance"))[1]
        tab["messages"]["honeypot"]["title"] = "New"
        tab["messages"]["verification"]["title"] = "New"
        _, data = await self.send("PUT", "/appearance", {"messages": tab["messages"]})
        self.assertIn("couldn't post", data["problem"])

    async def test_a_post_that_works_reports_nothing(self):
        await self.log_in()
        tab = (await self.get("/appearance"))[1]
        tab["messages"]["verification"]["title"] = "New"
        _, data = await self.send("PUT", "/appearance", {"messages": tab["messages"]})
        self.assertIsNone(data["problem"])

    async def test_both_a_profile_problem_and_a_failed_post_are_reported(self):
        await self.log_in()
        self.port.profile_problem = "Discord refused the name."
        self.app["post_message"] = AsyncMock(return_value=False)
        tab = (await self.get("/appearance"))[1]
        tab["messages"]["verification"]["title"] = "New"
        tab["appearance"]["nickname"] = "Warden"
        _, data = await self.send("PUT", "/appearance", {"messages": tab["messages"], "appearance": tab["appearance"]})
        self.assertIn("Discord refused the name.", data["problem"])
        self.assertIn("couldn't post", data["problem"])


class GuildView(Base):
    async def only_page(self, page):
        document = await self.service.get_settings(GUILD)
        document["permissions"]["pages"][page] = {"view": {"required": [], "overrides": [{"type": "role", "id": ROLE_A, "allow": True}]}}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=(), roles=(ROLE_A,))

    async def test_a_page_that_picks_nothing_doesnt_get_channel_and_role_names(self):
        await self.only_page("audit")
        status, data = await self.get("")
        self.assertEqual(status, 200, data)
        self.assertEqual((data["roles"], data["channels"]), ([], []))

    async def test_each_page_that_picks_them_does(self):
        for page in ("settings", "permissions", "appearance"):
            await self.only_page(page)
            _, data = await self.get("")
            self.assertTrue(data["roles"] and data["channels"], page)
            document = await self.service.get_settings(GUILD)
            del document["permissions"]["pages"][page]
            await self.service.save_settings(GUILD, document)

    async def test_the_bots_top_role_is_included(self):
        await self.log_in()
        self.assertEqual((await self.get(""))[1]["bot_top_role"], 5)


class AccessRules(Base):
    MOD = ("manage_guild", "manage_roles")

    def rule_body(self, page=None, level="edit", command=None, allow="everyone"):
        rule = {"required": [], "overrides": [{"type": "everyone", "allow": True}]}
        return {"permissions": {"pages": {page: {level: rule}} if page else {}, "commands": {command: rule} if command else {}}}

    async def test_someone_short_of_a_rules_permissions_cant_give_themselves_the_rules(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=self.MOD)
        status, data = await self.send("PUT", "/permissions", self.rule_body("settings"))
        self.assertEqual(status, 403)
        self.assertIn("Rules", data["error"])
        self.assertEqual((await self.service.get_settings(GUILD))["permissions"]["pages"], {})

    async def test_someone_who_lacks_uninstall_cant_open_it(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=self.MOD)
        status, data = await self.send("PUT", "/permissions", self.rule_body(command="uninstall"))
        self.assertEqual(status, 403)
        self.assertIn("/uninstall", data["error"])

    async def test_a_rule_they_pass_and_hold_can_change(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=self.MOD)
        status, data = await self.send("PUT", "/permissions", self.rule_body("audit", "view"))
        self.assertEqual(status, 200, data)

    async def test_passing_a_rule_by_an_override_isnt_enough_without_the_default_permissions(self):
        document = await self.service.get_settings(GUILD)
        document["permissions"]["pages"]["permissions"] = {"edit": {"required": [], "overrides": [{"type": "role", "id": ROLE_A, "allow": True}]}}
        document["permissions"]["pages"]["audit"] = {"view": {"required": [], "overrides": [{"type": "role", "id": ROLE_A, "allow": True}]}}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=(), roles=(ROLE_A,))
        body = {"permissions": {"pages": {**document["permissions"]["pages"], "audit": {"view": {"required": ["administrator"], "overrides": []}}}, "commands": {}}}
        status, data = await self.send("PUT", "/permissions", body)
        self.assertEqual(status, 403, data)

    async def test_holding_the_default_permissions_isnt_enough_when_an_override_shuts_them_out(self):
        document = await self.service.get_settings(GUILD)
        document["permissions"]["pages"]["audit"] = {"view": {"required": ["manage_guild"], "overrides": [{"type": "user", "id": OTHER_USER, "allow": False}]}}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=self.MOD)
        status, data = await self.send("PUT", "/permissions", {"permissions": {"pages": {"audit": {"view": {"required": ["manage_guild"], "overrides": []}}}, "commands": {}}})
        self.assertEqual(status, 403, data)

    async def test_leaving_a_rule_as_it_was_is_no_change_even_for_someone_who_couldnt_change_it(self):
        document = await self.service.get_settings(GUILD)
        kept = {"view": {"required": ["ban_members"], "overrides": []}}
        document["permissions"]["pages"]["audit"] = kept
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=self.MOD)
        status, data = await self.send("PUT", "/permissions", {"permissions": {"pages": {"audit": kept, "members": {"view": {"required": ["manage_guild"], "overrides": []}}}, "commands": {}}})
        self.assertEqual(status, 200, data)

    async def test_an_administrator_can_change_any_rule(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=("administrator",))
        status, data = await self.send("PUT", "/permissions", self.rule_body("settings"))
        self.assertEqual(status, 200, data)

    async def test_the_owner_can_change_any_rule(self):
        await self.log_in(user=OTHER_USER, owner=True, perms=())
        status, data = await self.send("PUT", "/permissions", self.rule_body(command="uninstall"))
        self.assertEqual(status, 200, data)

    async def test_the_rules_route_asks_discord_for_the_roles_as_they_are_now(self):
        await self.log_in()
        self.port.calls.clear()
        await self.get("/settings")
        self.assertEqual(self.port.did("fresh_member"), [])
        await self.send("POST", "/settings/export")
        self.assertEqual(self.port.did("fresh_member"), [("fresh_member", STAFF)])

    async def set_rule(self, command, rule):
        document = await self.service.get_settings(GUILD)
        document["permissions"]["commands"][command] = rule
        await self.service.save_settings(GUILD, document)

    async def test_the_raid_route_follows_the_raid_rule_and_not_the_rules_page(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild", "kick_members"))
        status, data = await self.send("POST", "/raid", {"active": True})
        self.assertEqual(status, 200, data)
        await self.set_rule("raid", {"required": ["ban_members"], "overrides": []})
        status, _ = await self.send("POST", "/raid", {"active": False})
        self.assertEqual(status, 403)

    async def test_the_raid_route_refuses_without_the_rule_even_for_a_rules_editor(self):
        perms = ("manage_guild", "manage_roles", "manage_channels", "manage_messages", "moderate_members", "kick_members", "ban_members")
        await self.set_rule("raid", {"required": ["view_audit_log"], "overrides": []})
        await self.log_in(user=OTHER_USER, owner=False, perms=perms)
        self.assertEqual((await self.get("/settings"))[1]["can_edit"], True)
        status, _ = await self.send("POST", "/raid", {"active": True})
        self.assertEqual(status, 403)

    async def test_the_post_route_follows_its_rule(self):
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild",))
        status, data = await self.send("POST", "/post-message", {"message": "verification"})
        self.assertEqual(status, 200, data)
        await self.set_rule("post-message", {"required": ["ban_members"], "overrides": []})
        self.assertEqual((await self.send("POST", "/post-message", {"message": "verification"}))[0], 403)

    async def test_setup_needs_only_its_own_rule(self):
        await self.db.run("UPDATE guilds SET setup_done = 0")
        self.port.extra_roles = [{"id": ROLE_A, "name": "Mod", "color": 0, "position": 3, "managed": False, "mentionable": False}]
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild",), roles=(ROLE_A,))
        status, data = await self.send("POST", "/setup", {"verified_role": VERIFIED_ROLE, "channel": CHANNEL})
        self.assertEqual(status, 200, data)
        self.assertEqual((await self.db.guild(GUILD))["setup_done"], 1)

    async def test_setup_follows_its_rule(self):
        await self.db.run("UPDATE guilds SET setup_done = 0")
        await self.set_rule("setup", {"required": ["ban_members"], "overrides": []})
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild",))
        self.assertEqual((await self.send("POST", "/setup", {"verified_role": VERIFIED_ROLE, "channel": CHANNEL}))[0], 403)

    async def test_setup_runs_only_once(self):
        await self.log_in()
        status, data = await self.send("POST", "/setup", {"verified_role": VERIFIED_ROLE, "channel": LOG_CHANNEL})
        self.assertEqual(status, 409, data)
        self.assertEqual((await self.service.get_settings(GUILD))["core"]["channel"], CHANNEL)

    async def test_setup_changes_only_what_it_asks_for(self):
        await self.db.run("UPDATE guilds SET setup_done = 0")
        await self.change(vpn={"action": "ban"})
        await self.log_in()
        status, _ = await self.send("POST", "/setup", {"verified_role": VERIFIED_ROLE, "channel": LOG_CHANNEL})
        self.assertEqual(status, 200)
        document = await self.service.get_settings(GUILD)
        self.assertEqual((document["core"]["channel"], document["checks"]["vpn"]["action"]), (LOG_CHANNEL, "ban"))


class MemberActions(Base):
    async def moderator(self, *perms):
        self.port.extra_roles = [{"id": ROLE_A, "name": "Mod", "color": 0, "position": 3, "managed": False, "mentionable": False},
                                 {"id": ROLE_B, "name": "Admin", "color": 0, "position": 4, "managed": False, "mentionable": False}]
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild", "manage_roles", *perms), roles=(ROLE_A,))

    async def test_nobody_acts_on_someone_at_or_above_them(self):
        await self.moderator()
        self.port.add_member(THIRD_USER, roles=(ROLE_B,))
        for action, body in (("verify", {}), ("reset", {}), ("bypass", {"skip": ["vpn"]}), ("trust", {"other": OLD_USER})):
            status, data = await self.send("POST", f"/members/{THIRD_USER}/{action}", body)
            self.assertEqual(status, 403, action)
            self.assertIn("at or above yours", data["error"])
        self.assertEqual(self.port.did("remove_role"), [])

    async def test_trusting_looks_at_both_accounts(self):
        await self.moderator()
        self.port.add_member(THIRD_USER, roles=(ROLE_B,))
        self.port.add_member(OLD_USER)
        status, _ = await self.send("POST", f"/members/{OLD_USER}/trust", {"other": THIRD_USER})
        self.assertEqual(status, 403)
        self.assertFalse(await self.db.is_trusted_pair(GUILD, OLD_USER, THIRD_USER))

    async def test_a_reset_answers_with_what_happened(self):
        await self.moderator()
        self.port.add_member(THIRD_USER, roles=(VERIFIED_ROLE,))
        await self.db.touch_member(GUILD, THIRD_USER)
        status, data = await self.send("POST", f"/members/{THIRD_USER}/reset")
        self.assertEqual(status, 200, data)
        self.assertEqual(set(data), {"ok", "told", "problem", "kept_hashes"})
        self.assertIs(data["ok"], True)
        self.assertIs(data["told"], True)
        self.assertIsNone(data["problem"])

    async def test_a_reset_reports_a_role_it_couldnt_take(self):
        await self.moderator()
        self.port.add_member(THIRD_USER, roles=(VERIFIED_ROLE,))
        await self.db.touch_member(GUILD, THIRD_USER)
        self.port.role_refusals[VERIFIED_ROLE] = "Discord refused."
        _, data = await self.send("POST", f"/members/{THIRD_USER}/reset")
        self.assertIn("Discord refused.", data["problem"])

    async def test_a_lookup_failure_during_the_check_is_a_503(self):
        await self.moderator()
        real = self.port.member

        async def down_for_the_target(guild_id, user_id, *, fresh=False):
            if user_id == THIRD_USER:
                raise DiscordUnavailable("down")
            return await real(guild_id, user_id, fresh=fresh)
        self.port.member = down_for_the_target
        status, data = await self.send("POST", f"/members/{THIRD_USER}/verify")
        self.assertEqual((status, data["error"]), (503, DISCORD_BUSY))

    async def test_trusting_goes_through_the_service_so_staff_hear_of_it(self):
        await self.log_in()
        self.port.add_member(OLD_USER)
        status, _ = await self.send("POST", f"/members/{OLD_USER}/trust", {"other": OTHER_USER})
        self.assertEqual(status, 200)
        self.assertTrue(await self.db.is_trusted_pair(GUILD, OLD_USER, OTHER_USER))
        titles = [notice.embeds[0]["title"] for _, notice in self.port.sent if notice.embeds]
        self.assertIn("Accounts trusted", titles)

    async def appeal_waiting(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        return (await self.db.one("SELECT id FROM appeals"))["id"]

    async def test_approving_an_appeal_needs_a_rank_above_the_role_it_gives(self):
        appeal = await self.appeal_waiting()
        self.port.extra_roles = [{"id": ROLE_A, "name": "Helper", "color": 0, "position": 1, "managed": False, "mentionable": False}]
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_roles",), roles=(ROLE_A,))  # above the member, below the verified role
        for decision in ("approve", "trust"):
            status, data = await self.send("POST", f"/appeals/{appeal}", {"decision": decision})
            self.assertEqual(status, 403, decision)
            self.assertIn("verified role", data["error"])
        self.assertEqual((await self.db.one("SELECT status FROM appeals"))["status"], "open")

    async def test_denying_an_appeal_gives_nothing_so_it_needs_no_rank(self):
        appeal = await self.appeal_waiting()
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_roles",))
        status, data = await self.send("POST", f"/appeals/{appeal}", {"decision": "deny"})
        self.assertEqual(status, 200, data)

    async def test_approving_with_a_high_enough_rank_goes_through(self):
        appeal = await self.appeal_waiting()
        await self.moderator()
        status, data = await self.send("POST", f"/appeals/{appeal}", {"decision": "approve"})
        self.assertEqual(status, 200, data)

    async def test_an_appeal_decision_says_whether_the_member_was_told(self):
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        await self.service.submit_appeal(GUILD, OLD_USER, "someone", "That was my home connection, not a VPN.")
        await self.log_in()
        appeal = await self.db.one("SELECT id FROM appeals")
        self.port.dm_open = False
        status, data = await self.send("POST", f"/appeals/{appeal['id']}", {"decision": "deny"})
        self.assertEqual((status, data), (200, {"ok": True, "told": False}))


class OddBodies(Base):
    async def test_row_ids_too_long_for_a_number_are_not_found(self):
        await self.log_in()
        for digits in ("1" * 19, "1" * 25, "1" * 5000, "١٢٣"):
            for method, path in (("POST", f"/appeals/{digits}"), ("DELETE", f"/webhooks/{digits}")):
                response = await self.client.request(method, f"/api/guilds/{GUILD}{path}", json={"decision": "deny"}, headers=self.headers)
                self.assertEqual(response.status, 404, (path[:20], digits[:5]))

    async def test_the_longest_row_id_reaches_the_route(self):
        await self.log_in()
        status, _ = await self.send("POST", f"/appeals/{'1' * 18}", {"decision": "deny"})
        self.assertEqual(status, 400, "no such appeal")
        status, _ = await self.send("DELETE", f"/webhooks/{'1' * 18}")
        self.assertEqual(status, 200)

    async def test_events_of_the_wrong_shape_are_refused(self):
        await self.log_in()
        for events in (None, 5, "member.verified", {"a": 1}):
            status, _ = await self.send("POST", "/webhooks", {"url": "https://example.com/hook", "events": events})
            self.assertEqual(status, 400, events)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM webhooks"), 0)

    async def test_a_preset_of_the_wrong_shape_is_refused(self):
        await self.log_in()
        for preset in ({}, [], 5, None):
            status, _ = await self.send("POST", "/settings/preset", {"preset": preset})
            self.assertEqual(status, 400, preset)

    async def test_ids_in_other_scripts_or_of_other_types_are_refused(self):
        await self.log_in()
        self.port.add_member(OLD_USER)
        arabic = "".join(chr(0x0660 + int(digit)) for digit in OTHER_USER)
        for other in (arabic, int(OTHER_USER), None, [OTHER_USER], "0" + OTHER_USER):
            status, _ = await self.send("POST", f"/members/{OLD_USER}/trust", {"other": other})
            self.assertEqual(status, 400, other)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM trusted_pairs"), 0)

    async def test_the_delete_route_takes_only_a_real_id_or_none(self):
        await self.verify_through()
        self.discord.user["id"] = OLD_USER
        response = await self.client.get("/login", params={"for": "member"}, allow_redirects=False)
        state = parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]
        response = await self.client.get("/dashboard/callback", params={"code": "abc", "state": state}, allow_redirects=False,
                                         headers={"Cookie": f"{FLOW_COOKIE}={response.cookies[FLOW_COOKIE].value}"})
        cookie = {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE].value}"}
        csrf = (await (await self.client.get("/api/me/data", headers=cookie)).json())["csrf"]
        arabic = "".join(chr(0x0660 + int(digit)) for digit in GUILD)
        for guild_id in (arabic, int(GUILD), [GUILD], True):
            self.app["limits"].buckets.clear()
            response = await self.client.post("/api/me/delete", json={"guild_id": guild_id}, headers={**cookie, "X-CSRF-Token": csrf})
            self.assertEqual(response.status, 400, guild_id)
        self.assertEqual((await self.client.get("/api/me/data", headers=cookie)).status, 200, "still signed in")

    async def test_overrides_for_discord_take_only_real_ids(self):
        self.assertEqual(api_module.clean_overrides([{"type": "role", "id": int(VERIFIED_ROLE), "allow": True},
                                                     {"type": "role", "id": "١" * 18, "allow": True},
                                                     {"type": "role", "id": VERIFIED_ROLE, "allow": True}]),
                         [{"type": "role", "id": VERIFIED_ROLE, "allow": True}])


class Integrations(Base):
    URL = "https://hooks.example.com/services/SECRET-PATH"

    async def test_a_viewer_who_cant_edit_sees_the_host_and_not_the_path(self):
        await self.service.add_webhook(GUILD, self.URL, "s" * 40, ["member.verified"])
        document = await self.service.get_settings(GUILD)
        document["permissions"]["pages"]["integrations"] = {"edit": {"required": ["ban_members"], "overrides": []}}
        await self.service.save_settings(GUILD, document)
        await self.log_in(user=OTHER_USER, owner=False, perms=("manage_guild",))
        status, data = await self.get("/integrations")
        self.assertEqual(status, 200)
        self.assertEqual(data["webhooks"][0]["url"], "https://hooks.example.com/...")
        self.assertFalse(data["can_edit"])
        self.assertNotIn("SECRET", json.dumps(data))

    async def test_an_editor_sees_the_whole_address_and_never_the_secret(self):
        await self.service.add_webhook(GUILD, self.URL, "s" * 40, ["member.verified"])
        await self.log_in()
        _, data = await self.get("/integrations")
        self.assertEqual(data["webhooks"][0]["url"], self.URL)
        self.assertEqual(data["webhooks"][0]["events"], ["member.verified"])
        self.assertTrue(data["can_edit"])
        self.assertNotIn("s" * 40, json.dumps(data))
        self.assertNotIn("secret", data["webhooks"][0])

    async def test_a_new_webhook_is_stored_sealed_and_read_back_open(self):
        await self.log_in()
        status, data = await self.send("POST", "/webhooks", {"url": self.URL})
        self.assertEqual(status, 200, data)
        row = await self.db.one("SELECT url, secret FROM webhooks")
        self.assertTrue(row["url"].startswith("v1.") and row["secret"].startswith("v1."))
        self.assertEqual((await self.service.webhooks(GUILD))[0]["secret"], data["secret"])

    async def test_an_address_over_the_limit_is_refused_and_not_cut(self):
        await self.log_in()
        fits = "https://example.com/" + "a" * (500 - len("https://example.com/"))
        self.assertEqual((await self.send("POST", "/webhooks", {"url": fits}))[0], 200)
        self.assertEqual((await self.send("POST", "/webhooks", {"url": fits + "a"}))[0], 400)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM webhooks"), 1)

    async def test_two_saves_at_once_cant_pass_the_webhook_count(self):
        await self.log_in()
        results = await asyncio.gather(*(self.send("POST", "/webhooks", {"url": self.URL}) for _ in range(9)))
        self.assertEqual(sorted(status for status, _ in results).count(200), 5)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM webhooks"), 5)

    async def test_two_saves_at_once_cant_pass_the_key_count(self):
        await self.log_in()
        results = await asyncio.gather(*(self.send("POST", "/keys", {"label": "x"}) for _ in range(9)))
        self.assertEqual(sorted(status for status, _ in results).count(200), 5)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM api_keys"), 5)

    async def test_webhooks_and_keys_leave_an_audit_trail_with_no_secrets(self):
        await self.log_in()
        _, hook = await self.send("POST", "/webhooks", {"url": self.URL, "events": ["member.verified"]})
        _, key = await self.send("POST", "/keys", {"label": "my bot"})
        _, listing = await self.get("/integrations")
        await self.send("DELETE", f"/webhooks/{listing['webhooks'][0]['id']}")
        await self.send("DELETE", f"/keys/{listing['api_keys'][0]['id']}")
        rows = await self.db.all("SELECT kind, actor_id, actor_name, detail FROM audit ORDER BY at, rowid")
        self.assertEqual([row["kind"] for row in rows], ["webhook_add", "key_add", "webhook_delete", "key_delete"])
        self.assertTrue(all(row["actor_id"] == STAFF and row["actor_name"] for row in rows))
        self.assertEqual(json.loads(rows[0]["detail"]), {"host": "hooks.example.com", "events": ["member.verified"]})
        self.assertEqual(json.loads(rows[1]["detail"]), {"label": "my bot"})
        self.assertEqual(json.loads(rows[2]["detail"]), {"host": "hooks.example.com"})
        self.assertEqual(json.loads(rows[3]["detail"]), {"label": "my bot"})
        text = json.dumps(rows)
        for secret in ("SECRET-PATH", hook["secret"], key["key"]):
            self.assertNotIn(secret, text)

    async def test_deleting_nothing_leaves_no_audit_row(self):
        await self.log_in()
        await self.send("DELETE", "/webhooks/99")
        await self.send("DELETE", "/keys/deadbeef")
        self.assertEqual(await self.audit_kinds(), [])

    async def test_raid_rows_name_who_did_it(self):
        await self.log_in()
        await self.send("POST", "/raid", {"active": True})
        await self.send("POST", "/raid", {"active": False})
        rows = await self.db.all("SELECT kind, actor_name FROM audit ORDER BY at, rowid")
        self.assertEqual([(row["kind"], bool(row["actor_name"])) for row in rows], [("raid_start", True), ("raid_stop", True)])

    async def test_posting_a_message_leaves_an_audit_row_and_a_refusal_doesnt(self):
        await self.log_in()
        await self.send("POST", "/post-message", {"message": "verification"})
        rows = await self.db.all("SELECT kind, actor_name, detail FROM audit")
        self.assertEqual([(row["kind"], json.loads(row["detail"])) for row in rows], [("post_message", {"message": "verification"})])
        self.app["post_message"] = AsyncMock(return_value=False)
        await self.send("POST", "/post-message", {"message": "verification"})
        self.assertEqual(len(await self.audit_kinds()), 1)

    async def test_webhooks_are_delivered_with_the_opened_address_and_secret(self):
        await self.service.add_webhook(GUILD, "https://hooks.example.com/x", "the-secret", ["raid.started"])
        sent = []

        class Answer:
            status = 200

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return False

        class Session:
            def post(self, url, *, data, headers, **_):
                sent.append((url, data, headers))
                return Answer()
        self.app["webhook_http"] = Session()
        await api_module.send_webhooks(self.app, GUILD, "raid.started", {"until": 1})
        url, data, headers = sent[0]
        self.assertEqual(url, "https://hooks.example.com/x")
        stamp, signature = headers["X-AltWarden-Signature"].removeprefix("t=").split(",v1=")
        self.assertEqual(signature, hmac.new(b"the-secret", f"{stamp}.{data}".encode(), hashlib.sha256).hexdigest())


class LookupKeys(Base):
    KEY = "111111-222222-333333-444444"

    async def test_a_key_proxycheck_doesnt_know_is_refused_and_not_saved(self):
        await self.log_in()
        self.app["check_lookup_key"] = AsyncMock(return_value=False)
        status, data = await self.send("PUT", "/lookup-key", {"key": self.KEY})
        self.assertEqual((status, data), (400, {"error": "proxycheck.io doesn't recognize that key."}))
        self.assertIsNone(await self.db.lookup_key(GUILD))
        self.app["check_lookup_key"].assert_awaited_once_with(self.KEY)

    async def test_a_key_that_cant_be_checked_is_saved_with_a_warning(self):
        await self.log_in()
        self.app["check_lookup_key"] = AsyncMock(return_value=None)
        status, data = await self.send("PUT", "/lookup-key", {"key": self.KEY})
        self.assertEqual(status, 200)
        self.assertEqual(data["warning"], "Saved, but proxycheck.io couldn't be reached to check it.")
        self.assertEqual(await self.service.lookup_key(GUILD), self.KEY)

    async def test_a_key_proxycheck_knows_is_saved_with_no_warning(self):
        await self.log_in()
        status, data = await self.send("PUT", "/lookup-key", {"key": self.KEY})
        self.assertEqual((status, data), (200, {"ok": True, "lookup_key": {"saved": True, "ending": "4444"}}))

    async def test_a_short_key_shows_no_ending(self):
        await self.log_in()
        for key, ending in (("abcdef-12345678", None), ("abcdef-123456789", "6789")):
            _, data = await self.send("PUT", "/lookup-key", {"key": key})
            self.assertEqual(data["lookup_key"]["ending"], ending, key)

    async def test_the_real_check_runs_through_the_apps_session(self):
        await self.log_in()
        fresh = build_app(self.service, self.keys, self.oauth)
        fresh["http"] = "the session"
        with patch.object(app_module, "check_lookup_key", AsyncMock(return_value=True)) as check:
            self.assertTrue(await fresh["check_lookup_key"]("key"))
        check.assert_awaited_once_with("the session", "key")

    async def test_a_sealed_key_reads_right_on_the_settings_page_and_health(self):
        await self.log_in()
        await self.send("PUT", "/lookup-key", {"key": self.KEY})
        document = await self.service.get_settings(GUILD)
        document["core"]["external_vpn_lookup"] = True
        await self.service.save_settings(GUILD, document)
        self.assertEqual((await self.get("/settings"))[1]["lookup_key"]["ending"], "4444")
        self.assertFalse((await self.get("/health"))[1]["lookup_without_key"])


class HealthPage(Base):
    async def test_public_bot_comes_fresh_with_a_five_minute_cache(self):
        await self.log_in()
        answers = [SimpleNamespace(bot_public=True), SimpleNamespace(bot_public=False)]
        reader = AsyncMock(side_effect=answers)
        self.app["application_info"] = reader
        self.assertIs((await self.get("/health"))[1]["public_bot"], True)
        self.assertIs((await self.get("/health"))[1]["public_bot"], True)
        self.assertEqual(reader.await_count, 1)
        self.service._public_bot = (0.0, True)  # five minutes later
        self.assertIs((await self.get("/health"))[1]["public_bot"], False)
        self.assertEqual(reader.await_count, 2)

    async def test_a_failed_read_keeps_the_last_answer_and_asks_again_next_time(self):
        await self.log_in()
        self.app["application_info"] = AsyncMock(return_value=SimpleNamespace(bot_public=True))
        await self.get("/health")
        self.service._public_bot = (0.0, True)
        self.app["application_info"] = AsyncMock(side_effect=RuntimeError("no"))
        with self.assertLogs("altwarden.service", "WARNING"):
            self.assertIs((await self.get("/health"))[1]["public_bot"], True)
            await self.get("/health")
        self.assertEqual(self.app["application_info"].await_count, 2)

    async def test_with_no_reader_yet_the_startup_value_answers(self):
        await self.log_in()
        self.app["public_bot"] = True
        self.assertIs((await self.get("/health"))[1]["public_bot"], True)

    async def test_the_lookup_with_no_key_is_only_news_in_web_mode(self):
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        document["core"].update(external_vpn_lookup=True, mode="button")
        await self.service.save_settings(GUILD, document)
        self.assertFalse((await self.get("/health"))[1]["lookup_without_key"])

    async def test_a_refused_lookup_shows_with_its_time_and_message(self):
        await self.log_in()
        self.assertIsNone((await self.get("/health"))[1]["lookup_refused"])
        self.service._lookup_failures[GUILD] = {"at": 1000.0, "message": "Your daily limit is used up."}
        self.assertEqual((await self.get("/health"))[1]["lookup_refused"], {"at": 1000.0, "message": "Your daily limit is used up."})

    async def test_each_list_reports_its_age_and_size(self):
        await self.log_in()
        lists = (await self.get("/health"))[1]["lists"]
        self.assertEqual(lists, self.net.list_status())
        self.assertTrue(all(set(entry) == {"name", "age_days", "rows"} for entry in lists))

    async def test_notices_are_always_a_list(self):
        await self.log_in()
        self.assertIsInstance((await self.get("/health"))[1]["notices"], list)

    async def test_notices_from_the_report_pass_through(self):
        await self.log_in()
        with patch("altwarden.web.api.health.report", return_value={"healthy": True, "issues": [], "notices": [{"title": "t", "fix": "f"}]}):
            self.assertIn({"title": "t", "fix": "f"}, (await self.get("/health"))[1]["notices"])


class SlowReads(Base):
    async def test_preview_has_a_limit(self):
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        answers = [(await self.send("POST", "/settings/preview", {"settings": document}))[0] for _ in range(12)]
        self.assertIn(429, answers)
        self.assertEqual((await self.send("POST", "/settings/preview", {"settings": document}))[1], {"error": "Too many requests."})

    async def test_analytics_has_a_limit(self):
        await self.log_in()
        answers = [(await self.get("/analytics"))[0] for _ in range(25)]
        self.assertIn(429, answers)

    async def test_the_public_api_has_a_limit(self):
        codes = [(await self.client.get(f"/api/v1/guilds/{GUILD}/members/{OLD_USER}")).status for _ in range(80)]
        self.assertIn(429, codes)

    async def test_a_key_costs_one_write_a_minute(self):
        await self.log_in()
        _, key = await self.send("POST", "/keys", {"label": "x"})
        headers = {"Authorization": f"Bearer {key['key']}"}
        await self.client.get(f"/api/v1/guilds/{GUILD}/members/{OLD_USER}", headers=headers)
        first = await self.db.scalar("SELECT last_used_at FROM api_keys")
        self.assertIsNotNone(first)
        await self.client.get(f"/api/v1/guilds/{GUILD}/members/{OLD_USER}", headers=headers)
        self.assertEqual(await self.db.scalar("SELECT last_used_at FROM api_keys"), first)
        await self.db.run("UPDATE api_keys SET last_used_at = last_used_at - 61")
        await self.client.get(f"/api/v1/guilds/{GUILD}/members/{OLD_USER}", headers=headers)
        self.assertGreater(await self.db.scalar("SELECT last_used_at FROM api_keys"), first - 61)

    async def test_posting_has_a_limit_per_server(self):
        await self.log_in()
        answers = [(await self.send("POST", "/post-message", {"message": "verification"}))[0] for _ in range(8)]
        self.assertIn(429, answers)
        self.assertEqual(answers[0], 200)


class Honeypots(Base):
    async def trapped(self):
        document = await self.service.get_settings(GUILD)
        self.port.extra_channels = [{"id": TRAP, "name": "trap", "type": "text", "category": None, "position": 2}]
        document["honeypot"].update(enabled=True, channel=TRAP)
        await self.service.save_settings(GUILD, document)
        await self.db.set_guild_field(GUILD, "honeypot_message_id", f"{TRAP}:555")
        await self.log_in()

    async def rules(self):
        return (await self.get("/settings"))[1]["settings"]

    async def test_turning_the_trap_off_takes_its_warning_down(self):
        await self.trapped()
        document = await self.rules()
        document["honeypot"]["enabled"] = False
        status, data = await self.send("PUT", "/settings", {"settings": document})
        self.assertEqual(status, 200, data)
        self.assertIn(("delete_message", TRAP, "555"), self.port.calls)
        self.assertIsNone((await self.db.guild(GUILD))["honeypot_message_id"])

    async def test_a_warning_that_wont_delete_stays_recorded_for_the_next_post(self):
        await self.trapped()
        self.port.delete_works = False
        document = await self.rules()
        document["honeypot"]["enabled"] = False
        await self.send("PUT", "/settings", {"settings": document})
        self.assertEqual((await self.db.guild(GUILD))["honeypot_message_id"], f"{TRAP}:555")

    async def test_a_save_that_leaves_the_trap_on_leaves_the_warning(self):
        await self.trapped()
        status, data = await self.send("PUT", "/settings", {"settings": await self.rules()})
        self.assertEqual(status, 200, data)
        self.assertEqual(self.port.did("delete_message"), [])

    async def test_the_warning_isnt_posted_with_the_trap_off(self):
        await self.log_in()
        status, data = await self.send("POST", "/post-message", {"message": "honeypot"})
        self.assertEqual(status, 400)
        self.assertIn("off", data["error"])
        self.assertEqual(self.posted, [])

    async def test_the_warning_is_posted_with_the_trap_on(self):
        await self.trapped()
        status, _ = await self.send("POST", "/post-message", {"message": "honeypot"})
        self.assertEqual(status, 200)
        self.assertEqual(self.posted, ["honeypot"])


class SmallRoutes(Base):
    async def test_an_import_lists_what_it_would_change_and_saves_nothing(self):
        await self.log_in()
        other = settings.normalize(settings.defaults())
        other["privacy"]["banned_days"] = 0
        other["checks"]["vpn"]["action"] = "ban"
        code = settings.export_code(other)
        status, data = await self.send("POST", "/settings/import", {"code": code})
        self.assertEqual(status, 200)
        changes = {change["path"]: change for change in data["changes"]}
        self.assertEqual(changes["checks.vpn.action"]["after"], "ban")
        self.assertEqual(changes["privacy.banned_days"]["after"], 0)
        self.assertEqual(set(changes["checks.vpn.action"]), {"path", "before", "after"})
        self.assertEqual(data["settings"]["checks"]["vpn"]["action"], "ban")
        self.assertNotEqual((await self.service.get_settings(GUILD))["checks"]["vpn"]["action"], "ban")

    async def test_importing_this_servers_own_code_changes_nothing(self):
        await self.log_in()
        code = settings.export_code(await self.service.get_settings(GUILD))
        self.assertEqual((await self.send("POST", "/settings/import", {"code": code}))[1]["changes"], [])

    async def test_a_slow_read_of_discords_overrides_leaves_the_page_working(self):
        await self.log_in()

        async def slow(guild_id):
            await asyncio.sleep(2)
        self.port.command_permissions = slow
        with patch.object(api_module, "DISCORD_READ_SECONDS", 0.05), self.assertLogs("altwarden.api", "WARNING"):
            status, data = await self.get("/permissions")
        self.assertEqual(status, 200)
        self.assertIsNone(data["discord"])
        self.assertIn("pages", data)

    async def test_a_discord_outage_on_that_read_leaves_it_working_too(self):
        await self.log_in()
        self.port.command_permissions = AsyncMock(side_effect=DiscordUnavailable("down"))
        status, data = await self.get("/permissions")
        self.assertEqual((status, data["discord"]), (200, None))

    async def test_holding_a_change_with_discord_down_is_a_503(self):
        await self.log_in()
        self.port.command_permissions = AsyncMock(return_value=None)
        status, data = await self.send("POST", "/permissions/discord", {"changes": {"1": []}})
        self.assertEqual((status, data["error"]), (503, DISCORD_BUSY))

    async def test_the_catalog_carries_the_preset_tables(self):
        data = await (await self.client.get("/api/catalog")).json()
        self.assertEqual(data["presets"]["strict"]["label"], "Strict")
        self.assertEqual(data["presets"]["strict"]["checks"]["vpn"][1], "kick")



if __name__ == "__main__":
    unittest.main()
