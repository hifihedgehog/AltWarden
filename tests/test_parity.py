"""Behaviors found by reading every published capability line by line against this code."""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import health, notices, settings
from altwarden.access import Viewer, allowed
from altwarden.engine import bypass_options
from altwarden.ports import ROLE_TOO_LOW
from altwarden.signals import browser_family
from altwarden.web.api import PublicResolver, webhook_problem
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, UNVERIFIED_ROLE, VERIFIED_ROLE
import test_flow
from test_detection import clean_report
from test_flow import Base

HIGH_ROLE = "970000000000000050"
MIDDLE_ROLE = "970000000000000051"
BOT_ROLE = "970000000000000052"
TOP_ROLE = "970000000000000053"


def new_account() -> str:
    """A Discord ID created a moment ago."""
    return str(int(time.time() * 1000 - 1420070400000) << 22)


def text_of(notice) -> str:
    parts = [notice.content]
    for embed in notice.embeds:
        parts += [embed.get("title", ""), embed.get("description", "")]
    return " ".join(parts)


class Helpers(Base):
    async def core(self, **values):
        document = await self.service.get_settings(GUILD)
        document["core"].update(values)
        await self.service.save_settings(GUILD, document)

    def dms_to(self, user):
        return [text_of(notice) for target, notice in self.port.dms if target == user]

    def logged(self):
        return json.dumps([notice.embeds for _, notice in self.port.sent])


class InstantMode(Helpers):
    async def test_auto_kick_covers_a_member_who_fails_on_join(self):
        await self.core(mode="instant", auto_kick={"enabled": True, "minutes": 10})
        await self.change(avatar={"enabled": True, "action": "deny"})
        await self.service.on_join(self.port.add_member(OTHER_USER, avatar=None))
        self.assertIsNotNone((await self.db.member(GUILD, OTHER_USER))["kick_at"])
        self.assertTrue(self.dms_to(OTHER_USER), "the failure DM goes out whatever Auto DM says")

    async def test_a_pass_clears_the_kick_timer(self):
        await self.core(mode="instant", auto_kick={"enabled": True, "minutes": 10})
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIsNone((await self.db.member(GUILD, OTHER_USER))["kick_at"])

    async def test_a_pass_only_sends_a_dm_with_auto_dm_on(self):
        await self.core(mode="instant", auto_dm=False)
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertEqual(self.dms_to(OTHER_USER), [])
        await self.core(mode="instant", auto_dm=True, remember_rejoin=False)
        await self.service.on_join(self.port.members[(GUILD, OTHER_USER)])
        self.assertTrue(self.dms_to(OTHER_USER))

    async def test_cooldown_reaches_the_member_by_dm(self):
        await self.core(mode="instant", cooldown={"enabled": True, "seconds": 300})
        member = self.port.add_member(OTHER_USER)
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.update_member(GUILD, OTHER_USER, last_fail_at=time.time())
        await self.service.on_join(member)
        self.assertIn("cooldown", self.dms_to(OTHER_USER)[0])

    async def test_role_problem_reaches_the_member_by_dm(self):
        await self.core(mode="instant")
        self.port.role_problem = "That role no longer exists."
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn("roles need fixing", self.dms_to(OTHER_USER)[0])

    async def test_reset_never_gives_the_unverified_role(self):
        await self.core(mode="instant", unverified_enabled=True, unverified_role=UNVERIFIED_ROLE)
        await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertFalse([call for call in self.port.did("add_role") if call[2] == UNVERIFIED_ROLE])
        self.assertIn("rejoin", self.dms_to(OLD_USER)[0])


class TellingMembersWhen(Helpers):
    async def test_account_age_dm_says_when_they_can_return(self):
        await self.core(mode="button")
        await self.change(account_age={"enabled": True, "action": "deny", "days": 30})
        user = new_account()
        result = await self.service.press_verify(self.port.add_member(user))
        self.assertIn("<t:", self.dms_to(user)[0])
        self.assertIn("<t:", result.discord_text())
        self.assertAlmostEqual(result.retry_on, time.time() + 30 * 86400, delta=120)

    async def test_attempt_limit_says_when_attempts_return(self):
        await self.core(mode="button")
        await self.change(max_attempts={"enabled": True, "action": "deny", "attempts": 1, "reset_minutes": 60})
        reached = time.time() - 60
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=1, limit_reached_at=reached)
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(result.reason, "max_attempts")
        self.assertAlmostEqual(result.retry_on, reached + 3600, delta=1)

    async def test_attempt_limit_says_nothing_without_a_reset(self):
        await self.core(mode="button")
        await self.change(max_attempts={"enabled": True, "action": "deny", "attempts": 1, "reset_minutes": 0})
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, fails=1, limit_reached_at=time.time())
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertIsNone(result.retry_on)

    async def test_cooldown_reply_in_discord_shows_the_time_left(self):
        await self.core(mode="button", cooldown={"enabled": True, "seconds": 300})
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, last_fail_at=time.time())
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(result.status, "cooldown")
        self.assertIn(":R>", result.discord_text())

    async def test_auto_kick_dm_follows_the_setting(self):
        await self.core(auto_dm=False, auto_kick={"enabled": True, "minutes": 5})
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.update_member(GUILD, OLD_USER, kick_at=time.time() - 1, status="pending")
        await self.service.tick()
        self.assertTrue(self.port.did("kick"))
        self.assertEqual(self.dms_to(OLD_USER), [])


class EarlierAccount(Helpers):
    async def alt_after(self, **options):
        await self.change(alt_account={"enabled": True, "methods": {"cookie": True, "fingerprint": False, "ip": False}, "min_confidence": "possible", **options})
        await self.verify_through(OLD_USER)
        self.port.add_member(OTHER_USER)
        self.port.dms.clear()
        return await self.verify_through(OTHER_USER)

    async def test_a_watched_alt_still_applies_the_main_action(self):
        result = await self.alt_after(alt_action="watch", main_action="kick")
        self.assertEqual(result["status"], "verified")
        self.assertEqual([call[1] for call in self.port.did("kick")], [OLD_USER])
        self.assertIn("removed from the server", self.dms_to(OLD_USER)[0])
        self.assertIn("earlier account kicked", self.logged())

    async def test_a_watched_alt_is_recorded_as_a_link(self):
        await self.alt_after(alt_action="watch", main_action="watch")
        row = await self.db.one("SELECT * FROM links WHERE guild_id = ?", (GUILD,))
        self.assertEqual((row["main_id"], row["alt_id"]), (OLD_USER, OTHER_USER))

    async def test_a_ban_of_the_main_account_is_recorded(self):
        await self.alt_after(alt_action="deny", main_action="ban")
        self.assertTrue(await self.db.is_banned(GUILD, OLD_USER))

    async def test_log_says_whether_system_and_browser_match(self):
        await self.alt_after(alt_action="deny", main_action="watch")
        self.assertIn("same system", self.logged())
        self.assertIn("same browser", self.logged())

    async def test_a_different_browser_is_named(self):
        await self.change(alt_account={"enabled": True, "alt_action": "deny", "methods": {"cookie": True, "fingerprint": False, "ip": False}, "min_confidence": "possible"})
        await self.verify_through(OLD_USER)
        self.port.add_member(OTHER_USER)
        report = clean_report()
        report["nav"]["ua"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"
        await self.verify_through(OTHER_USER, report=report)
        self.assertIn("different browser", self.logged())

    async def test_the_profile_hashes_never_add_to_a_match(self):
        await self.change(alt_account={"enabled": True, "alt_action": "deny", "methods": {"cookie": False, "fingerprint": False, "ip": False}, "min_confidence": "possible"})
        await self.verify_through(OLD_USER)
        self.port.add_member(OTHER_USER)
        result = await self.verify_through(OTHER_USER)
        self.assertEqual(result["status"], "verified")


class SpentLinks(Helpers):
    async def test_a_kicked_member_is_not_told_they_got_in(self):
        await self.change(vpn={"enabled": True, "action": "kick"})
        token = await self.link_for()
        await self.sign_in(token)
        result = await (await self.attempt(token, ip="45.33.32.7")).json()
        self.assertEqual(result["action"], "kick")
        state = await (await self.client.get(f"/api/verify/{token}")).json()
        self.assertEqual(state["step"], "expired")

    async def test_a_kicked_members_link_cannot_sign_in_again(self):
        await self.change(vpn={"enabled": True, "action": "ban"})
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token, ip="45.33.32.7")
        self.assertEqual(await self.service.attach_account(token, {"id": OLD_USER}), "link_expired")
        response = await self.client.get(f"/v/{token}/signin", allow_redirects=False)
        self.assertEqual(response.headers["Location"], f"/v/{token}")

    async def test_a_verified_members_link_still_says_so(self):
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token)
        self.assertEqual((await (await self.client.get(f"/api/verify/{token}")).json())["step"], "done")


class BypassLinks(Helpers):
    async def test_channel_notice_never_holds_the_link(self):
        url, told = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 2, "channel", STAFF, "staff", LOG_CHANNEL)
        self.assertTrue(told)
        self.assertEqual(self.port.dms, [])
        channel, notice = next(item for item in self.port.sent if item[1].mention_users)
        self.assertEqual(channel, CHANNEL)
        self.assertNotIn(url, notice.content)
        self.assertIn(CHANNEL, notice.content)

    async def test_pressing_verify_keeps_what_the_link_skips(self):
        first, _ = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 2, "channel", STAFF, "staff", CHANNEL)
        old = await self.service.session(first.rsplit("/", 1)[1])
        second = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        row = await self.service.session(second.rsplit("/", 1)[1])
        self.assertEqual(row["bypass"], ["vpn"])
        self.assertEqual(row["expires_at"], old["expires_at"])
        self.assertEqual(row["bypass_by"], STAFF)
        self.assertIsNone(await self.service.session(first.rsplit("/", 1)[1]), "the older link stops working")

    async def test_button_and_instant_servers_hand_out_the_web_link(self):
        for mode in ("button", "instant"):
            await self.core(mode=mode)
            await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 1, "none", STAFF, "staff")
            outcome = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
            self.assertIsInstance(outcome, str, mode)

    async def test_an_ordinary_link_carries_no_skips(self):
        url = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual((await self.service.session(url.rsplit("/", 1)[1]))["bypass"], [])

    async def test_a_used_bypass_is_not_inherited(self):
        await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 1, "none", STAFF, "staff")
        await self.db.run("UPDATE sessions SET state = 'done'")
        second = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual((await self.service.session(second.rsplit("/", 1)[1]))["bypass"], [])

    async def test_closed_dms_are_reported(self):
        self.port.dm_open = False
        _, told = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 1, "dm", STAFF, "staff")
        self.assertFalse(told)

    async def test_the_log_gives_the_expiry_and_never_the_link(self):
        url, _ = await self.service.create_bypass(GUILD, OLD_USER, ["vpn"], 3, "none", STAFF, "staff")
        logged = self.logged()
        self.assertIn(":f>", logged)
        self.assertNotIn(url, logged)

    async def test_cooldown_can_be_skipped(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["cooldown"]["enabled"] = True
        self.assertIn("cooldown", bypass_options(document))
        self.assertEqual(notices.check_name("cooldown"), "Cooldown")


class Resetting(Helpers):
    async def test_button_mode_dm_says_where_to_verify(self):
        await self.core(mode="button")
        await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertIn(f"<#{CHANNEL}>", self.dms_to(OLD_USER)[0])

    async def test_a_channel_ping_counts_as_telling_them(self):
        self.port.dm_open = False
        self.assertTrue(await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff"))
        self.port.channel_posts_work = False
        self.assertFalse(await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff"))


class HelpDesk(Helpers):
    async def desk(self, **options):
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, require_attempt=False, **options)
        document["core"]["logs"]["modules"]["help_desk"] = LOG_CHANNEL
        await self.service.save_settings(GUILD, document)

    async def test_pressing_help_again_reopens_the_thread(self):
        await self.desk()
        member = self.port.members[(GUILD, OLD_USER)]
        first, _ = await self.service.open_help(member)
        again, _ = await self.service.open_help(member)
        self.assertEqual(first, again)
        self.assertEqual(len(self.port.did("open_help_thread")), 1)
        self.assertTrue(self.port.did("reopen_thread"))

    async def test_a_deleted_thread_is_replaced(self):
        await self.desk()
        member = self.port.members[(GUILD, OLD_USER)]
        await self.service.open_help(member)
        self.port.thread_open = False
        await self.service.open_help(member)
        self.assertEqual(len(self.port.did("open_help_thread")), 2)

    async def test_auto_close_is_logged(self):
        await self.desk(auto_close=True)
        await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff")
        self.assertIn("Help thread closed", self.logged())
        self.assertIsNone((await self.db.member(GUILD, OLD_USER))["help_thread_id"])

    async def test_leaving_closes_and_logs(self):
        await self.desk()
        await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        await self.service.on_leave(GUILD, OLD_USER)
        self.assertTrue(self.port.did("close_thread"))
        self.assertIn("left the server", self.logged())

    async def test_a_save_that_breaks_the_desk_warns_its_log(self):
        await self.desk()
        document = await self.service.get_settings(GUILD)
        await self.service.warn_if_broken(GUILD, document, ["help_desk"])
        self.assertIn("help desk can't work", self.logged())


class Honeypot(Helpers):
    async def test_a_message_it_cannot_delete_is_reported(self):
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=LOG_CHANNEL, action="log")
        document["core"]["logs"]["modules"]["honeypot"] = LOG_CHANNEL
        await self.service.save_settings(GUILD, document)
        self.port.delete_works = False
        await self.service.honeypot_hit(GUILD, OTHER_USER, "x", LOG_CHANNEL, "1", role_ids=())
        self.assertIn("Manage Messages", self.logged())


class ServerStates(Helpers):
    async def result(self, token):
        return await (await self.attempt(token)).json()

    async def test_each_server_problem_has_its_own_guide(self):
        token = await self.link_for()
        await self.sign_in(token)
        self.port.loading = True
        result = await self.result(token)
        self.assertEqual((result["reason"], result["help"], result["retry"]), ("server_loading", "server-loading", True))
        self.port.loading = False
        self.port.absent = True
        self.assertEqual((await self.result(token))["help"], "app-removed")
        self.port.absent = False
        await self.db.run("UPDATE guilds SET setup_done = 0")
        self.assertEqual((await self.result(token))["help"], "not-set-up")

    async def test_role_above_the_bot_gets_the_matching_guide(self):
        token = await self.link_for()
        await self.sign_in(token)
        self.port.role_problem = ROLE_TOO_LOW
        result = await self.result(token)
        self.assertEqual((result["reason"], result["help"], result["retry"]), ("role_too_low", "role-too-low", True))

    async def test_any_other_role_failure_gets_the_general_guide(self):
        token = await self.link_for()
        await self.sign_in(token)
        self.port.role_problem = "That role no longer exists."
        self.assertEqual((await self.result(token))["help"], "role-problem")


class Presets(unittest.TestCase):
    def test_new_servers_start_with_these_three_on_and_stopping_people(self):
        document = settings.defaults()
        for check_id in ("mfa", "privacy", "rooted"):
            check = document["checks"][check_id]
            self.assertEqual((check["enabled"], check["action"]), (True, "deny"), check_id)
        self.assertEqual(settings.detect_preset(document), "standard")

    def test_no_default_only_watches(self):
        """Only the account that verified first stays on Watch, because the alt is the one being stopped."""
        document = settings.defaults()
        for check_id, check in document["checks"].items():
            self.assertNotEqual(check["action"], "watch", check_id)
        alt = document["checks"]["alt_account"]
        self.assertEqual((alt["alt_action"], alt["banned_alt_action"], alt["main_action"]), ("kick", "ban", "watch"))
        self.assertEqual(document["checks"]["fake_ua"]["action"], "kick")
        self.assertNotEqual(document["honeypot"]["action"], "log")

    def test_turning_on_a_check_that_starts_off_stops_people(self):
        document = settings.defaults()
        for check_id in ("avatar", "mobile_data", "geogate"):
            self.assertFalse(document["checks"][check_id]["enabled"], check_id)
            self.assertEqual(document["checks"][check_id]["action"], "deny", check_id)

    def test_strict_never_only_watches(self):
        document = settings.apply_preset(settings.defaults(), "strict")
        for check_id, check in document["checks"].items():
            self.assertNotEqual(check["action"], "watch", check_id)

    def test_new_servers_ask_rejoining_members_to_verify(self):
        self.assertFalse(settings.defaults()["core"]["remember_rejoin"])

    def test_a_preset_leaves_two_factor_alone(self):
        document = settings.defaults()
        document["checks"]["mfa"].update(enabled=True, action="kick")
        for name in ("gentle", "standard", "strict"):
            changed = settings.apply_preset(document, name)
            self.assertEqual(changed["checks"]["mfa"], document["checks"]["mfa"], name)

    def test_strict_turns_on_auto_kick(self):
        strict = settings.apply_preset(settings.defaults(), "strict")
        self.assertTrue(strict["core"]["auto_kick"]["enabled"])
        self.assertEqual(settings.detect_preset(strict), "strict")
        self.assertFalse(settings.apply_preset(strict, "standard")["core"]["auto_kick"]["enabled"])

    def test_turning_auto_kick_off_by_hand_leaves_the_preset(self):
        strict = settings.apply_preset(settings.defaults(), "strict")
        strict["core"]["auto_kick"]["enabled"] = False
        self.assertEqual(settings.detect_preset(strict), "custom")


class Validation(unittest.TestCase):
    def emoji(self, value):
        document = settings.defaults()
        document["messages"]["verification"]["verify_emoji"] = value
        return settings.normalize(document)["messages"]["verification"]["verify_emoji"]

    def test_a_good_emoji_survives(self):
        for value in ("✅", "🛡️", "<:shield:123456789012345678>", "<a:spin:123456789012345678>"):
            self.assertEqual(self.emoji(value), value)

    def test_text_that_would_break_the_button_is_dropped(self):
        for value in ("verify", "<:bad>", ":shield:", "hello world", "<@123456789012345678>"):
            self.assertEqual(self.emoji(value), "", value)

    def test_each_problem_points_at_a_setting(self):
        document = settings.defaults()
        document["honeypot"]["enabled"] = True
        items = settings.problem_items(document)
        self.assertEqual([item["item"] for item in items], ["core", "core", "honeypot"])
        self.assertEqual(settings.problems(document), [item["text"] for item in items])

    def test_browser_families(self):
        edge = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0"
        chrome = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
        safari = "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15"
        self.assertEqual([browser_family(value) for value in (edge, chrome, safari, "", "curl/8")], ["edge", "chrome", "safari", None, None])


class Roles(Helpers):
    def viewer(self, *roles, admin=False):
        return Viewer(STAFF, frozenset(roles), frozenset({"administrator"} if admin else {"manage_guild"}))

    async def refused(self, role, viewer, before=None):
        self.port.extra_roles = [
            {"id": HIGH_ROLE, "name": "Admins", "color": 0, "position": 4, "managed": False, "mentionable": False},
            {"id": MIDDLE_ROLE, "name": "Mods", "color": 0, "position": 3, "managed": False, "mentionable": False},
            {"id": BOT_ROLE, "name": "Some bot", "color": 0, "position": 1, "managed": True, "mentionable": False},
            {"id": TOP_ROLE, "name": "Owners", "color": 0, "position": 9, "managed": False, "mentionable": False},
        ]
        guild = await self.port.guild(GUILD)
        document = settings.defaults()
        document["core"]["verified_role"] = role
        return health.role_refusals(guild, before, document, viewer)

    async def test_a_role_above_your_own_is_refused(self):
        self.assertIn("below your own", (await self.refused(HIGH_ROLE, self.viewer(MIDDLE_ROLE)))[0]["text"])

    async def test_a_role_level_with_your_own_is_refused(self):
        self.assertTrue(await self.refused(MIDDLE_ROLE, self.viewer(MIDDLE_ROLE)))

    async def test_a_role_below_your_own_is_fine(self):
        self.assertEqual(await self.refused(VERIFIED_ROLE, self.viewer(MIDDLE_ROLE)), [])

    async def test_administrators_are_exempt(self):
        self.assertEqual(await self.refused(HIGH_ROLE, self.viewer(admin=True)), [])

    async def test_a_managed_role_is_refused_for_everyone(self):
        self.assertIn("regular role", (await self.refused(BOT_ROLE, self.viewer(admin=True)))[0]["text"])

    async def test_a_role_above_the_bot_is_refused_for_everyone(self):
        self.assertIn("drag AltWarden", (await self.refused(TOP_ROLE, self.viewer(admin=True)))[0]["text"])

    async def test_a_role_that_was_already_set_is_left_alone(self):
        before = settings.defaults()
        before["core"]["verified_role"] = HIGH_ROLE
        self.assertEqual(await self.refused(HIGH_ROLE, self.viewer(MIDDLE_ROLE), before), [])


class DashboardParity(Helpers):
    log_in = test_flow.Dashboard.log_in

    async def put(self, document):
        return await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": document}, headers=self.headers)

    async def current(self):
        return json.loads(json.dumps(await self.service.get_settings(GUILD)))

    async def test_a_bad_setting_is_named_so_the_page_can_point_at_it(self):
        await self.log_in()
        changed = await self.current()
        changed["honeypot"]["enabled"] = True
        response = await self.put(changed)
        self.assertEqual(response.status, 400)
        self.assertEqual((await response.json())["items"][0]["item"], "honeypot")

    async def test_staff_cannot_hand_out_a_role_above_their_own(self):
        self.port.extra_roles = [{"id": HIGH_ROLE, "name": "Admins", "color": 0, "position": 4, "managed": False, "mentionable": False}]
        await self.log_in(owner=False, perms=settings.PAGE_DEFAULTS["settings"]["edit"])
        changed = await self.current()
        changed["core"]["verified_role"] = HIGH_ROLE
        response = await self.put(changed)
        self.assertEqual(response.status, 400)
        self.assertIn("below your own", (await response.json())["error"])
        self.assertEqual((await self.service.get_settings(GUILD))["core"]["verified_role"], VERIFIED_ROLE)

    async def test_turning_the_honeypot_on_posts_its_warning(self):
        await self.log_in()
        changed = await self.current()
        changed["honeypot"].update(enabled=True, channel=LOG_CHANNEL)
        self.assertEqual((await self.put(changed)).status, 200)
        self.assertIn("honeypot", self.posted)

    async def test_saving_the_same_trap_again_posts_nothing(self):
        await self.log_in()
        changed = await self.current()
        changed["honeypot"].update(enabled=True, channel=CHANNEL)
        await self.put(changed)
        self.posted.clear()
        changed["honeypot"]["action"] = "kick"
        await self.put(changed)
        self.assertNotIn("honeypot", self.posted)

    async def test_members_list_counts_results(self):
        await self.log_in()
        await self.db.touch_member(GUILD, OTHER_USER, username="other")
        for _ in range(2):
            await self.db.add_attempt(GUILD, OTHER_USER, "failed", check_id="vpn", action="deny")
        await self.db.add_attempt(GUILD, OTHER_USER, "passed", mode="web")
        await self.db.add_attempt(GUILD, OTHER_USER, "started", mode="web")
        data = await (await self.client.get(f"/api/guilds/{GUILD}/members", headers=self.headers)).json()
        row = next(item for item in data["members"] if item["user_id"] == OTHER_USER)
        counted = {(item["outcome"], item["check"]): item["count"] for item in row["results"]}
        self.assertEqual(counted, {("failed", "vpn"): 2, ("passed", None): 1})

    async def test_bad_numbers_in_a_query_do_not_crash(self):
        await self.log_in()
        for query in ("size=abc&page=xyz", "size=-1&page=-5"):
            self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/members?{query}", headers=self.headers)).status, 200)
        for query in ("from=nan&to=inf", "from=abc"):
            self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/analytics?{query}", headers=self.headers)).status, 200)
        self.assertEqual((await self.client.get(f"/api/guilds/{GUILD}/analytics?from=200&to=100", headers=self.headers)).status, 400)

    async def test_compare_can_use_a_chosen_period(self):
        await self.log_in()
        now = time.time()
        row = await self.db.add_attempt(GUILD, OLD_USER, "passed", mode="web")
        await self.db.run("UPDATE attempts SET at = ? WHERE id = ?", (now - 40 * 86400, row))
        query = f"from={now - 86400}&to={now}&compare=1&compare_from={now - 45 * 86400}&compare_to={now - 35 * 86400}"
        data = await (await self.client.get(f"/api/guilds/{GUILD}/analytics?{query}", headers=self.headers)).json()
        self.assertEqual(data["previous"]["verified"], 1)
        self.assertEqual(data["cards"]["verified"], 0)

    async def bypass(self, **body):
        return await self.client.post(f"/api/guilds/{GUILD}/members/{OLD_USER}/bypass", json=body, headers=self.headers)

    async def test_dashboard_bypass_needs_a_check(self):
        await self.log_in()
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.assertEqual((await self.bypass(skip=[])).status, 400)
        self.assertEqual((await self.bypass(skip=["nonsense"])).status, 400)
        self.assertEqual((await self.bypass(skip=["vpn"], hours="many", notify="carrier pigeon")).status, 200)

    async def test_dashboard_bypass_lists_what_is_on(self):
        await self.log_in()
        await self.change(vpn={"enabled": True, "action": "deny"}, incognito={"enabled": False})
        await self.db.touch_member(GUILD, OLD_USER)
        data = await (await self.client.get(f"/api/guilds/{GUILD}/members/{OLD_USER}", headers=self.headers)).json()
        names = [option["id"] for option in data["bypass_options"]]
        self.assertIn("vpn", names)
        self.assertNotIn("incognito", names)

    async def test_a_changed_message_names_its_writer(self):
        await self.log_in()
        document = await self.service.get_settings(GUILD)
        messages = json.loads(json.dumps(document["messages"]))
        messages["verification"]["title"] = "New title"
        path = f"/api/guilds/{GUILD}/appearance"
        data = await (await self.client.put(path, json={"messages": messages}, headers=self.headers)).json()
        self.assertEqual(data["messages"]["verification"]["author"], STAFF)
        self.assertIsNone(data["messages"]["honeypot"]["author"])

        other = "175928847299117099"
        await self.log_in(user=other)
        same = await (await self.client.put(path, json={"messages": data["messages"]}, headers=self.headers)).json()
        self.assertEqual(same["messages"]["verification"]["author"], STAFF, "saving without a change keeps the writer")

        again = json.loads(json.dumps(same["messages"]))
        again["verification"]["title"] = "Another"
        data = await (await self.client.put(path, json={"messages": again}, headers=self.headers)).json()
        self.assertEqual(data["messages"]["verification"]["author"], other)

        restored = json.loads(json.dumps(data["messages"]))
        restored["verification"] = dict(settings.DEFAULT_MESSAGES["verification"])
        data = await (await self.client.put(path, json={"messages": restored}, headers=self.headers)).json()
        self.assertIsNone(data["messages"]["verification"]["author"], "the default message has no writer")


class EditDefaults(Helpers):
    log_in = test_flow.Dashboard.log_in

    async def test_changing_the_rules_takes_the_permissions_the_rules_use(self):
        await self.log_in(owner=False, perms=("manage_guild", "manage_roles"))
        changed = json.loads(json.dumps(await self.service.get_settings(GUILD)))
        response = await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": changed}, headers=self.headers)
        self.assertEqual(response.status, 403, "someone who can't ban must not be able to make the bot ban")

    def test_every_permission_has_discords_name(self):
        from altwarden.catalog import PERMISSION_LABELS
        for name in (*settings.PERMISSION_NAMES, *health.BITS):
            self.assertIn(name, PERMISSION_LABELS, name)
        self.assertEqual(PERMISSION_LABELS["manage_guild"], "Manage Server")
        self.assertEqual(PERMISSION_LABELS["moderate_members"], "Timeout Members")


class FailedPost(Helpers):
    log_in = test_flow.Dashboard.log_in

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.failing = True

    async def test_a_post_that_fails_is_reported(self):
        await self.client.close()

        async def post_message(guild_id, which):
            return False
        from aiohttp.test_utils import TestClient, TestServer
        import aiohttp
        app = test_flow.build_app(self.service, self.keys, self.oauth, trust_proxy=True)
        app["http"] = self.http
        app["post_message"] = post_message
        self.client = TestClient(TestServer(app), cookie_jar=aiohttp.CookieJar(unsafe=True))
        await self.client.start_server()
        await self.log_in()
        response = await self.client.post(f"/api/guilds/{GUILD}/post-message", json={"message": "verification"}, headers=self.headers)
        self.assertEqual(response.status, 400)


class Messages(unittest.TestCase):
    def test_a_custom_message_names_who_wrote_it(self):
        message = dict(settings.DEFAULT_MESSAGES["verification"], author=STAFF, description="Hello {server}")
        embed = notices.verification_message(message, guild_name="Test", help_desk=False, icon_url=None, public_url="https://x.test").embeds[0]
        self.assertIn(f"Written by <@{STAFF}>", embed["description"])
        self.assertIn("https://x.test/security#abuse", embed["description"])
        self.assertTrue(embed["description"].startswith("Hello Test"))

    def test_the_default_message_stays_clean(self):
        embed = notices.verification_message(dict(settings.DEFAULT_MESSAGES["verification"]), guild_name="Test", help_desk=False, icon_url=None).embeds[0]
        self.assertNotIn("Written by", embed["description"])


class WhatDeletionDeletes(Helpers):
    async def seed(self):
        await self.service.manual_verify(GUILD, OLD_USER, STAFF, "staff")
        await self.service.create_bypass(GUILD, OTHER_USER, ["vpn"], 1, "none", OLD_USER, "someone")
        await self.db.trust_pair(GUILD, OLD_USER, OTHER_USER, STAFF)
        await self.db.insert("INSERT INTO appeals (guild_id, user_id, text, status, created_at, decided_by) VALUES (?, ?, ?, ?, ?, ?)", (GUILD, OTHER_USER, "x" * 20, "denied", time.time(), OLD_USER))

    async def test_my_data_lists_appeals_and_counts_links_without_naming_them(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.insert("INSERT INTO appeals (guild_id, user_id, text, created_at) VALUES (?, ?, ?, ?)", (GUILD, OLD_USER, "Please check again", time.time()))
        await self.db.run("INSERT INTO links VALUES (?, ?, ?, ?, ?, ?, ?)", (GUILD, OLD_USER, OTHER_USER, "likely", 70, "[]", time.time()))
        record = (await self.service.my_data(OLD_USER))[0]
        self.assertEqual(record["appeals"][0]["text"], "Please check again")
        self.assertEqual(record["linked_accounts"], 1)
        self.assertNotIn(OTHER_USER, json.dumps(record))

    async def test_deleting_leaves_no_row_naming_the_person(self):
        await self.seed()
        document = await self.service.get_settings(GUILD)
        messages = json.loads(json.dumps(document["messages"]))
        messages["honeypot"]["author"] = OLD_USER
        await self.service.save_settings(GUILD, {**document, "messages": messages})
        await self.db.run("INSERT INTO web_sessions (token_hash, user_id, username, csrf, created_at, expires_at) VALUES ('h', ?, 'x', 'c', 0, 9e9)", (OLD_USER,))
        await self.db.run("INSERT INTO command_syncs VALUES ('s', ?, ?, '[]', 9e9)", (GUILD, OLD_USER))
        await self.service.delete_my_data(OLD_USER)
        leftovers = [line[:160] for line in self.database_dump().splitlines() if OLD_USER in line]
        self.assertEqual(leftovers, [])

    async def test_staff_records_about_other_people_survive(self):
        await self.seed()
        await self.service.delete_my_data(OLD_USER)
        row = await self.db.one("SELECT actor_id, actor_name, kind FROM audit WHERE kind = 'bypass'")
        self.assertEqual((row["actor_id"], row["actor_name"]), (None, "Deleted account"))

    async def test_deleting_works_with_no_records_anywhere(self):
        self.assertEqual(await self.service.delete_my_data("175928847299117777"), {"removed": [], "kept_for_ban": []})


class DepartedServers(Helpers):
    async def test_a_server_that_left_is_forgotten_after_thirty_days(self):
        await self.db.touch_member(GUILD, OLD_USER)
        document = await self.service.get_settings(GUILD)
        await self.db.set_guild_field(GUILD, "left_at", time.time() - 29 * 86400)
        await self.db.purge_expired({GUILD: document})
        self.assertIsNotNone(await self.db.guild(GUILD))
        await self.db.set_guild_field(GUILD, "left_at", time.time() - 31 * 86400)
        removed = await self.db.purge_expired({GUILD: document})
        self.assertEqual(removed["departed"], 1)
        self.assertIsNone(await self.db.guild(GUILD))
        self.assertIsNone(await self.db.member(GUILD, OLD_USER))

    async def test_a_server_that_came_back_is_kept(self):
        await self.db.set_guild_field(GUILD, "left_at", time.time() - 31 * 86400)
        await self.db.set_guild_field(GUILD, "left_at", None)
        await self.db.purge_expired({GUILD: await self.service.get_settings(GUILD)})
        self.assertIsNotNone(await self.db.guild(GUILD))

    async def test_ban_records_expire_with_the_setting(self):
        document = await self.service.get_settings(GUILD)
        await self.db.record_ban(GUILD, OLD_USER)
        await self.db.record_ban(GUILD, OTHER_USER)
        await self.db.run("UPDATE bans SET at = ? WHERE user_id = ?", (time.time() - (document["privacy"]["banned_days"] + 1) * 86400, OLD_USER))
        removed = await self.db.purge_expired({GUILD: document})
        self.assertEqual(removed["bans"], 1)
        self.assertFalse(await self.db.is_banned(GUILD, OLD_USER))
        self.assertTrue(await self.db.is_banned(GUILD, OTHER_USER))


class SignInLimits(Base):
    async def test_sign_in_is_rate_limited(self):
        codes = [(await self.client.get("/login", allow_redirects=False)).status for _ in range(30)]
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 302)


class PermissionDefaults(unittest.TestCase):
    def test_a_rule_at_its_default_is_not_stored(self):
        from altwarden import settings as module
        document = module.defaults()
        document["permissions"] = {
            "pages": {"settings": {"view": {"required": list(module.PAGE_DEFAULTS["settings"]["view"]), "overrides": []},
                                   "edit": {"required": ["view_audit_log"], "overrides": []}}},
            "commands": {"lookup": {"required": list(module.COMMAND_DEFAULTS["lookup"]), "overrides": []},
                         "raid": {"required": ["ban_members"], "overrides": []}},
        }
        saved = module.normalize(document)["permissions"]
        self.assertEqual(saved["pages"], {"settings": {"edit": {"required": ["view_audit_log"], "overrides": []}}})
        self.assertEqual(saved["commands"], {"raid": {"required": ["ban_members"], "overrides": []}})

    def test_a_rule_left_out_still_reads_as_its_default(self):
        from altwarden import settings as module
        document = module.normalize(module.defaults())
        self.assertEqual(module.page_rule(document, "members", "view")["required"], module.PAGE_DEFAULTS["members"]["view"])
        self.assertEqual(module.command_rule(document, "lookup")["required"], module.COMMAND_DEFAULTS["lookup"])


class ListRefresh(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import tempfile
        from pathlib import Path
        from altwarden import netintel
        self.module = netintel
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name)
        self.net = netintel.NetIntel(self.path)
        self.fetched = []

        async def fetch(session, name, url):
            self.fetched.append(name)
            (self.path / name).write_text("x")
            return 1
        self.net._fetch = fetch

        async def load():
            pass
        self.net.load = load

    async def asyncTearDown(self):
        self.folder.cleanup()

    async def test_an_empty_folder_is_stale_and_lists_everything_missing(self):
        self.assertTrue(self.net.stale())
        self.assertEqual(len(self.net.missing()), len(self.module.SOURCES))

    async def test_refresh_gets_everything_once_and_then_nothing(self):
        await self.net.refresh(session=object())
        self.assertEqual(len(self.fetched), len(self.module.SOURCES))
        self.assertFalse(self.net.stale())
        self.assertEqual(self.net.missing(), [])
        self.fetched.clear()
        self.assertEqual(await self.net.refresh(session=object()), 0)
        self.assertEqual(self.fetched, [])

    async def test_one_failed_list_is_retried_alone(self):
        await self.net.refresh(session=object())
        name = "vpn-open-mullvad.txt"
        (self.path / name).unlink()
        self.assertTrue(self.net.stale(), "one missing list must not wait a week")
        self.assertEqual(self.net.missing(), [name])
        self.fetched.clear()
        await self.net.refresh(session=object())
        self.assertEqual(self.fetched, [name])

    async def test_an_old_list_is_refreshed(self):
        import os
        await self.net.refresh(session=object())
        name = "country-ipv4.csv"
        old = 1_000_000_000
        os.utime(self.path / name, (old, old))
        self.assertTrue(self.net.stale())
        self.fetched.clear()
        await self.net.refresh(session=object())
        self.assertEqual(self.fetched, [name])

    async def test_a_failed_download_keeps_going_and_stays_missing(self):
        async def fetch(session, name, url):
            if name == "tor.txt":
                raise ValueError("no")
            (self.path / name).write_text("x")
            return 1
        self.net._fetch = fetch
        with self.assertLogs("altwarden.netintel", "WARNING"):
            await self.net.refresh(session=object())
        self.assertEqual(self.net.missing(), ["tor.txt"])


class ImagePolicy(Base):
    async def test_the_dashboard_can_show_a_staff_chosen_picture(self):
        response = await self.client.get("/dashboard")
        self.assertIn("img-src 'self' https: data:", response.headers["Content-Security-Policy"])
        self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])

    async def test_member_pages_keep_the_strict_rule(self):
        for path in ("/v/" + "a" * 43, "/help", "/my-data", "/"):
            response = await self.client.get(path)
            self.assertIn("img-src 'self' https://cdn.discordapp.com data:", response.headers["Content-Security-Policy"], path)


class Safety(Base):
    async def test_login_refuses_paths_that_leave_the_site(self):
        for bad in ("//evil.example", "/\\evil.example", "https://evil.example", "/\tevil", "evil"):
            response = await self.client.get("/login", params={"next": bad}, allow_redirects=False)
            row = await self.db.one("SELECT next_path FROM login_states ORDER BY rowid DESC LIMIT 1")
            self.assertEqual(row["next_path"], "/dashboard", bad)
            self.assertEqual(response.status, 302)

    async def test_login_keeps_a_normal_path(self):
        await self.client.get("/login", params={"next": f"/dashboard/{GUILD}/settings"}, allow_redirects=False)
        row = await self.db.one("SELECT next_path FROM login_states ORDER BY rowid DESC LIMIT 1")
        self.assertEqual(row["next_path"], f"/dashboard/{GUILD}/settings")

    async def test_webhook_addresses(self):
        for bad in ("http://example.com/x", "https://localhost/x", "https://127.0.0.1/x", "https://[::1]/x", "https://10.0.0.8/x",
                    "https://intranet.local/x", "https://x.internal/y", "https://localhost./x", "https:///nohost"):
            self.assertTrue(webhook_problem(bad), bad)
        self.assertIsNone(webhook_problem("https://hooks.example.com/altwarden"))

    async def test_a_host_that_resolves_to_this_machine_is_refused(self):
        with self.assertRaises(OSError):
            await PublicResolver().resolve("localhost", 443)

    async def test_retention_reaches_every_table(self):
        document = await self.service.get_settings(GUILD)
        old = time.time() - 2000 * 86400
        await self.db.add_audit(GUILD, "reset", actor_id=STAFF)
        await self.db.run("UPDATE audit SET at = ?", (old,))
        await self.db.insert("INSERT INTO appeals (guild_id, user_id, text, status, created_at) VALUES (?, ?, ?, ?, ?)", (GUILD, OTHER_USER, "x" * 20, "denied", old))
        await self.db.insert("INSERT INTO appeals (guild_id, user_id, text, status, created_at) VALUES (?, ?, ?, ?, ?)", (GUILD, OTHER_USER, "y" * 20, "open", old))
        await self.db.run("INSERT INTO links VALUES (?, ?, ?, ?, ?, ?, ?)", (GUILD, OLD_USER, OTHER_USER, "likely", 70, "[]", old))
        await self.db.touch_member(GUILD, OTHER_USER)
        await self.db.run("UPDATE members SET joined_at = ? WHERE user_id = ?", (old, OTHER_USER))
        await self.db.touch_member(GUILD, STAFF)
        await self.db.update_member(GUILD, STAFF, status="verified", joined_at=old)
        removed = await self.db.purge_expired({GUILD: document})
        self.assertEqual((removed["audit"], removed["appeals"], removed["links"], removed["members"]), (1, 1, 1, 1))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM appeals"), 1, "an open appeal waits for a decision")
        self.assertIsNotNone(await self.db.member(GUILD, STAFF), "a verified member's record stays")


class Coverage(Helpers):
    """Capabilities that had no direct test before the parity matrix asked for one."""

    log_in = test_flow.Dashboard.log_in

    async def test_verify_button_in_instant_mode_says_rejoin(self):
        await self.core(mode="instant")
        result = await self.service.press_verify(self.port.members[(GUILD, OLD_USER)])
        self.assertIn("rejoin", result.message)

    async def test_direct_signin_reaches_the_page(self):
        token = await self.link_for()
        self.assertFalse((await (await self.client.get(f"/api/verify/{token}")).json())["direct"])
        await self.core(direct_signin=True)
        self.assertTrue((await (await self.client.get(f"/api/verify/{token}")).json())["direct"])

    async def test_country_list_covers_250_places(self):
        from pathlib import Path
        rows = json.loads((Path(test_flow.__file__).parent.parent / "altwarden" / "web" / "static" / "countries.json").read_text(encoding="utf-8"))
        self.assertEqual(len(rows), 250)
        self.assertEqual(len({row["code"] for row in rows}), 250)
        self.assertTrue(all(row["continent"] and row["region"] for row in rows))

    async def test_unverified_role_comes_and_goes(self):
        await self.core(unverified_enabled=True, unverified_role=UNVERIFIED_ROLE)
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn(UNVERIFIED_ROLE, self.port.members[(GUILD, OTHER_USER)].role_ids)
        await self.service.manual_verify(GUILD, OTHER_USER, STAFF, "staff")
        roles = self.port.members[(GUILD, OTHER_USER)].role_ids
        self.assertNotIn(UNVERIFIED_ROLE, roles)
        self.assertIn(VERIFIED_ROLE, roles)
        await self.service.reset_member(GUILD, OTHER_USER, STAFF, "staff")
        self.assertIn(UNVERIFIED_ROLE, self.port.members[(GUILD, OTHER_USER)].role_ids)

    async def test_a_failed_unverified_role_reaches_staff(self):
        await self.core(unverified_enabled=True, unverified_role=UNVERIFIED_ROLE)
        self.port.role_problem = "That role no longer exists."
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn("Couldn't give the unverified role", self.logged())

    async def test_an_alert_pings_the_chosen_role(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["alerts"] = {"enabled": True, "roles": {"vpn": VERIFIED_ROLE}}
        await self.service.save_settings(GUILD, document)
        await self.change(vpn={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token, ip="45.33.32.7")
        notice = next(notice for _, notice in self.port.sent if notice.mention_roles)
        self.assertEqual(notice.mention_roles, [VERIFIED_ROLE])
        self.assertIn(f"<@&{VERIFIED_ROLE}>", notice.content)

    async def test_the_result_dm_ignores_auto_dm_off(self):
        await self.core(auto_dm=False)
        await self.verify_through(OLD_USER)
        self.assertIn("verified", self.dms_to(OLD_USER)[0])

    async def test_join_dm_says_how_long_they_have(self):
        await self.core(auto_kick={"enabled": True, "minutes": 30})
        await self.service.on_join(self.port.add_member(OTHER_USER))
        self.assertIn("within 30 minutes", self.dms_to(OTHER_USER)[0])
        row = await self.db.one("SELECT expires_at, created_at FROM sessions WHERE user_id = ?", (OTHER_USER,))
        self.assertAlmostEqual(row["expires_at"] - row["created_at"], 1800, delta=1)

    async def open_thread(self, **options):
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE, require_attempt=False, **options)
        await self.service.save_settings(GUILD, document)
        thread, _ = await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        return thread

    async def test_member_close_is_a_setting(self):
        thread = await self.open_thread()
        member = self.port.members[(GUILD, OLD_USER)]
        self.assertFalse((await self.service.close_help(GUILD, thread, member))[0])
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"]["member_close"] = True
        await self.service.save_settings(GUILD, document)
        self.assertTrue((await self.service.close_help(GUILD, thread, member))[0])

    async def test_support_role_and_manage_threads_can_close(self):
        thread = await self.open_thread()
        support = self.port.add_member(STAFF, roles=(VERIFIED_ROLE,))
        self.assertTrue((await self.service.close_help(GUILD, thread, support))[0])
        thread = (await self.service.open_help(self.port.members[(GUILD, OLD_USER)]))[0]
        manager = self.port.add_member(OTHER_USER, perms=("manage_threads",))
        self.assertTrue((await self.service.close_help(GUILD, thread, manager))[0])

    async def test_the_first_thread_message_lists_failed_attempts_and_the_server(self):
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny")
        document = await self.service.get_settings(GUILD)
        document["messages"]["help_desk"]["description"] = "Welcome to {server} support."
        await self.service.save_settings(GUILD, document)
        calls = []
        original = self.port.open_help_thread

        async def spy(channel_id, name, user_id, role_id, notice, **_):
            calls.append(notice)
            return await original(channel_id, name, user_id, role_id, notice)
        self.port.open_help_thread = spy
        await self.open_thread()
        text = json.dumps(calls[0].embeds)
        self.assertIn("Verification records", text)
        self.assertIn("VPN and proxy", text)
        self.assertIn("Welcome to Test Server support.", text)

    async def test_changing_the_help_desk_posts_the_message_again(self):
        await self.log_in()
        changed = json.loads(json.dumps(await self.service.get_settings(GUILD)))
        changed["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE)
        self.assertEqual((await self.client.put(f"/api/guilds/{GUILD}/settings", json={"settings": changed}, headers=self.headers)).status, 200)
        self.assertIn("verification", self.posted)

    async def test_editing_the_message_posts_it_again(self):
        await self.log_in()
        messages = json.loads(json.dumps((await self.service.get_settings(GUILD))["messages"]))
        messages["verification"]["title"] = "New"
        await self.client.put(f"/api/guilds/{GUILD}/appearance", json={"messages": messages}, headers=self.headers)
        self.assertIn("verification", self.posted)

    async def test_reset_works_after_the_member_left(self):
        del self.port.members[(GUILD, OLD_USER)]
        await self.db.touch_member(GUILD, OLD_USER)
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny")
        await self.service.reset_member(GUILD, OLD_USER, STAFF, "staff")
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM attempts WHERE user_id = ?", (OLD_USER,)), 0)
        self.assertFalse(self.port.did("remove_role"))


class ChannelRules(unittest.TestCase):
    rule = {"required": ["manage_roles"], "overrides": [{"type": "channel", "id": CHANNEL, "allow": True}]}

    def test_a_channel_rule_limits_staff(self):
        staff = Viewer(STAFF, frozenset(), frozenset({"manage_roles"}))
        self.assertTrue(allowed(self.rule, staff, CHANNEL))
        self.assertFalse(allowed(self.rule, staff, LOG_CHANNEL))

    def test_administrators_are_never_locked_out(self):
        self.assertTrue(allowed(self.rule, Viewer(STAFF, frozenset(), frozenset({"administrator"})), LOG_CHANNEL))


class NameStyles(unittest.TestCase):
    def style(self, **look):
        document = settings.defaults()
        document["appearance"].update(look)
        return settings.normalize(document)["appearance"]

    def test_defaults_to_no_style(self):
        look = settings.defaults()["appearance"]
        self.assertEqual((look["font"], look["effect"], look["colors"]), (None, None, []))

    def test_the_same_twelve_fonts_and_seven_effects(self):
        self.assertEqual(len(settings.NAME_FONTS), 12)
        self.assertEqual({name for name, _ in settings.NAME_EFFECTS.values()}, {"Solid", "Gradient", "Neon", "Toon", "Pop", "Gummy", "Prism"})

    def test_each_effect_gets_the_colors_discord_wants(self):
        for effect, (name, wanted) in settings.NAME_EFFECTS.items():
            look = self.style(font=3, effect=effect, colors=[1])
            self.assertEqual(len(look["colors"]), wanted, name)
            self.assertEqual(look["colors"][0], 1, name)
            self.assertEqual(len(set(look["colors"])), wanted, name)

    def test_too_many_colors_are_cut(self):
        self.assertEqual(self.style(font=3, effect=1, colors=[1, 2, 3])["colors"], [1])

    def test_a_font_alone_gets_a_solid_effect(self):
        look = self.style(font=7)
        self.assertEqual(look["effect"], settings.SOLID_EFFECT)
        self.assertEqual(len(look["colors"]), 1)

    def test_an_effect_alone_gets_the_default_font(self):
        self.assertEqual(self.style(effect=3)["font"], settings.DEFAULT_NAME_FONT)

    def test_junk_never_crashes_or_passes(self):
        for bad in ({"font": []}, {"font": True}, {"effect": {}}, {"font": 1}, {"effect": 6}, {"font": "3"}, {"effect": 1001}, {"font": -1}):
            look = self.style(**bad)
            self.assertEqual((look["font"], look["effect"]), (None, None), bad)

    def test_bad_colors_are_dropped(self):
        look = self.style(font=3, effect=1, colors=["#ffffff", -1, 2 ** 25, True, None, 255])
        self.assertEqual(look["colors"], [255])

    def test_a_retired_font_is_refused(self):
        for font in (1, 2, 5, 9):
            self.assertIsNone(self.style(font=font)["font"], font)


class StyleVerification(unittest.TestCase):
    wanted = {"display_name_font_id": 3, "display_name_effect_id": 2, "display_name_colors": [1, 2]}

    def problem(self, member, style=None):
        from altwarden.bot.gateway import style_problem
        return style_problem(style or self.wanted, member)

    def test_a_matching_answer_is_fine(self):
        self.assertIsNone(self.problem({"display_name_styles": {"font_id": 3, "effect_id": 2, "colors": [1, 2]}}))

    def test_a_dropped_style_is_reported(self):
        self.assertIn("didn't apply", self.problem({"display_name_styles": None}))
        self.assertIn("didn't apply", self.problem({"display_name_styles": {"font_id": 11, "effect_id": 1, "colors": [1]}}))

    def test_an_answer_without_the_field_proves_nothing(self):
        self.assertIsNone(self.problem({"user": {}, "nick": None}))

    def test_clearing_a_style_has_nothing_to_compare(self):
        self.assertIsNone(self.problem({"display_name_styles": None}, {"display_name_font_id": None, "display_name_effect_id": None, "display_name_colors": None}))


class ProfileSaves(Helpers):
    log_in = test_flow.Dashboard.log_in

    async def save(self, **look):
        document = await self.service.get_settings(GUILD)
        return await self.client.put(f"/api/guilds/{GUILD}/appearance", json={"appearance": {**document["appearance"], **look}}, headers=self.headers)

    def profile_calls(self):
        return self.port.did("apply_profile")

    async def test_only_what_changed_goes_to_discord(self):
        await self.log_in()
        await self.save(bio="Hello")
        self.assertEqual(self.profile_calls()[-1][1:], ({"bio": "Hello"}, None), "a bio needs no Change Nickname, so the name must stay out")

    async def test_a_style_uses_discords_field_names(self):
        await self.log_in()
        await self.save(font=12, effect=2, colors=[1, 2])
        self.assertEqual(self.profile_calls()[-1][2], {"display_name_font_id": 12, "display_name_effect_id": 2, "display_name_colors": [1, 2]})

    async def test_clearing_a_style_sends_nulls(self):
        await self.log_in()
        await self.save(font=12, effect=1, colors=[1])
        await self.save(font=None, effect=None, colors=[])
        self.assertEqual(self.profile_calls()[-1][2], {"display_name_font_id": None, "display_name_effect_id": None, "display_name_colors": None})

    async def test_saving_nothing_calls_nothing(self):
        await self.log_in()
        await self.save()
        self.assertEqual(self.profile_calls(), [])

    async def test_a_picture_goes_as_bytes(self):
        await self.log_in()
        await self.save(avatar="teal")
        self.assertIsInstance(self.profile_calls()[-1][1]["avatar"], bytes)
        await self.save(avatar="")
        self.assertIsNone(self.profile_calls()[-1][1]["avatar"])

    async def test_a_refusal_reaches_the_page(self):
        await self.log_in()
        self.port.profile_problem = "Discord refused the name style (400). The rest was saved."
        response = await self.save(font=12, effect=1, colors=[1])
        data = await response.json()
        self.assertEqual(response.status, 200)
        self.assertIn("refused the name style", data["problem"])
        self.assertEqual(data["appearance"]["font"], 12)

    async def test_a_message_too_long_for_discord_is_refused_before_saving(self):
        await self.log_in()
        messages = json.loads(json.dumps((await self.service.get_settings(GUILD))["messages"]))
        messages["verification"].update(title="t" * 256, description="d" * 4000, footer="f" * 2048)
        response = await self.client.put(f"/api/guilds/{GUILD}/appearance", json={"messages": messages}, headers=self.headers)
        self.assertEqual(response.status, 400)
        self.assertIn("under 5,800", (await response.json())["error"])
        self.assertEqual((await self.service.get_settings(GUILD))["messages"]["verification"]["description"], settings.DEFAULT_MESSAGES["verification"]["description"])

    async def test_name_styles_need_change_nickname(self):
        document = settings.defaults()
        document["appearance"].update(font=3, effect=1, colors=[1])
        self.assertIn("Name style", health.needed_permissions(settings.normalize(document))["change_nickname"])
        self.assertNotIn("change_nickname", health.needed_permissions(settings.defaults()))


class CommandSync(Helpers):
    log_in = test_flow.Dashboard.log_in

    async def start(self, changes, headers=None):
        return await self.client.post(f"/api/guilds/{GUILD}/permissions/discord", json={"changes": changes}, headers=headers or self.headers)

    async def approve(self, changes, user=None, params=None):
        """Start a change and walk Discord's approval the way a browser does."""
        response = await self.start(changes)
        self.assertEqual(response.status, 200, await response.text())
        url = (await response.json())["authorize"]
        query = test_flow.parse_qs(test_flow.urlsplit(url).query)
        self.discord.user["id"] = user or STAFF
        flow = response.cookies[test_flow.FLOW_COOKIE].value
        cookie = {"Cookie": f"{test_flow.FLOW_COOKIE}={flow}; {self.session_cookie['Cookie']}"}
        result = await self.client.get("/dashboard/callback", params=params or {"code": "abc", "state": query["state"][0]}, allow_redirects=False, headers=cookie)
        return result, query

    OVERRIDE = [{"type": "role", "id": VERIFIED_ROLE, "allow": True}]

    async def test_the_page_reads_discords_overrides(self):
        await self.log_in()
        data = await (await self.client.get(f"/api/guilds/{GUILD}/permissions", headers=self.headers)).json()
        self.assertEqual(data["discord"]["commands"][1]["overrides"], [{"type": "role", "id": VERIFIED_ROLE, "allow": False}])

    async def test_a_save_goes_through_the_persons_own_token_and_ends_it(self):
        await self.log_in()
        self.discord.revoked.clear()
        result, query = await self.approve({"900000000000000001": self.OVERRIDE})
        self.assertEqual(result.status, 302)
        self.assertEqual(result.headers["Location"], f"/dashboard/{GUILD}/permissions?discord=saved")
        self.assertIn("applications.commands.permissions.update", query["scope"][0])
        self.assertEqual(self.discord.command_writes, [(GUILD, "900000000000000001", {"permissions": [{"id": VERIFIED_ROLE, "type": 1, "permission": True}]})])
        self.assertEqual(self.discord.authorizations, ["Bearer fake-access"])
        self.assertEqual(self.discord.revoked, ["fake-access"])

    async def test_no_token_is_ever_stored(self):
        await self.log_in()
        await self.approve({"900000000000000001": self.OVERRIDE})
        self.assertNotIn("fake-access", self.database_dump())
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM command_syncs"), 0)

    async def test_the_change_is_audited_and_logged(self):
        await self.log_in()
        await self.approve({"900000000000000001": self.OVERRIDE})
        row = await self.db.one("SELECT kind, actor_id, detail FROM audit WHERE kind = 'command_permissions'")
        self.assertEqual(row["actor_id"], STAFF)
        self.assertIn("verify-user", row["detail"])
        self.assertIn("Command permissions changed", self.logged())

    async def test_all_commands_uses_the_application_id(self):
        await self.log_in()
        await self.approve({"123": [{"type": "role", "id": GUILD, "allow": False}, {"type": "channel", "id": str(int(GUILD) - 1), "allow": False}]})
        self.assertEqual(self.discord.command_writes[0][1], "123")
        self.assertEqual(self.discord.command_writes[0][2]["permissions"][1]["type"], 3)

    async def test_an_empty_list_clears_a_commands_overrides(self):
        await self.log_in()
        await self.approve({"900000000000000002": []})
        self.assertEqual(self.discord.command_writes[0][2], {"permissions": []})

    async def test_a_command_it_doesnt_know_is_refused(self):
        await self.log_in()
        self.assertEqual((await self.start({"555": self.OVERRIDE})).status, 400)

    async def test_bad_overrides_are_dropped(self):
        await self.log_in()
        junk = [{"type": "everyone", "id": GUILD}, {"type": "role", "id": "abc"}, "x", {"type": "role", "id": VERIFIED_ROLE, "allow": "yes"},
                {"type": "role", "id": VERIFIED_ROLE, "allow": True}, {"type": ["role"], "id": VERIFIED_ROLE}]
        await self.approve({"900000000000000001": junk})
        self.assertEqual(self.discord.command_writes[0][2]["permissions"], [{"id": VERIFIED_ROLE, "type": 1, "permission": False}])

    async def test_view_only_staff_cannot_start(self):
        await self.log_in(owner=False, perms=("manage_guild",))
        self.assertEqual((await self.start({"900000000000000001": self.OVERRIDE})).status, 403)

    async def test_a_write_needs_the_csrf_token(self):
        await self.log_in()
        self.assertEqual((await self.start({"900000000000000001": self.OVERRIDE}, headers=self.session_cookie)).status, 403)

    async def test_another_account_changes_nothing(self):
        await self.log_in()
        result, _ = await self.approve({"900000000000000001": self.OVERRIDE}, user=OTHER_USER)
        self.assertTrue(result.headers["Location"].endswith("discord=wrong-account"))
        self.assertEqual(self.discord.command_writes, [])
        self.assertEqual(self.discord.revoked[-1], "fake-access", "the stray token still gets revoked")

    async def test_a_canceled_approval_changes_nothing(self):
        await self.log_in()
        response = await self.start({"900000000000000001": self.OVERRIDE})
        url = (await response.json())["authorize"]
        state = test_flow.parse_qs(test_flow.urlsplit(url).query)["state"][0]
        flow = response.cookies[test_flow.FLOW_COOKIE].value
        result = await self.client.get("/dashboard/callback", params={"error": "access_denied", "state": state}, allow_redirects=False,
                                       headers={"Cookie": f"{test_flow.FLOW_COOKIE}={flow}; {self.session_cookie['Cookie']}"})
        self.assertTrue(result.headers["Location"].endswith("discord=declined"))
        self.assertEqual(self.discord.command_writes, [])

    async def test_a_refusal_from_discord_is_reported(self):
        await self.log_in()
        self.discord.command_write_status = 403
        result, _ = await self.approve({"900000000000000001": self.OVERRIDE})
        self.assertTrue(result.headers["Location"].endswith("discord=refused"))
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM audit WHERE kind = 'command_permissions'"), 0)

    async def test_a_rate_limit_is_waited_out(self):
        await self.log_in()
        self.discord.command_write_status = 429
        result, _ = await self.approve({"900000000000000001": self.OVERRIDE})
        self.assertTrue(result.headers["Location"].endswith("discord=saved"))
        self.assertEqual(len(self.discord.command_writes), 1)

    async def test_a_failed_token_exchange_changes_nothing(self):
        await self.log_in()
        self.discord.fail_exchange = True
        result, _ = await self.approve({"900000000000000001": self.OVERRIDE})
        self.assertTrue(result.headers["Location"].endswith("discord=failed"))

    async def test_uninstall_clears_a_waiting_change(self):
        await self.log_in()
        await self.start({"900000000000000001": self.OVERRIDE})
        await self.db.forget_guild(GUILD)
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM command_syncs"), 0)

    async def test_a_waiting_change_expires(self):
        await self.log_in()
        await self.start({"900000000000000001": self.OVERRIDE})
        await self.db.run("UPDATE command_syncs SET expires_at = 1")
        removed = await self.db.purge_expired({})
        self.assertEqual(removed["command_syncs"], 1)

    async def test_a_normal_sign_in_never_asks_for_this_scope(self):
        response = await self.client.get("/login", allow_redirects=False)
        scope = test_flow.parse_qs(test_flow.urlsplit(response.headers["Location"]).query)["scope"][0]
        self.assertNotIn("applications.commands", scope)


class PinPermission(unittest.TestCase):
    def test_the_invite_asks_for_it(self):
        self.assertTrue(health.invite_permissions() & (1 << 51))

    def view(self, *held):
        from altwarden.ports import GuildView
        channel = {"id": CHANNEL, "name": "verify", "type": "text", "category": None, "position": 0}
        return GuildView(id=GUILD, roles=[{"id": VERIFIED_ROLE, "name": "Verified", "color": 0, "position": 1, "managed": False, "mentionable": True}], channels=[channel],
                         bot_permissions=frozenset({"manage_roles"}), bot_top_role=5,
                         channel_permissions={CHANNEL: frozenset({"view_channel", "send_messages", "embed_links", *held})})

    def document(self, **change):
        document = settings.defaults()
        document["core"].update(verified_role=VERIFIED_ROLE, channel=CHANNEL)
        document.update(change)
        return settings.normalize(document)

    def test_administrator_brings_no_warning(self):
        guild = self.view()
        guild.bot_permissions = frozenset({"administrator"})
        report = health.report(guild, self.document())
        self.assertTrue(report["has_administrator"])
        self.assertTrue(report["healthy"], report["issues"])
        self.assertNotIn("advice", report)

    def test_the_honeypot_reports_it_missing(self):
        pot = {"enabled": True, "channel": CHANNEL, "action": "log"}
        titles = json.dumps(health.report(self.view("manage_messages"), self.document(honeypot=pot))["issues"])
        self.assertIn("Pin Messages", titles)
        titles = json.dumps(health.report(self.view("manage_messages", "pin_messages"), self.document(honeypot=pot))["issues"])
        self.assertNotIn("Pin Messages", titles)

    def test_the_help_desk_reports_it_missing(self):
        document = self.document()
        document["core"]["help_desk"].update(enabled=True, support_role=VERIFIED_ROLE)
        titles = json.dumps(health.report(self.view("create_private_threads", "send_messages_in_threads", "manage_threads"), document)["issues"])
        self.assertIn("Pin Messages", titles)


class LongMessages(unittest.TestCase):
    def test_a_long_description_keeps_the_writers_line(self):
        message = dict(settings.DEFAULT_MESSAGES["honeypot"], author=STAFF, description="{server} " * 500)
        embed = notices.plain_message(message, "x" * 100, "https://x.test").embeds[0]
        self.assertLessEqual(len(embed["description"]), 4096)
        self.assertIn("Written by", embed["description"])

    def test_a_blank_description_falls_back(self):
        document = settings.defaults()
        document["messages"]["honeypot"]["description"] = "    "
        self.assertEqual(settings.normalize(document)["messages"]["honeypot"]["description"], settings.DEFAULT_MESSAGES["honeypot"]["description"])


class BackgroundTasks(Helpers):
    async def test_a_running_webhook_task_is_held_and_then_let_go(self):
        import asyncio
        release = asyncio.Event()

        async def sender(guild_id, event, payload):
            await release.wait()
        self.service.webhook_sender = sender
        await self.service._emit(GUILD, "member.verified", {})
        self.assertEqual(len(self.service._background), 1)
        release.set()
        await asyncio.sleep(0.01)
        self.assertEqual(len(self.service._background), 0)


if __name__ == "__main__":
    unittest.main()
