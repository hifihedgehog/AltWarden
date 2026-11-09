"""What a member is told to do about each check that stopped them, on the page, in the DM and on the help pages."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import catalog, engine, fixes, notices
from altwarden.service import Result
from fakes import CHANNEL, GUILD, OLD_USER, STAFF
from test_detection import clean_report
from test_flow import Base as FlowBase


def chosen(reason, detail=None, system=None, browser=None):
    found = fixes.for_findings([engine.Finding(reason, "deny", reason, detail or {})], system=system, browser=browser)
    return found[0] if found else None


def headings(fix):
    return [way["heading"] for way in fix["ways"]]


class Choosing(unittest.TestCase):
    def test_two_factor_shows_the_phone_steps_first_on_a_phone(self):
        fix = chosen("mfa", system="ios", browser="safari")
        self.assertEqual(headings(fix), ["In the Discord app on a phone or tablet", "In Discord on a computer", "With a code app instead"])
        self.assertIn("Tap Account, then Security Keys, then Add.", fix["ways"][0]["steps"])

    def test_two_factor_shows_the_computer_steps_first_on_a_computer(self):
        fix = chosen("mfa", system="windows", browser="chrome")
        self.assertEqual(headings(fix)[:2], ["In Discord on a computer", "In the Discord app on a phone or tablet"])
        self.assertIn("Under Password and Authentication, click Register a Security Key, then follow the prompts.", fix["ways"][0]["steps"])

    def test_two_factor_with_no_browser_keeps_both_devices(self):
        fix = chosen("mfa")
        self.assertEqual(set(headings(fix)[:2]), {"In the Discord app on a phone or tablet", "In Discord on a computer"})
        self.assertEqual(fix["after"], fixes.SIGN_IN_AGAIN)

    def test_private_relay_gets_apples_steps_for_the_device(self):
        iphone = chosen("vpn", {"network": ["private relay"]}, "ios", "safari")
        mac = chosen("vpn", {"network": ["private relay"]}, "mac", "safari")
        self.assertEqual((iphone["title"], headings(iphone)), ("Turn off iCloud Private Relay", ["On an iPhone or iPad"]))
        self.assertEqual((mac["title"], headings(mac)), ("Turn off iCloud Private Relay", ["On a Mac"]))

    def test_a_vpn_and_a_data_center_lead_with_the_vpn(self):
        fix = chosen("vpn", {"network": ["vpn", "data center"]}, "windows", "chrome")
        self.assertEqual((fix["title"], headings(fix)), ("Turn off your VPN", ["If you use a VPN app", "If you don't use a VPN"]))

    def test_a_data_center_alone_says_so(self):
        fix = chosen("vpn", {"network": ["data center"]}, "windows", "chrome")
        self.assertEqual(fix["title"], "Your connection comes from a data center")
        self.assertIn("Turn off any VPN, proxy or privacy app, such as Cloudflare WARP, while you verify.", fix["ways"][0]["steps"])

    def test_a_vpn_found_by_the_outside_lookup_alone_still_gets_steps(self):
        self.assertEqual(headings(chosen("vpn", {"network": []}, "windows", "chrome")), ["If you use a VPN app"])

    def test_brave_shields_gets_the_lion_for_the_device(self):
        computer = chosen("privacy", {"signs": ["Brave Shields"]}, "windows", "chrome")
        phone = chosen("privacy", {"signs": ["Brave Shields"]}, "android", "chrome")
        self.assertEqual((computer["title"], headings(computer)), ("Turn off Brave Shields for this page", ["In Brave on a computer"]))
        self.assertEqual(headings(phone), ["In Brave on a phone"])

    def test_each_privacy_sign_gets_its_own_steps(self):
        self.assertEqual(chosen("privacy", {"signs": ["canvas randomized"]}, "windows", "firefox")["title"], "Turn off Firefox's extra protection for this page")
        self.assertEqual(chosen("privacy", {"signs": ["fingerprint library blocked"]}, "windows", "chrome")["title"], "Let this page load in full")
        self.assertEqual(chosen("privacy", {"signs": ["canvas functions rewritten"]}, "windows", "chrome")["title"], "Turn off your privacy extension for this page")
        self.assertEqual(headings(chosen("privacy", {"signs": ["something new"]}, "windows", "chrome")), ["Other privacy settings"])

    def test_software_graphics_names_the_browsers_own_setting(self):
        self.assertEqual(headings(chosen("vm", {"signs": ["software graphics"]}, "windows", "chrome")), ["In Chrome or Brave", "In another browser"])
        self.assertEqual(headings(chosen("vm", {"signs": ["software graphics"]}, "windows", "edge"))[0], "In Edge")
        self.assertEqual(headings(chosen("vm", {"signs": ["software graphics"]}, "linux", "firefox"))[0], "In Firefox")
        self.assertEqual(headings(chosen("vm", {"signs": ["software graphics"]}, "mac", "safari")), ["In another browser"])
        self.assertEqual(chosen("vm", {"signs": ["virtual machine graphics"]}, "windows", "chrome")["title"], "Open the link on your own device")

    def test_a_private_window_gets_the_steps_for_the_device(self):
        self.assertEqual(headings(chosen("incognito", system="windows", browser="chrome")), ["On a computer", "In a Chrome guest window"])
        self.assertEqual(headings(chosen("incognito", system="ios", browser="safari")), ["On a phone or tablet", "In a Chrome guest window"])

    def test_the_email_check_answers_by_what_it_found(self):
        self.assertEqual(chosen("no_email")["title"], "Verify your email in Discord")
        self.assertEqual(chosen("disposable_email")["title"], "Use a regular email address in Discord")

    def test_checks_nobody_can_fix_on_the_spot_get_none(self):
        for reason in ("account_age", "account_age_one", "max_attempts", "geogate", "cooldown"):
            self.assertIsNone(chosen(reason), reason)

    def test_fixes_follow_the_order_the_checks_ran(self):
        found = fixes.for_findings([engine.Finding("mfa", "deny", "mfa"), engine.Finding("vpn", "deny", "vpn", {"network": ["vpn"]})])
        self.assertEqual([fix["check"] for fix in found], ["mfa", "vpn"])

    def test_every_fix_belongs_to_a_failure_with_a_help_page(self):
        for reason, fix in fixes.FIXES.items():
            self.assertIn(reason, catalog.HELP_SLUG)
            self.assertTrue(fix.ways)
            for way in fix.ways:
                self.assertTrue(way.steps, (reason, way.heading))

    def test_every_string_is_listed_for_the_translations(self):
        english = set(json.loads((catalog_path() / "en.json").read_text(encoding="utf-8")))
        self.assertLessEqual(set(fixes.strings()), english)


def catalog_path():
    from altwarden.web.app import STATIC
    return STATIC / "i18n"


class TellingTheMember(unittest.TestCase):
    def two_problems(self, system="android"):
        return fixes.for_findings([engine.Finding("mfa", "deny", "mfa"), engine.Finding("vpn", "deny", "vpn", {"network": ["vpn"]})],
                                  system=system, browser="chrome")

    def test_the_dm_carries_both_devices_for_two_factor_and_says_where_to_go_next(self):
        notice = notices.failed_notice("Server", "mfa", "This server requires two-factor login on your Discord account.", "deny", "https://x", None, True,
                                       fixes=self.two_problems(), retry=True, channel_id=CHANNEL)
        text = notice.embeds[0]["description"]
        self.assertIn("**Turn on two-factor login in Discord**", text)
        self.assertIn("*In the Discord app on a phone or tablet*", text)
        self.assertIn("*In Discord on a computer*", text)
        self.assertNotIn("With a code app instead", text)
        self.assertIn("**Turn off your VPN**", text)
        self.assertTrue(text.endswith(f"When you're done, go to <#{CHANNEL}> and press **Verify** to try again."))

    def test_the_dm_says_nothing_about_steps_with_reasons_hidden(self):
        notice = notices.failed_notice("Server", "mfa", "hidden", "deny", "https://x", None, False, fixes=self.two_problems(), retry=True, channel_id=CHANNEL)
        text = notice.embeds[0]["description"]
        self.assertNotIn("Security Keys", text)
        self.assertNotIn("When you're done", text)

    def test_no_try_again_line_when_no_try_is_left(self):
        notice = notices.failed_notice("Server", "mfa", "text", "deny", "https://x", None, True, fixes=self.two_problems(), retry=False, channel_id=CHANNEL)
        self.assertNotIn("When you're done", notice.embeds[0]["description"])

    def test_instant_mode_keeps_its_rejoin_line(self):
        notice = notices.failed_notice("Server", "mfa", "text", "deny", "https://x", None, True, fixes=self.two_problems(), retry=True, channel_id=CHANNEL, instant=True)
        text = notice.embeds[0]["description"]
        self.assertIn("Leave the server and rejoin to try again.", text)
        self.assertNotIn("press **Verify**", text)

    def test_the_dm_stays_under_discords_limit_with_every_fix(self):
        every = [engine.Finding(reason, "deny", reason) for reason in fixes.FIXES]
        notice = notices.failed_notice("Server", "mfa", "text", "deny", "https://x", None, True,
                                       fixes=fixes.for_findings(every), retry=True, channel_id=CHANNEL)
        text = notice.embeds[0]["description"]
        self.assertLessEqual(len(text), notices.DESCRIPTION_LIMIT)
        self.assertTrue(text.endswith("to try again."))

    def test_a_button_reply_carries_the_steps(self):
        result = Result("failed", "You weren't verified", "message", fixes=self.two_problems())
        self.assertIn("Tap Account, then Security Keys, then Add.", result.discord_text())
        self.assertEqual(result.as_dict()["fixes"][0]["check"], "mfa")


class OnThePage(FlowBase):
    async def test_a_failed_attempt_sends_its_fixes_and_a_reload_keeps_them(self):
        await self.change(devtools={"enabled": True, "action": "deny"})
        report = clean_report()
        report["devtools"] = {"timing": True}
        result = await self.verify_through(report=report)
        self.assertEqual(result["status"], "failed")
        self.assertEqual([fix["check"] for fix in result["fixes"]], ["devtools"])
        state = await (await self.client.get(f"/api/verify/{self.last_token}", headers=self.cookie_header("__Host-aw_browser"))).json()
        self.assertTrue(state["tried"])
        self.assertEqual([fix["check"] for fix in state["fixes"]], ["devtools"])

    async def test_a_cooldown_keeps_the_last_attempts_fixes(self):
        await self.change(devtools={"enabled": True, "action": "deny"})
        document = await self.service.get_settings(GUILD)
        document["core"]["cooldown"] = {"enabled": True, "seconds": 600}
        await self.service.save_settings(GUILD, document)
        report = clean_report()
        report["devtools"] = {"timing": True}
        self.assertEqual((await self.verify_through(report=report))["status"], "failed")
        again = await (await self.attempt(self.last_token, report)).json()
        self.assertEqual(again["status"], "cooldown")
        state = await (await self.client.get(f"/api/verify/{self.last_token}", headers=self.cookie_header("__Host-aw_browser"))).json()
        self.assertEqual([fix["check"] for fix in state["fixes"]], ["devtools"])

    async def test_two_factor_sends_the_computer_steps_first_and_signs_in_again(self):
        self.discord.user["mfa_enabled"] = False
        result = await self.verify_through()
        fix = result["fixes"][0]
        self.assertEqual((fix["check"], fix["ways"][0]["heading"], fix["after"]), ("mfa", "In Discord on a computer", "signin"))
        dm = json.dumps(self.port.dms[-1][1].embeds)
        self.assertIn("Security Keys", dm)
        self.assertIn(f"<#{CHANNEL}>", dm)
        state = await (await self.client.get(f"/api/verify/{self.last_token}")).json()
        self.assertEqual((state["step"], state["fixes"]), ("signin", []))

    async def test_hidden_reasons_send_no_fixes(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["show_reason"] = False
        await self.service.save_settings(GUILD, document)
        self.discord.user["mfa_enabled"] = False
        result = await self.verify_through()
        self.assertEqual(result["fixes"], [])
        self.assertNotIn("Security Keys", json.dumps(self.port.dms[-1][1].embeds))

    async def test_a_ban_sends_no_fixes(self):
        await self.change(mfa={"enabled": True, "action": "ban"})
        self.discord.user["mfa_enabled"] = False
        result = await self.verify_through()
        self.assertEqual((result["action"], result["fixes"]), ("ban", []))

    async def verify_through(self, user=OLD_USER, report=None, ip="203.0.113.9"):
        token = await self.link_for(user)
        self.last_token = token
        response = await self.sign_in(token, user=user)
        self.assertIn(f"/v/{token}", response.headers["Location"])
        result = await self.attempt(token, report, ip)
        self.assertEqual(result.status, 200, await result.text())
        return await result.json()


class HelpThread(FlowBase):
    async def enable(self, **extra):
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, support_role="970000000000000002", require_attempt=True)
        document["core"].update(extra)
        await self.service.save_settings(GUILD, document)

    async def thread_embeds(self):
        await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        return self.port.threads[-1].embeds

    async def test_the_first_message_gives_the_steps_before_the_records(self):
        await self.enable()
        self.discord.user["mfa_enabled"] = False
        await self.verify_through()
        embeds = await self.thread_embeds()
        titles = [embed["title"] for embed in embeds]
        self.assertEqual(titles[1:], [notices.STEPS_TITLE, "Verification records"])
        steps = embeds[1]["description"]
        self.assertTrue(steps.startswith(notices.STEPS_LEAD))
        for heading in ("*In the Discord app on a phone or tablet*", "*In Discord on a computer*", "*With a code app instead*"):
            self.assertIn(heading, steps)
        self.assertLessEqual(sum(map(notices.embed_size, embeds)), notices.EMBED_LIMIT)

    async def test_the_first_lines_are_a_plain_checklist(self):
        await self.enable()
        self.discord.user["mfa_enabled"] = False
        await self.verify_through()
        thread, reply = await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        content = self.port.threads[-1].content
        self.assertTrue(content.startswith("Your last attempt didn't pass. To get in, you need to:\n- Turn on two-factor login in Discord\n"))
        self.assertIn(f"go to <#{CHANNEL}> and press **Verify**", content)
        self.assertIn("Staff aren't notified yet. If you've tried every step and still can't get in, mention <@&970000000000000002> and say what happened.", content)
        self.assertFalse(self.port.threads[-1].mention_roles)
        self.assertEqual(reply, f"Your help thread is <#{thread}>. The steps for what stopped you are in it.")

    async def failed_with_thread(self):
        await self.enable()
        self.discord.user["mfa_enabled"] = False
        await self.verify_through()
        thread, _ = await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        return thread

    def reminders(self, thread):
        return [notice for where, notice in self.port.sent if where == thread]

    async def test_the_members_first_post_brings_the_steps_back_once(self):
        thread = await self.failed_with_thread()
        self.assertTrue(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER))
        notice = self.reminders(thread)[0]
        self.assertTrue(notice.content.startswith(f"<@{OLD_USER}> Your last attempt needs this fixed:\n- Turn on two-factor login in Discord\n"))
        self.assertTrue(notice.content.endswith("mention <@&970000000000000002> and say what happened."))
        self.assertFalse(notice.mention_roles)
        self.assertEqual(notice.embeds[0]["title"], notices.STEPS_TITLE)
        self.assertEqual(notice.mention_users, [OLD_USER])
        self.assertFalse(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER))
        self.assertEqual(len(self.reminders(thread)), 1)

    async def test_a_new_failure_earns_a_new_reminder(self):
        thread = await self.failed_with_thread()
        await self.service.remind_in_help_thread(GUILD, thread, OLD_USER)
        await self.db.run("UPDATE members SET help_reminded_at = help_reminded_at - 60 WHERE user_id = ?", (OLD_USER,))
        await self.verify_through()
        self.assertTrue(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER))

    async def test_staff_posts_and_other_threads_get_nothing(self):
        thread = await self.failed_with_thread()
        self.assertFalse(await self.service.remind_in_help_thread(GUILD, thread, STAFF))
        self.assertFalse(await self.service.remind_in_help_thread(GUILD, "970000000000000123", OLD_USER))
        self.assertEqual(self.reminders(thread), [])

    async def test_no_reminder_once_the_member_got_in(self):
        thread = await self.failed_with_thread()
        await self.db.add_attempt(GUILD, OLD_USER, "passed", mode="web", detail={"findings": []})
        await self.db.mark_verified(GUILD, OLD_USER, "web")
        self.assertFalse(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER))
        self.assertEqual(self.reminders(thread), [])

    async def test_with_reasons_hidden_the_reminder_only_says_how_to_reach_staff(self):
        thread = await self.failed_with_thread()
        document = await self.service.get_settings(GUILD)
        document["core"]["show_reason"] = False
        await self.service.save_settings(GUILD, document)
        self.assertTrue(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER))
        notice = self.reminders(thread)[0]
        self.assertEqual(notice.content, f"<@{OLD_USER}> Staff aren't notified yet. If you still can't get in, mention <@&970000000000000002> and say what happened.")
        self.assertEqual(notice.embeds, [])

    async def test_a_post_that_calls_staff_gets_no_reminder(self):
        thread = await self.failed_with_thread()
        self.assertFalse(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER, ("970000000000000002",)))
        self.assertEqual(self.reminders(thread), [])
        self.assertFalse(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER))

    async def test_no_reminder_with_nothing_to_fix_and_no_role_to_call(self):
        thread = await self.failed_with_thread()
        document = await self.service.get_settings(GUILD)
        document["core"].update(show_reason=False)
        document["core"]["help_desk"]["support_role"] = None
        await self.service.save_settings(GUILD, document)
        self.assertFalse(await self.service.remind_in_help_thread(GUILD, thread, OLD_USER))

    async def test_reopening_after_a_new_failure_posts_the_current_steps(self):
        thread = await self.failed_with_thread()
        await self.service.remind_in_help_thread(GUILD, thread, OLD_USER)
        await self.db.run("UPDATE members SET help_reminded_at = help_reminded_at - 60 WHERE user_id = ?", (OLD_USER,))
        await self.verify_through()
        again, reply = await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        self.assertEqual(again, thread)
        self.assertEqual(len(self.reminders(thread)), 2)
        self.assertIn("The steps for what stopped you are in it.", reply)

    async def test_hidden_reasons_give_no_steps(self):
        await self.enable(show_reason=False)
        self.discord.user["mfa_enabled"] = False
        await self.verify_through()
        self.assertNotIn(notices.STEPS_TITLE, [embed["title"] for embed in await self.thread_embeds()])

    async def test_a_member_who_got_in_since_gets_no_steps(self):
        await self.enable()
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="mfa", action="deny", mode="web",
                                  detail={"findings": [{"check": "mfa", "action": "deny", "reason": "mfa", "detail": {}}]})
        await self.db.add_attempt(GUILD, OLD_USER, "passed", mode="web", detail={"findings": []})
        self.assertNotIn(notices.STEPS_TITLE, [embed["title"] for embed in await self.thread_embeds()])

    async def test_an_attempt_from_before_1_4_1_still_gets_its_steps(self):
        await self.enable()
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny", mode="web",
                                  detail={"findings": [{"check": "vpn", "action": "deny", "detail": {"network": ["private relay"]}}]})
        steps = (await self.thread_embeds())[1]["description"]
        self.assertIn("**Turn off iCloud Private Relay**", steps)
        self.assertIn("*On an iPhone or iPad*", steps)
        self.assertIn("*On a Mac*", steps)

    async def test_watched_findings_and_checks_with_no_fix_give_none(self):
        await self.enable()
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="account_age", action="deny", mode="web",
                                  detail={"findings": [{"check": "account_age", "action": "deny", "reason": "account_age", "detail": {}},
                                                       {"check": "vpn", "action": "watch", "reason": "vpn", "detail": {}}]})
        self.assertNotIn(notices.STEPS_TITLE, [embed["title"] for embed in await self.thread_embeds()])

    async def test_a_long_server_message_still_fits_discords_limit(self):
        document = await self.service.get_settings(GUILD)
        document["messages"]["help_desk"]["description"] = "x" * 3990
        await self.service.save_settings(GUILD, document)
        await self.enable()
        self.discord.user["mfa_enabled"] = False
        await self.verify_through()
        embeds = await self.thread_embeds()
        self.assertLessEqual(sum(map(notices.embed_size, embeds)), notices.EMBED_LIMIT)
        self.assertIn("Verification records", [embed["title"] for embed in embeds])

    async def test_an_attempt_stores_each_findings_reason(self):
        self.discord.user["mfa_enabled"] = False
        await self.verify_through()
        row = await self.db.one("SELECT detail FROM attempts WHERE user_id = ? AND outcome = 'failed' ORDER BY id DESC LIMIT 1", (OLD_USER,))
        self.assertEqual(json.loads(row["detail"])["findings"][0]["reason"], "mfa")

    async def verify_through(self, user=OLD_USER, report=None, ip="203.0.113.9"):
        token = await self.link_for(user)
        response = await self.sign_in(token, user=user)
        self.assertIn(f"/v/{token}", response.headers["Location"])
        result = await self.attempt(token, report, ip)
        self.assertEqual(result.status, 200, await result.text())
        return await result.json()


class HelpDeskMessage(unittest.TestCase):
    def test_the_old_default_message_becomes_the_new_one(self):
        from altwarden import settings
        document = settings.defaults()
        document["messages"]["help_desk"].update(title=settings.OLD_HELP_DESK[0], description=settings.OLD_HELP_DESK[1])
        message = settings.normalize(document)["messages"]["help_desk"]
        self.assertEqual((message["title"], message["description"]),
                         (settings.DEFAULT_MESSAGES["help_desk"]["title"], settings.DEFAULT_MESSAGES["help_desk"]["description"]))

    def test_a_servers_own_message_stays(self):
        from altwarden import settings
        document = settings.defaults()
        document["messages"]["help_desk"].update(title=settings.OLD_HELP_DESK[0], description="Our own words.")
        self.assertEqual(settings.normalize(document)["messages"]["help_desk"]["description"], "Our own words.")


class HelpPages(FlowBase):
    async def test_the_index_lists_every_fix_page(self):
        pages = (await (await self.client.get("/api/help")).json())["pages"]
        self.assertEqual([page["slug"] for page in pages], [catalog.HELP_SLUG[reason] for reason in fixes.FIXES])

    async def test_a_fix_page_holds_every_way(self):
        page = await (await self.client.get("/api/help/mfa")).json()
        self.assertEqual(page["title"], "Turn on two-factor login in Discord")
        self.assertEqual(len(page["ways"]), 3)
        page = await (await self.client.get("/api/help/no-email")).json()
        self.assertEqual(page["title"], "Verify your email in Discord")

    async def test_anything_else_is_not_found(self):
        for slug in ("nothing", "constructor", "link-expired", "account-age"):
            self.assertEqual((await self.client.get(f"/api/help/{slug}")).status, 404, slug)


if __name__ == "__main__":
    unittest.main()
