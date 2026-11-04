"""Behaviors added after checking every capability against the requirements."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import engine, settings
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, STAFF
from test_detection import clean_report
from test_flow import Base


class Stranded(Base):
    async def test_crash_during_a_check_does_not_strand_the_link(self):
        token = await self.link_for()
        await self.sign_in(token)
        original = self.service.net.lookup

        def explode(ip):
            raise RuntimeError("boom")
        self.service.net.lookup = explode
        response = await self.attempt(token)
        self.assertEqual(response.status, 500)
        self.service.net.lookup = original
        result = await (await self.attempt(token)).json()
        self.assertEqual(result["status"], "verified")

    async def test_member_who_left_gets_told(self):
        token = await self.link_for()
        await self.sign_in(token)
        self.port.members.pop((GUILD, OLD_USER))
        result = await (await self.attempt(token)).json()
        self.assertEqual((result["status"], result["reason"]), ("problem", "left_server"))


class AccountAge(Base):
    async def test_page_says_when_the_account_will_be_old_enough(self):
        await self.change(account_age={"enabled": True, "action": "deny", "days": 3650 * 2 if False else 3650})
        young = str((int(time.time() * 1000) - engine.DISCORD_EPOCH_MS) << 22)
        self.port.add_member(young)
        result = await self.verify_through(young)
        self.assertEqual(result["reason"], "account_age")
        self.assertGreater(result["retry_on"], time.time() + 3000 * 86400)
        self.assertEqual(result["args"], {"days": 3650})
        self.assertIn("{days}", result["template"])


class HelpFromThePage(Base):
    async def enable(self, redirect=True):
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, support_role="970000000000000002", redirect=redirect, require_attempt=True)
        await self.service.save_settings(GUILD, document)

    async def test_result_offers_staff_help_only_when_chosen(self):
        await self.enable(redirect=False)
        await self.change(vpn={"enabled": True, "action": "deny"})
        self.assertFalse((await self.verify_through(ip="45.33.32.7"))["staff_help"])
        await self.enable(redirect=True)
        self.assertTrue((await self.verify_through(ip="45.33.32.7"))["staff_help"])

    async def test_button_opens_a_thread_and_links_to_it(self):
        await self.enable()
        await self.change(vpn={"enabled": True, "action": "deny"})
        token = await self.link_for()
        await self.sign_in(token)
        await self.attempt(token, ip="45.33.32.7")
        response = await self.client.post(f"/api/verify/{token}/help", headers=self.cookie_header("__Host-aw_browser"))
        self.assertEqual(response.status, 200, await response.text())
        self.assertIn(f"/channels/{GUILD}/", (await response.json())["url"])

    async def test_second_press_finds_the_same_thread(self):
        await self.enable()
        await self.change(vpn={"enabled": True, "action": "deny"})
        await self.verify_through(ip="45.33.32.7")
        member = self.port.members[(GUILD, OLD_USER)]
        first, _ = await self.service.open_help(member)
        second, _ = await self.service.open_help(member)
        self.assertEqual(first, second)
        self.assertEqual(len(self.port.did("open_help_thread")), 1)

    async def test_attempt_required_first(self):
        await self.enable()
        thread, message = await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        self.assertIsNone(thread)
        self.assertIn("first", message)

    async def test_auto_close_on_verify(self):
        document = await self.service.get_settings(GUILD)
        document["core"]["help_desk"].update(enabled=True, support_role="970000000000000002", auto_close=True, require_attempt=False)
        await self.service.save_settings(GUILD, document)
        await self.service.open_help(self.port.members[(GUILD, OLD_USER)])
        await self.verify_through()
        self.assertTrue(self.port.did("close_thread"))


class HoneypotDetails(Base):
    async def turn_on(self):
        document = await self.service.get_settings(GUILD)
        document["honeypot"].update(enabled=True, channel=LOG_CHANNEL, action="kick")
        await self.service.save_settings(GUILD, document)

    async def test_flood_gets_one_action_but_every_post_goes(self):
        await self.turn_on()
        for index in range(5):
            await self.service.honeypot_hit(GUILD, OLD_USER, "x", LOG_CHANNEL, str(index), role_ids=())
        self.assertEqual(len(self.port.did("kick")), 1)
        self.assertEqual(len(self.port.did("delete_message")), 5)

    async def test_threads_under_the_trap_count(self):
        await self.turn_on()
        await self.service.honeypot_hit(GUILD, OLD_USER, "x", "970000000000000050", "9", role_ids=(), parent_id=LOG_CHANNEL)
        self.assertEqual(self.port.did("delete_message")[0][1], "970000000000000050")
        self.assertTrue(self.port.did("kick"))

    async def test_other_channels_are_ignored(self):
        await self.turn_on()
        await self.service.honeypot_hit(GUILD, OLD_USER, "x", CHANNEL, "9", role_ids=())
        self.assertFalse(self.port.did("delete_message"))


class Profile(Base):
    async def test_avatar_color_is_validated(self):
        document = settings.defaults()
        document["appearance"]["avatar"] = "blue"
        self.assertEqual(settings.normalize(document)["appearance"]["avatar"], "blue")
        document["appearance"]["avatar"] = "../../etc/passwd"
        self.assertEqual(settings.normalize(document)["appearance"]["avatar"], "")

    async def test_every_color_has_a_picture(self):
        from altwarden.web.app import STATIC
        for color in settings.AVATAR_COLORS:
            self.assertTrue((STATIC / "img" / "avatars" / f"{color}.png").exists(), color)


class Pages(Base):
    async def test_public_pages_are_real_documents(self):
        for path in ("/", "/privacy", "/terms", "/security", "/docs", "/help", "/help/vpn", "/my-data", f"/appeal/{GUILD}", "/dashboard"):
            response = await self.client.get(path)
            text = await response.text()
            self.assertEqual(response.status, 200, path)
            self.assertIn("AltWarden", text, path)

    async def test_a_deploy_reaches_browsers_at_once(self):
        response = await self.client.get("/static/dash/settings.js")
        self.assertEqual(response.headers["Cache-Control"], "no-cache")
        again = await self.client.get("/static/dash/settings.js", headers={"If-None-Match": response.headers["ETag"]})
        self.assertEqual(again.status, 304, "an unchanged file isn't sent twice")

    async def test_versioned_libraries_can_stay_cached(self):
        response = await self.client.get("/static/vendor/botd-2.0.0.esm.js")
        self.assertIn("immutable", response.headers["Cache-Control"])

    async def test_nothing_offers_to_add_the_bot(self):
        response = await self.client.get("/invite", allow_redirects=False)
        self.assertEqual(response.status, 404)
        for path in ("/", "/docs", "/security"):
            text = await (await self.client.get(path)).text()
            self.assertNotIn('href="/invite"', text, path)
            self.assertNotIn("Add to Discord", text, path)

    async def test_the_add_link_asks_for_administrator_and_what_works_without_it(self):
        import discord
        from altwarden import health
        permissions = discord.Permissions(int(health.invite_url("1").split("permissions=")[1]))
        names = {name for name, on in permissions if on}
        self.assertEqual(names, {"administrator", "manage_roles", "manage_channels", "kick_members", "ban_members", "create_instant_invite",
                                 "change_nickname", "read_messages", "moderate_members", "send_messages", "send_messages_in_threads",
                                 "create_private_threads", "manage_messages", "manage_threads", "embed_links", "read_message_history",
                                 "mention_everyone", "external_emojis", "pin_messages"})

    async def test_every_failure_links_to_a_help_page_that_exists(self):
        from altwarden.catalog import HELP_SLUG
        from altwarden.web.app import STATIC
        source = (STATIC / "js" / "help.js").read_text(encoding="utf-8")
        for slug in set(HELP_SLUG.values()) | {"link-expired", "security-check", "connection-check", "role-problem", "left-server", "not-set-up", "verification"}:
            self.assertTrue(f'"{slug}":' in source or f"{slug}:" in source, slug)


if __name__ == "__main__":
    unittest.main()
