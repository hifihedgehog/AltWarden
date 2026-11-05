"""What only holds once the web, bot and service layers run together."""
import os
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden.ports import MemberInfo
from altwarden.web.api import UNREADABLE_WEBHOOK
from fakes import GUILD, OLD_USER, STAFF
import test_member_states
import test_web_guards

STATIC = Path(__file__).resolve().parent.parent / "altwarden" / "web" / "static"
TWIN_LOW = "970000000000000090"
TWIN_HIGH = "970000000000000091"


class HealthRoute(test_web_guards.Base):
    async def test_the_page_gets_the_notices_lists_and_refusals_the_report_builds(self):
        await self.log_in()
        status, data = await self.get("/health")
        self.assertEqual(status, 200)
        self.assertIsInstance(data["notices"], list)
        self.assertIsInstance(data["lists"], list)
        self.assertIn("lookup_refused", data)
        self.assertIn("checked_at", data)


class UnreadableWebhook(test_web_guards.Base):
    async def test_a_row_that_cant_be_opened_can_be_seen_and_removed(self):
        await self.log_in()
        await self.db.run("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, 'v1.garbage', 'v1.garbage', '[]', 1)", (GUILD,))
        status, data = await self.get("/integrations")
        self.assertEqual(status, 200)
        self.assertEqual([hook["url"] for hook in data["webhooks"]], [UNREADABLE_WEBHOOK])
        status, _ = await self.send("DELETE", f"/webhooks/{data['webhooks'][0]['id']}")
        self.assertEqual(status, 200)
        self.assertEqual((await self.get("/integrations"))[1]["webhooks"], [])

    async def test_sending_still_skips_a_row_that_cant_be_opened(self):
        await self.db.run("INSERT INTO webhooks (guild_id, url, secret, events, created_at) VALUES (?, 'v1.garbage', 'v1.garbage', '[]', 1)", (GUILD,))
        self.assertEqual(await self.service.webhooks(GUILD), [])


class HoneypotAppeal(test_member_states.Base):
    trap = test_member_states.Honeypot.trap
    hit = test_member_states.Honeypot.hit

    async def appeal(self):
        await self.service.submit_appeal(GUILD, OLD_USER, "x", "this wasn't me at all")
        row = await self.db.one("SELECT id FROM appeals WHERE guild_id = ? AND user_id = ?", (GUILD, OLD_USER))
        return row["id"]

    async def test_approving_lifts_the_timeout_the_post_earned(self):
        await self.trap("timeout")
        await self.hit()
        appeal = await self.appeal()
        self.port.calls.clear()
        await self.service.settle_appeal(GUILD, appeal, "approve", STAFF, "staff")
        self.assertIn(("clear_timeout", OLD_USER), self.port.calls)

    async def test_turning_it_down_leaves_the_timeout(self):
        await self.trap("timeout")
        await self.hit()
        appeal = await self.appeal()
        self.port.calls.clear()
        await self.service.settle_appeal(GUILD, appeal, "deny", STAFF, "staff")
        self.assertNotIn(("clear_timeout", OLD_USER), self.port.calls)

    async def test_approving_another_kind_of_appeal_touches_no_timeout(self):
        await self.db.add_attempt(GUILD, OLD_USER, "failed", check_id="vpn", action="deny")
        appeal = await self.appeal()
        self.port.calls.clear()
        await self.service.settle_appeal(GUILD, appeal, "approve", STAFF, "staff")
        self.assertNotIn(("clear_timeout", OLD_USER), self.port.calls)


class EqualRolePositions(test_web_guards.Base):
    """Discord sorts roles at one position by ID, and the higher ID sits lower."""

    async def staff(self, role):
        return MemberInfo(GUILD, STAFF, "staff", None, False, (role,), frozenset({"manage_roles"}), False)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        real = await self.port.guild(GUILD)
        twins = [{"id": TWIN_LOW, "name": "Twin one", "color": 0, "position": 3, "managed": False, "mentionable": False},
                 {"id": TWIN_HIGH, "name": "Twin two", "color": 0, "position": 3, "managed": False, "mentionable": False}]

        async def guild(_guild_id):
            return replace(real, roles=[*real.roles, *twins])
        self.port.guild = guild

    async def test_the_lower_id_outranks_the_higher_one(self):
        self.port.add_member(OLD_USER, roles=(TWIN_HIGH,))
        self.assertIsNone(await self.service.staff_refusal(GUILD, await self.staff(TWIN_LOW), OLD_USER, "reset"))

    async def test_the_higher_id_doesnt_outrank_the_lower_one(self):
        self.port.add_member(OLD_USER, roles=(TWIN_LOW,))
        self.assertIn("at or above", await self.service.staff_refusal(GUILD, await self.staff(TWIN_HIGH), OLD_USER, "reset"))


class WrongAccountButton(unittest.TestCase):
    def test_after_the_wrong_account_the_next_sign_in_asks_discord_again(self):
        text = (STATIC / "js" / "verify.js").read_text(encoding="utf-8")
        self.assertIn('${problem === "wrong" ? "?switch=1" : ""}', text)


if __name__ == "__main__":
    unittest.main()
