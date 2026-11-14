"""A member's earlier links keep working when they ask for a new one, up to a cap."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from altwarden import crypto
from altwarden.service import LINKS_KEPT
from fakes import GUILD, OLD_USER, OTHER_USER, STAFF, VERIFIED_ROLE
from test_flow import Base as FlowBase


class LinksKept(FlowBase):
    async def step(self, token):
        return (await (await self.client.get(f"/api/verify/{token}")).json())["step"]

    async def test_the_dm_link_still_opens_after_a_press_in_the_channel(self):
        member = self.port.add_member(OTHER_USER)
        await self.service.on_join(member)
        dm_token = self.port.dms[-1][1].buttons[0].url.rsplit("/", 1)[1]
        pressed = await self.service.press_verify(member)
        self.assertIsInstance(pressed, str)
        self.assertEqual(await self.step(dm_token), "signin")
        self.assertEqual(await self.step(pressed.rsplit("/", 1)[1]), "signin")

    async def test_past_the_cap_the_oldest_link_goes(self):
        tokens = [await self.link_for() for _ in range(LINKS_KEPT + 1)]
        self.assertEqual(await self.step(tokens[0]), "expired")
        for token in tokens[1:]:
            self.assertEqual(await self.step(token), "signin")
        self.assertEqual(await self.db.scalar("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (OLD_USER,)), LINKS_KEPT)

    async def test_an_ended_link_is_cleared_when_a_new_one_is_made(self):
        first = await self.link_for()
        await self.db.run("UPDATE sessions SET expires_at = ? WHERE token_hash = ?", (time.time() - 1, crypto.token_hash(first)))
        await self.link_for()
        self.assertIsNone(await self.db.one("SELECT 1 FROM sessions WHERE token_hash = ?", (crypto.token_hash(first),)))

    async def test_an_older_link_of_a_verified_member_says_so(self):
        older = await self.link_for()
        result = await self.verify_through()
        self.assertEqual(result["status"], "verified")
        self.assertIn(VERIFIED_ROLE, self.port.members[(GUILD, OLD_USER)].role_ids)
        self.assertEqual(await self.step(older), "done")

    async def test_a_reset_still_ends_every_earlier_link(self):
        first = await self.link_for()
        await self.service.reset_member(GUILD, OLD_USER, STAFF)
        self.assertEqual(await self.step(first), "expired")


if __name__ == "__main__":
    unittest.main()
