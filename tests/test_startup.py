"""The real startup path with a stand-in for Discord's gateway: order, serving, and a clean end."""
import argparse
import asyncio
import os
import signal
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aiohttp

from altwarden import __main__ as entry
from altwarden.crypto import new_master_key
from altwarden.netintel import NetIntel
from fakes import FakePort

PORT = 8896


class StubBot:
    """Records what startup does to it. connect() blocks until a test decides how the gateway ends."""

    made = None

    def __init__(self):
        StubBot.made = self
        self.gateway = FakePort()
        self.service = None
        self.calls = []
        self.finish = asyncio.Event()
        self.failure = None

    async def login(self, token):
        self.calls.append("login")
        self.token = token

    async def application_info(self):
        self.calls.append("application_info")
        return SimpleNamespace(id=123)

    async def connect(self, reconnect=True):
        self.calls.append("connect")
        await self.finish.wait()
        if self.failure:
            raise self.failure

    async def close(self):
        self.calls.append("close")

    async def post_message(self, guild_id, which):
        return True


class Startup(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.args = argparse.Namespace(public_url="https://altwarden.test", host="127.0.0.1", port=PORT, data=self.folder.name)
        self.env = patch.dict(os.environ, {"DISCORD_TOKEN": "token", "DISCORD_CLIENT_SECRET": "secret", "MASTER_KEY": new_master_key()})
        self.env.start()
        self.bot = patch("altwarden.bot.client.AltWardenBot", StubBot)
        self.bot.start()
        self.refresh = patch.object(NetIntel, "refresh", AsyncMock(return_value=0))
        self.refresh.start()

    async def asyncTearDown(self):
        self.refresh.stop()
        self.bot.stop()
        self.env.stop()
        await asyncio.sleep(0.05)
        self.folder.cleanup()

    async def wait_until_serving(self):
        async with aiohttp.ClientSession() as session:
            for _ in range(100):
                try:
                    async with session.get(f"http://127.0.0.1:{PORT}/healthz") as response:
                        return await response.json()
                except aiohttp.ClientError:
                    await asyncio.sleep(0.05)
        self.fail("The site never came up")

    async def test_the_site_serves_while_the_gateway_connects(self):
        task = asyncio.ensure_future(entry.run(self.args))
        health = await self.wait_until_serving()
        self.assertTrue(health["ok"])
        bot = StubBot.made
        self.assertEqual(bot.calls, ["login", "application_info", "connect"], "the application ID is needed before serving sign-ins")
        self.assertIsNotNone(bot.service)
        bot.finish.set()
        await asyncio.wait_for(task, 10)
        self.assertEqual(bot.calls[-1], "close")

    async def test_a_gateway_failure_ends_the_process_after_cleaning_up(self):
        task = asyncio.ensure_future(entry.run(self.args))
        await self.wait_until_serving()
        bot = StubBot.made
        bot.failure = RuntimeError("gateway said no")
        bot.finish.set()
        with self.assertRaisesRegex(RuntimeError, "gateway said no"):
            await asyncio.wait_for(task, 10)
        self.assertEqual(bot.calls[-1], "close", "systemd restarts the process, so it must exit, not hang")
        async with aiohttp.ClientSession() as session:
            with self.assertRaises(aiohttp.ClientError):
                await session.get(f"http://127.0.0.1:{PORT}/healthz")

    async def test_stale_lists_refresh_without_holding_up_startup(self):
        task = asyncio.ensure_future(entry.run(self.args))
        await self.wait_until_serving()
        self.assertTrue(NetIntel.refresh.called, "an empty list folder counts as stale")
        StubBot.made.finish.set()
        await asyncio.wait_for(task, 10)

    @unittest.skipIf(sys.platform == "win32", "Windows has no signal handlers on the event loop")
    async def test_systemd_stop_closes_cleanly(self):
        task = asyncio.ensure_future(entry.run(self.args))
        await self.wait_until_serving()
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(task, 10)
        self.assertEqual(StubBot.made.calls[-1], "close")


if __name__ == "__main__":
    unittest.main()
