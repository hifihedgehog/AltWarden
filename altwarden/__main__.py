"""Starts the bot and the website in one process.

    python -m altwarden --public-url https://altwarden.example.com --port 8892

.env holds secrets only. Everything else comes from these flags, or from Discord and the dashboard.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path

import aiohttp
import discord
from aiohttp import web
from dotenv import load_dotenv

from . import __version__
from .crypto import Keyring, decode_master_key
from .db import Database
from .netintel import NetIntel, external_lookup
from .service import Service
from .web.api import PublicResolver, send_webhooks
from .web.app import STATIC, build_app
from .web.oauth import DiscordOAuth

log = logging.getLogger("altwarden")

SHUTDOWN_SECONDS = 10
# What the service unit's RestartPreventExitStatus names. A restart can't fix either cause, and each try spends an IDENTIFY call.
EXIT_NO_RESTART = 78


def load_regions() -> dict:
    rows = json.loads((STATIC / "countries.json").read_text(encoding="utf-8"))
    return {row["code"]: row for row in rows}


def load_zone_countries() -> dict:
    """Which countries each time zone belongs to, from the system's tz database if it has one."""
    table: dict[str, set] = {}
    for path in (Path("/usr/share/zoneinfo/zone.tab"), Path("/usr/share/zoneinfo/zone1970.tab")):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 3:
                table.setdefault(parts[2], set()).update(parts[0].split(","))
    return table


async def run(args: argparse.Namespace) -> None:
    from .bot.client import AltWardenBot
    from .health import invite_url

    data_dir = Path(args.data).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    keys = Keyring(decode_master_key(os.environ["MASTER_KEY"]))
    db = Database(data_dir / "altwarden.db")
    await db.open()
    # Whatever fails below, the database has to close. Its worker thread keeps the process alive
    # otherwise, and a process that won't die is one systemd never restarts.
    bot = http = webhook_http = runner = refresh = stop_waiter = service = None
    try:
        net = NetIntel(data_dir / "lists")
        await net.load()

        bot = AltWardenBot()
        service = Service(db, keys, net, bot.gateway, args.public_url, load_regions(), load_zone_countries())
        bot.service = service
        await service.seal_stored_secrets()

        http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
        token = os.environ["DISCORD_TOKEN"]
        await bot.login(token)
        application = await bot.application_info()
        log.info("Link to add this bot to a server: %s", invite_url(str(application.id)))
        if application.bot_public:
            log.warning("Public Bot is on in the Discord Developer Portal, so anyone can add this bot to their server.")
        oauth = DiscordOAuth(http, str(application.id), os.environ["DISCORD_CLIENT_SECRET"])
        app = build_app(service, keys, oauth, trust_proxy=True)
        app["http"] = http
        app["public_bot"] = application.bot_public
        app["application_info"] = bot.application_info  # for a fresh read of Public Bot, which can change while this runs
        webhook_http = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=PublicResolver()))
        app["webhook_http"] = webhook_http
        app["post_message"] = bot.post_message
        app["import_role"] = lambda guild_id, role_id, actor_id, actor_name: bot.import_role_members(bot.get_guild(int(guild_id)), role_id, actor_id, actor_name)
        service.webhook_sender = lambda guild_id, event, payload: send_webhooks(app, guild_id, event, payload)
        service.proxycheck = lambda ip, key: external_lookup(http, ip, key)

        runner = web.AppRunner(app, access_log=None)  # request logs would hold members' addresses
        await runner.setup()
        await web.TCPSite(runner, args.host, args.port).start()
        log.info("AltWarden %s serving %s on %s:%s", __version__, args.public_url, args.host, args.port)
        refresh = asyncio.ensure_future(net.refresh()) if net.stale() else None  # held here, because asyncio keeps only a weak reference
        connection = asyncio.ensure_future(bot.connect(reconnect=True))
        stopping = asyncio.Event()
        for name in (signal.SIGTERM, signal.SIGINT):
            try:
                asyncio.get_running_loop().add_signal_handler(name, stopping.set)
            except NotImplementedError:  # Windows has no signal handlers on the event loop
                pass
        stop_waiter = asyncio.ensure_future(stopping.wait())
        await asyncio.wait({connection, stop_waiter}, return_when=asyncio.FIRST_COMPLETED)
        if connection.done():
            connection.result()  # a failed login or gateway error should end the process, so systemd restarts it
        log.info("Shutting down")
    finally:
        # In the order things depend on each other. Handlers still running use the database and can send webhooks,
        # so the bot goes before the sessions, and the database goes last.
        try:
            for task in (stop_waiter, refresh):
                if task is not None:
                    task.cancel()
            if runner is not None:
                await runner.cleanup()
            if bot is not None:
                await bot.close()
            if service is not None and service._background:
                await asyncio.wait(service._background, timeout=SHUTDOWN_SECONDS)
            for session in (http, webhook_http):
                if session is not None:
                    await session.close()
        finally:
            await db.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="altwarden")
    parser.add_argument("--public-url", required=True, help="This site's address, with https and no trailing slash")
    parser.add_argument("--host", default="127.0.0.1", help="Address to listen on. Keep this local and put a proxy in front.")
    parser.add_argument("--port", type=int, default=8892)
    parser.add_argument("--data", default="data", help="Folder for the database and network lists")
    args = parser.parse_args()
    load_dotenv()
    missing = [name for name in ("DISCORD_TOKEN", "DISCORD_CLIENT_SECRET", "MASTER_KEY") if not os.environ.get(name)]
    if missing:
        sys.exit(f"Missing from .env: {', '.join(missing)}")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("discord").setLevel(logging.WARNING)
    try:
        asyncio.run(run(args))
    except discord.LoginFailure:
        log.critical("Discord refused the bot token. Put the right one in DISCORD_TOKEN, then start the service again.")
        sys.exit(EXIT_NO_RESTART)
    except discord.PrivilegedIntentsRequired:
        log.critical("Discord refused the Server Members intent. Turn it on in the Developer Portal, then start the service again.")
        sys.exit(EXIT_NO_RESTART)


if __name__ == "__main__":
    main()
