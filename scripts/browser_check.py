"""Run the real pages in a real browser against a fake Discord, and report what happened.

    python scripts/browser_check.py [--shots folder]

Starts the site on 127.0.0.1 with demo data, drives headless Edge or Chrome over the DevTools
protocol, and prints console errors, security policy violations and the verification result.
"""
import argparse
import asyncio
import base64
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import aiohttp
from aiohttp import web

from altwarden import crypto, db, settings
from altwarden.netintel import NetIntel, load_lists
from altwarden.service import Service
from altwarden.web.app import SESSION_COOKIE, build_app
from altwarden.web.oauth import DiscordOAuth
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, STAFF, VERIFIED_ROLE, FakePort

PORT = 8899
PUBLIC = f"http://127.0.0.1:{PORT}"
BROWSERS = (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe")


async def seed(service: Service, port: FakePort) -> None:
    doc = settings.defaults()
    doc["core"].update(verified_role=VERIFIED_ROLE, channel=CHANNEL)
    doc["core"]["logs"] = {"enabled": True, "modules": {"general": LOG_CHANNEL, "success": LOG_CHANNEL}}
    doc["checks"]["automation"].update(enabled=True, action="deny")
    await service.db.save_settings(GUILD, settings.normalize(doc), setup_done=True)
    port.add_member(OLD_USER, username="member_one")
    port.add_member(STAFF, username="staff_one", perms=("manage_guild", "manage_roles"), owner=True)
    rng = random.Random(4)
    now = time.time()
    checks = ["vpn", "alt_account", "automation", "account_age", "incognito"]
    for index in range(400):
        user = str(175928847299200000 + index % 60)
        at = now - rng.random() * 25 * 86400
        await service.db.touch_member(GUILD, user, username=f"user{index % 60}")
        failed = rng.random() < 0.25
        row = await service.db.add_attempt(GUILD, user, "failed" if failed else "passed", check_id=rng.choice(checks) if failed else None,
                                           action="deny" if failed else None, mode="web", seconds=rng.uniform(4, 300))
        await service.db.run("UPDATE attempts SET at = ? WHERE id = ?", (at, row))
        await service.db.update_member(GUILD, user, status="pending" if failed else "verified", verified_at=None if failed else at)
    await service.db.add_audit(GUILD, "settings", actor_id=STAFF, actor_name="staff_one",
                               detail={"changes": [{"path": "checks.vpn.action", "before": "watch", "after": "deny"}]})
    await service.db.insert("INSERT INTO appeals (guild_id, user_id, check_id, text, created_at) VALUES (?, ?, ?, ?, ?)",
                            (GUILD, "175928847299200001", "alt_account", "My brother and I share a laptop at home, so please check again.", now))


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Cdp:
    def __init__(self, ws):
        self.ws, self.next_id, self.pending, self.events = ws, 0, {}, []

    async def pump(self):
        async for message in self.ws:
            data = json.loads(message.data)
            if "id" in data:
                future = self.pending.pop(data["id"], None)
                if future is not None and not future.done():  # a call that timed out may still get its answer
                    future.set_result(data)
            else:
                self.events.append(data)

    async def call(self, method, **params):
        self.next_id += 1
        future = asyncio.get_running_loop().create_future()
        self.pending[self.next_id] = future
        await self.ws.send_json({"id": self.next_id, "method": method, "params": params})
        return (await asyncio.wait_for(future, 30)).get("result", {})

    async def evaluate(self, expression):
        result = await self.call("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
        return result.get("result", {}).get("value")

    async def open(self, url, wait=1.5):
        await self.call("Page.navigate", url=url)
        await asyncio.sleep(wait)

    async def until(self, expression, seconds=10):
        """Wait for a condition in the page, because a fixed sleep turns a slow load into a false failure."""
        for _ in range(int(seconds * 10)):
            value = await self.evaluate(expression)
            if value:
                return value
            await asyncio.sleep(0.1)
        return None

    async def shot(self, path):
        """A screenshot is for a person to look at. Headless Edge can stall on one under load, and that mustn't end the run."""
        await self.until("document.readyState === 'complete'")
        await asyncio.sleep(0.8)
        try:
            data = await asyncio.wait_for(self.call("Page.captureScreenshot", format="png", captureBeyondViewport=False), 12)
        except TimeoutError:
            print("screenshot stalled:", Path(path).name, await self.evaluate("document.visibilityState"))
            return
        Path(path).write_bytes(base64.b64decode(data["data"]))

    def problems(self):
        found = []
        for event in self.events:
            method, params = event["method"], event.get("params", {})
            if method == "Log.entryAdded" and params["entry"]["level"] in ("error", "warning"):
                if "runtime.lastError" in params["entry"].get("text", ""):
                    continue  # Edge's own built-in extensions report this into every page's log
                found.append(f"log: {params['entry'].get('text', '')[:200]} {params['entry'].get('url', '')[:90]}")
            elif method == "Runtime.exceptionThrown":
                details = params["exceptionDetails"]
                description = details.get("exception", {}).get("description", details.get("text", ""))
                if "chrome-extension://" in description or "chrome-extension://" in details.get("url", "") or "message channel closed" in description:
                    continue  # the same built-in extensions
                found.append(f"exception: {description[:260]}")
            elif method == "Runtime.consoleAPICalled" and params["type"] == "error":
                found.append("console.error: " + " ".join(str(arg.get("value", arg.get("description", ""))) for arg in params["args"])[:220])
        self.events.clear()
        return found


async def click_text(cdp, selector, text):
    """Click the first element matching a selector whose text contains the given words."""
    return await cdp.evaluate(f"""(() => {{
        const node = [...document.querySelectorAll({json.dumps(selector)})].find((item) => item.textContent.includes({json.dumps(text)}));
        if (!node) return false;
        node.click();
        return true;
    }})()""")


async def walk_dashboard(cdp, service, shots) -> None:
    """Prove the behavior a screenshot can't: drafts surviving page changes, search, and the save bar."""
    results = {}
    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/settings", wait=0.3)
    await cdp.until("document.getElementById('item-cooldown')")
    toggled = await cdp.evaluate("""(() => {
        const row = document.getElementById('item-cooldown');
        row.querySelector('input[type=checkbox]').click();
        return row.querySelector('input[type=checkbox]').checked;
    })()""")
    results["cooldown toggled on"] = toggled
    results["save bar shown"] = await cdp.evaluate("Boolean(document.querySelector('.savebar'))")
    results["amber dot on Rules"] = await cdp.evaluate("document.querySelector('.nav a[data-page=settings]').classList.contains('unsaved')")
    await click_text(cdp, ".nav a", "Messages")
    await cdp.until("location.pathname.endsWith('/appearance') && [...document.querySelectorAll('.field')].some((node) => node.textContent.startsWith('Title'))")
    results["moved without a prompt"] = await cdp.evaluate("location.pathname.endsWith('/appearance')")
    results["save bar still shown"] = await cdp.evaluate("Boolean(document.querySelector('.savebar'))")
    await cdp.evaluate("""(() => {
        const box = [...document.querySelectorAll('.field')].find((node) => node.textContent.startsWith('Title')).querySelector('input');
        box.value = 'Changed title';
        box.dispatchEvent(new Event('input'));
    })()""")
    await click_text(cdp, ".nav a", "Rules")
    await cdp.until("document.getElementById('item-cooldown')")
    results["Rules change survived"] = await cdp.evaluate("document.getElementById('item-cooldown').querySelector('input[type=checkbox]').checked")
    await click_text(cdp, ".savebar button", "Save changes")
    await cdp.until("!document.querySelector('.savebar')", 25)
    saved = await service.get_settings(GUILD)
    results["cooldown saved"] = saved["core"]["cooldown"]["enabled"]
    results["message saved from another page"] = saved["messages"]["verification"]["title"] == "Changed title"
    results["message names its author"] = saved["messages"]["verification"]["author"] == STAFF
    results["save bar gone"] = await cdp.evaluate("!document.querySelector('.savebar')")

    results["group counters"] = await cdp.evaluate("[...document.querySelectorAll('.section > h2 .count')].map((node) => node.textContent).join(' ')")
    results["active preset tagged"] = await cdp.evaluate("document.querySelector('.preset.on .active-tag')?.textContent")
    results["required labels"] = await cdp.evaluate("document.querySelectorAll('#item-core .required').length")
    await cdp.evaluate("document.getElementById('item-autokick').querySelector('input[type=checkbox]').click()")
    await asyncio.sleep(0.3)
    await cdp.evaluate("""(() => {
        const row = document.getElementById('item-autokick');
        const unit = row.querySelector('.duration select');
        unit.value = 'hours';
        unit.dispatchEvent(new Event('change'));
        const box = row.querySelector('.duration input');
        box.value = '2';
        box.dispatchEvent(new Event('input'));
    })()""")
    await click_text(cdp, ".savebar button", "Save changes")
    await cdp.until("!document.querySelector('.savebar')", 25)
    results["2 hours saved as 120 minutes"] = (await service.get_settings(GUILD))["core"]["auto_kick"]["minutes"] == 120
    await cdp.evaluate("""(() => {
        const box = document.getElementById('item-autokick').querySelector('.duration input');
        box.value = '200';
        box.dispatchEvent(new Event('input'));
    })()""")
    await click_text(cdp, ".savebar button", "Save changes")
    await asyncio.sleep(0.8)
    results["a value out of range isn't saved"] = (await service.get_settings(GUILD))["core"]["auto_kick"]["minutes"] == 120
    results["the bad value is focused"] = await cdp.evaluate("document.activeElement === document.getElementById('item-autokick').querySelector('.duration input')")
    await cdp.shot(shots / "dash-settings-top.png")
    await click_text(cdp, ".savebar button", "Discard")
    await asyncio.sleep(0.3)
    await cdp.evaluate("""(() => {
        const box = document.querySelector('input[type=search]');
        box.value = 'honeypot';
        box.dispatchEvent(new Event('input'));
    })()""")
    await asyncio.sleep(0.2)
    results["search leaves honeypot"] = await cdp.evaluate("!document.getElementById('item-honeypot').hidden && document.getElementById('item-vpn').hidden")
    await cdp.evaluate("""(() => {
        const box = document.querySelector('input[type=search]');
        box.value = '';
        box.dispatchEvent(new Event('input'));
    })()""")
    await cdp.evaluate("document.querySelector('[role=radiogroup][aria-label=\'Verification mode\'] button.button')?.click()")
    await click_text(cdp, "[aria-label='Verification mode'] button", "Button")
    await asyncio.sleep(0.4)
    results["paused rules warned"] = await cdp.evaluate("document.querySelector('.notice.warn')?.textContent.includes(\"can't run in this mode\")")
    results["paused rule striped"] = await cdp.evaluate("document.getElementById('item-vpn').classList.contains('paused')")
    await cdp.shot(shots / "dash-paused.png")
    await click_text(cdp, ".savebar button", "Discard")
    await asyncio.sleep(0.3)
    results["discard restored mode"] = await cdp.evaluate("!document.getElementById('item-vpn').classList.contains('paused')")

    await cdp.evaluate("document.getElementById('item-logs').querySelector('.rule-body button')?.click()")
    await asyncio.sleep(0.3)
    results["logs dialog has categories"] = await cdp.evaluate("document.querySelectorAll('.dialog .log-group').length")
    await cdp.shot(shots / "dash-logs.png")
    await click_text(cdp, ".dialog-foot button", "Done")
    await asyncio.sleep(0.2)

    await cdp.evaluate("dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))")
    await asyncio.sleep(0.2)
    await cdp.evaluate("""(() => {
        const box = document.querySelector('.palette input');
        box.value = 'verify-user';
        box.dispatchEvent(new Event('input'));
    })()""")
    await asyncio.sleep(0.2)
    results["search finds a permission"] = await cdp.evaluate("document.querySelector('.palette li small')?.textContent")
    await cdp.evaluate("document.querySelector('.palette li button').click()")
    results["permission card highlighted"] = await cdp.until("document.getElementById('item-command-verify-user')?.classList.contains('flash')", 25)

    await click_text(cdp, ".side-foot button", "Look")
    await asyncio.sleep(0.2)
    await click_text(cdp, "[aria-label='Theme'] button", "Gray")
    results["gray theme"] = await cdp.evaluate("document.documentElement.getAttribute('data-theme')")
    await cdp.shot(shots / "dash-gray.png")
    await click_text(cdp, "[aria-label='Theme'] button", "Match system")
    await click_text(cdp, ".dialog-foot button", "Done")

    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/members", wait=0.3)
    results["member results line"] = await cdp.until("document.querySelector('tbody td .chips')?.textContent")
    await cdp.shot(shots / "dash-members.png")

    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/appearance", wait=0.3)
    await cdp.until("document.querySelector('select[aria-label=Font]')")
    for label, value in (("Font", "12"), ("Effect", "2")):
        await cdp.evaluate(f"""(() => {{
            const box = document.querySelector('select[aria-label={label}]');
            box.value = {json.dumps(value)};
            box.dispatchEvent(new Event('change'));
        }})()""")
        await asyncio.sleep(0.2)
    results["font in the preview"] = await cdp.evaluate("document.querySelector('.profile-card .name-style').classList.contains('font-12')")
    results["gradient shows two color boxes"] = await cdp.evaluate("document.querySelectorAll('input[aria-label^=\\'Color \\']').length") == 2
    await asyncio.sleep(0.4)
    results["preview font file loaded"] = await cdp.evaluate("document.fonts.check('16px aw-zillaslab')")
    await cdp.shot(shots / "dash-name-style.png")
    await click_text(cdp, ".savebar button", "Save changes")
    await cdp.until("!document.querySelector('.savebar')", 25)
    saved = await service.get_settings(GUILD)
    results["name style saved"] = (saved["appearance"]["font"], saved["appearance"]["effect"], len(saved["appearance"]["colors"])) == (12, 2, 2)
    sent = service.port.did("apply_profile")
    results["name style sent to Discord"] = bool(sent) and sent[-1][2]["display_name_font_id"] == 12

    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/permissions", wait=0.3)
    await cdp.until("document.getElementById('item-discord-Verify')")
    results["Discord's overrides shown"] = await cdp.evaluate("document.getElementById('item-discord-Verify')?.textContent.includes('Verified: blocked')")
    await cdp.evaluate("document.getElementById('item-discord-verify-user').querySelector('button').click()")
    await asyncio.sleep(0.2)
    await click_text(cdp, ".dialog button", "Add Everyone")
    await click_text(cdp, ".dialog-foot button", "Done")
    await asyncio.sleep(0.2)
    results["Everyone override listed"] = await cdp.evaluate("document.getElementById('item-discord-verify-user').textContent.includes('Everyone: allowed')")
    results["Save to Discord offered"] = await cdp.evaluate("[...document.querySelectorAll('button')].some((node) => node.textContent === 'Save to Discord')")
    await cdp.shot(shots / "dash-access-discord.png")
    await click_text(cdp, ".toolbar button", "Discard")
    await asyncio.sleep(0.2)
    results["Discord draft discarded"] = await cdp.evaluate("![...document.querySelectorAll('button')].some((node) => node.textContent === 'Save to Discord')")

    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/settings", wait=0.3)
    await cdp.until("document.getElementById('item-geogate')")
    await cdp.evaluate("document.getElementById('item-geogate').querySelector('input[type=checkbox]').click()")
    await cdp.until("[...document.querySelectorAll('#item-geogate button')].length")
    await click_text(cdp, "#item-geogate button", "Choose countries")
    await cdp.until("document.querySelector('[aria-label=View]')")
    await click_text(cdp, "[aria-label=View] button", "Globe")
    await cdp.until("document.querySelector('.map-wrap circle')")
    await asyncio.sleep(0.3)
    spot = await cdp.evaluate("""(() => {
        const paths = [...document.querySelectorAll('.map-wrap path')];
        for (const path of paths) {
            const box = path.getBoundingClientRect();
            if (box.width < 30 || box.height < 30) continue;
            const x = box.left + box.width / 2, y = box.top + box.height / 2;
            if (document.elementFromPoint(x, y) === path) return { x, y };
        }
        return null;
    })()""")
    results["globe has a country to click"] = bool(spot)
    if spot:
        before = await cdp.evaluate("document.querySelector('.dialog p.muted').textContent")
        for kind in ("mousePressed", "mouseReleased"):
            await cdp.call("Input.dispatchMouseEvent", type=kind, x=spot["x"], y=spot["y"], button="left", clickCount=1, pointerType="mouse")
        await asyncio.sleep(0.4)
        after = await cdp.evaluate("document.querySelector('.dialog p.muted').textContent")
        results["clicking the globe picks a country"] = before != after and after.startswith("1 ")
        first = await cdp.evaluate("document.querySelector('.map-wrap path').getAttribute('d')")
        await cdp.call("Input.dispatchMouseEvent", type="mousePressed", x=spot["x"], y=spot["y"], button="left", clickCount=1, pointerType="mouse")
        for step in range(1, 6):
            await cdp.call("Input.dispatchMouseEvent", type="mouseMoved", x=spot["x"] + step * 12, y=spot["y"], button="left", buttons=1, pointerType="mouse")
            await asyncio.sleep(0.05)
        moved = await cdp.evaluate("document.querySelector('.map-wrap path').getAttribute('d')")
        await cdp.call("Input.dispatchMouseEvent", type="mouseReleased", x=spot["x"] + 60, y=spot["y"], button="left", clickCount=1, pointerType="mouse")
        await asyncio.sleep(0.2)
        results["the globe turns during a drag"] = first != moved
        results["a drag picks nothing"] = await cdp.evaluate("document.querySelector('.dialog p.muted').textContent") == after
    await cdp.shot(shots / "dash-globe.png")
    await click_text(cdp, ".dialog-foot button", "Cancel")
    await click_text(cdp, ".savebar button", "Discard")
    await asyncio.sleep(0.3)

    await cdp.call("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=2, mobile=True)
    overflowing = {}
    for path in ("analytics", "settings", "members", "appeals", "health", "appearance", "permissions", "audit", "integrations"):
        await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/{path}", wait=0.3)
        await cdp.until("document.querySelector('.view')?.children.length")
        await asyncio.sleep(0.5)
        width = await cdp.evaluate("document.documentElement.scrollWidth")
        if width > 391:
            overflowing[path] = [width, await cdp.evaluate("""[...document.querySelectorAll('.view *')].filter((node) => node.getBoundingClientRect().right > innerWidth + 1).slice(0, 6).map((node) => `${node.tagName}.${node.className.baseVal ?? node.className}`)""")]
        if path in ("settings", "appearance", "analytics", "permissions"):
            await cdp.shot(shots / f"phone-{path}.png")
    for path in ("", "docs", "privacy", "security", "help/vpn", "help", "my-data", f"appeal/{GUILD}"):
        await cdp.open(f"{PUBLIC}/{path}", wait=0.6)
        width = await cdp.evaluate("document.documentElement.scrollWidth")
        if width > 391:
            overflowing[path or "home"] = width
    results["nothing overflows at phone width"] = not overflowing
    if overflowing:
        print("overflowing:", overflowing)
    await cdp.call("Emulation.clearDeviceMetricsOverride")
    failed = [name for name, value in results.items() if value in (False, None, 0)]
    print("walk:", json.dumps(results, indent=1))
    print("walk failures:", failed or "none", cdp.problems())


async def main(shots: Path) -> None:
    shots.mkdir(parents=True, exist_ok=True)
    work = tempfile.mkdtemp(prefix="altwarden-check-")
    database = db.Database(os.path.join(work, "t.db"))
    await database.open()
    keys = crypto.Keyring(b"k" * 32)
    net = NetIntel(ROOT / "data" / "lists")
    net.lists = await asyncio.to_thread(load_lists, ROOT / "data" / "lists")
    port = FakePort()
    service = Service(database, keys, net, port, PUBLIC)
    await seed(service, port)
    http = aiohttp.ClientSession()
    app = build_app(service, keys, DiscordOAuth(http, "123", "x"), trust_proxy=False)
    app["http"] = http

    async def post_message(guild_id, which):
        return None
    app["post_message"] = post_message

    token = crypto.new_token()
    now = time.time()
    await database.run(
        "INSERT INTO web_sessions (token_hash, user_id, username, avatar, guilds, csrf, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (crypto.token_hash(token), STAFF, "staff_one", None,
         json.dumps([{"id": GUILD, "name": "Test Server", "icon": None, "owner": True, "permissions": "32"}]), "csrf-token", "dashboard", now, now + 3600))

    async def dev_login(request):
        response = web.HTTPFound("/dashboard")
        response.set_cookie(SESSION_COOKIE, token, path="/", secure=True, httponly=True, samesite="Lax")
        return response
    app.router.add_get("/__dev/login", dev_login)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()

    browser = next(path for path in BROWSERS if os.path.exists(path))
    profile = tempfile.mkdtemp(prefix="altwarden-browser-")
    debug_port = free_port()  # a browser left over from a killed run must not answer for this one
    process = subprocess.Popen([browser, "--headless=new", f"--remote-debugging-port={debug_port}", f"--user-data-dir={profile}", "--window-size=1280,900",
                                "--no-first-run", "--disable-gpu", "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows",
                                "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        targets = []
        for _ in range(60):
            try:
                async with http.get(f"http://127.0.0.1:{debug_port}/json") as response:
                    targets = await response.json()
                    if targets:
                        break
            except aiohttp.ClientError:
                await asyncio.sleep(0.25)
        target = next(item for item in targets if item["type"] == "page")
        async with http.ws_connect(target["webSocketDebuggerUrl"], max_msg_size=0) as ws:
            cdp = Cdp(ws)
            pump = asyncio.ensure_future(cdp.pump())
            for domain in ("Page", "Runtime", "Log", "Network"):
                await cdp.call(f"{domain}.enable")
            # A tab in the background stops drawing, which stalls screenshots and animation frames.
            await cdp.call("Page.bringToFront")
            await cdp.call("Emulation.setFocusEmulationEnabled", enabled=True)

            await cdp.open(f"{PUBLIC}/")
            await cdp.shot(shots / "landing.png")
            print("landing:", await cdp.evaluate("document.title"), cdp.problems())

            doc = await service.get_settings(GUILD)
            url, _ = await service.new_link(GUILD, OLD_USER, doc)
            link = url.rsplit("/", 1)[1]
            await cdp.open(url)
            await cdp.shot(shots / "verify-signin.png")
            print("signin text:", (await cdp.evaluate("document.getElementById('card').innerText"))[:120].replace("\n", " | "), cdp.problems())

            await service.attach_account(link, {"id": OLD_USER, "username": "member_one", "avatar": "abc", "mfa": True})
            await cdp.open(url, wait=0.6)
            await cdp.shot(shots / "verify-checking.png")
            text = ""
            for _ in range(40):
                await asyncio.sleep(0.5)
                text = await cdp.evaluate("document.getElementById('card').innerText")
                if "Checking" not in text:
                    break
            await cdp.shot(shots / "verify-result.png")
            print("verify result:", text[:200].replace("\n", " | "))
            print("verify problems:", cdp.problems())
            rows = await database.all("SELECT outcome, check_id, action, detail FROM attempts WHERE user_id = ? ORDER BY id DESC LIMIT 2", (OLD_USER,))
            print("recorded:", json.dumps(rows)[:900])
            print("hashes:", await database.all("SELECT kind, COUNT(*) AS n FROM identifiers WHERE user_id = ? GROUP BY kind", (OLD_USER,)))

            await cdp.open(f"{PUBLIC}/__dev/login", wait=2)
            for page in ("analytics", "settings", "members", "appeals", "health", "appearance", "permissions", "audit", "integrations"):
                await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/{page}", wait=1.8)
                await cdp.shot(shots / f"dash-{page}.png")
                print(f"dash {page}:", await cdp.evaluate("document.querySelector('.view')?.innerText.length"), cdp.problems())
            await walk_dashboard(cdp, service, shots)
            for page in ("help/vpn", "docs", "privacy", "security", "my-data", f"appeal/{GUILD}"):
                await cdp.open(f"{PUBLIC}/{page}", wait=0.9)
                print(f"page {page}:", cdp.problems())
            pump.cancel()
    finally:
        process.terminate()
        await http.close()
        await runner.cleanup()
        await database.close()
        await asyncio.sleep(0.5)
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--shots", default=str(ROOT / "data" / "shots"))
    asyncio.run(main(Path(parser.parse_args().shots)))
