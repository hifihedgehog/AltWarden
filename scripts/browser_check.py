"""Run the real pages in a real browser against a fake Discord, and report what happened.

    python scripts/browser_check.py [--shots folder]
    python scripts/browser_check.py --controls
    python scripts/browser_check.py --dash [scenario ...]

Starts the site on 127.0.0.1 with demo data, drives headless Edge or Chrome over the DevTools
protocol, and prints console errors, security policy violations and the verification result.
--controls changes every control and reads the saved settings back. --dash runs the dashboard
scenarios, one for each behavior, and exits 1 if any fails.
"""
import argparse
import asyncio
import base64
import json
import os
import random
import re
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

from altwarden import access, catalog, crypto, db, settings
from altwarden.netintel import NetIntel, load_lists
from altwarden.ports import GuildView, MemberInfo
from altwarden.service import Service
from altwarden.web import api as web_api
from altwarden.web.app import SESSION_COOKIE, build_app
from altwarden.web.oauth import DiscordOAuth
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, VERIFIED_ROLE, FakePort

PORT = 8899
PUBLIC = f"http://127.0.0.1:{PORT}"
BROWSERS = (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe")


async def seed(service: Service, port: FakePort) -> None:
    doc = settings.defaults()
    doc["core"].update(verified_role=VERIFIED_ROLE, channel=CHANNEL, fail_open=True)  # a checkout has no network lists, and a new server waits for them
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
    await service.db.set_guild_field(GUILD, "verify_message_id", f"{CHANNEL}:1")  # Health says so when the Verify post is missing


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
                if data["method"] == "Page.javascriptDialogOpening":  # a page left with unsaved changes asks, and nobody is here to answer
                    asyncio.ensure_future(self.call("Page.handleJavaScriptDialog", accept=True))

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
            # A page element can't come back by value, so ask for its truth instead of waiting out the clock.
            if await self.evaluate(f"Boolean({expression})"):
                return True
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


async def walk_retry(cdp, service, port) -> None:
    """A failed attempt offers Try again, a reload spends nothing, and the button runs the check once more."""
    results = {}
    original = json.loads(json.dumps(await service.get_settings(GUILD)))
    rules = json.loads(json.dumps(original))
    rules["checks"]["devtools"].update(enabled=True, action="deny")  # this harness counts as a debugger on the console
    await service.save_settings(GUILD, rules)
    port.add_member(OTHER_USER, username="member_two")
    url, _ = await service.new_link(GUILD, OTHER_USER, rules)
    await service.attach_account(url.rsplit("/", 1)[1], {"id": OTHER_USER, "username": "member_two", "avatar": "abc", "mfa": True, "email_verified": True, "email_disposable": False})

    async def failures():
        return await service.db.scalar("SELECT COUNT(*) FROM attempts WHERE user_id = ? AND outcome = 'failed'", (OTHER_USER,))
    await cdp.open(url, wait=0.3)
    await cdp.until("document.querySelector('.result-mark.bad')", 40)
    results["the first attempt failed once"] = await failures() == 1
    results["it offers Try again"] = await cdp.evaluate("[...document.querySelectorAll('.verify-actions a')].some((node) => node.textContent.includes('Try again'))")
    await cdp.open(url, wait=0.3)
    await cdp.until("document.getElementById('card')?.innerText.includes('last attempt')", 10)
    results["a reload waits to be asked"] = await cdp.evaluate("document.getElementById('card').innerText.includes('last attempt')")
    results["a reload spends nothing"] = await failures() == 1
    await click_text(cdp, ".verify-actions a", "Try again")
    await cdp.until("document.querySelector('.result-mark.bad')", 40)
    results["Try again runs it once more"] = await failures() == 2
    results["the address bar has no leftover flag"] = await cdp.evaluate("!location.search")
    await service.save_settings(GUILD, original)
    print("retry:", json.dumps(results, indent=1))
    print("retry failures:", [name for name, value in results.items() if not value] or "none", cdp.problems())


# Finds every setting a page can change, by a name that stays the same when the page redraws.
CONTROLS = r"""(() => {
  const nameOf = (node) => (node.closest('.field')?.querySelector('span')?.textContent || node.getAttribute('aria-label') || node.closest('label')?.textContent || node.getAttribute('placeholder') || '').trim();
  const kindOf = (node) => node.matches('.segments') ? 'segments' : node.matches('.switch input') ? 'toggle' : node.matches('input[type=checkbox]') ? 'chip' : node.matches('select') ? 'select' : 'value';
  window.__controls = () => {
    const seen = new Map();
    const list = [];
    for (const node of document.querySelector('.view').querySelectorAll('input:not([type=search]):not([type=file]):not([type=password]), select, textarea, .segments')) {
      if (node.disabled || node.matches('.duration select') || node.closest('[hidden], .preview-tools') || node.getAttribute('aria-label') === 'Message') continue;
      const row = node.closest('[id^=item-]')?.id.slice(5) ?? '';
      const base = `${row}/${kindOf(node)}/${nameOf(node)}`;
      const count = seen.get(base) ?? 0;
      seen.set(base, count + 1);
      list.push({ key: count ? `${base}/${count}` : base, row, kind: kindOf(node), name: nameOf(node), node });
    }
    return list;
  };
  window.__keys = () => window.__controls().map(({ key, row, kind, name }) => ({ key, row, kind, name }));
  const valueOf = (node) => node.matches('.segments') ? node.querySelector('[aria-checked=true]')?.textContent : node.type === 'checkbox' ? node.checked : node.value;
  window.__values = () => Object.fromEntries(window.__controls().map(({ key, node }) => [key, valueOf(node)]));
  window.__change = (key, attempt) => {
    const entry = window.__controls().find((item) => item.key === key);
    if (!entry) return false;
    const { node, kind, name } = entry;
    if (kind === 'toggle' || kind === 'chip') {
      node.click();
    } else if (kind === 'segments') {
      const others = [...node.querySelectorAll('button:not([aria-checked=true])')];
      others[attempt % others.length].click();
    } else if (kind === 'select') {
      const options = [...node.options];
      const choice = options[(options.findIndex((option) => option.value === node.value) + 1 + attempt) % options.length];
      node.value = choice.value;
      node.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      if (node.type === 'number') {
        const current = Number(node.value);
        node.value = node.max !== '' && current + 1 > Number(node.max) ? current - 1 : current + 1;
      } else if (node.type === 'color') {
        node.value = `#${(attempt + 1).toString(16).padStart(2, '0')}3456`;
      } else if (name === 'Name') {
        node.value = node.value === 'Verification' ? 'Verifier' : 'Verification';
      } else if (/link/i.test(name)) {
        node.value = `https://example.invalid/${attempt}${node.value.length}.png`;
      } else if (/emoji/i.test(name)) {
        node.value = node.value === '\u2705' ? '\u2b50' : '\u2705';
      } else {
        node.value = `${node.value}${node.value.length % 2 ? 'x' : 'y'}`.slice(-(node.maxLength > 0 ? node.maxLength : 4000));
      }
      node.dispatchEvent(new Event('input', { bubbles: true }));
    }
    return true;
  };
})()"""

RULE_PATHS = {"core": ("core.mode", "core.verified_role", "core.channel"), "unverified": ("core.unverified",), "autodm": ("core.auto_dm",), "closeddms": ("core.notify_closed_dms",),
              "autokick": ("core.auto_kick",), "cooldown": ("core.cooldown",), "rejoin": ("core.remember_rejoin",), "reason": ("core.show_reason",), "failopen": ("core.fail_open",),
              "direct": ("core.direct_signin",), "external": ("core.external_vpn_lookup",), "logs": ("core.logs",), "alerts": ("core.alerts",), "helpdesk": ("core.help_desk",),
              "appeals": ("appeals.",), "raid": ("raid.",), "honeypot": ("honeypot.",), "retention": ("privacy.",)}
CONTROL_ORDER = {"value": 0, "chip": 1, "select": 2, "segments": 3, "toggle": 4}


async def save_bar(cdp) -> bool:
    """Press Save. True if the save bar went away, which means the server took the change."""
    if not await cdp.until("document.querySelector('.savebar')", 2):
        return False
    await click_text(cdp, ".savebar button", "Save changes")
    if await cdp.until("!document.querySelector('.savebar')", 3):
        return True
    await click_text(cdp, ".savebar button", "Discard")
    await cdp.until("!document.querySelector('.savebar')", 3)
    return False


async def change_each_control(cdp, service, expected) -> tuple[dict, list]:
    """Change every control once, save, and read the server's copy. A control that looks right and writes nothing fails here."""
    delivered, failed, done = {}, [], set()
    while True:
        keys = await cdp.evaluate("__keys()")
        if keys is None:
            return delivered, failed + [{"control": "the page stopped answering", "after": sorted(done)[-3:]}]
        waiting = sorted((item for item in keys if item["key"] not in done), key=lambda item: CONTROL_ORDER[item["kind"]])
        if not waiting:
            return delivered, failed
        entry = waiting[0]
        done.add(entry["key"])
        before = await service.get_settings(GUILD)
        saved = False
        for attempt in range(5):  # a value the server refuses, like the verified role as the unverified role, gets another try
            await cdp.evaluate(f"__change({json.dumps(entry['key'])}, {attempt})")
            if await save_bar(cdp):
                saved = True
                break
        paths = [change["path"] for change in settings.diff(before, await service.get_settings(GUILD)) if change["path"] != "preset"]
        allowed = expected(entry)
        if not saved or not paths or not all(path.startswith(allowed) for path in paths):
            failed.append({"control": entry["key"], "saved": saved, "paths": paths, "wanted": allowed})
        delivered[entry["key"]] = paths


async def walk_every_control(cdp, service, port) -> None:
    """Every control on the Rules, Messages and Access pages has to reach the server's copy of the settings, and read back after a reload."""
    results, failures = {}, []
    # With only two roles to pick from, a role picker can't change without being refused for naming the other one.
    port.extra_roles.extend({"id": f"97000000000000009{index}", "name": f"Extra {index}", "color": 0, "position": index, "managed": False, "mentionable": False} for index in (3, 4))
    # The same goes for channels: the honeypot can't share the verification channel.
    port.extra_channels.extend({"id": f"97000000000000008{index}", "name": f"extra-{index}", "type": "text", "category": None, "position": index} for index in (2, 3))
    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/settings", wait=0.3)
    await cdp.until("document.getElementById('item-core')")
    await cdp.evaluate(CONTROLS)
    for _ in range(100):  # each click redraws the page, so look again each time
        clicked = await cdp.evaluate("""(() => {
            const off = [...document.querySelectorAll('.view .switch input')].find((node) => !node.checked && !node.disabled);
            off?.click();
            return Boolean(off);
        })()""")
        if not clicked:
            break
    await cdp.evaluate("""(() => {
        for (const box of document.querySelectorAll('.view select')) {
            if (box.value === '' && box.options[0]?.text.startsWith('Pick a')) {
                box.value = [...box.options].filter((option) => option.value).at(-1).value;
                box.dispatchEvent(new Event('change', { bubbles: true }));
            }
        }
    })()""")
    await asyncio.sleep(0.2)
    await cdp.evaluate("""(() => {
        const box = [...document.querySelectorAll('#item-honeypot select')].find((node) => [...node.options].some((option) => option.value === 'timeout'));
        box.value = 'timeout';
        box.dispatchEvent(new Event('change', { bubbles: true }));
    })()""")
    results["everything switched on and saved"] = await save_bar(cdp)
    saved = await service.get_settings(GUILD)
    catalog_checks = list(saved["checks"])
    results["every check switched on"] = all(saved["checks"][check]["enabled"] for check in catalog_checks)

    await click_text(cdp, "#item-logs button", "Choose channels")
    await cdp.until("document.querySelector('.dialog select')")
    await cdp.evaluate(f"""(() => {{
        const box = document.querySelector('.dialog select');
        box.value = {json.dumps(LOG_CHANNEL)};
        box.dispatchEvent(new Event('change', {{ bubbles: true }}));
    }})()""")
    await asyncio.sleep(0.2)
    await click_text(cdp, ".dialog-foot button", "Done")
    results["logs dialog saved"] = await save_bar(cdp)
    saved = await service.get_settings(GUILD)
    results["one channel for every log category"] = set(saved["core"]["logs"]["modules"].values()) == {LOG_CHANNEL} and all(check in saved["core"]["logs"]["modules"] for check in catalog_checks)
    await click_text(cdp, "#item-alerts button", "Customize")
    await cdp.until("document.querySelector('.dialog select')")
    await cdp.evaluate(f"""(() => {{
        const box = document.querySelector('.dialog select');
        box.value = {json.dumps(VERIFIED_ROLE)};
        box.dispatchEvent(new Event('change', {{ bubbles: true }}));
    }})()""")
    await click_text(cdp, ".dialog-foot button", "Done")
    results["alerts dialog saved"] = await save_bar(cdp)
    results["a log category pings a role"] = len((await service.get_settings(GUILD))["core"]["alerts"]["roles"]) == 1

    def rule_paths(entry):
        return RULE_PATHS.get(entry["row"], (f"checks.{entry['row']}.",))
    await cdp.until("document.getElementById('item-core')")
    delivered, failed = await change_each_control(cdp, service, rule_paths)
    failures += failed
    results["controls on the Rules page"] = len(delivered)

    # The proxycheck.io key has its own button, and has to stay out of the settings and off the page.
    if await cdp.evaluate("(() => { const box = document.querySelector('#item-external .switch input'); if (box.checked) return false; box.click(); return true; })()"):
        await save_bar(cdp)
    await cdp.until("document.querySelector('#item-external input[type=password]')", 3)
    lookup_key = "walk-1234-5678"
    await cdp.evaluate(f"document.querySelector('#item-external input[type=password]').value = {json.dumps(lookup_key)}")
    await click_text(cdp, "#item-external button", "Save key")
    await cdp.until("document.querySelector('#item-external input[type=password]')?.placeholder.includes('ending in')", 3)
    results["proxycheck key saved by its own button"] = await service.lookup_key(GUILD) == lookup_key
    results["the page shows only the key's last four"] = await cdp.evaluate(
        "(() => { const box = document.querySelector('#item-external input[type=password]'); return box.placeholder === 'Saved, ending in 5678' && box.value === ''; })()")
    results["the key stays out of the settings"] = lookup_key not in json.dumps(await service.get_settings(GUILD))
    await click_text(cdp, "#item-external button", "Remove key")
    await cdp.until("document.querySelector('#item-external input[type=password]')?.placeholder.includes('Paste')", 3)
    results["proxycheck key removed"] = await service.lookup_key(GUILD) is None

    await cdp.evaluate("document.querySelector('#item-core .segments button.web')?.click()")
    await save_bar(cdp)
    shown = await cdp.evaluate("__values()")
    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/settings", wait=0.3)
    await cdp.until("document.getElementById('item-core')")
    await cdp.evaluate(CONTROLS)
    results["Rules page reads back the same after a reload"] = shown == await cdp.evaluate("__values()")

    for name, label in (("gentle", "Gentle"), ("standard", "Standard"), ("strict", "Strict")):
        await click_text(cdp, "button.preset", label)
        await cdp.until(f"document.querySelector('.preset.on')?.textContent.includes({json.dumps(label)})", 3)
        await save_bar(cdp)
        results[f"{label} preset saved and marked Active"] = (await service.get_settings(GUILD))["preset"] == name and await cdp.evaluate(f"document.querySelector('.preset.on .active-tag') !== null && document.querySelector('.preset.on').textContent.includes({json.dumps(label)})")
    await cdp.evaluate("document.querySelector('#item-vpn .segments button:not([aria-checked=true])').click()")
    await save_bar(cdp)
    results["a change away from a preset becomes Custom"] = (await service.get_settings(GUILD))["preset"] == "custom" and await cdp.evaluate("document.querySelector('.preset.on')?.textContent.includes('Custom')")

    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/appearance", wait=0.3)
    await cdp.until("document.querySelector('.editor')")
    await cdp.evaluate(CONTROLS)
    total = 0
    for name, label in (("verification", "Verification message"), ("help_desk", "Help desk message"), ("honeypot", "Honeypot warning")):
        await click_text(cdp, ".segments[aria-label=Message] button", label)
        await asyncio.sleep(0.2)
        delivered, failed = await change_each_control(cdp, service, lambda entry, name=name: (f"messages.{name}.", "appearance."))
        failures += failed
        total += len(delivered)
    results["controls on the Messages page"] = total

    await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/permissions", wait=0.3)
    await cdp.until("document.querySelector('[id^=item-page-]')")
    rows = await cdp.evaluate("[...document.querySelectorAll('[id^=item-page-], [id^=item-command-]')].map((node) => node.id)")
    for row in rows:
        before = await service.get_settings(GUILD)
        await click_text(cdp, f"#{row} button", "Edit")
        await cdp.until("document.querySelector('.dialog input[type=checkbox]')", 3)
        await cdp.evaluate("document.querySelector('.dialog input[type=checkbox]').click()")
        await click_text(cdp, ".dialog-foot button", "Done")
        took = await save_bar(cdp)
        paths = [change["path"] for change in settings.diff(before, await service.get_settings(GUILD))]
        if row.startswith("item-page-"):
            page, level = row.removeprefix("item-page-").rsplit("-", 1)
            allowed = (f"permissions.pages.{page}.{level}", f"permissions.pages.{page}") if len(before["permissions"]["pages"].get(page, {})) == 0 else f"permissions.pages.{page}.{level}"
        else:
            allowed = f"permissions.commands.{row.removeprefix('item-command-')}"
        if not took or not paths or not all(path.startswith(allowed) for path in paths):
            failures.append({"control": row, "saved": took, "paths": paths, "wanted": allowed})
    results["rows on the Access page"] = len(rows)

    print("every control:", json.dumps(results, indent=1))
    print("controls that failed to deliver:", json.dumps(failures, indent=1) if failures else "none")
    print("control walk problems:", [problem for problem in cdp.problems() if not any(expected in problem for expected in ("example.invalid", "ERR_NAME_NOT_RESOLVED", "status of 400"))])


# --- dashboard scenarios --------------------------------------------------------------------------
# python scripts/browser_check.py --dash [scenario ...]    all of them when none are named. Exit 1 on any failure.

GUILD_B = "970000000000000101"
ROLE_B = "970000000000000102"
CHANNEL_B = "970000000000000104"

# Runs before each page's own scripts. A scenario can answer any request itself: a refusal, a slow reply, the
# fields a newer server adds. What it hasn't faked goes to the real app.
PAGE_HOOKS = r"""(() => {
  const stored = () => { try { return JSON.parse(sessionStorage.getItem('__fakes') || '[]'); } catch { return []; } };
  const store = (rules) => { try { sessionStorage.setItem('__fakes', JSON.stringify(rules)); } catch {} };
  const real = window.fetch.bind(window);
  window.__calls = [];
  window.__fake = (rule) => { store([...stored(), rule]); };
  window.__clearFakes = () => store([]);
  window.fetch = async (url, init = {}) => {
    const method = init.method || 'GET';
    const path = String(url);
    window.__calls.push({ method, url: path, body: init.body ?? null });
    const rules = stored();
    const index = rules.findIndex((rule) => rule.method === method && new RegExp(rule.url).test(path));
    if (index < 0) return real(url, init);
    const rule = rules[index];
    if (rule.times !== undefined && --rule.times <= 0) rules.splice(index, 1);
    store(rules);
    if (rule.delay) await new Promise((done) => setTimeout(done, rule.delay));
    if (rule.network) throw new TypeError('Failed to fetch');
    if (rule.html) return new Response(rule.html, { status: rule.status ?? 502, headers: { 'Content-Type': 'text/html' } });
    if (rule.pass) {
      const answer = await real(url, init);
      const data = { ...(await answer.json()), ...(rule.merge ?? {}) };
      return new Response(JSON.stringify(data), { status: answer.status, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify(rule.body ?? {}), { status: rule.status ?? 200, headers: { 'Content-Type': 'application/json' } });
  };
  window.__confirms = [];
  window.__confirmAnswer = true;
  window.confirm = (text) => { window.__confirms.push(text); return window.__confirmAnswer; };
  window.__copied = [];
  window.__clipboard = (mode) => {
    const writeText = mode === 'refuse' ? () => Promise.reject(new Error('not allowed')) : (text) => { window.__copied.push(text); return Promise.resolve(); };
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: mode === 'absent' ? undefined : { writeText } });
  };
  window.__dirty = async () => (await import('/static/dash/drafts.js')).dirtyKeys();
  window.__puts = (part) => window.__calls.filter((call) => call.method === 'PUT' && call.url.endsWith(part));
  window.__fire = (node, kind) => node.dispatchEvent(new Event(kind, { bubbles: true }));
  window.__set = (node, value) => { node.value = value; window.__fire(node, node.tagName === 'SELECT' ? 'change' : 'input'); };
  window.__noToasts = () => document.querySelectorAll('.toast').forEach((node) => node.remove());
})()"""


class TwoServers(FakePort):
    """The fake Discord, with a second server the same staff member runs."""

    async def guild(self, guild_id):
        if guild_id != GUILD_B:
            return await super().guild(guild_id)
        return GuildView(id=GUILD_B, name="Second Server", icon=None, owner_id=STAFF, member_count=4,
                         roles=[{"id": ROLE_B, "name": "Member", "color": 0, "position": 1, "managed": False, "mentionable": False}],
                         channels=[{"id": CHANNEL_B, "name": "start-here", "type": "text", "category": None, "position": 0}],
                         bot_permissions=frozenset({"manage_roles", "kick_members", "ban_members"}), bot_top_role=5,
                         channel_permissions={CHANNEL_B: frozenset({"view_channel", "send_messages", "embed_links"})})


class Scene:
    """One scenario's page, server and findings."""

    def __init__(self, cdp, service, port):
        self.cdp, self.service, self.port, self.failures, self.count = cdp, service, port, [], 0

    def check(self, name, ok, detail=None):
        self.count += 1
        if not ok:
            self.failures.append(f"{name}{'' if detail is None else f': {detail}'}")

    async def ev(self, expression):
        return await self.cdp.evaluate(expression)

    async def wait(self, expression, seconds=6):
        return await self.cdp.until(expression, seconds)

    async def need(self, name, expression, seconds=6):
        ok = await self.wait(expression, seconds)
        self.check(name, ok, None if ok else f"waited for {expression[:140]}")
        return ok

    async def open(self, page="settings", ready=None, guild=GUILD, search=""):
        await self.cdp.call("Page.navigate", url=f"{PUBLIC}/dashboard/{guild}/{page}{search}")
        marks = {"settings": "document.getElementById('item-core')", "permissions": "document.querySelector('[id^=item-page-]')", "appearance": "document.querySelector('.editor')",
                 "members": "document.querySelector('tbody tr')", "analytics": "document.querySelector('.kpi')", "health": "document.querySelector('.view .notice')",
                 "appeals": "document.querySelector('.view .panel, .view .faint')", "audit": "document.querySelector('.timeline, .view .faint')", "integrations": "document.querySelector('.view section')"}
        ok = await self.wait(ready or marks.get(page, "document.querySelector('.view')"), 10)
        self.check(f"{page} opened", ok, None if ok else await self.ev("document.querySelector('#root')?.textContent.slice(0, 200)"))

    async def fake(self, method, url, **rule):
        await self.ev(f"__fake({json.dumps({'method': method, 'url': url, **rule})})")

    async def click(self, selector, text=None):
        if text is None:
            return await self.ev(f"(() => {{ const node = document.querySelector({json.dumps(selector)}); node?.click(); return Boolean(node); }})()")
        return await click_text(self.cdp, selector, text)

    async def switch(self, row):
        await self.ev(f"document.querySelector('#item-{row} .switch input').click()")

    async def press(self, key):
        codes = {"Tab": 9, "Enter": 13, "Escape": 27, " ": 32, "ArrowDown": 40}
        common = {"key": key, "code": {" ": "Space"}.get(key, key), "windowsVirtualKeyCode": codes.get(key, 0)}
        await self.cdp.call("Input.dispatchKeyEvent", type="keyDown", text={"Enter": "\r", " ": " "}.get(key, ""), **common)
        await self.cdp.call("Input.dispatchKeyEvent", type="keyUp", **common)
        await asyncio.sleep(0.1)

    async def search(self, words):
        await self.ev("dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))")
        await self.wait("document.querySelector('.palette input')", 2)
        await self.ev(f"__set(document.querySelector('.palette input'), {json.dumps(words)})")
        await self.ev("document.querySelector('.palette li button')?.click()")

    async def errors(self):
        return await self.ev("[...document.querySelectorAll('.toast.error')].map((node) => node.textContent)")

    async def toasts(self):
        return await self.ev("[...document.querySelectorAll('.toast')].map((node) => node.textContent)")

    async def saved(self, guild=GUILD):
        return await self.service.get_settings(guild)

    async def someone_else_changes(self, change, guild=GUILD):
        document = json.loads(json.dumps(await self.saved(guild)))
        change(document)
        await self.service.save_settings(guild, settings.normalize(document))

    def requests(self, piece):
        return [event["params"]["request"]["url"] for event in self.cdp.events
                if event["method"] == "Network.requestWillBeSent" and piece in event["params"]["request"]["url"]]


SCENARIOS = {}


def scenario(run):
    SCENARIOS[run.__name__] = run
    return run


@scenario
async def a_draft_stays_behind_when_search_opens_another_server(s):
    await s.open()
    await s.switch("cooldown")
    s.check("the edit is unsaved", await s.ev("__dirty()") == ["settings"])
    await s.ev("__confirmAnswer = false")
    await s.search("Second Server")
    await asyncio.sleep(0.2)
    s.check("leaving asks first", await s.ev("__confirms.length") == 1)
    s.check("refusing stays put", await s.ev(f"location.pathname.includes('{GUILD}')") and await s.ev("__dirty()") == ["settings"])
    await s.ev("__confirmAnswer = true")
    await s.search("Second Server")
    await s.need("search reached the other server", f"location.pathname.includes('{GUILD_B}') && document.querySelector('.server-button')?.textContent.includes('Second')")
    s.check("the draft is gone", await s.ev("__dirty()") == [])
    s.check("no save bar", await s.ev("!document.querySelector('.savebar')"))
    await s.click(".nav a", "Rules")
    await s.need("the other server's rules opened", "document.getElementById('item-cooldown')")
    s.check("its cooldown is its own", await s.ev("!document.querySelector('#item-cooldown .switch input').checked"))
    await s.switch("autodm")
    await s.click(".savebar button", "Save changes")
    await s.need("saved", "!document.querySelector('.savebar')")
    second, first = await s.saved(GUILD_B), await s.saved()
    s.check("the first server's edit didn't reach the second", second["core"]["cooldown"]["enabled"] is False)
    s.check("the second server's own edit landed", second["core"]["auto_dm"] is False)
    s.check("its own channel survived", second["core"]["channel"] == CHANNEL_B)
    s.check("the first server is untouched", first["core"]["cooldown"]["enabled"] is False)


@scenario
async def a_draft_stays_behind_when_back_opens_another_server(s):
    await s.open(guild=GUILD_B)
    await s.click(".server-button")
    await s.click(f".side .nav a[href='/dashboard/{GUILD}']")
    await s.need("moved to the first server", f"location.pathname.endsWith('{GUILD}') && document.querySelector('.kpi')")
    await s.click(".nav a", "Rules")
    await s.need("rules opened", "document.getElementById('item-cooldown')")
    await s.switch("cooldown")
    await s.ev("__confirmAnswer = false")
    await s.ev("history.back()")
    await s.need("back inside one server keeps the draft", f"location.pathname.endsWith('{GUILD}') && document.querySelector('.kpi')")
    s.check("nothing asked yet", await s.ev("__confirms.length") == 0)
    s.check("still unsaved", await s.ev("__dirty()") == ["settings"])
    await s.ev("history.back()")
    await s.need("refusing puts the address back", f"__confirms.length === 1 && location.pathname.includes('{GUILD}')")
    s.check("still unsaved after refusing", await s.ev("__dirty()") == ["settings"])
    await s.ev("__confirmAnswer = true")
    await s.ev("history.back()")
    await s.need("accepting goes back", f"location.pathname.includes('{GUILD_B}') && document.querySelector('.server-button')?.textContent.includes('Second')")
    s.check("the draft is gone", await s.ev("__dirty()") == [])
    await s.need("the other server's rules opened", "document.getElementById('item-cooldown')")
    s.check("its switch is its own", await s.ev("!document.querySelector('#item-cooldown .switch input').checked"))


@scenario
async def drafts_belong_to_one_server_whatever_path_reached_them(s):
    await s.open("analytics")
    found = await s.ev("""(async () => {
      const drafts = await import('/static/dash/drafts.js');
      const part = drafts.draftFor('111111111111111', 'probe', { value: 1 }, async () => {});
      part.draft.value = 2;
      const dirty = drafts.dirtyKeys();
      const other = drafts.draftFor('222222222222222', 'probe', { value: 5 }, async () => {});
      return { dirty, draft: other.draft.value, after: drafts.dirtyKeys() };
    })()""")
    s.check("the first draft counted", found and found["dirty"] == ["probe"], found)
    s.check("the second server starts from its own document", found and found["draft"] == 5, found)
    s.check("nothing is left to save", found and found["after"] == [], found)


@scenario
async def a_slow_page_left_behind_cant_take_over_the_drafts(s):
    for route, label in (("settings", "Rules"), ("permissions", "Access"), ("appearance", "Messages")):
        await s.open("analytics")
        await s.ev("__clearFakes()")
        await s.fake("GET", f"/guilds/{GUILD}/{route}$", delay=3000, **{"pass": True})
        await s.click(".nav a", label)
        # The page has to be waiting on its own answer, or the newer navigation drops it earlier than this.
        await s.need(f"{label}: the page is waiting", f"__calls.some((call) => call.method === 'GET' && call.url.endsWith('/{route}'))")
        await s.click(".server-button")
        await s.click(f".side .nav a[href='/dashboard/{GUILD_B}']")
        await s.need(f"{label}: the other server opened", "document.querySelector('.server-button')?.textContent.includes('Second') && document.querySelector('.kpi')")
        await s.click(".nav a", "Rules")
        await s.need(f"{label}: its rules opened", "document.getElementById('item-cooldown')")
        await s.switch("cooldown")
        await asyncio.sleep(3.3)
        s.check(f"{label}: the late answer left the draft alone", await s.ev("__dirty()") == ["settings"], await s.ev("__dirty()"))
        s.check(f"{label}: the page is still the second server's", await s.ev(f"location.pathname.includes('{GUILD_B}')"))
        wanted = not (await s.saved(GUILD_B))["core"]["cooldown"]["enabled"]
        await s.click(".savebar button", "Save changes")
        await s.need(f"{label}: saved", "!document.querySelector('.savebar')")
        s.check(f"{label}: the save went to the second server", (await s.saved(GUILD_B))["core"]["cooldown"]["enabled"] is wanted)
        s.check(f"{label}: the first server never saw it", (await s.saved())["core"]["cooldown"]["enabled"] is False)


@scenario
async def the_newest_navigation_wins(s):
    await s.open("analytics")
    await s.fake("GET", f"/guilds/{GUILD}$", delay=900, times=1, **{"pass": True})
    await s.click(".nav a", "Rules")
    await s.click(".nav a", "Members")
    await s.need("members opened", "location.pathname.endsWith('/members') && document.querySelector('tbody tr')", 8)
    await asyncio.sleep(1.1)
    s.check("the slow page didn't draw over it", await s.ev("document.querySelector('.topbar h1').textContent") == "Members" and await s.ev("Boolean(document.querySelector('tbody tr'))"))


@scenario
async def a_link_cant_break_a_page_with_an_object_key(s):
    for search in ("?discord=constructor", "?discord=__proto__", "?discord=toString"):
        await s.open("permissions", ready="document.querySelector('[id^=item-page-]') || document.querySelector('.view .notice.bad')", search=search)
        s.check(f"Access draws with {search}", await s.ev("!document.querySelector('.view .notice.bad') && Boolean(document.querySelector('[id^=item-page-]'))"))
    await s.open("permissions", search="?discord=saved")
    s.check("a real outcome still shows", "saved" in " ".join(await s.toasts()))
    await s.open("appearance", ready="document.querySelector('.editor') || document.querySelector('.view .notice.bad')", search="#constructor")
    s.check("Messages draws with #constructor", await s.ev("!document.querySelector('.view .notice.bad') && Boolean(document.querySelector('.editor'))"))


@scenario
async def a_server_word_cant_break_a_page_with_an_object_key(s):
    await s.open("analytics")
    await s.fake("GET", "/members\\?", body={"total": 1, "page": 1, "size": 20, "members": [{"user_id": OLD_USER, "username": "x", "avatar": None, "status": "constructor", "last_at": 0,
                                                                                           "results": [{"outcome": "constructor", "check": "constructor", "count": 1}]}]})
    await s.open("members")
    s.check("members draws", await s.ev("document.querySelector('tbody .pill')?.textContent") == "constructor")
    s.check("the result isn't a function's source", "function" not in await s.ev("document.querySelector('tbody').textContent"))
    await s.ev("__clearFakes()")
    await s.fake("GET", "/audit$", body={"entries": [{"at": 1, "actor_id": None, "actor_name": None, "kind": "constructor", "detail": {}}]})
    await s.open("audit")
    s.check("audit draws an unknown kind", "function" not in await s.ev("document.querySelector('.view').textContent") and await s.ev("Boolean(document.querySelector('.timeline li'))"))
    await s.ev("__clearFakes()")
    await s.fake("GET", "/health$", body={"healthy": True, "issues": [], "ok": [{"area": "constructor", "label": "a", "value": "b"}], "needs": {}, "lists_loaded": True, "lists_missing": [], "checked_at": 1})
    await s.open("health")
    s.check("health draws an unknown area", await s.ev("!document.querySelector('.view .notice.bad')"))


@scenario
async def a_failed_first_load_says_so(s):
    await s.open("analytics")
    await s.fake("GET", "/api/catalog$", html="<html>Bad Gateway</html>", status=502)
    await s.cdp.call("Page.navigate", url=f"{PUBLIC}/dashboard/{GUILD}/analytics")
    await s.need("a bad gateway shows a message", "document.getElementById('root').textContent.includes('Something went wrong')")
    s.check("it offers a reload", await s.ev("Boolean(document.querySelector('#root a'))"))
    s.check("Loading is gone", "Loading" not in await s.ev("document.getElementById('root').textContent"))
    await s.ev("__clearFakes()")
    await s.fake("GET", "/api/session$", network=True)
    await s.cdp.call("Page.navigate", url=f"{PUBLIC}/dashboard/{GUILD}/analytics")
    await s.need("a dropped connection shows a message", "document.getElementById('root').textContent.includes(\"couldn't be reached\")")


@scenario
async def a_refused_action_says_why_and_its_button_works_again(s):
    refusal = {"status": 400, "body": {"error": "Refused by the server."}}

    async def expect(name):
        await s.need(f"{name} shows the refusal", "[...document.querySelectorAll('.toast.error')].some((node) => node.textContent === 'Refused by the server.')")
        await s.ev("__noToasts(); __clearFakes()")
    await s.open()
    await s.fake("POST", "/settings/preset$", **refusal)
    await s.click("button.preset", "Strict")
    await expect("a preset")
    s.check("the preset button isn't left waiting", await s.ev("![...document.querySelectorAll('button.preset')].some((node) => node.getAttribute('aria-busy') === 'true')"))
    await s.fake("POST", "/settings/preview$", **refusal)
    await s.click("button", "Preview on the last 30 days")
    await expect("a preview")
    await s.fake("POST", "/settings/export$", **refusal)
    await s.click("button", "Copy to another server")
    await expect("an export")
    await s.open("members")
    await s.fake("GET", "/members\\?", **refusal)
    await s.ev("__set(document.querySelector('input[type=search]'), 'abc')")
    await expect("a member search")
    await s.open("appeals")
    await s.fake("GET", "/appeals\\?", **refusal)
    await s.ev("__set(document.querySelector('select[aria-label=Status]'), 'denied')")
    await expect("an appeal filter")
    await s.open("analytics")
    await s.fake("GET", "/analytics\\?", **refusal)
    await s.ev("__set(document.querySelector('select[aria-label=Compare]'), 'period')")
    await expect("an overview filter")
    await s.open("health")
    await s.fake("GET", "/health$", **refusal)
    await s.click("button", "Check again")
    await expect("Check again")
    s.check("Check again can be pressed again", await s.ev("![...document.querySelectorAll('button')].find((node) => node.textContent === 'Check again').disabled"))
    await s.open("integrations")
    await s.fake("POST", "/keys$", **refusal)
    await s.click("button", "Create key")
    await expect("Create key")
    s.check("no secret dialog opened", await s.ev("!document.querySelector('.dialog')"))
    await s.open()
    await s.fake("POST", "/raid$", **refusal)
    await s.click("#item-raid button", "raid mode now")
    await expect("the raid button")
    await s.cdp.call("Runtime.evaluate", expression="Promise.reject(new TypeError('a bug in the page')); 1")
    await s.need("an unexpected failure gets one plain message", "[...document.querySelectorAll('.toast.error')].some((node) => node.textContent === 'Something went wrong.')")
    s.cdp.events[:] = [event for event in s.cdp.events if event["method"] != "Runtime.exceptionThrown"]  # the one this scenario threw on purpose


@scenario
async def toasts_stack_and_errors_are_announced(s):
    await s.open("analytics")
    found = await s.ev("""(async () => {
      const { toast } = await import('/static/dash/ui.js');
      toast('First note', true);
      toast('Second note');
      const nodes = [...document.querySelectorAll('.toast')];
      const [a, b] = nodes.map((node) => node.getBoundingClientRect());
      return { count: nodes.length, apart: a.bottom <= b.top || b.bottom <= a.top, roles: nodes.map((node) => node.getAttribute('role')) };
    })()""")
    s.check("two toasts show", found["count"] == 2, found)
    s.check("neither hides the other", found["apart"], found)
    s.check("the error is an alert and the note is a status", found["roles"] == ["alert", "status"], found)


@scenario
async def the_logs_dialog_keeps_its_place_and_says_mixed(s):
    await s.open()
    await s.click("#item-logs button", "Choose channels")
    await s.need("the dialog opened", "document.querySelectorAll('.dialog .log-group').length > 1")
    await s.ev("document.querySelectorAll('.dialog .log-group')[1].open = true")
    picked = await s.ev(f"""(() => {{
        const box = document.querySelectorAll('.dialog .log-group')[1].querySelectorAll('select')[1];
        box.focus();
        const name = box.closest('.field').querySelector('span').textContent;
        __set(box, {json.dumps(LOG_CHANNEL)});
        return name;
    }})()""")
    await asyncio.sleep(0.1)
    s.check("the group stays open", await s.ev("document.querySelectorAll('.dialog .log-group')[1].open"))
    s.check("focus stays on the picker", await s.ev("document.activeElement.closest('.field')?.querySelector('span').textContent") == picked, await s.ev("document.activeElement.outerHTML.slice(0, 120)"))
    s.check("every category says Mixed", (await s.ev("document.querySelector('.dialog select').selectedOptions[0].textContent")).startswith("Mixed"))
    await s.ev("__set(document.querySelector('.dialog select'), '')")
    await asyncio.sleep(0.1)
    s.check("Not logged clears a mixed set", await s.ev("document.querySelectorAll('.dialog .log-group')[1].querySelectorAll('select')[1].value") == "")
    await s.click(".dialog-foot button", "Done")
    await s.click(".savebar button", "Discard")


@scenario
async def the_overview_redraws_without_asking_the_server_again(s):
    await s.open("analytics")
    await s.ev("__calls.length = 0")
    await s.ev("document.querySelector('.check-filter').open = true")
    for index in (0, 1):
        await s.ev(f"document.querySelectorAll('.check-filter input')[{index}].click()")
        await asyncio.sleep(0.05)
    await s.ev("__set(document.querySelector('select[aria-label=\"Chart type\"]'), 'bars')")
    await asyncio.sleep(0.1)
    s.check("the filter stays open", await s.ev("document.querySelector('.check-filter').open"))
    s.check("nothing was fetched", await s.ev("__calls.length") == 0, await s.ev("JSON.stringify(__calls)"))
    days = [{"day": "2026-10-01", "verified": 3, "blocked": 5, "checks": {"vpn": 4, "automation": 1}}, {"day": "2026-10-02", "verified": 1, "blocked": 1, "checks": {"vpn": 1}}]
    grid = [[0] * 24 for _ in range(7)]
    grid[2][5] = 7
    body = {"cards": {"verified": 4, "blocked": 6, "pass_rate": 40.0, "members": 5, "median_seconds": 120}, "previous": {"verified": 3, "blocked": 6, "pass_rate": 37.7, "members": 5, "median_seconds": 60},
            "verifying_now": 0, "daily": days, "reasons": [["vpn", 5], ["automation", 1]], "funnel": {"started": 1, "finished": 1, "verified": 1, "unfinished": 0, "retried": 0}, "heatmap": grid,
            "durations": [], "outcomes": {"modes": {}, "actions": {}, "bypassed": 0}, "range": {"start": 1, "end": 2, "clamped": True}}
    await s.fake("GET", "/analytics\\?", body=body)
    await s.open("analytics")
    cards = await s.ev("document.querySelector('.kpis').textContent")
    s.check("a rate change has its unit", "+2.3 points vs previous" in cards, cards)
    s.check("a time change reads as time", "+1m vs previous" in cards, cards)
    s.check("a cut period says so", "starts on" in await s.ev("document.querySelector('.view').textContent"))
    table = "document.querySelector('.day-table tbody')"
    s.check("the table shows every stopped attempt at first", await s.ev(f"{table}?.rows[0].cells[2].textContent") == "5")
    await s.ev("document.querySelector('.check-filter').open = true")
    await s.ev("[...document.querySelectorAll('.check-filter label')].find((node) => node.textContent.includes('VPN')).querySelector('input').click()")
    await asyncio.sleep(0.1)
    s.check("a hidden check leaves the table", await s.ev(f"{table}?.rows[0].cells[2].textContent") == "1")
    s.check("a hidden check leaves the reasons", "VPN" not in await s.ev("[...document.querySelectorAll('.panel')].find((node) => node.textContent.includes('Why attempts')).textContent"))
    label = await s.ev("document.querySelector('.chart svg').getAttribute('aria-label')")
    s.check("the chart has a sentence", "4 verified and 1 stopped" in label, label)
    s.check("the heat map has a table", await s.ev("document.querySelector('.heat-table td')?.textContent") == "Wed" and await s.ev("document.querySelector('.heat-table tbody')?.rows[0].cells[2].textContent") == "7")


@scenario
async def a_slow_older_answer_cant_replace_a_newer_one(s):
    member = lambda name, uid: {"total": 1, "page": 1, "size": 20, "members": [{"user_id": uid, "username": name, "avatar": None, "status": "pending", "last_at": 0, "results": []}]}
    await s.open("members")
    await s.fake("GET", "/members\\?.*q=slow", delay=900, body=member("old answer", "1"))
    await s.fake("GET", "/members\\?.*q=new", body=member("new answer", "2"))
    await s.ev("__set(document.querySelector('input[type=search]'), 'slow')")
    await asyncio.sleep(0.35)
    await s.ev("__set(document.querySelector('input[type=search]'), 'new')")
    await s.need("the newer answer shows", "document.querySelector('tbody').textContent.includes('new answer')")
    await asyncio.sleep(1)
    s.check("the older answer didn't replace it", await s.ev("document.querySelector('tbody').textContent.includes('new answer')"))
    await s.ev("__clearFakes()")
    await s.open("analytics")
    busy = {"cards": {"verified": 99, "blocked": 0, "pass_rate": 100, "members": 1, "median_seconds": None}, "previous": {"verified": 99}, "verifying_now": 0, "daily": [], "reasons": [],
            "funnel": {"started": 0, "finished": 0, "verified": 0, "unfinished": 0, "retried": 0}, "heatmap": [[0] * 24 for _ in range(7)], "durations": [], "outcomes": {"modes": {}, "actions": {}, "bypassed": 0}}
    await s.fake("GET", "/analytics\\?.*compare=1", delay=900, body=busy)
    await s.ev("__set(document.querySelector('select[aria-label=Compare]'), 'period')")
    await s.ev("__set(document.querySelector('select[aria-label=Compare]'), '')")
    await asyncio.sleep(1.1)
    s.check("an older overview answer is dropped", await s.ev("document.querySelector('.kpi .value').textContent") != "99")
    await s.ev("__clearFakes()")
    await s.open("appeals")
    await s.fake("GET", "/appeals\\?status=denied", delay=900, body={"appeals": [{"id": 1, "user_id": OLD_USER, "username": "stale appeal", "avatar": None, "status": "denied", "text": "t", "created_at": 1, "check_id": "vpn"}]})
    await s.fake("GET", "/appeals\\?status=approved", body={"appeals": []})
    await s.ev("__set(document.querySelector('select[aria-label=Status]'), 'denied')")
    await s.ev("__set(document.querySelector('select[aria-label=Status]'), 'approved')")
    await asyncio.sleep(1.1)
    s.check("an older appeals answer is dropped", "stale appeal" not in await s.ev("document.querySelector('.view').textContent"))


@scenario
async def a_number_that_cant_be_saved_blocks_the_save(s):
    await s.open()
    box = "document.querySelector('#item-max_attempts input[type=number]')"
    await s.ev(f"__set({box}, '')")
    s.check("a blank box is invalid", await s.ev(f"!{box}.validity.valid"))
    await s.switch("autodm")
    await s.click(".savebar button", "Save changes")
    await asyncio.sleep(0.4)
    s.check("a blank box stops the save", (await s.saved())["core"]["auto_dm"] is True)
    await s.ev("__noToasts()")
    await s.ev(f"__set({box}, '99999')")
    s.check("too large is invalid", await s.ev(f"!{box}.validity.valid"))
    await s.click(".nav a", "Messages")
    await s.need("moved away", "document.querySelector('.editor')")
    await s.click(".savebar button", "Save changes")
    await s.need("saving from another page goes back to the bad value", "location.pathname.endsWith('/settings') && document.activeElement?.matches('#item-max_attempts input[type=number]')", 8)
    s.check("nothing was saved", (await s.saved())["checks"]["max_attempts"]["attempts"] == 5 and (await s.saved())["core"]["auto_dm"] is True)
    s.check("the reason shows", await s.errors() != [])
    await s.click(".savebar button", "Discard")
    await asyncio.sleep(0.2)
    reset = "document.querySelector('#item-max_attempts .duration input')"
    await s.ev("__set(document.querySelector('#item-max_attempts .duration select'), 'minutes')")
    for value, good in (("3", False), ("0", True), ("5", True)):
        await s.ev(f"__set({reset}, '{value}')")
        s.check(f"give attempts back after {value} minutes", await s.ev(f"{reset}.validity.valid") is good)
    await s.ev(f"__set({reset}, '3')")
    await s.click(".savebar button", "Save changes")
    await asyncio.sleep(0.4)
    s.check("3 minutes isn't saved", (await s.saved())["checks"]["max_attempts"]["reset_minutes"] != 3)
    await s.ev(f"__set({reset}, '0')")
    await s.click(".savebar button", "Save changes")
    await s.need("0 saves", "!document.querySelector('.savebar')")
    s.check("0 is stored", (await s.saved())["checks"]["max_attempts"]["reset_minutes"] == 0)


@scenario
async def a_deleted_role_or_channel_doesnt_look_unset(s):
    gone = "970000000000000777"
    await s.someone_else_changes(lambda doc: (doc["core"]["logs"]["modules"].update(general=gone), doc["core"]["help_desk"].update(enabled=True, support_role=gone)))
    await s.open()
    s.check("a deleted role says so", (await s.ev("document.querySelector('#item-helpdesk select').selectedOptions[0].textContent")).startswith("Deleted"))
    count = await s.ev("document.querySelector('#item-logs .rule-title span').textContent")
    s.check("the count leaves out the deleted channel", count.startswith("1 module has a channel"), count)
    s.port.extra_roles.extend([{"id": "970000000000000888", "name": "Above", "color": 0, "position": 9, "managed": False, "mentionable": False},
                               {"id": "970000000000000889", "name": "Booster", "color": 0, "position": 1, "managed": True, "mentionable": False}])
    await s.open()
    options = "[...document.querySelector('#item-core select').options]"
    s.check("a role above AltWarden can't be handed out", await s.ev(f"{options}.find((node) => node.value === '970000000000000888')?.disabled"))
    s.check("a managed role can't be handed out", await s.ev(f"!{options}.some((node) => node.value === '970000000000000889')"))
    s.check("a role below AltWarden can", await s.ev(f"!{options}.find((node) => node.value === {json.dumps(VERIFIED_ROLE)}).disabled"))
    s.check("a role that's only pinged may sit above AltWarden", await s.ev("![...document.querySelector('#item-helpdesk select').options].find((node) => node.value === '970000000000000888')?.disabled"))
    await s.open("permissions")
    await s.click("#item-command-verify-user button", "Edit")
    await s.need("the rule opened", "document.querySelector('.dialog select')")
    s.check("Access can name a managed role", await s.ev("[...document.querySelector('.dialog select[aria-label=\"Add a role\"]').options].some((node) => node.value === '970000000000000889')"))
    await s.click(".dialog-foot button", "Done")


@scenario
async def every_way_out_of_a_dialog_refreshes_the_page(s):
    await s.open()
    before = await s.ev("document.querySelector('#item-logs .rule-title span').textContent")
    await s.click("#item-logs button", "Choose channels")
    await s.need("logs opened", "document.querySelector('.dialog select')")
    await s.ev(f"__set(document.querySelector('.dialog select'), {json.dumps(LOG_CHANNEL)})")
    await s.press("Escape")
    s.check("Escape closed it", await s.ev("!document.querySelector('.dialog')"))
    s.check("the count moved", await s.ev("document.querySelector('#item-logs .rule-title span').textContent") != before)
    await s.click(".savebar button", "Discard")
    await s.open("permissions")
    summary = await s.ev("document.querySelector('#item-command-verify-user .rule-title span').textContent")
    await s.click("#item-command-verify-user button", "Edit")
    await s.need("the rule opened", "document.querySelector('.dialog input[type=checkbox]')")
    await s.ev("document.querySelector('.dialog input[type=checkbox]').click()")
    await s.ev("document.querySelector('.overlay').click()")
    await s.need("a backdrop click closed it", "!document.querySelector('.dialog')")
    s.check("the summary moved", await s.ev("document.querySelector('#item-command-verify-user .rule-title span').textContent") != summary)
    await s.click(".savebar button", "Discard")
    await s.open("integrations")
    await s.click("button", "Create key")
    await s.need("the key is shown", "document.querySelector('.dialog input[readonly]')")
    await s.ev("document.querySelector('.overlay').click()")
    await s.press("Escape")
    s.check("a one-time secret survives a stray click and Escape", await s.ev("Boolean(document.querySelector('.dialog input[readonly]'))"))
    s.check("a one-time secret can be copied", await s.ev("[...document.querySelectorAll('.dialog-foot button')].some((node) => node.textContent === 'Copy')"))
    await s.click(".dialog-foot button", "I saved it")
    answers = await s.ev("""(async () => {
      const { confirmDialog } = await import('/static/dash/ui.js');
      const escape = confirmDialog('Sure?', 'Words', 'Yes');
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      const first = await Promise.race([escape, new Promise((done) => setTimeout(() => done('hung'), 400))]);
      document.querySelector('.overlay')?.remove();
      const backdrop = confirmDialog('Sure?', 'Words', 'Yes');
      document.querySelector('.overlay').click();
      const second = await Promise.race([backdrop, new Promise((done) => setTimeout(() => done('hung'), 400))]);
      return [first, second];
    })()""")
    s.check("a confirm dialog answers no when dismissed", answers == [False, False], answers)


@scenario
async def a_refused_bypass_keeps_the_dialog_and_one_press_makes_one_link(s):
    await s.open("members")
    await s.ev("document.querySelector('tbody tr').click()")
    await s.need("the drawer opened", "[...document.querySelectorAll('.drawer button')].some((node) => node.textContent === 'Bypass link')")
    await s.click(".drawer button", "Bypass link")
    await s.need("the dialog opened", "document.querySelector('.dialog input[type=checkbox]')")
    await s.fake("POST", "/bypass$", status=400, body={"error": "Pick at least one check to skip."})
    await s.click(".dialog-foot button", "Create link")
    await s.need("the refusal shows", "[...document.querySelectorAll('.toast.error')].some((node) => node.textContent.includes('Pick at least one'))")
    s.check("the dialog stays", await s.ev("Boolean(document.querySelector('.dialog input[type=checkbox]'))"))
    await s.ev("__clearFakes(); __calls.length = 0")
    await s.fake("POST", "/bypass$", delay=300, body={"url": "https://example.invalid/link", "delivered": False})
    await s.ev("[...document.querySelectorAll('.dialog-foot button')].find((node) => node.textContent === 'Create link').click(); [...document.querySelectorAll('.dialog-foot button')].find((node) => node.textContent === 'Create link').click()")
    await s.need("the link shows", "document.querySelector('.dialog input[readonly]')")
    s.check("two presses made one request", await s.ev("__calls.filter((call) => call.url.endsWith('/bypass')).length") == 1)
    await s.click(".dialog-foot button", "Close")


@scenario
async def copied_is_only_said_when_something_was_copied(s):
    await s.open()
    await s.click("button", "Copy to another server")
    await s.need("the code shows", "document.querySelector('.dialog textarea')")
    for mode in ("absent", "refuse"):
        await s.ev(f"__clipboard('{mode}'); __noToasts()")
        await s.click(".dialog-foot button", "Copy code")
        await s.need(f"{mode}: failure said", "document.querySelector('.toast.error')")
        s.check(f"{mode}: not called copied", "Copied." not in await s.toasts(), await s.toasts())
        s.check(f"{mode}: the code is selected for a manual copy", await s.ev("(() => { const box = document.querySelector('.dialog textarea'); return box.selectionEnd > box.selectionStart; })()"))
    await s.ev("__clipboard('work'); __noToasts()")
    await s.click(".dialog-foot button", "Copy code")
    await s.need("a real copy says so", "[...document.querySelectorAll('.toast')].some((node) => node.textContent === 'Copied.')")
    s.check("the text reached the clipboard", await s.ev("__copied.length") == 1)
    await s.click(".dialog-foot button", "Close")
    await s.open("members")
    await s.ev("document.querySelector('tbody tr').click()")
    await s.need("the drawer opened", "document.querySelector('.drawer .who')")
    await s.ev("__clipboard('absent')")
    s.check("the ID is a button", await s.ev("document.querySelector('.drawer .who button')?.title") == "Copy this ID")
    await s.ev("document.querySelector('.drawer .who button')?.click()")
    await s.need("copying the ID with no clipboard says so", "document.querySelector('.toast.error')")


@scenario
async def the_country_map_paints_what_the_rule_does(s):
    await s.open()
    await s.switch("geogate")
    await s.need("the row opened", "[...document.querySelectorAll('#item-geogate button')].length")
    await s.click("#item-geogate button", "Choose countries")
    await s.need("the map drew", "document.querySelector('.map-wrap path')", 10)
    await s.ev("[...document.querySelectorAll('.tree summary input')][0].click()")
    await asyncio.sleep(0.1)
    picked = await s.ev("document.querySelectorAll('.map-wrap .picked').length")
    s.check("block: a listed country is painted", picked > 0)
    await s.click("[aria-label='List type'] button", "Allow only these")
    await asyncio.sleep(0.1)
    s.check("allow: listed countries read as allowed", await s.ev("document.querySelectorAll('.map-wrap .allowed').length") == picked)
    s.check("allow: every other country is what gets acted on", await s.ev("document.querySelectorAll('.map-wrap .picked').length") > 0 and await s.ev("document.querySelectorAll('.map-wrap .allowed.picked').length") == 0)
    await s.ev("document.querySelectorAll('.tree details')[0].open = true")
    await s.ev("document.querySelectorAll('.tree details details')[0].open = true")
    s.check("allow: a listed country has no action to pick", await s.ev("document.querySelector('.tree label.country select').disabled"))
    await s.ev("document.querySelector('.tree label.country input').click()")
    await asyncio.sleep(0.1)
    s.check("picking from the list keeps the tree open", await s.ev("document.querySelectorAll('.tree details')[0].open && document.querySelectorAll('.tree details details')[0].open"))
    s.check("allow: an unlisted country has one", await s.ev("!document.querySelector('.tree label.country select').disabled"))
    s.check("the count says what the rest get", "Every other country" in await s.ev("document.querySelector('.dialog p.muted').textContent"))
    await s.click(".dialog-foot button", "Cancel")


@scenario
async def raid_controls_stay_reachable_and_the_page_follows_them(s):
    await s.open()
    s.check("no raid pill at first", await s.ev("!document.querySelector('.raid-pill')"))
    await s.click("#item-raid button", "Start raid mode now")
    await s.need("the pill appears", "document.querySelector('.raid-pill')")
    await s.need("the button turned", "[...document.querySelectorAll('#item-raid button')].some((node) => node.textContent === 'End raid mode now')")
    await s.switch("raid")
    await asyncio.sleep(0.1)
    s.check("switching the rule off keeps End reachable", await s.ev("[...document.querySelectorAll('#item-raid button')].some((node) => node.textContent === 'End raid mode now')"))
    s.check("switching it off hides the settings", await s.ev("!document.querySelector('#item-raid input[type=number]')"))
    await s.click("#item-raid button", "End raid mode now")
    await s.need("the pill goes", "!document.querySelector('.raid-pill')")
    s.check("no button left with the rule off and no raid", await s.ev("![...document.querySelectorAll('#item-raid button')].some((node) => node.textContent.includes('raid mode now'))"))
    await s.click(".savebar button", "Discard")
    await asyncio.sleep(0.1)
    s.check("the health dot starts clear", await s.ev("document.querySelector('.nav [data-page=health]').querySelector('.dot:not(.amber)') === null"))
    await s.fake("GET", f"/guilds/{GUILD}$", merge={"healthy": False}, **{"pass": True})
    await s.click("#item-raid button", "Start raid mode now")
    await s.need("the health dot follows", "document.querySelector('.nav [data-page=health]').querySelector('.dot:not(.amber)')")
    await s.ev("__clearFakes()")
    await s.click("#item-raid button", "End raid mode now")
    await s.need("the pill goes again", "!document.querySelector('.raid-pill')")
    s.check("raid text says where the alert goes", "log channel" in await s.ev("document.querySelector('#item-raid .rule-title span').textContent"))


@scenario
async def the_member_drawer_is_one_panel_on_the_keyboard(s):
    await s.open("members")
    await s.ev("document.querySelectorAll('tbody tr')[0].focus(); document.querySelectorAll('tbody tr')[0].click()")
    await s.need("the first drawer opened", "document.querySelector('.drawer .who')")
    s.check("focus moved to Close", await s.ev("document.activeElement.textContent") == "Close")
    await s.ev("document.querySelectorAll('tbody tr')[1].focus(); document.querySelectorAll('tbody tr')[1].click()")
    await asyncio.sleep(0.4)
    s.check("one drawer at a time", await s.ev("document.querySelectorAll('.drawer').length") == 1)
    second = await s.ev("document.querySelectorAll('tbody tr')[1].dataset.key")
    await s.need("the drawer focused again", "document.activeElement.textContent === 'Close'")
    await s.press("Escape")
    s.check("Escape closed it", await s.ev("!document.querySelector('.drawer')"))
    s.check("focus went back to the row", second and await s.ev("document.activeElement.dataset.key") == second)
    await s.press("Enter")
    await s.need("Enter opens the row", "document.querySelector('.drawer .who')")
    await s.click(".nav a", "Health")
    await s.need("moved on", "location.pathname.endsWith('/health')")
    await asyncio.sleep(0.2)
    s.check("a new page closes the drawer", await s.ev("!document.querySelector('.drawer')"))


@scenario
async def member_results_have_words_for_every_outcome(s):
    await s.open("analytics")
    await s.fake("GET", "/members\\?", body={"total": 1, "page": 1, "size": 20, "members": [{"user_id": OLD_USER, "username": "x", "avatar": None, "status": "pending", "last_at": 0, "results": [
        {"outcome": "role_problem", "check": "role_problem", "count": 2}, {"outcome": "auto_kick_failed", "check": None, "count": 1}, {"outcome": "honeypot", "check": "honeypot", "count": 1}]}]})
    await s.fake("GET", f"/members/{OLD_USER}$", body={"member": {"user_id": OLD_USER, "username": "x", "avatar": None, "status": "pending"}, "links": [], "bypass_options": [], "banned": False, "attempts": [
        {"at": 1, "outcome": "role_problem", "check_id": "role_problem", "action": None, "bypassed": 0, "detail": {}},
        {"at": 2, "outcome": "auto_kick_failed", "check_id": None, "action": None, "bypassed": 0, "detail": {}},
        {"at": 3, "outcome": "honeypot", "check_id": "honeypot", "action": "softban", "bypassed": 0, "detail": {}}]})
    await s.open("members")
    row = await s.ev("document.querySelector('tbody').textContent")
    s.check("the role problem has words", "2 × Couldn't give the role" in row, row)
    s.check("a failed auto kick has words", "Auto kick failed" in row, row)
    s.check("the honeypot has words", "Honeypot" in row, row)
    await s.ev("document.querySelector('tbody tr').click()")
    await s.need("the history drew", "document.querySelector('.drawer .timeline')")
    history = await s.ev("document.querySelector('.drawer .timeline').textContent")
    for words in ("Couldn't give the role", "Auto kick failed", "Posted in the honeypot"):
        s.check(f"history says {words}", words in history, history)
    s.check("no raw outcome word", "role_problem" not in history and "auto_kick_failed" not in history, history)


@scenario
async def a_reset_says_what_happened(s):
    await s.open("members")
    await s.ev("document.querySelector('tbody tr').click()")
    await s.need("the drawer opened", "[...document.querySelectorAll('.drawer button')].some((node) => node.textContent === 'Reset')")
    for answer, words, error in (({"ok": True, "told": True, "problem": None, "kept_hashes": False}, "Reset. They've been told.", False),
                                 ({"ok": True, "told": False, "problem": None, "kept_hashes": False}, "Reset, but they couldn't be told.", False),
                                 ({"ok": True, "told": False, "problem": "The role couldn't be removed.", "kept_hashes": False}, "The role couldn't be removed.", True)):
        await s.ev("__clearFakes(); __noToasts()")
        await s.fake("POST", "/reset$", body=answer)
        await s.click(".drawer button", "Reset")
        await s.need("the confirm opened", "document.querySelector('.dialog-foot .danger')")
        await s.click(".dialog-foot .danger")
        await s.need(f"the toast says {words}", f"[...document.querySelectorAll('{'.toast.error' if error else '.toast'}')].some((node) => node.textContent === {json.dumps(words)})")
        await s.need("the drawer is ready again", "[...document.querySelectorAll('.drawer button')].some((node) => node.textContent === 'Reset') && !document.querySelector('.drawer [aria-busy=true]')")


@scenario
async def messages_open_for_staff_who_cant_see_rules_and_post_only_what_is_saved(s):
    await s.open("analytics")
    await s.fake("GET", "/settings$", status=403, body={"error": "You don't have access to this page."})
    await s.open("appearance", ready="document.querySelector('.editor') || document.querySelector('.view .notice.bad')")
    s.check("Messages opens without Rules", await s.ev("!document.querySelector('.view .notice.bad')"))
    s.check("it asked its own route", await s.ev("__calls.some((call) => call.url.endsWith('/appearance') && call.method === 'GET')"))
    post = "[...document.querySelectorAll('button')].find((node) => node.textContent === 'Post it again')"
    s.check("Post it again starts enabled", await s.ev(f"{post}?.disabled === false"))
    await s.ev("__set([...document.querySelectorAll('.field')].find((node) => node.textContent.startsWith('Title')).querySelector('input'), 'Unsaved title')")
    s.check("unsaved edits disable it", await s.ev(f"{post}?.disabled"))
    s.check("it says why", "Save your changes" in await s.ev("document.querySelector('.view').innerText"))
    await s.click(".savebar button", "Discard")
    await asyncio.sleep(0.2)
    s.check("discarding enables it", await s.ev(f"{post}?.disabled === false"))
    await s.click(".segments[aria-label=Message] button", "Honeypot warning")
    await asyncio.sleep(0.1)
    s.check("a honeypot that's off has nothing to post", await s.ev(f"!{post}"))


@scenario
async def the_preview_names_who_the_real_message_will_name(s):
    other = "175928847299999999"
    await s.someone_else_changes(lambda doc: doc["messages"]["verification"].update(title="Their title", author=other))
    await s.open("appearance")
    line = "document.querySelector('.preview .subtext')?.textContent"
    s.check("someone else's message isn't credited to the viewer", "another staff member" in (await s.ev(line) or ""), await s.ev(line))
    await s.ev("__set([...document.querySelectorAll('.field')].find((node) => node.textContent.startsWith('Title')).querySelector('input'), 'My title')")
    s.check("the viewer's own change is credited to them", "staff_one" in (await s.ev(line) or ""), await s.ev(line))
    await s.click(".savebar button", "Discard")


@scenario
async def a_webhook_failure_reads_as_a_failure_and_revoking_asks_first(s):
    await s.open("analytics")
    await s.fake("GET", "/integrations$", body={"can_edit": True, "events": ["member.verified"], "webhooks": [
        {"id": 1, "url": "https://a.example/hook", "last_status": 0, "last_sent_at": 100, "events": []},
        {"id": 2, "url": "https://b.example/hook", "last_status": 500, "last_sent_at": 100, "events": []},
        {"id": 3, "url": "https://c.example/hook", "last_status": 204, "last_sent_at": 100, "events": []},
        {"id": 4, "url": "https://d.example/hook", "last_status": None, "last_sent_at": None, "events": []}],
        "api_keys": [{"id": "abc", "label": "Mine", "created_at": 1, "last_used_at": None}]})
    await s.open("integrations", ready="document.querySelector('.rule')")
    rows = await s.ev("[...document.querySelectorAll('.rule-title span')].map((node) => node.textContent)")
    s.check("no answer is a failure", "Failed" in rows[0] and "no answer" in rows[0], rows)
    s.check("a 500 is a failure", "Failed" in rows[1] and "500" in rows[1], rows)
    s.check("a 204 is fine", "Failed" not in rows[2] and "204" in rows[2], rows)
    s.check("never sent says so", "Failed" not in rows[3] and "Never" in rows[3], rows)
    await s.ev("__calls.length = 0")
    await s.click("button", "Revoke")
    await s.need("revoking asks first", "document.querySelector('.dialog')")
    s.check("nothing was revoked yet", await s.ev("__calls.filter((call) => call.method === 'DELETE').length") == 0)
    await s.click(".dialog-foot button", "Cancel")
    await asyncio.sleep(0.1)
    s.check("cancel revokes nothing", await s.ev("__calls.filter((call) => call.method === 'DELETE').length") == 0)
    await s.ev("__clearFakes()")
    await s.fake("GET", "/integrations$", body={"can_edit": False, "events": [], "webhooks": [], "api_keys": []})
    await s.open("integrations")
    s.check("the server's can_edit decides the forms", await s.ev("![...document.querySelectorAll('button')].some((node) => node.textContent === 'Add webhook')"))


@scenario
async def rules_search_looks_at_rules_and_says_when_nothing_matches(s):
    s.port.extra_roles.append({"id": "970000000000000890", "name": "Zebrafish", "color": 0, "position": 1, "managed": False, "mentionable": False})
    await s.open()
    box = "document.querySelector('.view > .toolbar input[type=search]')"
    await s.ev(f"__set({box}, 'zebrafish')")
    await asyncio.sleep(0.1)
    s.check("a role name in a picker matches nothing", await s.ev("[...document.querySelectorAll('.rule, .panel')].every((node) => !node.offsetParent)"))
    s.check("nothing matching says so", await s.ev("[...document.querySelectorAll('.view p')].some((node) => node.textContent === 'No rule matches.' && node.offsetParent)"))
    await s.ev(f"__set({box}, 'help desk')")
    await asyncio.sleep(0.1)
    s.check("a rule's own words match", await s.ev("!document.getElementById('item-helpdesk').hidden && document.getElementById('item-vpn').hidden"))
    s.check("the empty note goes", await s.ev("[...document.querySelectorAll('.view p')].every((node) => node.textContent !== 'No rule matches.' || !node.offsetParent)"))


@scenario
async def access_says_why_nothing_was_added(s):
    await s.open("permissions")
    await s.click("#item-command-verify-user button", "Edit")
    await s.need("the rule opened", "document.querySelector('.dialog input[placeholder=\"Member ID\"]')")
    box = "document.querySelector('.dialog input[placeholder=\"Member ID\"]')"
    await s.ev(f"__set({box}, '123')")
    await s.click(".dialog button", "Add member")
    await s.need("a bad ID says so", "[...document.querySelectorAll('.toast.error')].some((node) => node.textContent.includes('15 to 21'))")
    await s.ev(f"__set({box}, {json.dumps(OLD_USER)}); {box}.focus()")
    await s.press("Enter")
    await s.need("Enter adds the member", f"document.querySelector('.dialog').textContent.includes({json.dumps('Member: ' + OLD_USER)})")
    s.check("the box empties", await s.ev(f"{box}.value") == "")
    await s.ev("__noToasts()")
    await s.ev(f"__set({box}, {json.dumps(OLD_USER)})")
    await s.click(".dialog button", "Add member")
    await s.need("a duplicate says so", "[...document.querySelectorAll('.toast.error')].some((node) => node.textContent.includes('already'))")
    picker = "document.querySelector('.dialog select[aria-label=\"Add a role\"]')"
    await s.ev(f"__set({picker}, {json.dumps(VERIFIED_ROLE)})")
    s.check("the role picker empties for the next one", await s.ev(f"{picker}?.value") == "")
    await s.click(".dialog-foot button", "Done")
    await s.click(".savebar button", "Discard")


@scenario
async def a_locked_page_is_said_to_be_locked(s):
    await s.open("analytics")
    locked = {"analytics": {"view": True, "edit": True}, "settings": {"view": False, "edit": False}}
    await s.fake("GET", f"/guilds/{GUILD}$", merge={"pages": locked}, **{"pass": True})
    await s.open("analytics")
    s.check("a locked page isn't a link", await s.ev("!document.querySelector('.nav a[data-page=settings]') && !document.querySelector('.nav a[data-page=members]')"))
    s.check("it says it's locked", await s.ev("document.querySelector('.nav [data-page=settings]')?.getAttribute('aria-disabled')") == "true")
    s.check("the lock is a drawing", await s.ev("Boolean(document.querySelector('.nav [data-page=settings] svg'))"))
    s.check("screen readers hear it", "locked" in await s.ev("document.querySelector('.nav [data-page=settings]')?.textContent"))
    await s.open("settings", ready="document.querySelector('.view .notice') || document.querySelector('.kpi')")
    s.check("the address of a locked page says no", await s.ev("document.querySelector('.view .notice')?.textContent") == "You don't have access to this page.")
    s.check("the address isn't quietly another page", await s.ev("!document.querySelector('.kpi')"))
    await s.ev("dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))")
    await s.wait("document.querySelector('.palette input')", 2)
    await s.ev("__set(document.querySelector('.palette input'), 'Cooldown')")
    s.check("search doesn't offer rules on a locked page", await s.ev("!document.querySelector('.palette li button')"))
    await s.press("Escape")


@scenario
async def a_refused_key_stays_in_the_box_with_its_reason(s):
    await s.open()
    await s.switch("external")
    await s.need("the box appeared", "document.querySelector('#item-external input[type=password]')")
    box = "document.querySelector('#item-external input[type=password]')"
    s.check("password managers leave it alone", await s.ev(f"{box}.autocomplete") == "new-password")
    await s.ev(f"__set({box}, 'bad-key-1234')")
    await s.switch("cooldown")
    await asyncio.sleep(0.1)
    s.check("a pasted key survives a redraw", await s.ev(f"{box}.value") == "bad-key-1234")
    await s.fake("PUT", "/lookup-key$", status=400, body={"error": "proxycheck.io doesn't recognize that key."})
    await s.click("#item-external button", "Save key")
    await s.need("the reason shows by the box", "document.querySelector('#item-external .help.error')?.textContent === \"proxycheck.io doesn't recognize that key.\"")
    s.check("the key is still there", await s.ev(f"{box}.value") == "bad-key-1234")
    s.check("no key was claimed saved", await s.ev(f"!{box}.placeholder.includes('ending')") and "Key saved." not in await s.toasts())
    await s.ev("__clearFakes()")
    await s.fake("PUT", "/lookup-key$", body={"ok": True, "lookup_key": {"saved": True, "ending": "1234"}, "warning": "Saved, but proxycheck.io couldn't be reached to check it."})
    await s.click("#item-external button", "Save key")
    await s.need("a warning is a toast", "[...document.querySelectorAll('.toast')].some((node) => node.textContent.startsWith('Saved, but proxycheck.io'))")
    s.check("the box empties", await s.ev(f"{box}.value") == "")
    s.check("the reason goes", await s.ev("!document.querySelector('#item-external .help.error')"))
    s.check("it shows the ending", "1234" in await s.ev(f"{box}.placeholder"))
    await s.click(".savebar button", "Discard")


@scenario
async def health_shows_what_the_server_reports(s):
    await s.open("analytics")
    await s.fake("GET", "/health$", body={"healthy": False, "issues": [{"title": "One thing", "fix": "Fix it"}], "ok": [], "needs": {}, "lists_loaded": True, "lists_missing": ["a"], "checked_at": 1, "public_bot": False,
                                          "lookup_without_key": False, "lookup_refused": {"at": 100, "message": "Key disabled"}, "lists": [{"name": "Tor exits", "age_days": 1, "rows": 1000}, {"name": "VPNs", "age_days": None, "rows": 0}],
                                          "notices": [{"title": "Everyone can read", "fix": "Hide those channels."}, {"title": "The outside VPN lookup isn't answering", "fix": "proxycheck.io said: Key disabled"},
                                                      {"title": "Some network lists haven't downloaded", "fix": "Not downloaded yet: VPNs."}]})
    await s.open("health")
    text = await s.ev("document.querySelector('.view').textContent")
    s.check("one thing is singular", "1 thing needs fixing." in text, text)
    s.check("a list missing is said once, by its notice", "Some network lists haven't downloaded" in text and "hasn't downloaded yet" not in text, text)
    s.check("a refused key is said once, by its notice", text.count("Key disabled") == 1, text)
    s.check("a notice shows with its fix", "Everyone can read" in text and "Hide those channels." in text, text)
    s.check("lists show their age", "Tor exits" in text and "1,000" in text and "1 day old" in text, text)
    s.check("a list never downloaded says so", "VPNs" in text and "not downloaded" in text, text)
    s.check("a notice doesn't count as an issue", await s.ev("document.querySelectorAll('.rule').length") == 1)
    await s.ev("__clearFakes()")
    await s.fake("GET", "/health$", body={"healthy": True, "issues": [], "ok": [], "needs": {}, "lists_loaded": True, "lists_missing": [], "checked_at": 1})
    await s.open("health")
    s.check("an older server's answer still draws", await s.ev("!document.querySelector('.view .notice.bad')"))


@scenario
async def plurals_read_right_on_the_pages(s):
    await s.someone_else_changes(lambda doc: doc["checks"]["geogate"].update(enabled=True, countries=["US"]))
    await s.open()
    s.check("one country is singular", "1 country" in await s.ev("document.querySelector('#item-geogate .rule-body').textContent"))
    await s.click("#item-geogate button", "Choose countries")
    await s.need("the picker drew", "document.querySelector('.dialog p.muted')?.textContent.includes('picked')", 10)
    s.check("the picker's count is singular", (await s.ev("document.querySelector('.dialog p.muted').textContent")).startswith("1 country picked."))
    await s.click(".dialog-foot button", "Cancel")
    await s.fake("GET", "/members\\?", body={"total": 1, "page": 1, "size": 20, "members": [{"user_id": OLD_USER, "username": "x", "avatar": None, "status": "pending", "last_at": 0, "results": []}]})
    await s.open("members")
    s.check("one member is singular", (await s.ev("document.querySelector('.pager span').textContent")).startswith("1 member, page 1"))
    await s.ev("__clearFakes()")
    await s.open()
    await s.fake("POST", "/settings/preview$", body={"days": 30, "attempts": 1, "blocked_then": 1, "blocked_now": 0, "newly_blocked": 1, "newly_passed": 1, "by_check": [], "not_replayed": 1})
    await s.click("button", "Preview on the last 30 days")
    await s.need("the preview opened", "document.querySelector('.dialog p')")
    text = await s.ev("document.querySelector('.dialog').textContent")
    s.check("one attempt is singular", "Replayed 1 attempt " in text, text)
    s.check("one member is singular in the preview", "1 member who got in would be stopped" in text and "1 who was stopped would get in" in text, text)
    s.check("attempts it couldn't replay are counted", "1 attempt where a country rule" in text, text)
    await s.click(".dialog-foot button", "Close")


@scenario
async def appeals_and_the_audit_log_read_like_people_wrote_them(s):
    await s.open("analytics")
    await s.fake("GET", "/appeals\\?status=open", body={"appeals": [{"id": 1, "user_id": OLD_USER, "username": "x", "avatar": None, "status": "open", "text": "t", "created_at": 1, "check_id": "vpn"}]})
    await s.fake("GET", "/appeals\\?status=denied", body={"appeals": [{"id": 2, "user_id": OLD_USER, "username": "x", "avatar": None, "status": "denied", "text": "t", "created_at": 1, "check_id": "vpn", "decided_at": 100, "decided_by": STAFF, "note": "Not this time"}] * 100})
    await s.open("appeals", ready="document.querySelector('.view .panel')")
    await s.fake("POST", "/appeals/1$", body={"ok": True, "problem": None, "told": False})
    await s.click("button", "Approve")
    await s.need("a member who wasn't told isn't said to be", "[...document.querySelectorAll('.toast')].some((node) => node.textContent === \"Decided, but the member couldn't be told.\")")
    await s.ev("__set(document.querySelector('select[aria-label=Status]'), 'denied')")
    await s.need("decided appeals draw", "document.querySelector('.view').textContent.includes('Not this time')")
    text = await s.ev("document.querySelector('.view').textContent")
    s.check("no raw status", "denied " not in text and "Turned down" in text, text[:300])
    s.check("who decided", STAFF in text, text[:300])
    s.check("the note", "Not this time" in text, text[:300])
    s.check("a full page says it's cut", "newest 100" in text, text[-200:])
    await s.ev("__clearFakes()")
    await s.fake("GET", "/audit$", body={"entries": [
        {"at": 1, "actor_id": None, "actor_name": None, "kind": "raid_stop", "detail": {"why": "The timer ran out"}},
        {"at": 2, "actor_id": STAFF, "actor_name": "staff_one", "kind": "settings", "detail": {}},
        {"at": 3, "actor_id": STAFF, "actor_name": "staff_one", "kind": "settings", "detail": {"changes": [{"path": "a", "before": 1, "after": 2}], "total": 42}},
        {"at": 4, "actor_id": None, "actor_name": "Deleted account 12345678", "kind": "data_deleted", "detail": {"nested": {"a": 1}, "list": [1, {"b": 2}], "told": True}},
        {"at": 5, "actor_id": STAFF, "actor_name": "staff_one", "kind": "webhook_added", "detail": {"host": "a.example"}}]})
    await s.open("audit")
    s.check("a row with no changes doesn't blank the page", await s.ev("document.querySelectorAll('.timeline > li').length") == 5)
    text = await s.ev("document.querySelector('.view').textContent")
    s.check("no [object Object]", "[object" not in text, text)
    s.check("a deletion has a name", "Deleted a member's data" in text, text)
    s.check("nested values read", '"a":1' in text, text)
    s.check("a yes reads as yes", "told: yes" in text, text)
    s.check("a timer's raid end has a name", "Ended raid mode" in text and "The timer ran out" in text, text)
    s.check("a long change list says how many", "42" in text, text)
    s.check("a new kind still reads", "Webhook added" in text, text)


@scenario
async def the_honeypot_action_says_what_it_does(s):
    await s.open()
    await s.switch("honeypot")
    await s.need("the row opened", "document.querySelector('#item-honeypot select')")
    picker = "[...document.querySelectorAll('#item-honeypot select')].find((node) => [...node.options].some((option) => option.value === 'softban'))"
    seen = {}
    for action in ("log", "timeout", "kick", "softban", "ban"):
        await s.ev(f"__set({picker}, '{action}')")
        await asyncio.sleep(0.05)
        seen[action] = await s.ev(f"{picker}.closest('.field').querySelector('.help')?.textContent") or ""
    s.check("log touches no account", "Nothing happens to the account" in seen["log"], seen)
    s.check("timeout times out", "time them out" in seen["timeout"], seen)
    s.check("kick kicks", "kick them" in seen["kick"], seen)
    s.check("softban explains itself", "ban, then unban" in seen["softban"] and "last hour" in seen["softban"], seen)
    s.check("ban bans", "ban them" in seen["ban"], seen)
    s.check("bots are named", all("bot" in line.lower() for line in seen.values()), seen)
    await s.click(".savebar button", "Discard")


@scenario
async def the_keyboard_stays_put_across_a_redraw(s):
    await s.open()
    await s.ev("document.querySelector('#item-autokick .switch input').focus()")
    await s.press(" ")
    await asyncio.sleep(0.1)
    s.check("Space toggled it", await s.ev("document.querySelector('#item-autokick .switch input').checked"))
    s.check("focus stayed on the switch", await s.ev("document.activeElement === document.querySelector('#item-autokick .switch input')"), await s.ev("document.activeElement.outerHTML.slice(0, 120)"))
    await s.press(" ")
    await asyncio.sleep(0.1)
    s.check("and back", await s.ev("document.activeElement === document.querySelector('#item-autokick .switch input')"))
    await s.ev("document.querySelector('#item-core .segments button.button').focus()")
    await s.press("Enter")
    await asyncio.sleep(0.1)
    s.check("a segment keeps focus", await s.ev("document.activeElement === document.querySelector('#item-core .segments button.button')"), await s.ev("document.activeElement.outerHTML.slice(0, 120)"))
    await s.ev("document.querySelector('#item-core .segments button.web').click()")
    await s.ev("document.querySelector('#item-vpn .segments button.watch').focus()")
    await s.press("Enter")
    await asyncio.sleep(0.1)
    s.check("a segment that redraws nothing keeps focus", await s.ev("document.activeElement === document.querySelector('#item-vpn .segments button.watch')"), await s.ev("document.activeElement.outerHTML.slice(0, 120)"))
    await s.ev("[...document.querySelectorAll('button.preset')].find((node) => node.textContent.includes('Gentle')).focus()")
    await s.press("Enter")
    await s.need("the preset applied", "document.querySelector('.preset.on')?.textContent.includes('Gentle')")
    s.check("a preset button keeps focus", await s.ev("document.activeElement.matches('button.preset') && document.activeElement.textContent.includes('Gentle')"), await s.ev("document.activeElement.outerHTML.slice(0, 120)"))
    await s.click(".savebar button", "Discard")
    await s.open("appearance")
    await s.ev("__set(document.querySelector('select[aria-label=Font]'), '12')")
    await s.need("swatches drew", "document.querySelector('.swatch')")
    await s.ev("document.querySelectorAll('.swatch')[2].focus()")
    name = await s.ev("document.activeElement.getAttribute('aria-label')")
    await s.press("Enter")
    await asyncio.sleep(0.1)
    s.check("a swatch keeps focus", await s.ev("document.activeElement.getAttribute('aria-label')") == name, await s.ev("document.activeElement.outerHTML.slice(0, 120)"))
    await s.ev("[...document.querySelectorAll('button')].find((node) => node.title === 'Default').focus()")
    await s.press("Enter")
    await asyncio.sleep(0.1)
    s.check("a picture button keeps focus", await s.ev("document.activeElement.title") == "Default", await s.ev("document.activeElement.outerHTML.slice(0, 120)"))
    await s.click(".savebar button", "Discard")


@scenario
async def every_picker_has_its_own_name(s):
    await s.open()
    await s.switch("helpdesk")
    await s.switch("honeypot")
    await s.switch("unverified")
    await s.need("the help desk opened", "document.querySelector('#item-helpdesk select')")
    names = await s.ev("[...document.querySelectorAll('.view select')].map((node) => node.getAttribute('aria-label'))")
    s.check("every select is named", all(names), names)
    s.check("none is just Role or Channel", not any(name in ("Role", "Channel") for name in names), names)
    s.check("the verified role says so", any((name or "").startswith("Verified role") for name in names), names)
    s.check("the support role says so", "Support role" in names, names)
    await s.click("#item-logs button", "Choose channels")
    await s.need("logs opened", "document.querySelector('.dialog select')")
    names = await s.ev("[...document.querySelectorAll('.dialog select')].map((node) => node.getAttribute('aria-label'))")
    s.check("every log picker is named for its module", "Staff actions" in names and "Every category" in names, names)
    await s.click(".dialog-foot button", "Done")
    await s.click(".savebar button", "Discard")


@scenario
async def a_dialog_holds_the_keyboard_and_gives_it_back(s):
    await s.open()
    await s.ev("document.querySelector('#item-logs button').focus()")
    await s.ev("document.querySelector('#item-logs button').click()")
    await s.need("the dialog opened", "document.querySelector('.dialog select')")
    s.check("the page behind is out of reach", await s.ev("document.getElementById('root').inert"))
    s.check("focus went inside", await s.ev("document.querySelector('.dialog').contains(document.activeElement)"))
    await s.click(".dialog-foot button", "Done")
    await asyncio.sleep(0.1)
    s.check("the page is back", await s.ev("!document.getElementById('root').inert"))
    s.check("focus went back to the opener", await s.ev("document.activeElement.textContent") == "Choose channels", await s.ev("document.activeElement.outerHTML.slice(0, 100)"))
    await s.ev("dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }))")
    await s.need("the palette opened", "document.querySelector('.palette input')")
    s.check("the palette is modal", await s.ev("document.querySelector('.palette').getAttribute('aria-modal')") == "true" and await s.ev("document.getElementById('root').inert"))
    s.check("the results are a list box", await s.ev("document.querySelector('.palette ul').getAttribute('role')") == "listbox" and await s.ev("document.querySelector('.palette li button').getAttribute('role')") == "option")
    active = await s.ev("document.querySelector('.palette input').getAttribute('aria-activedescendant')")
    s.check("the selected result is announced", active and active == await s.ev("document.querySelector('.palette li button[aria-selected=true]')?.id"))
    await s.ev("document.querySelector('.palette li button').focus()")
    await s.press("Escape")
    s.check("Escape works from a result", await s.ev("!document.querySelector('.palette')"))
    s.check("the palette gives the page back", await s.ev("!document.getElementById('root').inert"))


@scenario
async def the_small_screen_menu_opens_and_closes(s):
    await s.cdp.call("Emulation.setDeviceMetricsOverride", width=700, height=800, deviceScaleFactor=1, mobile=False)
    await s.open("analytics")
    toggle = "document.querySelector('.menu-toggle')"
    s.check("closed links can't take focus", await s.ev("getComputedStyle(document.getElementById('side')).visibility") == "hidden")
    await s.ev(f"{toggle}.click()")
    await s.wait("getComputedStyle(document.getElementById('side')).visibility === 'visible'", 2)
    s.check("open says so", await s.ev(f"{toggle}.getAttribute('aria-expanded')") == "true")
    s.check("focus moved into the menu", await s.ev("document.getElementById('side').contains(document.activeElement)"))
    await s.press("Escape")
    s.check("Escape closes it", await s.ev("!document.getElementById('side').classList.contains('open')"))
    s.check("focus returned to the button", await s.ev(f"document.activeElement === {toggle}"))
    await s.ev(f"{toggle}.click()")
    await s.ev("document.querySelector('.scrim')?.click()")
    s.check("the backdrop closes it", await s.ev("!document.getElementById('side').classList.contains('open')"))
    await s.ev(f"{toggle}.click()")
    s.check("a backdrop shows", await s.ev("getComputedStyle(document.querySelector('.scrim')).display") != "none")
    await s.click("#side button", "Close menu")
    s.check("the menu has its own close button", await s.ev("!document.getElementById('side').classList.contains('open')"))


@scenario
async def the_earlier_account_offers_only_what_acts_on_it(s):
    await s.open()
    await s.ev("(() => { const box = document.querySelector('#item-alt_account .switch input'); if (!box.checked) box.click(); })()")
    await s.need("the options opened", "document.querySelector('#item-alt_account .rule-body')")
    labels = await s.ev("[...document.querySelectorAll('#item-alt_account .field')].find((node) => node.textContent.startsWith('The earlier account')).querySelector('.segments').textContent")
    s.check("Watch, Kick and Ban", labels == "WatchKickBan", labels)
    other = await s.ev("[...document.querySelectorAll('#item-alt_account .field')].find((node) => node.textContent.startsWith('Alt of a member')).querySelector('.segments').textContent")
    s.check("the alt itself still has all four", other == "WatchDenyKickBan", other)


CONFIDENCE_WORDS = {"possible": "Any match",
                    "likely": "The same connection, or stronger",
                    "confirmed": "Only the same browser cookie"}


@scenario
async def the_alt_rule_warns_when_its_evidence_cant_reach_its_floor(s):
    await s.open()
    row = "#item-alt_account"
    await s.ev(f"(() => {{ const box = document.querySelector('{row} .switch input'); if (!box.checked) box.click(); }})()")
    await s.need("the options opened", f"document.querySelector('{row} .rule-body')")
    picker = f"[...document.querySelectorAll('{row} .field')].find((node) => node.textContent.startsWith('Act when')).querySelector('select')"
    labels = await s.ev(f"[...{picker}.options].map((node) => node.textContent)")
    s.check("the labels say what each level is", labels == list(CONFIDENCE_WORDS.values()), labels)
    warn = f"document.querySelector('{row} .evidence-warning')?.textContent"
    box = lambda index: f"document.querySelectorAll('{row} .chips input')[{index}]"
    s.check("all three evidence kinds raise no warning", not await s.ev(warn), await s.ev(warn))
    await s.ev(f"{box(0)}.click()")
    await asyncio.sleep(0.05)
    s.check("no cookie still reaches any match", not await s.ev(warn), await s.ev(warn))
    await s.ev(f"__set({picker}, 'confirmed')")
    await asyncio.sleep(0.05)
    s.check("no cookie can't reach the cookie's level", "nothing reaches that level" in (await s.ev(warn) or ""), await s.ev(warn))
    await s.ev(f"__set({picker}, 'possible')")
    await asyncio.sleep(0.05)
    await s.ev(f"{box(1)}.click()")
    await asyncio.sleep(0.05)
    s.check("a connection alone reaches any match", not await s.ev(warn), await s.ev(warn))
    await s.ev(f"{box(2)}.click()")
    await asyncio.sleep(0.05)
    s.check("no evidence at all", "can't match anyone" in (await s.ev(warn) or ""), await s.ev(warn))
    await s.click(".savebar button", "Discard")


@scenario
async def alerts_offer_only_what_pings_there(s):
    await s.someone_else_changes(lambda doc: (doc["core"]["logs"]["modules"].update(raid=LOG_CHANNEL, appeals=LOG_CHANNEL, honeypot=LOG_CHANNEL), doc["core"]["alerts"].update(enabled=True, roles={"raid": VERIFIED_ROLE})))
    await s.open()
    await s.click("#item-alerts button", "Customize")
    await s.need("alerts opened", "document.querySelector('.dialog select')")
    names = await s.ev("[...document.querySelectorAll('.dialog .field > span:first-child')].map((node) => node.textContent)")
    s.check("Raid and Appeals have their own role settings", "Raid alerts" not in names and "Appeals" not in names, names)
    s.check("the honeypot stays", "Honeypot" in names, names)
    await s.click(".dialog-foot button", "Done")
    count = await s.ev("document.querySelector('#item-alerts .rule-title span').textContent")
    s.check("the count leaves them out", count.startswith("0 modules"), count)


@scenario
async def a_saved_command_allow_is_offered_to_discord(s):
    await s.open("permissions", ready="document.getElementById('item-discord-verify-user')")
    await s.click("#item-command-verify-user button", "Edit")
    await s.need("the rule opened", "document.querySelector('.dialog select')")
    await s.ev(f"__set(document.querySelector('.dialog select[aria-label=\"Add a role\"]') ?? document.querySelector('.dialog select'), {json.dumps(VERIFIED_ROLE)})")
    await s.click(".dialog-foot button", "Done")
    await s.click(".savebar button", "Save changes")
    await s.need("the offer appears", "document.querySelector('.dialog')?.textContent.includes('/verify-user')")
    s.check("nothing is on Discord's side until asked", "Verified: allowed" not in await s.ev("document.getElementById('item-discord-verify-user').textContent"))
    s.check("the button says what it does", await s.ev("[...document.querySelectorAll('.dialog-foot button')].some((node) => node.textContent === 'Allow on Discord')"))
    s.check("the offer says Discord will ask", "approve the change with your own account" in await s.ev("document.querySelector('.dialog').textContent"))
    await s.fake("POST", r"/permissions/discord$", body={"authorize": "/__dev/blank"}, delay=400)
    await s.click(".dialog-foot button", "Allow on Discord")
    sent = await s.ev("JSON.stringify(window.__calls ?? [])")
    s.check("the press sends that allow", VERIFIED_ROLE in sent, sent)
    await s.need("the press goes to Discord", "location.pathname === '/__dev/blank'")
    await s.open("permissions", ready="document.getElementById('item-discord-verify-user')")
    await s.click("#item-command-reset-user button", "Edit")
    await s.need("the other rule opened", "document.querySelector('.dialog input[type=checkbox]')")
    await s.ev("document.querySelector('.dialog input[type=checkbox]').click()")
    await s.click(".dialog-foot button", "Done")
    await s.click(".savebar button", "Save changes")
    await s.need("saved", "!document.querySelector('.savebar')")
    await asyncio.sleep(0.2)
    s.check("a save with no new allow offers nothing", await s.ev("!document.querySelector('.dialog')"))


@scenario
async def the_active_tag_follows_each_edit(s):
    await s.someone_else_changes(lambda doc: doc.update(settings.apply_preset(doc, "standard")))
    await s.open()
    active = "document.querySelector('.preset.on')?.textContent"
    s.check("starts on Standard", "Standard" in await s.ev(active), await s.ev(active))
    await s.ev("document.querySelector('#item-avatar .switch input').click()")
    await asyncio.sleep(0.05)
    s.check("a toggle moves it to Custom", "Custom" in await s.ev(active), await s.ev(active))
    await s.ev("document.querySelector('#item-avatar .switch input').click()")
    await asyncio.sleep(0.05)
    s.check("undoing moves it back", "Standard" in await s.ev(active), await s.ev(active))
    await s.ev("document.querySelector('#item-account_age input[type=number]').focus()")
    await s.ev("__set(document.querySelector('#item-account_age input[type=number]'), '8')")
    await asyncio.sleep(0.05)
    s.check("typing a number moves it", "Custom" in await s.ev(active), await s.ev(active))
    s.check("the box keeps focus", await s.ev("document.activeElement === document.querySelector('#item-account_age input[type=number]')"))
    await s.ev("__set(document.querySelector('#item-account_age input[type=number]'), '7')")
    await asyncio.sleep(0.05)
    s.check("back again", "Standard" in await s.ev(active), await s.ev(active))
    s.check("nothing unsaved after undoing", await s.ev("__dirty()") == [], await s.ev("__dirty()"))


@scenario
async def the_page_names_a_preset_exactly_as_the_server_does(s):
    await s.open()
    base = json.loads(json.dumps(await s.saved()))
    documents = []
    for name, table in catalog.PRESETS.items():
        document = settings.apply_preset(base, name)
        documents.append(document)
        for flip in (lambda d: d["core"]["auto_kick"].update(enabled=not d["core"]["auto_kick"]["enabled"]),
                     lambda d: d["core"]["auto_kick"].update(minutes=d["core"]["auto_kick"]["minutes"] + 1),
                     lambda d: d["core"].update(auto_dm=False),
                     lambda d: d["core"]["notify_closed_dms"].update(seconds=31),
                     lambda d: d["core"]["notify_closed_dms"].update(enabled=False),
                     lambda d: d["core"].update(cooldown={"enabled": True, "seconds": 5}),
                     lambda d: d["checks"]["mfa"].update(enabled=not d["checks"]["mfa"]["enabled"]),
                     lambda d: d["checks"]["geogate"].update(enabled=True),
                     lambda d: d["checks"]["alt_account"]["methods"].update(ip=False),
                     lambda d: d["checks"]["alt_account"].update(min_confidence="possible"),
                     lambda d: d["checks"]["alt_account"].update(methods={"ip": True, "fingerprint": True, "cookie": True})):
            changed = json.loads(json.dumps(document))
            flip(changed)
            documents.append(changed)
        for check_id, (enabled, action, extras) in table["checks"].items():
            changed = json.loads(json.dumps(document))
            changed["checks"][check_id]["enabled"] = not enabled
            documents.append(changed)
            changed = json.loads(json.dumps(document))
            changed["checks"][check_id]["action"] = "watch" if action != "watch" else "deny"
            documents.append(changed)
            for key, value in extras.items():
                if isinstance(value, (int, str)):
                    changed = json.loads(json.dumps(document))
                    changed["checks"][check_id][key] = value + 1 if isinstance(value, int) else "watch"
                    documents.append(changed)
    wanted = [settings.detect_preset(document) for document in documents]
    found = await s.ev(f"""(async () => {{
      const {{ detectPreset }} = await import('/static/dash/settings.js');
      return {json.dumps(documents)}.map((document) => detectPreset(document));
    }})()""")
    s.check(f"{len(documents)} documents agree", found == wanted, None if found is None else [(index, wanted[index], found[index]) for index in range(len(wanted)) if wanted[index] != found[index]][:6])
    s.check("the set covers every answer", {"custom", "gentle", "standard", "strict"} <= set(wanted), set(wanted))


@scenario
async def a_stale_save_keeps_the_draft_and_offers_reload(s):
    await s.open()
    await s.switch("cooldown")
    await s.someone_else_changes(lambda doc: doc["raid"].update(joins=33))
    await s.click(".savebar button", "Save changes")
    await s.need("the conflict shows", "document.querySelector('.dialog')?.textContent.includes('Someone else changed')")
    s.check("the other person's change stands", (await s.saved())["raid"]["joins"] == 33 and (await s.saved())["core"]["cooldown"]["enabled"] is False)
    s.check("the save sent its base", await s.ev("JSON.parse(__puts('/settings')[0].body).base") is not None)
    await s.click(".dialog-foot button", "Keep editing")
    await asyncio.sleep(0.1)
    s.check("the draft is kept", await s.ev("document.querySelector('#item-cooldown .switch input').checked") and await s.ev("__dirty()") == ["settings"])
    await s.click(".savebar button", "Save changes")
    await s.need("it asks again", "document.querySelector('.dialog')?.textContent.includes('Someone else changed')")
    await s.click(".dialog-foot button", "Reload")
    await s.need("reloading shows their change", "document.querySelectorAll('#item-raid input[type=number]')[0]?.value === '33'")
    s.check("reloading drops the draft", await s.ev("!document.querySelector('#item-cooldown .switch input').checked") and await s.ev("__dirty()") == [])
    await s.switch("cooldown")
    await s.click(".savebar button", "Save changes")
    await s.need("the next save goes through", "!document.querySelector('.savebar')")
    s.check("it landed beside their change", (await s.saved())["raid"]["joins"] == 33 and (await s.saved())["core"]["cooldown"]["enabled"] is True)
    await s.switch("cooldown")
    await s.click(".savebar button", "Save changes")
    await s.need("a second save uses the new revision", "!document.querySelector('.savebar')")
    s.check("no false conflict", await s.ev("!document.querySelector('.dialog')"))
    await s.switch("cooldown")
    await s.ev("__calls.length = 0")
    await s.fake("PUT", "/settings$", delay=400, times=1, **{"pass": True})
    await s.ev("[...document.querySelectorAll('.savebar button')].find((node) => node.textContent === 'Save changes').click(); [...document.querySelectorAll('.savebar button')].find((node) => node.textContent === 'Save changes').click()")
    await s.need("a double press saves", "!document.querySelector('.savebar')")
    await asyncio.sleep(0.3)
    s.check("a double press sends one save", await s.ev("__puts('/settings').length") == 1, await s.ev("__puts('/settings').length"))
    s.check("a double press raises no conflict", await s.ev("!document.querySelector('.dialog')"))
    await s.switch("cooldown")
    await s.click(".nav a", "Messages")
    await s.need("moved away", "document.querySelector('.editor')")
    await s.someone_else_changes(lambda doc: doc["raid"].update(joins=44))
    await s.click(".nav a", "Rules")
    await s.need("back on Rules", "document.getElementById('item-cooldown')")
    await s.click(".savebar button", "Save changes")
    await s.need("a draft kept across pages still conflicts", "document.querySelector('.dialog')?.textContent.includes('Someone else changed')")
    s.check("their change stands", (await s.saved())["raid"]["joins"] == 44)
    await s.click(".dialog-foot button", "Reload")


@scenario
async def messages_and_access_saves_check_their_revision_too(s):
    await s.open("appearance")
    title = "[...document.querySelectorAll('.field')].find((node) => node.textContent.startsWith('Title'))?.querySelector('input')"
    await s.ev(f"__set({title}, 'Mine')")
    await s.someone_else_changes(lambda doc: doc["messages"]["verification"].update(title="Theirs"))
    await s.click(".savebar button", "Save changes")
    await s.need("Messages conflicts", "document.querySelector('.dialog')?.textContent.includes('Someone else changed')")
    s.check("their title stands", (await s.saved())["messages"]["verification"]["title"] == "Theirs")
    s.check("the draft is kept", await s.ev(f"{title}.value") == "Mine")
    await s.click(".dialog-foot button", "Reload")
    await s.need("reloading shows theirs", f"{title}?.value === 'Theirs'")
    await s.ev(f"__set({title}, 'Mine now')")
    await s.click(".savebar button", "Save changes")
    await s.need("Messages saves", "!document.querySelector('.savebar')")
    s.check("the Messages save sent its base", await s.ev("Boolean(JSON.parse(__puts('/appearance').at(-1).body).base)"))
    await s.open("permissions")
    await s.click("#item-command-verify-user button", "Edit")
    await s.need("the rule opened", "document.querySelector('.dialog input[type=checkbox]')")
    await s.ev("document.querySelector('.dialog input[type=checkbox]').click()")
    await s.click(".dialog-foot button", "Done")
    await s.someone_else_changes(lambda doc: doc["permissions"]["commands"].update({"reset-user": {"required": ["ban_members"], "overrides": []}}))
    await s.click(".savebar button", "Save changes")
    await s.need("Access conflicts", "document.querySelector('.dialog')?.textContent.includes('Someone else changed')")
    s.check("the Access save sent its base", await s.ev("Boolean(JSON.parse(__puts('/permissions').at(-1).body).base)"))
    await s.click(".dialog-foot button", "Reload")
    await s.need("reloading drops the draft", "document.querySelector('[id^=item-page-]') && !document.querySelector('.savebar')")
    await s.someone_else_changes(lambda doc: doc["raid"].update(joins=55))
    await s.click("#item-command-verify-user button", "Edit")
    await s.need("the rule opened again", "document.querySelector('.dialog input[type=checkbox]')")
    await s.ev("document.querySelector('.dialog input[type=checkbox]').click()")
    await s.click(".dialog-foot button", "Done")
    await s.click(".savebar button", "Save changes")
    await s.need("a Rules change doesn't conflict with Access", "!document.querySelector('.savebar')")


@scenario
async def pages_that_pick_nothing_need_no_roles_or_channels(s):
    await s.open("analytics")
    await s.fake("GET", f"/guilds/{GUILD}$", merge={"roles": [], "channels": []}, **{"pass": True})
    for page in ("analytics", "members", "appeals", "health", "audit", "integrations", "appearance"):
        await s.open(page)
        s.check(f"{page} draws", await s.ev("!document.querySelector('.view .notice.bad')"), await s.ev("document.querySelector('.view .notice.bad')?.textContent"))
    await s.ev("__clearFakes()")
    await s.fake("GET", f"/guilds/{GUILD}$", merge={"setup_done": False, "roles": [], "channels": [], "pages": {"audit": {"view": True, "edit": False}}}, **{"pass": True})
    await s.open("audit", ready="document.querySelector('.view .notice')")
    s.check("a viewer who can't finish setup is told", "finish" in await s.ev("document.querySelector('.view .notice')?.textContent"))
    s.check("no pickers with nothing in them", await s.ev("!document.querySelector('.view select')"))


@scenario
async def a_preview_picture_loads_only_from_discord_unless_asked(s):
    image = "[...document.querySelectorAll('.field')].find((node) => node.textContent.startsWith('Image link')).querySelector('input')"
    tracker = "https://tracker.invalid/p.png"
    await s.someone_else_changes(lambda doc: doc["messages"]["help_desk"].update(image="https://cdn.discordapp.com/saved.png"))
    await s.open("appearance", search="#help_desk")
    s.check("a saved picture on Discord shows without a wait", await s.ev("Boolean(document.querySelector(\'.preview img[src=\"https://cdn.discordapp.com/saved.png\"]\'))"))
    await s.someone_else_changes(lambda doc: doc["messages"]["verification"].update(image=tracker))
    await s.open("appearance")
    await asyncio.sleep(0.8)
    s.check("a saved picture elsewhere doesn't load by itself", not s.requests("tracker.invalid"), s.requests("tracker.invalid"))
    s.check("it offers a button naming the host", await s.ev("[...document.querySelectorAll('.preview button')].some((node) => node.textContent.includes('tracker.invalid'))"))
    await s.click(".preview button", "tracker.invalid")
    await s.need("pressing loads it", f"document.querySelector('.preview img[src=\"{tracker}\"]')")
    await asyncio.sleep(0.3)
    s.check("that one request was made", len(s.requests("tracker.invalid")) == 1, s.requests("tracker.invalid"))
    for partial in ("https://cdn.discordapp.com/attach", "https://cdn.discordapp.com/attachm", "https://cdn.discordapp.com/attachments/1.png"):
        await s.ev(f"__set({image}, {json.dumps(partial)})")
        await asyncio.sleep(0.1)
    s.check("typing loads nothing yet", not s.requests("discordapp.com/attach"), s.requests("discordapp.com/attach"))
    await s.need("after a pause Discord's address loads", "document.querySelector('.preview img[src=\"https://cdn.discordapp.com/attachments/1.png\"]')", 3)
    await asyncio.sleep(0.2)
    s.check("only the finished address was requested", s.requests("discordapp.com/attach") == ["https://cdn.discordapp.com/attachments/1.png"], s.requests("discordapp.com/attach"))
    await s.ev(f"__set({image}, 'https://media.discordapp.net/a.png')")
    await s.need("Discord's other host loads too", "document.querySelector('.preview img[src=\"https://media.discordapp.net/a.png\"]')", 3)
    for lookalike in ("https://cdn.discordapp.com.evil.invalid/a.png", "https://evil.invalid/cdn.discordapp.com/a.png"):
        await s.ev(f"__set({image}, {json.dumps(lookalike)})")
        await asyncio.sleep(0.9)
        s.check(f"{lookalike} isn't Discord's", not s.requests(lookalike), s.requests(lookalike))
    await s.ev(f"__set({image}, 'not a link')")
    await asyncio.sleep(0.8)
    s.check("a broken address says so", "isn't a valid https address" in await s.ev("document.querySelector('.preview').textContent"))
    await s.click(".savebar button", "Discard")


@scenario
async def an_import_lists_what_it_changes_before_anything_moves(s):
    await s.open()
    await s.switch("cooldown")
    current = await s.saved()
    export = settings.export_code({**json.loads(json.dumps(current)), "privacy": {**current["privacy"], "banned_days": 0}, "raid": {**current["raid"], "joins": 77}})
    await s.click("button", "Import rules")
    await s.need("the box opened", "document.querySelector('.dialog textarea')")
    await s.ev(f"__set(document.querySelector('.dialog textarea'), {json.dumps(export)})")
    await s.click(".dialog-foot button", "Import")
    await s.need("the changes are listed", "document.querySelector('.change-list li')")
    text = await s.ev("document.querySelector('.dialog').textContent")
    s.check("retention is listed", "privacy.banned_days: 730 → 0" in text, text)
    s.check("the raid number is listed", "raid.joins: 15 → 77" in text, text)
    s.check("retention gets a warning", "how long records are kept" in text, text)
    s.check("what's risky comes first", "privacy.banned_days" in await s.ev("document.querySelector('.change-list li').textContent"))
    s.check("unsaved edits are named", "unsaved" in text, text)
    s.check("nothing moved yet", await s.ev("document.querySelectorAll('#item-raid input[type=number]')[0].value") == "15")
    await s.click(".dialog-foot button", "Cancel")
    await asyncio.sleep(0.1)
    s.check("canceling leaves the page as it was", await s.ev("document.querySelectorAll('#item-raid input[type=number]')[0].value") == "15" and await s.ev("document.querySelector('#item-cooldown .switch input').checked"))
    await s.click("button", "Import rules")
    await s.need("the box opened again", "document.querySelector('.dialog textarea')")
    await s.ev(f"__set(document.querySelector('.dialog textarea'), {json.dumps(export)})")
    await s.click(".dialog-foot button", "Import")
    await s.need("the changes are listed again", "document.querySelector('.change-list li')")
    await s.click(".dialog-foot button", "Accept")
    await s.need("accepting fills the page", "document.querySelectorAll('#item-raid input[type=number]')[0].value === '77'")
    s.check("nothing saved until Save", (await s.saved())["raid"]["joins"] == 15)
    await s.click(".savebar button", "Discard")
    await s.click("button", "Import rules")
    await s.need("the box opened a third time", "document.querySelector('.dialog textarea')")
    await s.ev("__set(document.querySelector('.dialog textarea'), 'not a code')")
    await s.click(".dialog-foot button", "Import")
    await s.need("a bad code is refused in place", "document.querySelector('.toast.error')")
    s.check("the box stays", await s.ev("Boolean(document.querySelector('.dialog textarea'))"))
    await s.click(".dialog-foot button", "Cancel")


@scenario
async def the_words_on_the_rules_page_match_what_the_rules_do(s):
    await s.open()
    lead = await s.ev("document.querySelector('.section .lead').textContent")
    s.check("a preset names what it leaves alone", "Two-factor login, country rules" in lead and "every rule" not in lead, lead)
    external = await s.ev("document.querySelector('#item-external .rule-title span').textContent")
    s.check("the outside lookup says when it asks", "VPN or Threat" in external, external)
    await s.fake("POST", "/settings/preview$", body={"days": 30, "attempts": 2, "blocked_then": 0, "blocked_now": 0, "newly_blocked": 0, "newly_passed": 0, "by_check": [], "not_replayed": 0})
    await s.click("button", "Preview on the last 30 days")
    await s.need("the preview opened", "document.querySelector('.dialog p')")
    s.check("no country line when none were skipped", "country rule" not in await s.ev("document.querySelector('.dialog').textContent"))
    await s.click(".dialog-foot button", "Close")
    s.check("the limit role says when it's given", await s.ev("document.querySelector('#item-max_attempts').textContent.includes('Given when the action is Watch or Deny, and when the limit holds at Deny')"))
    s.check("0 or 5 and up", await s.ev("document.querySelector('#item-max_attempts').textContent.includes('0 means never, otherwise 5 minutes or more')"))
    await s.ev("(() => { const box = document.querySelector('#item-alt_account .switch input'); if (!box.checked) box.click(); })()")
    await s.wait("document.querySelector('#item-alt_account .rule-body')", 2)
    alt = await s.ev("document.querySelector('#item-alt_account').textContent")
    s.check("the alt action says who it's for", "Applies to the newer account." in alt, alt)
    s.check("the banned action says who it's for", "Applies when the earlier account is banned." in alt, alt)
    s.check("the earlier account states its own", "Applies to the account that verified first." in alt, alt)
    await s.ev("document.querySelectorAll('.savebar button')[0]?.click()")
    await s.fake("GET", f"/guilds/{GUILD}$", merge={"setup_done": False, "can_setup": True}, **{"pass": True})
    await s.open("analytics", ready="document.querySelector('.view .notice')")
    words = await s.ev("document.querySelector('.view .notice')?.textContent")
    s.check("setup says what Standard does", words == "Your server starts on the Standard rules, which stop anyone who fails a check.", words)


@scenario
async def nothing_on_a_page_breaks_the_strict_policy(s):
    for page in ("analytics", "settings", "members", "appeals", "health", "appearance", "permissions", "audit", "integrations"):
        await s.open(page)
    found = [event["params"]["entry"]["text"] for event in s.cdp.events if event["method"] == "Log.entryAdded" and "Content Security Policy" in event["params"]["entry"].get("text", "")]
    s.check("no policy violations", not found, found[:3])


async def run_scenarios(cdp, service, port, names) -> bool:
    """Each scenario gets clean settings, a clean session and a clean page, so a failure stays its own."""
    base_first = json.loads(json.dumps(await service.get_settings(GUILD)))
    second = settings.defaults()
    second["core"].update(verified_role=ROLE_B, channel=CHANNEL_B)
    await service.db.save_settings(GUILD_B, settings.normalize(second), setup_done=True)
    service._settings.pop(GUILD_B, None)
    base_second = json.loads(json.dumps(await service.get_settings(GUILD_B)))
    port.members[(GUILD_B, STAFF)] = MemberInfo(GUILD_B, STAFF, "staff_one", None, False, (), frozenset({"manage_guild", "manage_roles"}), True, False)
    await cdp.call("Page.addScriptToEvaluateOnNewDocument", source=PAGE_HOOKS)
    await cdp.call("Network.setBlockedURLs", urls=["https://*", "*.invalid/*"])
    failed = []
    for name in names:
        await cdp.call("Emulation.clearDeviceMetricsOverride")
        await cdp.call("Page.navigate", url=f"{PUBLIC}/__dev/blank")
        await cdp.until("location.pathname === '/__dev/blank'", 5)
        await cdp.evaluate("sessionStorage.clear()")
        for guild, document in ((GUILD, base_first), (GUILD_B, base_second)):
            await service.db.save_settings(guild, json.loads(json.dumps(document)), setup_done=True)
            service._settings.pop(guild, None)
        await service.db.run("UPDATE guilds SET raid_until = 0")
        await service.db.run("DELETE FROM webhooks")
        await service.db.run("DELETE FROM api_keys")
        port.extra_roles.clear()
        port.extra_channels.clear()
        cdp.events.clear()
        scene = Scene(cdp, service, port)
        try:
            await SCENARIOS[name](scene)
        except Exception as error:  # a scenario that throws has failed, and the rest still run
            scene.failures.append(f"stopped: {type(error).__name__}: {error}")
        thrown = [problem for problem in cdp.problems() if problem.startswith("exception:") or "Content Security Policy" in problem]
        scene.check("no uncaught errors", not thrown, thrown[:3])
        if scene.failures:
            failed.append(name)
            print(f"FAIL {name} ({len(scene.failures)} of {scene.count} checks)")
            for failure in scene.failures:
                print(f"     {str(failure)[:600]}")
        else:
            print(f"ok   {name} ({scene.count} checks)")
    print(f"{len(names) - len(failed)} of {len(names)} scenarios passed." + (f" Failed: {', '.join(failed)}" if failed else ""))
    return not failed


async def main(shots: Path, only_controls: bool = False, scenarios: list | None = None) -> bool:
    global PORT, PUBLIC
    shots.mkdir(parents=True, exist_ok=True)
    if scenarios is not None:
        PORT = free_port()  # another copy of this script can be running beside this one
        PUBLIC = f"http://127.0.0.1:{PORT}"
    work = tempfile.mkdtemp(prefix="altwarden-check-")
    keys = crypto.Keyring(b"k" * 32)
    database = db.Database(os.path.join(work, "t.db"), keys.database_key())
    await database.open()
    net = NetIntel(ROOT / "data" / "lists")
    net.lists = await asyncio.to_thread(load_lists, ROOT / "data" / "lists")
    port = TwoServers() if scenarios is not None else FakePort()
    service = Service(database, keys, net, port, PUBLIC)
    await seed(service, port)
    http = aiohttp.ClientSession()
    app = build_app(service, keys, DiscordOAuth(http, "123", "x"), trust_proxy=False)
    app["http"] = http

    async def post_message(guild_id, which):
        return None
    app["post_message"] = post_message
    app["import_role"] = lambda *_: True

    token = crypto.new_token()
    now = time.time()
    await database.run(
        "INSERT INTO web_sessions (token_hash, user_id, username, avatar, guilds, csrf, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (crypto.token_hash(token), STAFF, "staff_one", None,
         json.dumps([{"id": GUILD, "name": "Test Server", "icon": None, "owner": True, "permissions": "32"},
                     *([{"id": GUILD_B, "name": "Second Server", "icon": None, "owner": True, "permissions": "32"}] if scenarios is not None else [])]),
         "csrf-token", "dashboard", now, now + 3600))

    async def dev_login(request):
        response = web.HTTPFound("/dashboard")
        response.set_cookie(SESSION_COOKIE, token, path="/", secure=True, httponly=True, samesite="Lax")
        return response
    app.router.add_get("/__dev/login", dev_login)
    if scenarios is not None:
        async def blank(request):
            return web.Response(text="<!doctype html><title>blank</title>", content_type="text/html")
        app.router.add_get("/__dev/blank", blank)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()

    browser = next(path for path in BROWSERS if os.path.exists(path))
    profile = tempfile.mkdtemp(prefix="altwarden-browser-")
    debug_port = free_port()  # a browser left over from a killed run must not answer for this one
    process = subprocess.Popen([browser, "--headless=new", f"--remote-debugging-port={debug_port}", f"--user-data-dir={profile}", "--window-size=1280,900",
                                "--no-first-run", "--disable-gpu", "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows",
                                "--disable-background-networking", "--disable-sync", "--disable-component-update",
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

            if scenarios is not None:
                await cdp.open(f"{PUBLIC}/__dev/login", wait=1)
                passed = await run_scenarios(cdp, service, port, scenarios or list(SCENARIOS))
                pump.cancel()
                return passed

            if only_controls:
                await cdp.open(f"{PUBLIC}/__dev/login", wait=2)
                await walk_every_control(cdp, service, port)
                pump.cancel()
                return True

            await cdp.open(f"{PUBLIC}/")
            await cdp.shot(shots / "landing.png")
            print("landing:", await cdp.evaluate("document.title"), cdp.problems())

            doc = await service.get_settings(GUILD)
            url, _ = await service.new_link(GUILD, OLD_USER, doc)
            link = url.rsplit("/", 1)[1]
            await cdp.open(url)
            await cdp.shot(shots / "verify-signin.png")
            print("signin text:", (await cdp.evaluate("document.getElementById('card').innerText"))[:120].replace("\n", " | "), cdp.problems())

            await service.attach_account(link, {"id": OLD_USER, "username": "member_one", "avatar": "abc", "mfa": True, "email_verified": True, "email_disposable": False})
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

            await walk_retry(cdp, service, port)

            await cdp.open(f"{PUBLIC}/__dev/login", wait=2)
            for page in ("analytics", "settings", "members", "appeals", "health", "appearance", "permissions", "audit", "integrations"):
                await cdp.open(f"{PUBLIC}/dashboard/{GUILD}/{page}", wait=1.8)
                await cdp.shot(shots / f"dash-{page}.png")
                print(f"dash {page}:", await cdp.evaluate("document.querySelector('.view')?.innerText.length"), cdp.problems())
            await walk_dashboard(cdp, service, shots)
            await walk_every_control(cdp, service, port)
            for page in ("help/vpn", "docs", "privacy", "security", "my-data", f"appeal/{GUILD}"):
                await cdp.open(f"{PUBLIC}/{page}", wait=0.9)
                print(f"page {page}:", cdp.problems())
            pump.cancel()
            return True
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
    parser.add_argument("--controls", action="store_true", help="only change every control and read the saved settings back")
    parser.add_argument("--dash", nargs="*", metavar="SCENARIO", help="run the dashboard scenarios, or just the ones named")
    arguments = parser.parse_args()
    unknown = [name for name in arguments.dash or [] if name not in SCENARIOS]
    if unknown:
        parser.error(f"no such scenario: {', '.join(unknown)}")
    sys.exit(0 if asyncio.run(main(Path(arguments.shots), arguments.controls, arguments.dash)) else 1)
