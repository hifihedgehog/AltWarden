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
from fakes import CHANNEL, GUILD, LOG_CHANNEL, OLD_USER, OTHER_USER, STAFF, VERIFIED_ROLE, FakePort

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
    await click_text(cdp, "#item-alerts button", "Choose roles")
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
    results["proxycheck key saved by its own button"] = await service.db.lookup_key(GUILD) == lookup_key
    results["the page shows only the key's last four"] = await cdp.evaluate(
        "(() => { const box = document.querySelector('#item-external input[type=password]'); return box.placeholder === 'Saved, ending in 5678' && box.value === ''; })()")
    results["the key stays out of the settings"] = lookup_key not in json.dumps(await service.get_settings(GUILD))
    await click_text(cdp, "#item-external button", "Remove key")
    await cdp.until("document.querySelector('#item-external input[type=password]')?.placeholder.includes('Paste')", 3)
    results["proxycheck key removed"] = await service.db.lookup_key(GUILD) is None

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


async def main(shots: Path, only_controls: bool = False) -> None:
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

            if only_controls:
                await cdp.open(f"{PUBLIC}/__dev/login", wait=2)
                await walk_every_control(cdp, service, port)
                pump.cancel()
                return

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
    arguments = parser.parse_args()
    asyncio.run(main(Path(arguments.shots), arguments.controls))
