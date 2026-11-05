"""Prove each browser detector fires when it should and stays quiet when it shouldn't.

Serves the real static site, opens a real browser, and collects the real report under controlled
conditions: a clean profile, spoofed hardware, canvas noise, a hidden webdriver flag, a private
window, blocked libraries, no graphics, and each browser API the collector reads made to throw. Each
report then goes through signals.evaluate, the same code production uses.

    python scripts/detector_controls.py [--broken]

--broken runs only the broken API controls.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import aiohttp
from aiohttp import web

from altwarden import signals
from altwarden.web.app import CSP, STATIC

PORT = 8898
URL = f"http://127.0.0.1:{PORT}/help"
BROWSER = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PLAIN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v} Safari/537.36 Edg/{v}"

SPOOF_CORES = """Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { get() { return 4; } });"""
CANVAS_NOISE = """
const original = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function (...args) {
  const context = this.getContext('2d');
  if (context) { context.fillStyle = `rgb(${Math.random() * 255}, 0, 0)`; context.fillRect(0, 0, 1, 1); }
  return original.apply(this, args);
};"""
HIDE_WEBDRIVER = """Object.defineProperty(Navigator.prototype, 'webdriver', { get() { return false; } });"""
OWN_WEBDRIVER = """Object.defineProperty(navigator, 'webdriver', { get: () => false });"""
NO_WEBDRIVER = """delete Navigator.prototype.webdriver;"""
PROXY_CORES = """const real = Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency');
Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { ...real, get: new Proxy(real.get, { apply: () => 4 }) });"""
REWRITE_TOSTRING = """const real = Function.prototype.toString; Function.prototype.toString = function () { return real.call(this); };"""


def throwing_getter(owner, name):
    return f"Object.defineProperty({owner}, '{name}', {{ get() {{ throw new Error('broken'); }}, configurable: true }});"


def throwing_method(owner, name):
    return f"{owner}.{name} = function () {{ throw new Error('broken'); }};"


# A member with one broken API must get a report the server accepts, and must never be called automated for it.
BROKEN = {
    "core count": throwing_getter("Navigator.prototype", "hardwareConcurrency"),
    "user agent": throwing_getter("Navigator.prototype", "userAgent"),
    "screen width": throwing_getter("Screen.prototype", "width"),
    "time zone name": throwing_method("Intl.DateTimeFormat.prototype", "resolvedOptions"),
    "time zone offset": throwing_method("Date.prototype", "getTimezoneOffset"),
    "canvas": throwing_method("HTMLCanvasElement.prototype", "getContext"),
    "console table": "console.table = undefined;",
    "css support test": throwing_method("CSS", "supports"),
    "client hints": throwing_method("NavigatorUAData.prototype", "getHighEntropyValues"),
    "iframes, so the tamper test can't run": """const make = Document.prototype.createElement;
Document.prototype.createElement = function (tag, ...rest) { if (String(tag).toLowerCase() === 'iframe') throw new Error('broken'); return make.call(this, tag, ...rest); };""",
    "printing a function": throwing_method("Function.prototype", "toString"),
    "the high resolution clock": throwing_method("Performance.prototype", "now"),
    "web workers": "window.Worker = function () { throw new Error('broken'); };",
}


async def serve():
    app = web.Application()

    async def page(request):
        return web.Response(text=(STATIC / "help.html").read_text(encoding="utf-8"), content_type="text/html",
                            headers={"Content-Security-Policy": CSP})
    app.router.add_get("/help", page)
    app.router.add_static("/static", STATIC)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()
    return runner


async def collect(http, *, flags=(), inject=None, user_agent=None, port=9334, console_attached=True, blocked=()):
    profile = tempfile.mkdtemp(prefix="aw-controls-")
    process = subprocess.Popen([BROWSER, "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={profile}", "--window-size=1280,900",
                                "--no-first-run", *flags, "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        targets = []
        for _ in range(80):
            try:
                async with http.get(f"http://127.0.0.1:{port}/json") as response:
                    targets = await response.json()
                    if any(item["type"] == "page" for item in targets):
                        break
            except aiohttp.ClientError:
                pass
            await asyncio.sleep(0.25)
        target = next(item for item in targets if item["type"] == "page")
        async with http.ws_connect(target["webSocketDebuggerUrl"], max_msg_size=0) as ws:
            counter = 0

            async def call(method, **params):
                nonlocal counter
                counter += 1
                await ws.send_json({"id": counter, "method": method, "params": params})
                while True:
                    message = json.loads((await asyncio.wait_for(ws.receive(), 30)).data)
                    if message.get("id") == counter:
                        return message.get("result", {})
            await call("Page.enable")
            if console_attached:
                await call("Runtime.enable")
            if user_agent:
                await call("Network.setUserAgentOverride", userAgent=user_agent)
            if blocked:
                await call("Network.enable")
                await call("Network.setBlockedURLs", urls=list(blocked))
            if inject:
                await call("Page.addScriptToEvaluateOnNewDocument", source=inject)
            await call("Page.navigate", url=URL)
            await asyncio.sleep(1.2)
            script = """(async () => {
                for (const src of ['/static/vendor/a-5.3.0.min.js', '/static/vendor/c-1.9.0.min.js']) {
                    await new Promise((done) => { const s = document.createElement('script'); s.src = src; s.onload = done; s.onerror = done; document.head.append(s); });
                }
                const module = await import('/static/js/collector.js');
                const report = await module.collect();
                let timing = 0;
                try {
                    for (let round = 0; round < 20; round++) if (module.developerTools().timing) timing++;
                } catch {
                    timing = "the test threw";  // the collector catches this itself, and this loop calls the test directly
                }
                report.timingRounds = timing;
                return JSON.stringify(report);
            })()"""
            result = await call("Runtime.evaluate", expression=script, awaitPromise=True, returnByValue=True)
            raw = result.get("result", {}).get("value")
            if raw is None:
                raise RuntimeError(str(result)[:400])
            agent = (await call("Runtime.evaluate", expression="(() => { try { return navigator.userAgent; } catch { return null; } })()", returnByValue=True))["result"].get("value")
            return json.loads(raw), agent or user_agent
    finally:
        process.terminate()
        await asyncio.sleep(0.6)
        shutil.rmtree(profile, ignore_errors=True)


def summary(name, report, agent):
    verdict = signals.evaluate(report, {"User-Agent": agent})
    flags = [key for key in ("automated", "antidetect", "fake_ua", "devtools", "private", "privacy", "vm", "emulated") if getattr(verdict, key)]
    print(f"\n== {name}")
    print("   flags:", flags or "none", "| tamper", verdict.tamper_score, "| bot", verdict.bot_score)
    print("   reasons:", json.dumps(verdict.reasons)[:520])
    lies = report.get("lies", {})
    print("   lies:", lies.get("total"), lies.get("apis", [])[:6], "| canvas", report.get("canvas"), "| fp", bool(verdict.fingerprint), "| device", bool(verdict.device))
    print("   private:", report.get("private"), "| bot:", report.get("bot"), "| worker:", bool(report.get("worker")), "| gpu:", str(report.get("gpu", {}).get("renderer"))[:60])
    print("   sections that failed:", [name for name, value in report.items() if isinstance(value, dict) and value.get("failed")])
    print("   console timing fired", report.get("timingRounds"), "of 20 rounds")
    return verdict


async def broken_apis(http, normal):
    for name, inject in BROKEN.items():
        report, agent = await collect(http, user_agent=normal, inject=inject)
        verdict = summary(f"Broken API, {name}: should not be automated", report, agent)
        print("   automated:", verdict.automated)


async def main():
    runner = await serve()
    async with aiohttp.ClientSession() as http:
        report, agent = await collect(http)
        summary("Headless as shipped: should be automated", report, agent)
        version = agent.split("Chrome/")[1].split(" ")[0] if "Chrome/" in agent else "130.0.0.0"
        normal = PLAIN_UA.format(v=version)
        if "--broken" in sys.argv:
            await broken_apis(http, normal)
            await runner.cleanup()
            return
        report, agent = await collect(http, user_agent=normal)
        baseline = summary("Normal identity string: fewest flags expected", report, agent)
        report, agent = await collect(http, user_agent=normal, console_attached=False)
        summary("No debugger on the console: developer tools should stay quiet", report, agent)
        report, agent = await collect(http, user_agent=normal, inject=SPOOF_CORES)
        summary("Spoofed core count: should be anti-detect", report, agent)
        report, agent = await collect(http, user_agent=normal, inject=CANVAS_NOISE)
        summary("Canvas noise from a wrapped function: should be privacy, not anti-detect", report, agent)
        report, agent = await collect(http, user_agent=normal, inject=REWRITE_TOSTRING)
        summary("Rewritten toString: tamper score should rise", report, agent)
        report, agent = await collect(http, user_agent=normal, inject=HIDE_WEBDRIVER)
        summary("Rewritten webdriver getter: should be automated", report, agent)
        report, agent = await collect(http, user_agent=normal, inject=OWN_WEBDRIVER)
        summary("Webdriver set on the object: should be automated", report, agent)
        report, agent = await collect(http, user_agent=normal, inject=NO_WEBDRIVER)
        summary("Webdriver removed: should be automated", report, agent)
        report, agent = await collect(http, user_agent=normal, flags=("--disable-blink-features=AutomationControlled",))
        summary("The usual flag for hiding automation: the driver still shows as developer tools", report, agent)
        report, agent = await collect(http, user_agent=normal, inject=PROXY_CORES)
        summary("Core count wrapped in a Proxy: should be anti-detect", report, agent)
        report, agent = await collect(http, user_agent=normal, flags=("--inprivate",))
        summary("Private window: should be private", report, agent)
        report, agent = await collect(http, user_agent=normal, flags=("--disable-gpu", "--disable-software-rasterizer"))
        summary("No WebGL at all: hiding nothing, so no privacy flag", report, agent)
        report, agent = await collect(http, user_agent=normal, flags=("--use-angle=swiftshader", "--enable-unsafe-swiftshader"))
        summary("Software graphics: should be a virtual machine, reading software graphics", report, agent)
        for name, url in (("fingerprint", "*a-5.3.0.min.js"), ("automation", "*b-2.0.0.esm.js"), ("private window", "*c-1.9.0.min.js")):
            report, agent = await collect(http, user_agent=normal, blocked=(url,))
            summary(f"The {name} library blocked: should be privacy", report, agent)
        await broken_apis(http, normal)
        print("\nbaseline fingerprint stable across two runs:", end=" ")
        first, agent_one = await collect(http, user_agent=normal)
        second, agent_two = await collect(http, user_agent=normal)
        print(first["fp"]["id"] == second["fp"]["id"], "| device value:", signals.evaluate(first, {"User-Agent": agent_one}).device == signals.evaluate(second, {"User-Agent": agent_two}).device)
        del baseline
    await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
