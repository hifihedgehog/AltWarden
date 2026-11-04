"""Run the browser report on real Firefox and WebKit, to catch false alarms on members' browsers.

Edge alone can't show this. A rule that fires on a clean Firefox or Safari would turn away real
members, so each engine runs clean, and with the setting a rule should catch.

    pip install playwright
    python -m playwright install firefox webkit
    python scripts/engine_controls.py
"""
import asyncio
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aiohttp import web
from playwright.async_api import async_playwright

from altwarden import signals
from altwarden.web.app import CSP, STATIC

PORT = 8897
URL = f"http://127.0.0.1:{PORT}/help"
CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
QUIET = {"dom.webdriver.enabled": False}  # a person's Firefox reports false here, and automation reports true
REWRITE = "const real = Function.prototype.toString; Function.prototype.toString = function () { return real.call(this); };"
OWN_WEBDRIVER = "Object.defineProperty(navigator, 'webdriver', { get: () => false });"
NO_WEBDRIVER = "delete Navigator.prototype.webdriver;"
PROXY_CORES = """const real = Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency');
Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { ...real, get: new Proxy(real.get, { apply: () => 4 }) });"""
STAND_IN_CORES = "Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { get() { return 4; }, configurable: true });"
COLLECT = """async () => {
    for (const src of ['/static/vendor/fingerprintjs-5.3.0.min.js', '/static/vendor/detectincognito-1.9.0.min.js']) {
        await new Promise((done) => { const s = document.createElement('script'); s.src = src; s.onload = done; s.onerror = done; document.head.append(s); });
    }
    const module = await import('/static/js/collector.js');
    const report = await module.collect();
    let timing = 0;
    for (let round = 0; round < 20; round++) if (module.developerTools().timing) timing++;
    return { report, agent: navigator.userAgent, timing };
}"""


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


def show(name, report, agent, expect_flag=None):
    verdict = signals.evaluate(report, {"User-Agent": agent})
    flags = [key for key in ("automated", "antidetect", "fake_ua", "devtools", "private", "privacy", "vm", "emulated") if getattr(verdict, key)]
    print(f"\n== {name}")
    print("   agent:", agent[:110])
    print("   flags:", flags or "none", "| tamper", verdict.tamper_score, "| bot", verdict.bot_score)
    print("   reasons:", json.dumps(verdict.reasons)[:520])
    print("   lies:", report["lies"]["total"], report["lies"]["apis"][:8], "| canvas", report["canvas"], "| eval", report["eng"]["evalLen"])
    print("   fp:", bool(verdict.fingerprint), "| device:", bool(verdict.device), "| worker:", bool(report["worker"]), "| gpu:", report["gpu"]["renderer"][:50], "| private:", report["private"])
    if expect_flag:
        print("   expected", expect_flag, "->", "yes" if expect_flag in flags else "NO")
    return flags


async def collect(launcher, name, *, prefs=None, user_agent=None, expect=None, inject=None):
    folder = tempfile.mkdtemp(prefix="aw-engine-")
    options = {"headless": True}
    if prefs is not None:
        options["firefox_user_prefs"] = prefs
    if user_agent:
        options["user_agent"] = user_agent
    try:
        context = await launcher.launch_persistent_context(folder, **options)
        try:
            if inject:
                await context.add_init_script(inject)
            page = context.pages[0] if context.pages else await context.new_page()
            problems = []
            page.on("pageerror", lambda error: problems.append(str(error)[:160]))
            await page.goto(URL)
            data = await page.evaluate(COLLECT)
            flags = show(name, data["report"], data["agent"], expect)
            print("   console timing fired", data["timing"], "of 20 rounds, with the test harness on the console")
            if problems:
                print("   page errors:", problems[:4])
            return flags
        finally:
            await context.close()
    finally:
        shutil.rmtree(folder, ignore_errors=True)


async def main():
    runner = await serve()
    async with async_playwright() as playwright:
        firefox, webkit = playwright.firefox, playwright.webkit
        await collect(firefox, "Firefox, clean", prefs=QUIET)
        await collect(firefox, "Firefox, webdriver left on: should be automated", prefs={}, expect="automated")
        await collect(firefox, "Firefox, rewritten toString: tamper score should rise", prefs=QUIET, inject=REWRITE)
        await collect(firefox, "Firefox, resistFingerprinting: should be privacy", prefs={**QUIET, "privacy.resistFingerprinting": True}, expect="privacy")
        await collect(firefox, "Firefox pretending to be Chrome: should be a fake identity", prefs={**QUIET, "general.useragent.override": CHROME_UA}, expect="fake_ua")
        await collect(webkit, "WebKit, clean. Playwright's build says Mac on Windows, so its system flag is an artifact")
        await collect(webkit, "WebKit, rewritten toString: tamper score should rise", inject=REWRITE)
        await collect(webkit, "WebKit pretending to be Chrome: should be a fake identity", user_agent=CHROME_UA, expect="fake_ua")
        for label, launcher, prefs in (("Firefox", firefox, QUIET), ("WebKit", webkit, None)):
            await collect(launcher, f"{label}, webdriver set on the object: should be automated", prefs=prefs, inject=OWN_WEBDRIVER, expect="automated")
            await collect(launcher, f"{label}, cores wrapped in a Proxy: should be anti-detect", prefs=prefs, inject=PROXY_CORES, expect="antidetect")
            await collect(launcher, f"{label}, cores replaced by a stand-in: should be anti-detect", prefs=prefs, inject=STAND_IN_CORES, expect="antidetect")
        await collect(firefox, "Firefox, webdriver removed: should be automated", prefs=QUIET, inject=NO_WEBDRIVER, expect="automated")
    await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
