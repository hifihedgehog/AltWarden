"""Run the browser report on real Firefox and WebKit, to catch false alarms on members' browsers.

Edge alone can't show this. A rule that fires on a clean Firefox or Safari would turn away real
members, so each engine runs clean, and with the setting a rule should catch. Firefox also runs under
strict protection, and with its console panel open, which is the positive control for the developer
tools test. That last run opens a real window for a few seconds.

Firefox 157 under Playwright reports webdriver true whatever QUIET sets, so `automated` in a Firefox run
is the harness's own driver. Read the other flags there. A Playwright context isn't a private window
(detectIncognito reads it as normal, even with private browsing set to start), so that case isn't run.

    pip install playwright
    python -m playwright install firefox webkit
    python scripts/engine_controls.py [--firefox-protection]

--firefox-protection runs only the Firefox protection and console panel runs.
"""
import asyncio
import json
import re
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
QUIET = {"dom.webdriver.enabled": False}  # asks for what a person's Firefox reports. See the note above on what Firefox 157 does with it
REWRITE = "const real = Function.prototype.toString; Function.prototype.toString = function () { return real.call(this); };"
OWN_WEBDRIVER = "Object.defineProperty(navigator, 'webdriver', { get: () => false });"
NO_WEBDRIVER = "delete Navigator.prototype.webdriver;"
PROXY_CORES = """const real = Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency');
Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { ...real, get: new Proxy(real.get, { apply: () => 4 }) });"""
STAND_IN_CORES = "Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', { get() { return 4; }, configurable: true });"
# What Firefox's Strict setting turns on, with its fingerprinting protection, which is what randomizes a canvas.
STRICT = {**QUIET, "browser.contentblocking.category": "strict", "privacy.trackingprotection.enabled": True, "privacy.trackingprotection.socialtracking.enabled": True,
          "privacy.trackingprotection.fingerprinting.enabled": True, "privacy.trackingprotection.cryptomining.enabled": True, "privacy.fingerprintingProtection": True,
          "network.cookie.cookieBehavior": 5}
CONSOLE_OPEN = {**QUIET, "devtools.toolbox.host": "bottom", "devtools.toolbox.selectedTool": "webconsole", "devtools.chrome.enabled": True}
COLLECT = """async () => {
    for (const src of ['/static/vendor/a-5.3.0.min.js', '/static/vendor/c-1.9.0.min.js']) {
        await new Promise((done) => { const s = document.createElement('script'); s.src = src; s.onload = done; s.onerror = done; document.head.append(s); });
    }
    const module = await import('/static/js/collector.js');
    const report = await module.collect();
    let timing = 0;
    for (let round = 0; round < 20; round++) if (module.developerTools().timing) timing++;
    // The collector draws twice and compares. FingerprintJS reads one canvas twice. Noise seeded by content can pass the first and not the second.
    const canvas = document.createElement('canvas');
    canvas.width = 240; canvas.height = 60;
    const context = canvas.getContext('2d');
    context.fillStyle = '#069'; context.font = '16px Arial'; context.fillText('AltWarden, check me 12345', 4, 22);
    const oneCanvasTwice = canvas.toDataURL() !== canvas.toDataURL();
    // Compared across runs, this shows whether a protection setting really changed the pixels.
    const canvasDigest = [...canvas.toDataURL()].reduce((hash, letter) => (hash * 31 + letter.charCodeAt(0)) | 0, 7);
    return { report, agent: navigator.userAgent, timing, oneCanvasTwice, canvasDigest };
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
    print("   lies:", report["lies"]["total"], report["lies"]["apis"][:8], "| canvas", report["canvas"], "| eval", report["eng"]["evalLen"], "| privacy", report["privacy"])
    print("   fp:", (verdict.fingerprint or "none")[:8], "| device:", bool(verdict.device), "| worker:", bool(report["worker"]), "| gpu:", report["gpu"]["renderer"][:50], "| private:", report["private"], "| bot:", report["bot"])
    if expect_flag:
        print("   expected", expect_flag, "->", "yes" if expect_flag in flags else "NO")
    return flags


async def collect(launcher, name, *, prefs=None, user_agent=None, expect=None, inject=None, windowed=False, args=(), settle=0):
    folder = tempfile.mkdtemp(prefix="aw-engine-")
    options = {"headless": not windowed, "args": list(args)}
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
            await asyncio.sleep(settle)
            data = await page.evaluate(COLLECT)
            flags = show(name, data["report"], data["agent"], expect)
            print("   console timing fired", data["timing"], "of 20 rounds, with the test harness on the console | one canvas read twice differs:", data["oneCanvasTwice"], "| canvas digest:", data["canvasDigest"])
            if problems:
                print("   page errors:", problems[:4])
            return flags
        finally:
            await context.close()
    finally:
        shutil.rmtree(folder, ignore_errors=True)


async def console_panel(firefox):
    """The positive control: the page's own test in a real Firefox with its console panel open, then with none.

    With the panel open, an async evaluation never finishes under Playwright, even a bare timer, so the module
    can't be imported there. The test's source is read from the collector and run as one plain call.
    """
    source = (STATIC / "js" / "collector.js").read_text(encoding="utf-8")
    test = re.search(r"export function developerTools\(\) \{.*?\n\}\n", source, re.S).group(0).removeprefix("export ")
    run = "() => { " + test + " let fired = 0; for (let call = 0; call < 6; call++) if (developerTools().timing) fired++; return fired; }"
    for label, args in (("console panel open", ("-devtools",)), ("no panel", ())):
        folder = tempfile.mkdtemp(prefix="aw-engine-")
        try:
            context = await firefox.launch_persistent_context(folder, headless=False, args=list(args), firefox_user_prefs=CONSOLE_OPEN)
            try:
                page = context.pages[0] if context.pages else await context.new_page()
                await page.goto(URL)
                await asyncio.sleep(10)
                print(f"\n== Firefox, {label}: the page's console test fired {await asyncio.wait_for(page.evaluate(run), 90)} of 6 calls")
            finally:
                await asyncio.wait_for(context.close(), 20)
        except Exception as exc:
            print(f"\n== Firefox, {label}: couldn't be driven:", type(exc).__name__, str(exc)[:200])
        finally:
            shutil.rmtree(folder, ignore_errors=True)


async def firefox_protection(firefox):
    await collect(firefox, "Firefox, clean: the canvas digest to compare", prefs=QUIET)
    await collect(firefox, "Firefox, clean again: does the digest repeat without protection?", prefs=QUIET)
    await collect(firefox, "Firefox, strict protection: privacy if its canvas noise reaches the two draws", prefs=STRICT)
    await collect(firefox, "Firefox, strict protection again: does the digest change per session?", prefs=STRICT)
    await collect(firefox, "Firefox, resistFingerprinting: should be privacy", prefs={**QUIET, "privacy.resistFingerprinting": True}, expect="privacy")
    await console_panel(firefox)


async def main():
    runner = await serve()
    async with async_playwright() as playwright:
        firefox, webkit = playwright.firefox, playwright.webkit
        if "--firefox-protection" in sys.argv:
            await firefox_protection(firefox)
            await runner.cleanup()
            return
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
        await firefox_protection(firefox)
    await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
