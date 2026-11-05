"""Reads the browser report from the verification page and decides what it shows.

The rules follow proven open implementations rather than guesses:

  automation     BotD's detectors run in the browser. Their verdict arrives in `bot`.
  private window detectIncognito runs in the browser. Its verdict arrives in `private`.
  tampering      CreepJS's lie detection: native functions must look native, in every way.
  worker scope   CreepJS compares a Web Worker's view of the device with the page's. A spoofing
                 tool that patches the page usually forgets the worker.
  virtual machines  a hypervisor's graphics name, or a software rasterizer. BotD names only Mesa OffScreen and
                 CreepJS only SwiftShader, so this list is this project's own. A VirtualBox guest with 3D off looks
                 exactly like a PC with hardware acceleration off, so both count, and the member's text gives the remedy.
  modified phones no web API reports root, and the services that do report it read it from a native
                 app. Chromium's model hint is the phone's ro.product.model property, which root
                 tools can rewrite, so a Pixel's model is compared with its graphics chip and its
                 Android version. A phone that changes nothing, or a jailbroken iPhone, stays unseen.
  engine check   BotD's eval length rule: 33 on Chromium, 37 on Gecko and WebKit.
  developer tools devtools-detector's console timing, on Chromium and Firefox. Side panels and vertical tabs
                 make the same window gap as a docked panel, so the gap isn't used, and Safari has no test.

A report comes from the member's own browser, so a determined attacker with a custom client can
forge it. These rules raise the cost and catch ordinary tools. Server-side facts, such as the
Discord account and the network, can't be forged this way, and the docs say so plainly.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field

MAX_REPORT_BYTES = 64 * 1024

VM_RENDERER = re.compile(r"vmware|virtualbox|parallels|qemu|virtio|virgl|hyper-v|xen |svga3d", re.IGNORECASE)
SOFTWARE_RENDERER = re.compile(r"llvmpipe|softpipe|swiftshader|mesa offscreen|microsoft basic render|microsoft remote display|citrix", re.IGNORECASE)
EMULATOR_MODEL = re.compile(r"sdk_gphone|android sdk built|emulator|genymotion|vbox86|bluestacks|\bnox(?:player)?\b|ldplayer|\bmemu", re.IGNORECASE)
# NVIDIA's Tegra is a real Android chip, in the Shield TV. Its desktop cards aren't.
EMULATOR_RENDERER = re.compile(r"android emulator|swiftshader|llvmpipe|virgl|geforce|radeon|intel\(r\)|nvidia(?! tegra)", re.IGNORECASE)
HEADLESS = re.compile(r"HeadlessChrome|PhantomJS|Electron|SlimerJS", re.IGNORECASE)

# The last Android version Google shipped for each Pixel that no longer gets updates. Anything
# newer on one of these phones is custom firmware. Newer Pixels aren't listed, because their
# ceiling can still rise.
FINAL_ANDROID = {"Pixel": 10, "Pixel XL": 10, "Pixel 2": 11, "Pixel 2 XL": 11, "Pixel 3": 12, "Pixel 3 XL": 12, "Pixel 3a": 12,
                 "Pixel 3a XL": 12, "Pixel 4": 13, "Pixel 4 XL": 13, "Pixel 4a": 13, "Pixel 4a (5G)": 14, "Pixel 5": 14, "Pixel 5a": 14}

# What the page always sends, and a field each section always holds. A section the browser couldn't build still
# arrives, as {"failed": true}, so one that's absent or the wrong shape never came from the page.
ALWAYS_SENT = {"nav": ("ua", str), "scr": ("w", float), "tz": ("offset", float), "gpu": ("renderer", str), "eng": ("evalLen", float),
               "lies": ("total", float), "canvas": ("noisy", bool), "privacy": (None, None), "devtools": ("timing", bool), "act": ("ms", float)}
# One broken API can take out a section or two, and a third is possible. A browser where most of them fail isn't running this page.
MAX_FAILED_SECTIONS = 3

# Functions anti-detect tools patch, by what they describe. A privacy extension usually rewrites one
# family, and an anti-detect tool rewrites several, so a rewrite only counts as one from two families up.
HARDWARE_APIS = {"Navigator.hardwareConcurrency": "navigator", "Navigator.deviceMemory": "navigator", "Navigator.platform": "navigator",
                 "Navigator.userAgent": "navigator", "Navigator.languages": "navigator", "Screen.width": "screen", "Screen.height": "screen",
                 "WebGLRenderingContext.getParameter": "webgl", "WebGL2RenderingContext.getParameter": "webgl",
                 "Intl.DateTimeFormat.resolvedOptions": "time", "Date.getTimezoneOffset": "time"}
# Canvas protection extensions rewrite these. That hides a fingerprint, and says nothing about the device.
CANVAS_APIS = ("HTMLCanvasElement.toDataURL", "CanvasRenderingContext2D.getImageData")
# BotD detectors that read the environment and not a tool's name. BotD's own comments give real cases for some
# (rtt.ts, window_size.ts), so one alone adds to the bot score and only two together are automation. The plugin
# count isn't here: it has a narrower excuse of its own, for a browser set to download PDFs.
WEAK_DETECTORS = frozenset({"detectRTT", "detectWindowSize", "detectNotificationPermissions", "detectPluginsArray",
                            "detectMimeTypesConsistent", "detectLanguagesLengthInconsistency", "detectProductSub"})


def os_family(text: str) -> str | None:
    """Reduce a user agent or platform string to one operating system family."""
    value = (text or "").lower()
    if "android" in value:
        return "android"
    if "iphone" in value or "ipad" in value or "ipod" in value:
        return "ios"
    if re.search(r"\bwin(?:dows|ce|\d\d)?\b", value):  # a plain "win" would match Darwin
        return "windows"
    if "mac" in value:
        return "mac"
    if "cros" in value or "chrome os" in value or "chromium os" in value:
        return "chromeos"
    if "linux" in value or "x11" in value or "ubuntu" in value:
        return "linux"
    return None


def engine_of(ua: str) -> str | None:
    value = ua or ""
    if "Firefox/" in value:  # Firefox on iPhone says FxiOS, and runs on WebKit like every iOS browser
        return "gecko"
    if "Chrome/" in value or "Chromium/" in value or "Edg/" in value or "OPR/" in value:
        return "blink"
    if "Safari/" in value and "AppleWebKit" in value:
        return "webkit"
    return None


def browser_family(ua: str) -> str | None:
    """Which browser a user agent names. Chromium browsers carry their own token before Chrome's."""
    value = ua or ""
    for token, name in (("Edg", "edge"), ("OPR/", "opera"), ("SamsungBrowser/", "samsung"), ("Firefox/", "firefox"),
                        ("FxiOS/", "firefox"), ("CriOS/", "chrome"), ("Chrome/", "chrome"), ("Safari/", "safari")):
        if token in value:
            return name
    return None


def gpu_os(renderer: str) -> str | None:
    """Some renderer strings only exist on one operating system."""
    value = renderer or ""
    if "Mesa" in value or re.search(r"\(G1\d", value):  # Linux's own driver, including on Apple hardware
        return None
    if "Direct3D" in value or "D3D11" in value or "D3D9" in value:
        return "windows"
    if re.search(r"Apple (M\d|GPU|A\d)", value) or "Metal" in value:
        return "apple"
    return None


def gpu_model(renderer: str) -> str:
    """Strip the wrapper each browser puts around the same graphics card."""
    # Whitespace is squeezed first, because the pattern below backtracks quadratically over a long run of it.
    value = " ".join((renderer or "").upper().split())
    match = re.search(r"ANGLE \([^,]*,\s*([^,]+?)(?:\s+DIRECT3D|\s+OPENGL|\s+\(0X|,|\))", value)
    if match:
        value = match.group(1)
    value = re.sub(r"\(.*?\)|DIRECT3D\S*|D3D\d+|VS_\S+|PS_\S+|OPENGL\S*|/PCIE/SSE2|\bINC\b\.?|\bCORPORATION\b|,", " ", value)
    return " ".join(value.split())


def _apple_agent(value: str) -> str:
    """An iPad in desktop mode can call itself a Mac on the page and an iPad in a worker, so what that changes is dropped from a Safari agent."""
    if engine_of(value) != "webkit":
        return value
    return " ".join(re.sub(r"\((?:Macintosh|iPad|iPhone|iPod)[^)]*\)|\bMobile/\S+|\bSafari/\S+", " ", value).split())


def _text(value, limit: int = 300) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _number(value, fallback=None):
    """A real number, or the fallback. Python's JSON parser accepts NaN and Infinity, and a whole number can be too long for a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    return fallback if isinstance(value, float) and not math.isfinite(value) else value


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


@dataclass
class BrowserVerdict:
    """What the report shows. `reasons` holds short labels for staff, with no raw values."""

    automated: bool = False
    antidetect: bool = False
    fake_ua: bool = False
    devtools: bool = False
    private: bool = False
    privacy: bool = False
    vm: bool = False
    emulated: bool = False
    tamper_score: int = 0
    bot_score: int = 0
    weak_detector: bool = False
    reasons: dict = field(default_factory=dict)
    os: str | None = None
    browser: str | None = None
    fingerprint: str | None = None
    device: str | None = None
    weak_fingerprint: bool = False

    def note(self, key: str, reason: str) -> None:
        self.reasons.setdefault(key, []).append(reason)


def evaluate(report: dict, headers: dict, *, device_cookie: bool = True) -> BrowserVerdict:
    """Turn one untrusted report into a verdict. Every field is type-checked, and a required one that's missing is a finding.

    `device_cookie` is False when a browser that holds the sign-in cookie sent no valid device cookie, which the page
    sets before every submit. Only a client that isn't a browser, or one that stripped it to look new, arrives that way.
    """
    report = _dict(report)
    # Header names keep whatever case the browser and proxy sent. Over HTTP/2 that's lower case.
    headers = {str(name).lower(): value for name, value in headers.items()}
    verdict = BrowserVerdict()
    nav = _dict(report.get("nav"))
    uad = _dict(report.get("uad"))
    scr = _dict(report.get("scr"))
    gpu = _dict(report.get("gpu"))
    worker = _dict(report.get("worker"))
    lies = _dict(report.get("lies"))
    canvas = _dict(report.get("canvas"))
    tz = _dict(report.get("tz"))
    eng = _dict(report.get("eng"))
    bot = _dict(report.get("bot"))
    tools = _dict(report.get("devtools"))
    privacy = _dict(report.get("privacy"))

    ua = _text(nav.get("ua"), 500)
    header_ua = _text(headers.get("user-agent"), 500)
    renderer = _text(gpu.get("renderer"))
    claimed_os = os_family(ua) or os_family(header_ua)
    verdict.os = claimed_os
    verdict.browser = browser_family(ua or header_ua)
    # The report's own uad.mobile isn't read, because it would let a desktop agent claim the weaker evidence of a phone.
    mobile = claimed_os in ("android", "ios") or "Mobi" in ua or _android_in_desktop_mode(claimed_os, uad, nav)
    lied_apis = [name for name in lies.get("apis", []) if isinstance(name, str)][:64] if isinstance(lies.get("apis"), list) else []
    lie_total = max(0, min(64, int(_number(lies.get("total"), 0))))  # the collector checks fewer functions than this

    _check_report_exists(verdict, report, header_ua, device_cookie)
    _check_automation(verdict, bot, nav, ua, header_ua, worker, lied_apis)
    _check_identity(verdict, nav, uad, ua, header_ua, headers, eng, renderer, worker, claimed_os)
    _check_antidetect(verdict, canvas, worker, nav, gpu, lied_apis, tz, privacy, engine_of(ua))
    _check_tampering(verdict, lies, lied_apis, lie_total)
    _check_privacy(verdict, privacy, canvas, lied_apis, ua, (_dict(report.get("fp")), bot, _dict(report.get("private"))))
    _check_devtools(verdict, tools, mobile, engine_of(ua))
    _check_device(verdict, renderer, uad, nav, claimed_os)

    private = _dict(report.get("private"))
    if private.get("isPrivate") is True:
        verdict.private = True
        verdict.note("private", "private window")

    _fingerprints(verdict, report, nav, scr, tz, claimed_os, renderer, mobile)
    verdict.bot_score = _bot_score(verdict, report)
    return verdict


def _android_in_desktop_mode(claimed_os, uad, nav) -> bool:
    """Request desktop site makes an Android phone or tablet send a Linux desktop agent, and these still give it away."""
    if claimed_os != "linux":
        return False
    touch_arm = re.match(r"Linux (?:arm|aarch64)", _text(nav.get("platform"), 60)) and (_number(nav.get("touch"), 0) or 0) > 1
    return bool(touch_arm) or os_family(_text(uad.get("platform"), 40)) == "android"


def _check_report_exists(verdict, report, header_ua, device_cookie) -> None:
    """The collector always sends these, so a report without them never came from the page."""
    failed = 0
    complete = True
    for name, (key, kind) in ALWAYS_SENT.items():
        section = report.get(name)
        if isinstance(section, dict) and section.get("failed") is True:
            failed += 1
        elif not isinstance(section, dict) or (key and not _has_field(section.get(key), kind)) or (name == "nav" and not section["ua"]):
            complete = False
    if failed:
        verdict.note("tamper", f"{failed} report sections failed in the browser")
    if not complete or failed > MAX_FAILED_SECTIONS:
        verdict.automated = True
        verdict.note("automated", "incomplete browser report")
    if not device_cookie:
        verdict.automated = True
        verdict.note("automated", "no device cookie")
    if header_ua and not header_ua.startswith("Mozilla/"):
        verdict.automated = True
        verdict.note("automated", "not a browser")


def _has_field(value, kind) -> bool:
    return isinstance(value, kind) if kind in (str, bool) else _number(value) is not None


def _check_automation(verdict, bot, nav, ua, header_ua, worker, lied_apis) -> None:
    fired = [name for name in bot.get("fired", []) if isinstance(name, str)] if isinstance(bot.get("fired"), list) else []
    # A desktop Chrome set to download PDFs has no plugins, which BotD reads as headless. If nothing
    # else fired and the browser says its PDF viewer is off, that's all this is.
    download_pdfs = fired == ["detectPluginsLengthInconsistency"] and nav.get("pdf") is False
    lone_weak = len(fired) == 1 and fired[0] in WEAK_DETECTORS
    if bot.get("bot") is True and lone_weak and not download_pdfs:
        verdict.weak_detector = True
    elif bot.get("bot") is True and not download_pdfs:
        verdict.automated = True
        kind = _text(bot.get("botKind"), 30)
        verdict.note("automated", f"BotD: {kind if re.fullmatch(r'[A-Za-z_]+', kind) else 'unknown'}")
    if nav.get("webdriver") is True:
        verdict.automated = True
        verdict.note("automated", "webdriver flag")
    # CreepJS's rule: a browser new enough to have this CSS feature always has this property. The usual way
    # to hide automation removes it. Kept to Chromium and Firefox, because Safari can't be tested without a driver.
    if nav.get("modern") is True and engine_of(ua) in ("blink", "gecko") and nav.get("webdriver") is None:
        verdict.automated = True
        verdict.note("automated", "webdriver flag removed")
    if "Navigator.webdriver" in lied_apis:
        verdict.automated = True
        verdict.note("automated", "webdriver flag hidden")
    for label, value in (("page", ua), ("request", header_ua), ("worker", _text(worker.get("ua"), 500))):
        if HEADLESS.search(value):
            verdict.automated = True
            verdict.note("automated", f"headless name in {label} user agent")


def _check_identity(verdict, nav, uad, ua, header_ua, headers, eng, renderer, worker, claimed_os) -> None:
    # Brave pads its user agent with spaces, and only in some of these places. A proxy can add a token to
    # the request's agent, so one being the start of the other isn't a different browser.
    page_ua, sent_ua = ua.strip(), header_ua.strip()
    if page_ua and sent_ua and not (sent_ua.startswith(page_ua) or page_ua.startswith(sent_ua)):
        verdict.fake_ua = True
        verdict.note("fake_ua", "page and request disagree")
    worker_ua = _text(worker.get("ua"), 500)
    if ua and worker_ua and _apple_agent(ua.strip()) != _apple_agent(worker_ua.strip()):
        verdict.fake_ua = True
        verdict.note("fake_ua", "page and worker disagree")

    platform_os = os_family(_text(nav.get("platform"), 60))
    # "Request desktop site" makes a phone report a desktop agent on real hardware, so a Linux
    # agent on an Android platform is ordinary and an iPad reporting Mac is too. Only a jump to a
    # different family of system counts.
    # A Chromebook is the same: its agent says CrOS and its platform says Linux.
    compatible = {("linux", "android"), ("android", "linux"), ("mac", "ios"), ("ios", "mac"), ("linux", "chromeos"), ("chromeos", "linux")}
    if claimed_os and platform_os and claimed_os != platform_os and (claimed_os, platform_os) not in compatible:
        verdict.fake_ua = True
        verdict.note("fake_ua", "agent and platform name different systems")
    hint_os = os_family(_text(headers.get("sec-ch-ua-platform"), 40).strip('"'))
    uad_os = os_family(_text(uad.get("platform"), 40))
    for label, other in (("client hints", hint_os), ("user agent data", uad_os)):
        if claimed_os and other and claimed_os != other and (claimed_os, other) not in compatible:
            verdict.fake_ua = True
            verdict.note("fake_ua", f"agent and {label} name different systems")

    engine = engine_of(ua)
    eval_length = _number(eng.get("evalLen"))
    if engine and eval_length is not None:
        expected = {"blink": 33, "gecko": 37, "webkit": 37}[engine]
        if eval_length != expected:
            verdict.fake_ua = True
            verdict.note("fake_ua", "engine doesn't match agent")
    # Chromium browsers set this string as they like, so only another engine's name gives anything away.
    vendor = nav.get("vendor")
    if isinstance(vendor, str) and ((engine == "blink" and vendor.startswith("Apple")) or (engine == "webkit" and vendor != "Apple Computer, Inc.")
                                    or (engine == "gecko" and vendor != "")):
        verdict.fake_ua = True
        verdict.note("fake_ua", "vendor doesn't match agent")

    hardware = gpu_os(renderer)
    if hardware == "windows" and claimed_os and claimed_os != "windows":
        verdict.fake_ua = True
        verdict.note("fake_ua", "Windows graphics on another system")
    if hardware == "apple" and claimed_os in ("windows", "android", "linux"):
        verdict.fake_ua = True
        verdict.note("fake_ua", "Apple graphics on another system")


def _check_antidetect(verdict, canvas, worker, nav, gpu, lied_apis, tz, privacy, engine) -> None:
    spoofed = [name for name in lied_apis if name in HARDWARE_APIS]
    if len({HARDWARE_APIS[name] for name in spoofed}) >= 2:
        verdict.antidetect = True
        verdict.note("antidetect", f"{len(spoofed)} device functions rewritten")
    if worker:
        comparisons = (("cores", nav.get("cores"), worker.get("cores")),
                       ("memory", nav.get("memory"), worker.get("memory")),
                       ("platform", _apple_platform(nav.get("platform")), _apple_platform(worker.get("platform"))),
                       ("graphics", gpu.get("renderer"), worker.get("gpu")))
        for label, page_value, worker_value in comparisons:
            if page_value not in (None, "") and worker_value not in (None, "") and page_value != worker_value:
                verdict.antidetect = True
                verdict.note("antidetect", f"worker sees different {label}")
        if tz.get("name") and worker.get("tz") and tz.get("name") != worker.get("tz"):
            verdict.antidetect = True
            verdict.note("antidetect", "worker sees a different time zone")
    # A canvas that changes between two identical draws is being randomized. Safari and Firefox add
    # noise on their own (FingerprintJS skips the canvas there for that reason), and so does Brave, so
    # this only means something on other Chrome-family browsers. Noise from a canvas function a privacy
    # extension rewrote is the privacy check's to report. Noise with nothing rewritten is built into the browser.
    wrapped_canvas = any(name in CANVAS_APIS for name in lied_apis)
    if canvas.get("noisy") is True and engine == "blink" and privacy.get("brave") is not True and not wrapped_canvas:
        verdict.antidetect = True
        verdict.note("antidetect", "canvas output changes between draws")
    offset = _number(tz.get("offset"))
    expected = _number(tz.get("intlOffset"))
    if offset is not None and expected is not None and offset != expected:
        verdict.antidetect = True
        verdict.note("antidetect", "clock and time zone disagree")


def _apple_platform(value):
    """An iPad in desktop mode says MacIntel on the page and iPad in a worker, so those count as one value."""
    return "apple" if value in ("MacIntel", "iPad", "iPhone") else value


def _check_tampering(verdict, lies, lied_apis, lie_total) -> None:
    score = min(lie_total, 10) * 10
    if lies.get("toString") is True:
        score += 40
        verdict.note("tamper", "Function.toString rewritten")
    if lies.get("proxy") is True:
        score += 30
        verdict.note("tamper", "native functions wrapped in a proxy")
    if lied_apis:
        verdict.note("tamper", f"{len(lied_apis)} functions rewritten")
    verdict.tamper_score = min(100, score)


def _check_privacy(verdict, privacy, canvas, lied_apis, ua, libraries) -> None:
    # Brave with Shields down hides nothing. A noisy canvas shows they're up, whatever the mode test read.
    if privacy.get("brave") is True and (privacy.get("braveMode") in ("standard", "strict") or canvas.get("noisy") is True):
        verdict.privacy = True
        verdict.note("privacy", "Brave Shields")
    # The file never arrived, which is what a request blocker does. A slow phone reports a timeout and isn't touched.
    for name, section in zip(("fingerprint", "automation", "private window"), libraries):
        if section.get("blocked") is True:
            verdict.privacy = True
            verdict.note("privacy", f"{name} library blocked")
    if privacy.get("resist") is True:
        verdict.privacy = True
        verdict.note("privacy", "fingerprint resistance on")
    if privacy.get("tor") is True:
        verdict.privacy = True
        verdict.note("privacy", "Tor Browser")
    if canvas.get("blocked") is True:
        verdict.privacy = True
        verdict.note("privacy", "canvas blocked")
    if any(name in CANVAS_APIS for name in lied_apis):
        verdict.privacy = True
        verdict.note("privacy", "canvas functions rewritten")
    # As of Firefox 145, Firefox randomizes canvas only in private windows and under strict protection
    # (wiki.mozilla.org/Fingerprinting), so its users chose this. If a later Firefox does it by default, drop this
    # rule, as was done for Safari: secondary sources say Safari 26 adds noise in ordinary browsing, unverified on a
    # real device, and a rule that may stop every iPhone isn't worth keeping. On Chromium, see _check_antidetect.
    # Measured on Firefox 157: two draws matched under strict protection and differed only under resistFingerprinting.
    if engine_of(ua) == "gecko" and canvas.get("noisy") is True:
        verdict.privacy = True
        verdict.note("privacy", "canvas randomized")
    if engine_of(ua) == "blink" and privacy.get("gpuHidden") is True:
        verdict.privacy = True
        verdict.note("privacy", "graphics details hidden")


def _check_devtools(verdict, tools, mobile, engine) -> None:
    if mobile:
        return  # phones have no docked panel, and their window gaps are browser toolbars
    # In real Edge the console test fired on none of 20 rounds with no debugger, and on 17 to 20 with one
    # attached, docked or not. Firefox 157 fired on 5 of 6 calls with its console panel open and none of 6
    # with it closed. Safari's inspector can't be detached in a test, so a quiet run can't be shown there,
    # and a false alarm would turn away real members.
    # Side panels and vertical tabs leave the same window gap as a docked panel, so the gap isn't used.
    if engine in ("blink", "gecko") and tools.get("timing") is True:
        verdict.devtools = True
        verdict.note("devtools", "console timing")


def pixel_generation(model: str) -> int | None:
    """Which Pixel generation a model name claims. The first generation has no number."""
    if model in ("Pixel", "Pixel XL"):
        return 1
    if model in ("Pixel Fold", "Pixel Tablet"):
        return 7
    found = re.match(r"Pixel (\d+)", model)
    return int(found.group(1)) if found else None


def model_fits_gpu(model: str, renderer: str) -> bool:
    """Pixels 1 to 5 use Qualcomm chips with Adreno graphics. Google's Tensor chips use Mali or PowerVR."""
    generation = pixel_generation(model)
    if generation is None:
        return True
    if generation <= 5:
        return "Mali" not in renderer and "PowerVR" not in renderer
    return "Adreno" not in renderer


def newer_than_shipped(model: str, platform_version: str) -> bool:
    found = re.match(r"(\d+)", platform_version)
    return bool(found and model in FINAL_ANDROID and int(found.group(1)) > FINAL_ANDROID[model])


def _check_device(verdict, renderer, uad, nav, claimed_os) -> None:
    if VM_RENDERER.search(renderer):
        verdict.vm = True
        verdict.note("vm", "virtual machine graphics")
    elif SOFTWARE_RENDERER.search(renderer):
        verdict.vm = True
        verdict.note("vm", "software graphics")
    if claimed_os != "android":
        return
    model = _text(uad.get("model"), 80)
    if EMULATOR_MODEL.search(model):
        verdict.emulated = True
        verdict.note("emulated", "emulator model name")
    if not model_fits_gpu(model, renderer):
        verdict.emulated = True
        verdict.note("emulated", "phone model doesn't fit its graphics chip")
    if newer_than_shipped(model, _text(uad.get("platformVersion"), 20)):
        verdict.emulated = True
        verdict.note("emulated", "Android newer than this phone ever shipped with")
    if EMULATOR_RENDERER.search(renderer):
        verdict.emulated = True
        verdict.note("emulated", "desktop or software graphics on Android")
    if _text(uad.get("architecture"), 20).lower().startswith("x86") or "x86" in _text(nav.get("platform"), 60):
        verdict.emulated = True
        verdict.note("emulated", "x86 processor on Android")


def _fingerprints(verdict, report, nav, scr, tz, claimed_os, renderer, mobile) -> None:
    fp = _dict(report.get("fp"))
    visitor = fp.get("id")
    if isinstance(visitor, str) and re.fullmatch(r"[0-9a-f]{16,64}", visitor):
        verdict.fingerprint = visitor
    # Phones and Chromebooks of one model look alike to a browser, so a match there is weak evidence.
    # FingerprintJS rates its own identifier 0.4 on Android and 0.3 on phone Safari. An iPad in its
    # default desktop mode says it's a Mac, and its touch screen is what gives it away.
    ipad_as_mac = claimed_os == "mac" and (_number(nav.get("touch"), 0) or 0) > 1
    verdict.weak_fingerprint = mobile or claimed_os == "chromeos" or ipad_as_mac
    # The device value leaves out anything one browser reports differently from another. It is
    # shared by every identical machine in a time zone, so alt matching gives it little weight.
    model = gpu_model(renderer)
    width, height = _number(scr.get("w")), _number(scr.get("h"))
    cores = _number(nav.get("cores"))
    zone = _text(tz.get("name"), 60)
    if model and width and height and cores and zone:
        source = f"{claimed_os}|{model}|{min(width, height)}x{max(width, height)}|{cores}|{zone}"
        verdict.device = hashlib.sha256(source.encode()).hexdigest()


def _bot_score(verdict, report) -> int:
    act = _dict(report.get("act"))
    score = 0
    if verdict.automated:
        score = 100
    if verdict.tamper_score >= 50:
        score = max(score, 60)
    duration = _number(act.get("ms"), 0) or 0
    interacted = any((_number(act.get(key), 0) or 0) > 0 for key in ("pointer", "keys", "touches", "scrolls"))
    if not interacted and duration < 1500:
        score += 25
    if verdict.weak_detector:
        score += 25
    if act.get("visible") is False:
        score += 15
    return min(100, score)


# How much each fact adds to the suspect score. The weights are judgment calls, listed here so a
# server can read them, and the score only blocks anyone if a server sets a threshold.
SUSPECT_WEIGHTS = {
    "vpn": 30, "tor": 50, "relay": 15, "hosting": 35,
    "automated": 60, "antidetect": 45, "fake_ua": 30, "tamper": 25, "vm": 20, "emulated": 30,
    "private": 10, "privacy": 10, "devtools": 10,
    "timezone_mismatch": 15, "young_account": 15, "no_avatar": 5, "disposable": 20,
}


def suspect_score(verdict: BrowserVerdict, net, *, account_days: float | None, has_avatar: bool,
                  disposable: bool, timezone_mismatch: bool) -> tuple[int, list[str]]:
    facts = {
        "vpn": net.vpn, "tor": net.tor, "relay": net.relay, "hosting": net.hosting,
        "automated": verdict.automated, "antidetect": verdict.antidetect, "fake_ua": verdict.fake_ua,
        "tamper": verdict.tamper_score >= 30, "vm": verdict.vm, "emulated": verdict.emulated,
        "private": verdict.private, "privacy": verdict.privacy, "devtools": verdict.devtools,
        "timezone_mismatch": timezone_mismatch,
        "young_account": account_days is not None and account_days < 7,
        "no_avatar": not has_avatar, "disposable": disposable,
    }
    hits = [name for name, present in facts.items() if present]
    return min(100, sum(SUSPECT_WEIGHTS[name] for name in hits)), hits
