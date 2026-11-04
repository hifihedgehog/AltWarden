"""Reads the browser report from the verification page and decides what it shows.

The rules follow proven open implementations rather than guesses:

  automation     BotD's detectors run in the browser. Their verdict arrives in `bot`.
  private window detectIncognito runs in the browser. Its verdict arrives in `private`.
  tampering      CreepJS's lie detection: native functions must look native, in every way.
  worker scope   CreepJS compares a Web Worker's view of the device with the page's. A spoofing
                 tool that patches the page usually forgets the worker.
  software GPUs  the renderer names CreepJS and BotD list for virtual machines and headless Chrome.
  modified phones no web API reports root, and the services that do report it read it from a native
                 app. Chromium's model hint is the phone's ro.product.model property, which root
                 tools can rewrite, so a Pixel's model is compared with its graphics chip and its
                 Android version. A phone that changes nothing, or a jailbroken iPhone, stays unseen.
  engine check   BotD's eval length rule: 33 on Chromium, 37 on Gecko and WebKit.
  developer tools devtools-detector's console timing on Chromium, devtools-detect's window gap elsewhere.

A report comes from the member's own browser, so a determined attacker with a custom client can
forge it. These rules raise the cost and catch ordinary tools. Server-side facts, such as the
Discord account and the network, can't be forged this way, and the docs say so plainly.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

MAX_REPORT_BYTES = 64 * 1024

VM_RENDERER = re.compile(r"vmware|virtualbox|parallels|qemu|virtio|virgl|hyper-v|microsoft basic render|citrix|"
                         r"xen |svga3d|llvmpipe|softpipe|swiftshader|mesa offscreen|microsoft remote display", re.IGNORECASE)
EMULATOR_MODEL = re.compile(r"sdk_gphone|android sdk built|emulator|genymotion|vbox86|bluestacks|nox|ldplayer|memu", re.IGNORECASE)
# NVIDIA's Tegra is a real Android chip, in the Shield TV. Its desktop cards aren't.
EMULATOR_RENDERER = re.compile(r"android emulator|swiftshader|llvmpipe|virgl|geforce|radeon|intel\(r\)|nvidia(?! tegra)", re.IGNORECASE)
HEADLESS = re.compile(r"HeadlessChrome|PhantomJS|Electron|SlimerJS", re.IGNORECASE)

# The last Android version Google shipped for each Pixel that no longer gets updates. Anything
# newer on one of these phones is custom firmware. Newer Pixels aren't listed, because their
# ceiling can still rise.
FINAL_ANDROID = {"Pixel": 10, "Pixel XL": 10, "Pixel 2": 11, "Pixel 2 XL": 11, "Pixel 3": 12, "Pixel 3 XL": 12, "Pixel 3a": 12,
                 "Pixel 3a XL": 12, "Pixel 4": 13, "Pixel 4 XL": 13, "Pixel 4a": 13, "Pixel 4a (5G)": 14, "Pixel 5": 14, "Pixel 5a": 14}

# Functions whose lies matter most, because anti-detect tools patch exactly these.
HARDWARE_APIS = ("Navigator.hardwareConcurrency", "Navigator.deviceMemory", "Navigator.platform",
                 "Navigator.userAgent", "Navigator.languages", "Screen.width", "Screen.height",
                 "WebGLRenderingContext.getParameter", "WebGL2RenderingContext.getParameter",
                 "HTMLCanvasElement.toDataURL", "CanvasRenderingContext2D.getImageData",
                 "Intl.DateTimeFormat.resolvedOptions", "Date.getTimezoneOffset")


def os_family(text: str) -> str | None:
    """Reduce a user agent or platform string to one operating system family."""
    value = (text or "").lower()
    if "android" in value:
        return "android"
    if "iphone" in value or "ipad" in value or "ipod" in value:
        return "ios"
    if "win" in value:
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
    value = (renderer or "").upper()
    match = re.search(r"ANGLE \([^,]*,\s*([^,]+?)(?:\s+DIRECT3D|\s+OPENGL|\s+\(0X|,|\))", value)
    if match:
        value = match.group(1)
    value = re.sub(r"\(.*?\)|DIRECT3D\S*|D3D\d+|VS_\S+|PS_\S+|OPENGL\S*|/PCIE/SSE2|\bINC\b\.?|\bCORPORATION\b|,", " ", value)
    return " ".join(value.split())


def _text(value, limit: int = 300) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _number(value, fallback=None):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else fallback


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
    reasons: dict = field(default_factory=dict)
    os: str | None = None
    browser: str | None = None
    fingerprint: str | None = None
    device: str | None = None
    weak_fingerprint: bool = False

    def note(self, key: str, reason: str) -> None:
        self.reasons.setdefault(key, []).append(reason)


def evaluate(report: dict, headers: dict) -> BrowserVerdict:
    """Turn one untrusted report into a verdict. Every field is optional and type-checked."""
    report = _dict(report)
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
    header_ua = _text(headers.get("User-Agent"), 500)
    renderer = _text(gpu.get("renderer"))
    claimed_os = os_family(ua) or os_family(header_ua)
    verdict.os = claimed_os
    verdict.browser = browser_family(ua or header_ua)
    mobile = bool(uad.get("mobile")) or claimed_os in ("android", "ios") or "Mobi" in ua
    lied_apis = [name for name in lies.get("apis", []) if isinstance(name, str)][:64] if isinstance(lies.get("apis"), list) else []
    lie_total = int(_number(lies.get("total"), 0) or 0)

    _check_automation(verdict, bot, nav, ua, header_ua, worker, lied_apis)
    _check_identity(verdict, nav, uad, ua, header_ua, headers, eng, renderer, worker, claimed_os)
    _check_antidetect(verdict, canvas, worker, nav, gpu, lied_apis, tz, privacy, engine_of(ua))
    _check_tampering(verdict, lies, lied_apis, lie_total)
    _check_privacy(verdict, privacy, canvas, gpu, ua)
    _check_devtools(verdict, tools, mobile, engine_of(ua))
    _check_device(verdict, renderer, uad, nav, mobile, claimed_os)

    private = _dict(report.get("private"))
    if private.get("isPrivate") is True:
        verdict.private = True
        verdict.note("private", "private window")

    _fingerprints(verdict, report, nav, scr, gpu, tz, claimed_os, renderer)
    verdict.bot_score = _bot_score(verdict, report)
    return verdict


def _check_automation(verdict, bot, nav, ua, header_ua, worker, lied_apis) -> None:
    if bot.get("bot") is True:
        verdict.automated = True
        verdict.note("automated", f"BotD: {_text(bot.get('botKind'), 40) or 'unknown'}")
    if nav.get("webdriver") is True:
        verdict.automated = True
        verdict.note("automated", "webdriver flag")
    if "Navigator.webdriver" in lied_apis:
        verdict.automated = True
        verdict.note("automated", "webdriver flag hidden")
    for label, value in (("page", ua), ("request", header_ua), ("worker", _text(worker.get("ua"), 500))):
        if HEADLESS.search(value):
            verdict.automated = True
            verdict.note("automated", f"headless name in {label} user agent")


def _check_identity(verdict, nav, uad, ua, header_ua, headers, eng, renderer, worker, claimed_os) -> None:
    if ua and header_ua and ua != header_ua:
        verdict.fake_ua = True
        verdict.note("fake_ua", "page and request disagree")
    worker_ua = _text(worker.get("ua"), 500)
    if ua and worker_ua and ua != worker_ua:
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
    hint_os = os_family(_text(headers.get("Sec-CH-UA-Platform"), 40).strip('"'))
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
    needed_vendor = {"blink": "Google Inc.", "webkit": "Apple Computer, Inc.", "gecko": ""}.get(engine)
    if needed_vendor is not None and isinstance(nav.get("vendor"), str) and "Edg/" not in ua and "OPR/" not in ua:
        if nav["vendor"] != needed_vendor and not (engine == "blink" and nav["vendor"] in ("", "Google Inc.")):
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
    if spoofed:
        verdict.antidetect = True
        verdict.note("antidetect", f"{len(spoofed)} device functions rewritten")
    if worker:
        comparisons = (("cores", nav.get("cores"), worker.get("cores")),
                       ("memory", nav.get("memory"), worker.get("memory")),
                       ("platform", nav.get("platform"), worker.get("platform")),
                       ("graphics", gpu.get("renderer"), worker.get("gpu")))
        for label, page_value, worker_value in comparisons:
            if page_value not in (None, "") and worker_value not in (None, "") and page_value != worker_value:
                verdict.antidetect = True
                verdict.note("antidetect", f"worker sees different {label}")
        if tz.get("name") and worker.get("tz") and tz.get("name") != worker.get("tz"):
            verdict.antidetect = True
            verdict.note("antidetect", "worker sees a different time zone")
    # A canvas that changes between two identical draws is being randomized. Safari's private
    # windows and Firefox add noise on their own (FingerprintJS skips the canvas there for that
    # reason), and so does Brave, so this only means something on other Chrome-family browsers.
    if canvas.get("noisy") is True and engine == "blink" and not privacy.get("brave"):
        verdict.antidetect = True
        verdict.note("antidetect", "canvas output changes between draws")
    offset = _number(tz.get("offset"))
    expected = _number(tz.get("intlOffset"))
    if offset is not None and expected is not None and offset != expected:
        verdict.antidetect = True
        verdict.note("antidetect", "clock and time zone disagree")


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


def _check_privacy(verdict, privacy, canvas, gpu, ua) -> None:
    if privacy.get("brave") is True:
        verdict.privacy = True
        verdict.note("privacy", "Brave")
    if privacy.get("resist") is True:
        verdict.privacy = True
        verdict.note("privacy", "fingerprint resistance on")
    if privacy.get("tor") is True:
        verdict.privacy = True
        verdict.note("privacy", "Tor Browser")
    if canvas.get("blocked") is True:
        verdict.privacy = True
        verdict.note("privacy", "canvas blocked")
    # Firefox randomizes canvas under fingerprinting protection and Safari in private windows. Their
    # users chose that for privacy. On Chromium, where nothing built in does it, it means a spoofer.
    if engine_of(ua) in ("gecko", "webkit") and canvas.get("noisy") is True:
        verdict.privacy = True
        verdict.note("privacy", "canvas randomized")
    if engine_of(ua) == "blink" and privacy.get("gpuHidden") is True:
        verdict.privacy = True
        verdict.note("privacy", "graphics details hidden")


def _check_devtools(verdict, tools, mobile, engine) -> None:
    if mobile:
        return  # phones have no docked panel, and their window gaps are browser toolbars
    if engine == "blink":
        # In real Edge the console test fired on none of 20 rounds with no debugger, and on 17 to 20
        # with one attached, docked or not. Side panels and vertical tabs leave the same window gap
        # as a docked panel, so on Chromium the gap proves nothing the console test can't.
        if tools.get("timing") is True:
            verdict.devtools = True
            verdict.note("devtools", "console timing")
        return
    if tools.get("size") is True:
        verdict.devtools = True
        verdict.note("devtools", "window gap")
    # Safari's inspector can't be detached in a test, so a quiet run can't be shown there, and a
    # false alarm would turn away real members. Firefox stayed quiet on all 20 rounds.
    if engine == "gecko" and tools.get("timing") is True:
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


def _check_device(verdict, renderer, uad, nav, mobile, claimed_os) -> None:
    if VM_RENDERER.search(renderer):
        verdict.vm = True
        verdict.note("vm", "virtual or software graphics")
    if claimed_os != "android" and not (mobile and claimed_os == "android"):
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


def _fingerprints(verdict, report, nav, scr, gpu, tz, claimed_os, renderer) -> None:
    fp = _dict(report.get("fp"))
    visitor = fp.get("id")
    if isinstance(visitor, str) and re.fullmatch(r"[0-9a-f]{16,64}", visitor):
        verdict.fingerprint = visitor
    # Every iPhone of one model looks alike to a browser, so a match there is weak evidence.
    verdict.weak_fingerprint = claimed_os == "ios"
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
