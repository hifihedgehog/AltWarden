// Gathers the browser report the server judges. The proven parts run as published:
//   FingerprintJS  the browser identifier
//   BotD           automation detection
//   detectIncognito private window detection
// The rest compares what the browser says about itself in different places. A real browser agrees
// with itself, and a spoofed one usually doesn't. Nothing here leaves this site.

const started = performance.now();
const activity = { pointer: 0, keys: 0, touches: 0, scrolls: 0 };
addEventListener("pointermove", () => activity.pointer++, { passive: true });
addEventListener("keydown", () => activity.keys++, { passive: true });
addEventListener("touchstart", () => activity.touches++, { passive: true });
addEventListener("scroll", () => activity.scrolls++, { passive: true });

const within = (promise, ms, fallback = null) =>
  Promise.race([Promise.resolve(promise).catch(() => fallback), new Promise((resolve) => setTimeout(() => resolve(fallback), ms))]);

function isNativeSource(source, name) {
  return source === `function ${name}() { [native code] }` ||
    source === `function get ${name}() { [native code] }` ||
    source === `function ${name}() {\n    [native code]\n}` ||
    source === `function get ${name}() {\n    [native code]\n}`;
}

// A native function looks native in every way, not only in its printed source. These are the tests
// CreepJS runs: printed source, own properties, and the errors a real native function throws. Only the
// tests the language and WebIDL specs guarantee are here, so a browser update can't turn them on real members.
function functionLies(fn, name, cleanToString, proto) {
  const lies = [];
  try {
    if (!isNativeSource(cleanToString.call(fn), name)) lies.push("source");
    if (Object.prototype.hasOwnProperty.call(fn, "prototype")) lies.push("prototype");
    const own = Object.getOwnPropertyNames(fn).sort().join(",");
    if (own !== "length,name") lies.push("properties");
    if (Object.prototype.hasOwnProperty.call(fn, "toString")) lies.push("own toString");
    let threw = false;
    try { Object.create(fn).toString(); } catch (error) { threw = error instanceof TypeError; }
    if (!threw) lies.push("object toString");
    threw = false;
    try { new fn(); } catch (error) { threw = error instanceof TypeError; }
    if (!threw) lies.push("constructor");
    // WebIDL: reading an attribute on the prototype itself throws. A stand-in getter usually just answers.
    if (Object.getOwnPropertyDescriptor(proto, name)?.get) {
      threw = false;
      try { proto[name]; } catch (error) { threw = error instanceof TypeError; }
      if (!threw) lies.push("illegal");
    }
    // A cycle in a prototype chain throws a TypeError. The search for one stops at a Proxy
    // (ECMA-262, OrdinarySetPrototypeOf), so a wrapped function lets the cycle in.
    const parent = Object.getPrototypeOf(fn);
    threw = false;
    try { Object.setPrototypeOf(fn, Object.create(fn)); } catch (error) { threw = error instanceof TypeError; }
    Object.setPrototypeOf(fn, parent);
    if (!threw) lies.push("proxy chain");
  } catch {
    lies.push("inspection failed");
  }
  return lies;
}

const TARGETS = () => [
  ["Navigator", Navigator.prototype, ["hardwareConcurrency", "deviceMemory", "platform", "userAgent", "languages", "webdriver", "vendor", "maxTouchPoints"]],
  ["Screen", Screen.prototype, ["width", "height", "colorDepth", "availWidth", "availHeight"]],
  ["HTMLCanvasElement", HTMLCanvasElement.prototype, ["toDataURL", "toBlob", "getContext"]],
  ["CanvasRenderingContext2D", CanvasRenderingContext2D.prototype, ["getImageData", "fillText", "measureText"]],
  ["WebGLRenderingContext", window.WebGLRenderingContext?.prototype, ["getParameter", "getExtension"]],
  ["WebGL2RenderingContext", window.WebGL2RenderingContext?.prototype, ["getParameter"]],
  ["Date", Date.prototype, ["getTimezoneOffset"]],
  ["Intl.DateTimeFormat", Intl.DateTimeFormat.prototype, ["resolvedOptions"]],
];

function detectLies() {
  // An iframe gives a clean copy of Function.prototype.toString to check the page's copy against.
  const frame = document.createElement("iframe");
  frame.hidden = true;
  document.body.appendChild(frame);
  const cleanToString = frame.contentWindow?.Function?.prototype?.toString ?? Function.prototype.toString;
  const report = { total: 0, apis: [], toString: false, proxy: false };
  try {
    // Chromium prints a native function on one line, and Firefox and Safari across three.
    if (!isNativeSource(cleanToString.call(Function.prototype.toString), "toString")) report.toString = true;
    for (const [label, proto, names] of TARGETS()) {
      if (!proto) continue;
      for (const name of names) {
        const descriptor = Object.getOwnPropertyDescriptor(proto, name);
        const fn = descriptor?.get ?? descriptor?.value;
        const lies = typeof fn === "function" ? functionLies(fn, name, cleanToString, proto) : [];
        // These live on the prototype in every browser, so one set on the object itself was put there.
        const instance = { Navigator: navigator, Screen: screen }[label];
        if (instance && Object.prototype.hasOwnProperty.call(instance, name)) lies.push("own property");
        if (lies.length) {
          report.total++;
          report.apis.push(`${label}.${name}`);
          // A Proxy alone doesn't count here. Privacy extensions use them, and a server's Watch on those has to hold.
          if (lies.includes("constructor") && !lies.includes("source")) report.proxy = true;
        }
      }
    }
  } finally {
    frame.remove();
  }
  return report;
}

function drawCanvas() {
  const canvas = document.createElement("canvas");
  canvas.width = 240;
  canvas.height = 60;
  const context = canvas.getContext("2d");
  if (!context) return "";
  context.textBaseline = "top";
  context.font = "16px Arial";
  context.fillStyle = "#f60";
  context.fillRect(10, 5, 90, 30);
  context.fillStyle = "#069";
  context.fillText("AltWarden, check me 12345", 4, 22);
  context.fillStyle = "rgba(102, 204, 0, 0.7)";
  context.beginPath();
  context.arc(180, 30, 22, 0, Math.PI * 2);
  context.fill();
  return canvas.toDataURL();
}

function canvasCheck() {
  try {
    const first = drawCanvas();
    const second = drawCanvas();
    const blank = document.createElement("canvas");
    blank.width = 240;
    blank.height = 60;
    return { noisy: first !== second, blocked: !first || first === blank.toDataURL() };
  } catch {
    return { noisy: false, blocked: true };
  }
}

function graphics() {
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (!gl) return { vendor: "", renderer: "", hidden: true };
    const info = gl.getExtension("WEBGL_debug_renderer_info");
    return info
      ? { vendor: String(gl.getParameter(info.UNMASKED_VENDOR_WEBGL)), renderer: String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL)), hidden: false }
      : { vendor: String(gl.getParameter(gl.VENDOR)), renderer: String(gl.getParameter(gl.RENDERER)), hidden: true };
  } catch {
    return { vendor: "", renderer: "", hidden: true };
  }
}

function workerView() {
  return new Promise((resolve) => {
    try {
      const worker = new Worker("/static/js/workers/probe.js");
      worker.onmessage = ({ data }) => { worker.terminate(); resolve(data); };
      worker.onerror = () => { worker.terminate(); resolve(null); };
    } catch {
      resolve(null);
    }
  });
}

// Firefox's resistFingerprinting and Tor clamp the clock, so timers land on the same last digit.
async function clockIsClamped() {
  const digits = [];
  for (let i = 0; i < 8; i++) {
    await new Promise((resolve) => setTimeout(resolve, i));
    digits.push(Date.now() % 10);
  }
  return digits.every((digit) => digit === digits[0]);
}

// FingerprintJS's test. Firefox drops old names over time, so it takes four of six rather than one.
function isGecko() {
  const signs = ["buildID" in navigator, "MozAppearance" in document.documentElement.style, "onmozfullscreenchange" in window,
    "mozInnerScreenX" in window, "CSSMozDocumentRule" in window, "CanvasCaptureMediaStream" in window];
  return signs.filter(Boolean).length >= 4;
}

async function privacyState(gpu) {
  const state = { gpuHidden: gpu.hidden };
  try {
    state.brave = Boolean(navigator.brave && await navigator.brave.isBrave());
  } catch {
    state.brave = false;
  }
  // With resistFingerprinting on, Firefox names its graphics "Mozilla". Newer versions clamp the
  // clock too finely for the digit test, so the name goes first.
  if (isGecko() && (gpu.renderer === "Mozilla" || await clockIsClamped())) {
    state.resist = true;
    state.tor = !("RTCRtpTransceiver" in window) && !("MediaDevices" in window) && !("Credential" in window);
  }
  return state;
}

// devtools-detector's console timing test: printing a large table is far slower than logging it only
// while the console panel is open, or a script is driving the browser. That project keeps a running
// maximum across many checks over time. This page checks once, so it takes three rounds, and all three
// must agree, because one slow moment on a busy machine looks the same.
export function developerTools() {
  const row = Object.fromEntries(Array.from({ length: 500 }, (_, i) => [i, String(i)]));
  const rows = Array(50).fill(row);
  const time = (print) => { const begin = performance.now(); print(); return performance.now() - begin; };
  let slowestLog = 0;
  let agreed = 0;
  for (let round = 0; round < 3; round++) {
    const tableTime = time(() => console.table(rows));
    slowestLog = Math.max(slowestLog, time(() => console.log(rows)), time(() => console.log(rows)));
    if (slowestLog > 0 && tableTime > slowestLog * 10) agreed++;
  }
  console.clear();
  return { timing: agreed === 3 };
}

async function userAgentData() {
  const data = navigator.userAgentData;
  if (!data) return null;
  const extra = await within(data.getHighEntropyValues(["architecture", "bitness", "model", "platformVersion", "uaFullVersion"]), 500, {});
  return { brands: data.brands, mobile: data.mobile, platform: data.platform, ...extra };
}

function timeZone() {
  const name = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const now = new Date();
  // What the zone's name says the offset should be, worked out without getTimezoneOffset.
  let intlOffset = null;
  try {
    const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
      timeZone: name, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric",
    }).formatToParts(now).map(({ type, value }) => [type, Number(value)]));
    const local = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
    intlOffset = Math.round((Math.floor(now.getTime() / 1000) * 1000 - local) / 60000);
  } catch {
    intlOffset = null;
  }
  return { name, offset: now.getTimezoneOffset(), intlOffset };
}

export async function collect() {
  const gpu = graphics();
  // Which detectors fired goes along too, because one of them alone is ordinary on a real browser.
  const botd = within(import("/static/vendor/botd-2.0.0.esm.js").then((module) => module.load()).then((detector) => {
    const verdict = detector.detect();
    return { ...verdict, fired: Object.entries(detector.getDetections() ?? {}).filter(([, found]) => found.bot).map(([name]) => name) };
  }), 2500);
  const fingerprint = within(window.FingerprintJS?.load({ monitoring: false }).then((agent) => agent.get()), 4000);
  const privateWindow = within(window.detectIncognito?.detectIncognito?.() ?? window.detectIncognito?.(), 2000);
  const [uad, worker, privacy, fp, bot, incognito] = await Promise.all([
    userAgentData(), within(workerView(), 1500), privacyState(gpu), fingerprint, botd, privateWindow,
  ]);
  const connection = navigator.connection;
  return {
    v: 1,
    fp: fp ? { id: fp.visitorId, confidence: fp.confidence?.score } : null,
    bot: bot ?? null,
    private: incognito ? { isPrivate: incognito.isPrivate, browser: incognito.browserName } : null,
    nav: {
      ua: navigator.userAgent, platform: navigator.platform, vendor: navigator.vendor, webdriver: navigator.webdriver,
      cores: navigator.hardwareConcurrency, memory: navigator.deviceMemory, languages: navigator.languages,
      touch: navigator.maxTouchPoints, pdf: navigator.pdfViewerEnabled, modern: CSS.supports("border-end-end-radius: initial"),
    },
    uad,
    scr: { w: screen.width, h: screen.height, iw: innerWidth, ih: innerHeight, ow: outerWidth, oh: outerHeight, dpr: devicePixelRatio },
    tz: timeZone(),
    gpu: { vendor: gpu.vendor, renderer: gpu.renderer },
    worker,
    eng: { evalLen: eval.toString().length },
    lies: detectLies(),
    canvas: canvasCheck(),
    privacy,
    devtools: developerTools(),
    conn: connection ? { type: connection.type, effectiveType: connection.effectiveType } : null,
    act: { ...activity, ms: Math.round(performance.now() - started), visible: document.visibilityState === "visible" },
  };
}

export function solvePuzzle(salt, bits) {
  return new Promise((resolve, reject) => {
    const worker = new Worker("/static/js/workers/pow.js");
    worker.onmessage = ({ data }) => { worker.terminate(); resolve(data.counter); };
    worker.onerror = () => { worker.terminate(); reject(new Error("puzzle failed")); };
    worker.postMessage({ salt, bits });
  });
}
