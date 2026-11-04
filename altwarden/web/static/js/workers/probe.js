// Reports what a Web Worker sees of the device. Tools that fake values on the page often miss the
// worker, so the server compares the two views. This follows CreepJS's worker scope comparison.
function graphicsRenderer() {
  try {
    const canvas = new OffscreenCanvas(1, 1);
    const gl = canvas.getContext("webgl");
    if (!gl) return "";
    const info = gl.getExtension("WEBGL_debug_renderer_info");
    return info ? String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL)) : "";
  } catch {
    return "";
  }
}

self.postMessage({
  ua: navigator.userAgent,
  platform: navigator.platform,
  cores: navigator.hardwareConcurrency,
  memory: navigator.deviceMemory,
  languages: navigator.languages,
  tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
  gpu: graphicsRenderer(),
});
