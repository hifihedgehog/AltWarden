// Real translations for member pages, picked from the browser's language. English is built in, so a
// missing or blocked language file never breaks a page.
const SUPPORTED = ["de", "es", "fr", "ja", "ko", "pt", "ru", "zh"];
let strings = {};

export async function loadLanguage() {
  const wanted = (navigator.language || "en").slice(0, 2).toLowerCase();
  if (!SUPPORTED.includes(wanted)) return;
  try {
    const response = await fetch(`/static/i18n/${wanted}.json`, { signal: AbortSignal.timeout?.(20000) });
    if (response.ok) {
      strings = await response.json();
      // Only now, or a screen reader would read English text in the wrong voice. The Chinese strings are Simplified, for every Chinese browser.
      document.documentElement.lang = wanted === "zh" ? "zh-Hans" : wanted;
    }
  } catch {
    strings = {};
  }
}

export function t(english, values = {}) {
  const text = strings[english] ?? english;
  return text.replace(/\{(\w+)\}/g, (match, key) => values[key] ?? match);
}
