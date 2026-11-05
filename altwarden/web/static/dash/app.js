// The dashboard shell: session, server picker, navigation, search, and the shared save bar.
import { dirtyKeys, discardAll, draftsOwner, forget, forgetAll, onChange, pagesClosed, saveAll } from "/static/dash/drafts.js";
import { api, ApiError, avatarUrl, dialog, field, focusMark, h, iconUrl, leavePage, openLayer, report, restoreFocus, segments, state, svg, syncLayers, topLayer } from "/static/dash/ui.js";

window.pageStarted = true;  // tells loading-guard.js this script loaded
const PAGES = [
  { id: "analytics", label: "Overview", load: () => import("/static/dash/analytics.js") },
  { id: "settings", label: "Rules", load: () => import("/static/dash/settings.js") },
  { id: "members", label: "Members", load: () => import("/static/dash/members.js") },
  { id: "appeals", label: "Appeals", load: () => import("/static/dash/appeals.js") },
  { id: "health", label: "Health", load: () => import("/static/dash/health.js") },
  { id: "appearance", label: "Messages", load: () => import("/static/dash/appearance.js") },
  { id: "permissions", label: "Access", load: () => import("/static/dash/permissions.js") },
  { id: "audit", label: "Audit log", load: () => import("/static/dash/audit.js") },
  { id: "integrations", label: "Integrations", load: () => import("/static/dash/integrations.js") },
];

const root = document.getElementById("root");
let saving = false;
let showInvalid = false;

function conflictDialog(part, message) {
  dialog("Someone else changed these settings", h("p", { text: `${message} Reloading drops your unsaved changes on this page. They can't be saved until you do.` }), { buttons: [
    { label: "Keep editing" },
    { label: "Reload", kind: "primary", onClick: () => {
      forget(part.key);
      route();
    } },
  ] });
}

// A setting the server refused gets shown, even when the save started on another page.
async function saveEverything() {
  // A second press would send the revision the first press is about to replace, and look like a conflict.
  if (saving) return;
  saving = true;
  const guildId = state.guild.id;
  let failed;
  try {
    failed = await saveAll();
  } finally {
    saving = false;
  }
  if (state.guild?.id !== guildId) return;
  if (!failed) {
    refreshGuild(guildId);
    return;
  }
  if (failed.error?.data?.conflict) {
    conflictDialog(failed.part, failed.error.message);
    return;
  }
  const page = failed.part.key;
  const here = location.pathname.endsWith(`/${page}`);
  const item = failed.error?.data?.items?.[0]?.item;
  if (failed.invalid && !here) {
    showInvalid = true;
    navigate(`/dashboard/${guildId}/${page}`);
  } else if (item && here) {
    showItem(item);
  } else if (item) {
    navigate(`/dashboard/${guildId}/${page}#${item}`);
  }
}

// A save can change what Health says, and only this shell shows that.
async function refreshGuild(guildId) {
  try {
    const guild = await api(`/api/guilds/${guildId}`);
    if (state.guild?.id === guildId) {
      state.guild = guild;
      drawGuildMarks();
    }
  } catch {
    // The marks stay as they were until the next page opens.
  }
}

function showItem(target) {
  const node = target && document.getElementById(`item-${target}`);
  if (!node) return;
  node.scrollIntoView({ block: "center" });
  node.classList.add("flash");
  setTimeout(() => node.classList.remove("flash"), 1800);
}

function drawSaveBar() {
  const keys = dirtyKeys();
  document.querySelector(".savebar")?.remove();
  for (const link of document.querySelectorAll(".nav a[data-page]")) link.classList.toggle("unsaved", keys.includes(link.dataset.page));
  if (!keys.length) return;
  document.body.append(h("div", { class: "savebar" },
    h("span", { text: "You have unsaved changes." }),
    h("button", { class: "button small", text: "Discard", onclick: discardAll }),
    h("button", { class: "button small primary", text: "Save changes", onclick: saveEverything })));
  syncLayers();  // an edit in a dialog can bring the bar up, and it stays behind that dialog
}
onChange(drawSaveBar);

// The raid pill and the Health dot belong to the shell, so a page that changes them says so.
function drawGuildMarks() {
  const title = document.querySelector(".topbar h1");
  document.querySelector(".raid-pill")?.remove();
  if (title && state.guild?.raid_until * 1000 > Date.now()) title.after(h("span", { class: "pill bad raid-pill", text: "Raid mode on" }));
  const health = document.querySelector(".nav [data-page=health]");
  const amber = health?.querySelector(".dot.amber");  // a locked page has no dots at all
  if (amber) {
    health.querySelector(".dot:not(.amber)")?.remove();
    if (state.guild?.healthy === false) amber.before(h("span", { class: "dot", title: "Something needs fixing" }));
  }
}
document.addEventListener("aw-guild", drawGuildMarks);

function readLook() {
  try {
    return { theme: localStorage.getItem("aw-theme") || "auto", accent: localStorage.getItem("aw-accent") || "" };
  } catch {
    return { theme: "auto", accent: "" };
  }
}

function applyLook({ theme, accent }) {
  const root = document.documentElement;
  if (theme === "auto") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", theme);
  for (const name of ["--accent", "--accent-strong"]) {
    if (accent) root.style.setProperty(name, accent);
    else root.style.removeProperty(name);
  }
}

function saveLook(look) {
  applyLook(look);
  try {
    localStorage.setItem("aw-theme", look.theme);
    localStorage.setItem("aw-accent", look.accent);
  } catch {
    // The choice just won't last past this visit.
  }
}

function lookButton() {
  applyLook(readLook());
  return h("button", { class: "icon-button", text: "Look", title: "Theme and accent color", onclick: () => {
    const look = readLook();
    dialog("Look", h("div", { class: "grid" },
      field("Theme", segments([{ id: "auto", label: "Match system" }, { id: "dark", label: "Dark" }, { id: "gray", label: "Gray" }, { id: "light", label: "Light" }], look.theme, (value) => { look.theme = value; saveLook(look); }, { label: "Theme" })),
      field("Accent color", h("input", { type: "color", value: look.accent || "#14b8a6", oninput: (event) => { look.accent = event.target.value; saveLook(look); } })),
      h("button", { class: "button small", text: "Use the default color", onclick: () => { look.accent = ""; saveLook(look); } })),
    { buttons: [{ label: "Done" }] });
  } });
}

function serverMenu(current) {
  const list = h("div", { class: "nav" }, state.session.guilds.map((guild) => h("a", { href: `/dashboard/${guild.id}` },
    h("img", { class: "server-icon", src: iconUrl(guild.id, guild.icon), alt: "" }),
    h("span", { text: guild.name }))));
  list.hidden = true;
  const button = h("button", { class: "server-button", "aria-expanded": "false", onclick: () => {
    list.hidden = !list.hidden;
    button.setAttribute("aria-expanded", String(!list.hidden));
  } },
  h("img", { src: iconUrl(current?.id, current?.icon), alt: "" }), h("span", { text: current?.name ?? "Pick a server" }), h("small", { class: "faint", text: "▾" }));
  return [button, list];
}

function lockIcon() {
  return svg("svg", { class: "lock", viewBox: "0 0 16 16", width: 12, height: 12, "aria-hidden": "true" },
    svg("path", { d: "M4 7V5a4 4 0 0 1 8 0v2h1v8H3V7Zm2 0h4V5a2 2 0 0 0-4 0Z", fill: "currentColor" }));
}

// A locked page isn't a link, so the keyboard can't land on it and a screen reader says why it's there.
function navItem(item, page, guild, open) {
  if (!open) {
    return h("span", { class: "locked", "data-page": item.id, "aria-disabled": "true", title: "You don't have access to this page" },
      item.label, lockIcon(), h("span", { class: "visually-hidden", text: " (locked)" }));
  }
  return h("a", { href: `/dashboard/${guild.id}/${item.id}`, class: item.id === page ? "active" : "", "data-page": item.id, "aria-current": item.id === page ? "page" : null }, item.label,
    item.id === "health" && guild.healthy === false ? h("span", { class: "dot", title: "Something needs fixing" }) : null,
    h("span", { class: "dot amber", title: "Unsaved changes" }));
}

function closeMenu(returnFocus = true) {
  const side = document.getElementById("side");
  if (!side?.classList.contains("open")) return;
  side.classList.remove("open");
  const toggle = document.querySelector(".menu-toggle");
  toggle?.setAttribute("aria-expanded", "false");
  if (returnFocus) toggle?.focus();
}

function openMenu() {
  const side = document.getElementById("side");
  side.classList.add("open");
  document.querySelector(".menu-toggle").setAttribute("aria-expanded", "true");
  side.querySelector("button")?.focus();
}

function sideBar(page) {
  const guild = state.guild;
  const allowed = guild?.pages ?? {};
  const nav = guild ? h("nav", { class: "nav", "aria-label": "Pages" }, PAGES.map((item) => navItem(item, page, guild, allowed[item.id]?.view))) : null;
  return h("aside", { class: "side", id: "side" },
    h("button", { class: "icon-button side-close", text: "Close menu", onclick: () => closeMenu() }),
    h("a", { class: "brand", href: "/" }, h("img", { src: "/static/img/logo.svg", alt: "" }), "AltWarden"),
    serverMenu(guild), nav,
    h("div", { class: "side-links" },
      h("a", { href: "/docs", target: "_blank", text: "Docs" }),
      h("a", { href: "https://github.com/hifihedgehog/AltWarden/issues", target: "_blank", rel: "noopener", text: "Support" })),
    h("div", { class: "side-foot" },
      h("img", { src: avatarUrl(state.session.user.id, state.session.user.avatar), alt: "" }),
      h("span", { class: "name", text: state.session.user.name }),
      lookButton(),
      h("button", { class: "icon-button", text: "Sign out", onclick: async () => {
        await api("/api/logout", { method: "POST" });
        location.href = "/";
      } })));
}

function shell(page, title) {
  const view = h("div", { class: "view", id: "view" });
  root.replaceChildren(h("div", { class: "shell" }, sideBar(page), h("div", { class: "scrim", onclick: () => closeMenu() }),
    h("main", { class: "main" },
      h("header", { class: "topbar" },
        h("button", { class: "icon-button menu-toggle", text: "Menu", "aria-expanded": "false", "aria-controls": "side", onclick: () => {
          if (document.getElementById("side").classList.contains("open")) closeMenu();
          else openMenu();
        } }),
        h("h1", { text: title }),
        state.guild ? h("button", { class: "search-open", onclick: openSearch }, "Search", h("kbd", { text: "Ctrl K" })) : null),
      view)));
  drawGuildMarks();
  return view;
}

function searchEntries() {
  const entries = PAGES.filter((item) => state.guild.pages[item.id]?.view).map((item) => ({ label: item.label, kind: "Page", go: `/dashboard/${state.guild.id}/${item.id}` }));
  if (state.guild.pages.settings?.view) {
    for (const check of state.catalog.checks) entries.push({ label: check.name, kind: "Rule", go: `/dashboard/${state.guild.id}/settings#${check.id}` });
    for (const [id, label] of [["core", "Verification mode"], ["core", "Verified role"], ["core", "Verification channel"], ["unverified", "Unverified role"], ["autodm", "DM new members"],
      ["closeddms", "Ping when DMs are closed"], ["autokick", "Auto kick"], ["cooldown", "Cooldown"], ["rejoin", "Remember verified members"], ["reason", "Tell members why"],
      ["failopen", "Let members through if network data is missing"], ["external", "Outside VPN lookup"], ["direct", "Skip the start page"], ["logs", "Logs"], ["alerts", "Alerts"],
      ["helpdesk", "Help desk"], ["honeypot", "Honeypot"], ["raid", "Raid mode"], ["appeals", "Appeals setup"], ["retention", "Data retention"]]) {
      entries.push({ label, kind: "Setting", go: `/dashboard/${state.guild.id}/settings#${id}` });
    }
  }
  if (state.guild.pages.permissions?.view) {
    for (const name of state.catalog.commands) entries.push({ label: `/${name}`, kind: "Permission", go: `/dashboard/${state.guild.id}/permissions#command-${name}` });
    for (const page of PAGES) entries.push({ label: `Who can open ${page.label}`, kind: "Permission", go: `/dashboard/${state.guild.id}/permissions#page-${page.id}-view` });
  }
  for (const guild of state.session.guilds) entries.push({ label: guild.name, kind: "Server", go: `/dashboard/${guild.id}` });
  return entries;
}

function openSearch() {
  if (!state.guild || topLayer()) return;
  const opener = focusMark();
  const entries = searchEntries();
  let selected = 0;
  let shown = entries;
  let closeLayer = () => {};
  const list = h("ul", { role: "listbox", id: "palette-list", "aria-label": "Results" });
  const close = (back = true) => {
    closeLayer();
    if (back) restoreFocus(opener);
  };
  const go = (entry) => { close(false); navigate(entry.go); };
  const draw = () => {
    list.replaceChildren(...shown.slice(0, 30).map((entry, index) => h("li", { role: "none" }, h("button", {
      role: "option", id: `palette-${index}`, "aria-selected": String(index === selected), class: index === selected ? "on" : "", onclick: () => go(entry) },
    h("span", { text: entry.label }), h("small", { text: entry.kind })))));
    if (shown.length) input.setAttribute("aria-activedescendant", `palette-${selected}`);
    else input.removeAttribute("aria-activedescendant");
  };
  const input = h("input", { type: "search", role: "combobox", "aria-expanded": "true", "aria-controls": "palette-list", placeholder: "Search pages, rules and servers", "aria-label": "Search", oninput: (event) => {
    const term = event.target.value.toLowerCase();
    shown = entries.filter((entry) => entry.label.toLowerCase().includes(term));
    selected = 0;
    draw();
  }, onkeydown: (event) => {
    if (event.key === "ArrowDown") { selected = Math.min(selected + 1, shown.length - 1); draw(); event.preventDefault(); }
    if (event.key === "ArrowUp") { selected = Math.max(selected - 1, 0); draw(); event.preventDefault(); }
    if (event.key === "Enter" && shown[selected]) go(shown[selected]);
  } });
  const overlay = h("div", { class: "overlay", onclick: (event) => { if (event.target === overlay) close(); } },
    h("div", { class: "dialog palette", role: "dialog", "aria-modal": "true", "aria-label": "Search" }, input, list));
  closeLayer = openLayer(overlay, close);
  draw();
  input.focus();
  syncLayers();
}

addEventListener("keydown", (event) => {
  const mod = event.ctrlKey || event.metaKey;
  if (mod && event.key.toLowerCase() === "k") { event.preventDefault(); openSearch(); }
  if (mod && event.key.toLowerCase() === "s" && dirtyKeys().length) { event.preventDefault(); saveEverything(); }
  if (event.key === "Escape" && !topLayer()) closeMenu();
});

// Every way into another server comes through here: a link, the search palette, Back and Forward.
function mayLeaveFor(path) {
  const target = new URL(path, location.origin).pathname.split("/")[2];
  if (!dirtyKeys().length || target === draftsOwner()) return true;
  if (!confirm("You have unsaved changes in this server. Leave and lose them?")) return false;
  forgetAll();
  return true;
}

export function navigate(path) {
  if (!mayLeaveFor(path)) return;
  history.pushState(null, "", path);
  route();
}

document.addEventListener("click", (event) => {
  const link = event.target.closest?.("a[href^='/dashboard']");
  if (link && !event.ctrlKey && !event.metaKey) {
    event.preventDefault();
    navigate(link.getAttribute("href"));
  }
});

let shownPath = location.pathname + location.search + location.hash;
addEventListener("popstate", () => {
  if (!mayLeaveFor(location.pathname)) {
    history.pushState(null, "", shownPath);  // the page never left, so the address shouldn't have
    return;
  }
  route();
});
addEventListener("beforeunload", (event) => { if (dirtyKeys().length) event.preventDefault(); });
// An action nothing else is waiting on still has to say it failed. A request's failure is expected, so it isn't a page error.
addEventListener("unhandledrejection", (event) => {
  if (event.reason instanceof ApiError) event.preventDefault();
  report(event.reason);
});

function showServers() {
  const view = shell(null, "Your servers");
  const guilds = state.session.guilds;
  if (!guilds.length) {
    view.append(h("p", { class: "muted", text: "AltWarden isn't running on any server you have access to. If you just added it, sign out and back in." }));
    return;
  }
  view.append(h("div", { class: "grid two" }, guilds.map((guild) => h("div", { class: "panel" },
    h("div", { class: "who" }, h("img", { src: iconUrl(guild.id, guild.icon), alt: "" }), h("strong", { text: guild.name })),
    h("div", { class: "toolbar" }), h("a", { class: "button primary small", href: `/dashboard/${guild.id}`, text: "Open" })))));
}

// Only the newest navigation may draw, because an older one can answer last.
let routeTurn = 0;

async function route() {
  const turn = ++routeTurn;
  shownPath = location.pathname + location.search + location.hash;
  leavePage();
  pagesClosed();
  const [, , guildId, pageId] = location.pathname.split("/");
  if (!guildId) {
    state.guild = null;
    showServers();
    return;
  }
  let guild;
  try {
    guild = await api(`/api/guilds/${guildId}`);
  } catch (error) {
    if (turn !== routeTurn) return;
    state.guild = null;
    shell(null, "Can't open this server").append(h("p", { class: "muted", text: error.message }));
    return;
  }
  if (turn !== routeTurn) return;
  state.guild = guild;
  document.title = `${state.guild.name} | AltWarden`;
  if (!state.guild.setup_done) {
    const view = shell(null, "Set up AltWarden");
    try {
      (await import("/static/dash/setup.js")).render(view, () => route());
    } catch (error) {
      view.append(h("div", { class: "notice bad", text: error.message }));
    }
    return;
  }
  const first = PAGES.find((item) => state.guild.pages[item.id]?.view);
  const asked = PAGES.find((item) => item.id === pageId);
  if (asked && !state.guild.pages[asked.id]?.view) {
    shell(null, asked.label).append(h("div", { class: "notice bad", text: "You don't have access to this page." }));
    return;
  }
  const page = asked ?? first;
  if (!page) {
    shell(null, "No access").append(h("p", { class: "muted", text: "You don't have access to any page here." }));
    return;
  }
  const view = shell(page.id, page.label);
  try {
    await (await page.load()).render(view);
    if (turn !== routeTurn) return;
    drawSaveBar();
    showItem(location.hash.slice(1));
    if (showInvalid) {
      showInvalid = false;
      const bad = view.querySelector("input:invalid");
      bad?.scrollIntoView({ block: "center" });
      bad?.focus();
    }
  } catch (error) {
    if (turn !== routeTurn) return;
    view.append(h("div", { class: "notice bad", text: error.message }));
  }
}

async function start() {
  try {
    state.session = await api("/api/session");
    state.csrf = state.session.csrf;
    state.catalog = await api("/api/catalog");
  } catch (error) {
    if (!error.signingIn) root.replaceChildren(h("p", { class: "prose" }, `${error.message} `, h("a", { href: location.href, text: "Reload" }), " to try again."));
    return;
  }
  await route();
}

start();
