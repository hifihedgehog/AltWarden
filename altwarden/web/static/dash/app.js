// The dashboard shell: session, server picker, navigation, search, and the shared save bar.
import { dirtyKeys, discardAll, forgetAll, onChange, pagesClosed, saveAll } from "/static/dash/drafts.js";
import { api, avatarUrl, dialog, field, h, iconUrl, segments, state } from "/static/dash/ui.js";

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

// A setting the server refused gets shown, even when the save started on another page.
async function saveEverything() {
  const failed = await saveAll();
  const item = failed?.error?.data?.items?.[0]?.item;
  if (!item) return;
  const page = failed.part.key;
  if (location.pathname.endsWith(`/${page}`)) showItem(item);
  else navigate(`/dashboard/${state.guild.id}/${page}#${item}`);
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
}
onChange(drawSaveBar);

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

function sideBar(page) {
  const guild = state.guild;
  const allowed = guild?.pages ?? {};
  const nav = guild ? h("nav", { class: "nav", "aria-label": "Pages" }, PAGES.map((item) => {
    const open = allowed[item.id]?.view;
    return h("a", { href: `/dashboard/${guild.id}/${item.id}`, class: `${item.id === page ? "active" : ""} ${open ? "" : "locked"}`,
      "data-page": item.id, "aria-current": item.id === page ? "page" : null }, item.label,
    item.id === "health" && guild.healthy === false ? h("span", { class: "dot", title: "Something needs fixing" }) : null,
    h("span", { class: "dot amber", title: "Unsaved changes" }));
  })) : null;
  return h("aside", { class: "side", id: "side" },
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
  const raid = state.guild && state.guild.raid_until * 1000 > Date.now();
  root.replaceChildren(h("div", { class: "shell" }, sideBar(page),
    h("main", { class: "main" },
      h("header", { class: "topbar" },
        h("button", { class: "icon-button menu-toggle", text: "Menu", onclick: () => document.getElementById("side").classList.toggle("open") }),
        h("h1", { text: title }),
        raid ? h("span", { class: "pill bad", text: "Raid mode on" }) : null,
        state.guild ? h("button", { class: "search-open", onclick: openSearch }, "Search", h("kbd", { text: "Ctrl K" })) : null),
      view)));
  return view;
}

function searchEntries() {
  const entries = PAGES.filter((item) => state.guild.pages[item.id]?.view).map((item) => ({ label: item.label, kind: "Page", go: `/dashboard/${state.guild.id}/${item.id}` }));
  for (const check of state.catalog.checks) entries.push({ label: check.name, kind: "Rule", go: `/dashboard/${state.guild.id}/settings#${check.id}` });
  for (const [id, label] of [["core", "Verification mode"], ["core", "Verified role"], ["core", "Verification channel"], ["unverified", "Unverified role"], ["autodm", "DM new members"],
    ["closeddms", "Ping when DMs are closed"], ["autokick", "Auto kick"], ["cooldown", "Cooldown"], ["rejoin", "Remember verified members"], ["reason", "Tell members why"],
    ["failopen", "Let members through if network data is missing"], ["external", "Outside VPN lookup"], ["direct", "Skip the start page"], ["logs", "Logs"], ["alerts", "Alerts"],
    ["helpdesk", "Help desk"], ["honeypot", "Honeypot"], ["raid", "Raid mode"], ["appeals", "Appeals setup"], ["retention", "Data retention"]]) {
    entries.push({ label, kind: "Setting", go: `/dashboard/${state.guild.id}/settings#${id}` });
  }
  if (state.guild.pages.permissions?.view) {
    for (const name of state.catalog.commands) entries.push({ label: `/${name}`, kind: "Permission", go: `/dashboard/${state.guild.id}/permissions#command-${name}` });
    for (const page of PAGES) entries.push({ label: `Who can open ${page.label}`, kind: "Permission", go: `/dashboard/${state.guild.id}/permissions#page-${page.id}-view` });
  }
  for (const guild of state.session.guilds) entries.push({ label: guild.name, kind: "Server", go: `/dashboard/${guild.id}` });
  return entries;
}

function openSearch() {
  if (!state.guild || document.querySelector(".palette")) return;
  const entries = searchEntries();
  let selected = 0;
  let shown = entries;
  const list = h("ul");
  const close = () => overlay.remove();
  const go = (entry) => { close(); navigate(entry.go); };
  const draw = () => list.replaceChildren(...shown.slice(0, 30).map((entry, index) => h("li", {}, h("button", {
    class: index === selected ? "on" : "", onclick: () => go(entry) }, h("span", { text: entry.label }), h("small", { text: entry.kind })))));
  const input = h("input", { type: "search", placeholder: "Search pages, rules and servers", "aria-label": "Search", oninput: (event) => {
    const term = event.target.value.toLowerCase();
    shown = entries.filter((entry) => entry.label.toLowerCase().includes(term));
    selected = 0;
    draw();
  }, onkeydown: (event) => {
    if (event.key === "ArrowDown") { selected = Math.min(selected + 1, shown.length - 1); draw(); event.preventDefault(); }
    if (event.key === "ArrowUp") { selected = Math.max(selected - 1, 0); draw(); event.preventDefault(); }
    if (event.key === "Enter" && shown[selected]) go(shown[selected]);
    if (event.key === "Escape") close();
  } });
  const overlay = h("div", { class: "overlay", onclick: (event) => { if (event.target === overlay) close(); } },
    h("div", { class: "dialog palette", role: "dialog", "aria-label": "Search" }, input, list));
  document.body.append(overlay);
  draw();
  input.focus();
}

addEventListener("keydown", (event) => {
  const mod = event.ctrlKey || event.metaKey;
  if (mod && event.key.toLowerCase() === "k") { event.preventDefault(); openSearch(); }
  if (mod && event.key.toLowerCase() === "s" && dirtyKeys().length) { event.preventDefault(); saveEverything(); }
});

export function navigate(path) {
  history.pushState(null, "", path);
  route();
}

document.addEventListener("click", (event) => {
  const link = event.target.closest?.("a[href^='/dashboard']");
  if (link && !event.ctrlKey && !event.metaKey) {
    event.preventDefault();
    const target = link.getAttribute("href");
    if (dirtyKeys().length && target.split("/")[2] !== state.guild?.id) {
      if (!confirm("You have unsaved changes in this server. Leave and lose them?")) return;
      forgetAll();
    }
    navigate(target);
  }
});
addEventListener("popstate", route);
addEventListener("beforeunload", (event) => { if (dirtyKeys().length) event.preventDefault(); });

function showServers() {
  const view = shell(null, "Your servers");
  const guilds = state.session.guilds;
  if (!guilds.length) {
    view.append(h("p", { class: "muted", text: "AltWarden isn't running on any server you have access to." }));
    return;
  }
  view.append(h("div", { class: "grid two" }, guilds.map((guild) => h("div", { class: "panel" },
    h("div", { class: "who" }, h("img", { src: iconUrl(guild.id, guild.icon), alt: "" }), h("strong", { text: guild.name })),
    h("div", { class: "toolbar" }), h("a", { class: "button primary small", href: `/dashboard/${guild.id}`, text: "Open" })))));
}

async function route() {
  pagesClosed();
  const [, , guildId, pageId] = location.pathname.split("/");
  if (!guildId) {
    state.guild = null;
    showServers();
    return;
  }
  try {
    state.guild = await api(`/api/guilds/${guildId}`);
  } catch (error) {
    shell(null, "Can't open this server").append(h("p", { class: "muted", text: error.message }));
    return;
  }
  document.title = `${state.guild.name} | AltWarden`;
  if (!state.guild.setup_done) {
    const view = shell(null, "Set up AltWarden");
    (await import("/static/dash/setup.js")).render(view, () => route());
    return;
  }
  const first = PAGES.find((item) => state.guild.pages[item.id]?.view);
  const page = PAGES.find((item) => item.id === pageId && state.guild.pages[item.id]?.view) ?? first;
  if (!page) {
    shell(null, "No access").append(h("p", { class: "muted", text: "You don't have access to any page here." }));
    return;
  }
  const view = shell(page.id, page.label);
  try {
    await (await page.load()).render(view);
    drawSaveBar();
    showItem(location.hash.slice(1));
  } catch (error) {
    view.append(h("div", { class: "notice bad", text: error.message }));
  }
}

async function start() {
  try {
    state.session = await api("/api/session");
  } catch {
    return;
  }
  state.csrf = state.session.csrf;
  state.catalog = await api("/api/catalog");
  await route();
}

start();
