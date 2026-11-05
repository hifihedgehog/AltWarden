// Small building blocks. Text always goes through textContent, so server data can't become markup.
export function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === "value" || key === "checked" || key === "disabled" || key === "selected" || key === "hidden") node[key] = value;
    else node.setAttribute(key, value);
  }
  append(node, children);
  return node;
}

// What a control is, in words that survive a redraw: its row, its group, its field and its name.
// A button whose words change gives itself a data-key instead.
const FOCUSABLE = "input, select, textarea, button, summary, a[href], [tabindex]";

function controlKey(node) {
  if (node.dataset.key) return node.dataset.key;
  const row = node.closest("[id^='item-']")?.id ?? "";
  const group = node.parentElement?.closest("[aria-label]")?.getAttribute("aria-label") ?? "";
  const field = node.closest(".field")?.querySelector("span")?.textContent ?? "";
  const name = node.getAttribute("aria-label") || node.getAttribute("title") || (node.matches("button, summary, a") ? node.textContent : "")
    || node.getAttribute("placeholder") || node.closest("label")?.textContent || "";
  return [row, group, field, node.tagName, node.type ?? "", name].join("|");
}

// Controls with the same words are told apart by their order.
function keyedControls(root) {
  const seen = new Map();
  return [...root.querySelectorAll(FOCUSABLE)].map((node) => {
    const key = controlKey(node);
    const count = seen.get(key) ?? 0;
    seen.set(key, count + 1);
    return [`${key}#${count}`, node];
  });
}

// Where the keyboard is now, to come back to once the page has been rebuilt.
export function focusMark(root = document.body) {
  const active = document.activeElement;
  if (!active || active === document.body || !root.contains(active)) return null;
  const found = keyedControls(root).find(([, node]) => node === active);
  return found ? { key: found[0], row: active.closest("[id^='item-']")?.id ?? null } : null;
}

export function restoreFocus(mark, root = document.body) {
  if (!mark) return;
  const controls = keyedControls(root).filter(([, node]) => !node.disabled);
  const same = controls.find(([key]) => key === mark.key)?.[1];
  // A control can go with the redraw, such as the options under a switch turned off. Its row is the next best place.
  const near = mark.row ? controls.find(([, node]) => node.closest("[id^='item-']")?.id === mark.row)?.[1] : null;
  (same ?? near)?.focus({ preventScroll: true });
}

function detailsKey(node) {
  return node.dataset.key ?? node.querySelector("summary span")?.textContent ?? node.querySelector("summary")?.textContent ?? "";
}

// Replaces a node's contents, skipping empty values and flattening lists, the way h() does. A redraw keeps
// what the person was doing: the group they opened, and the control the keyboard was on.
export function fill(node, ...children) {
  const mark = focusMark(node);
  const opened = new Set([...node.querySelectorAll("details[open]")].map(detailsKey));
  node.replaceChildren();
  append(node, children);
  for (const details of node.querySelectorAll("details")) {
    if (opened.has(detailsKey(details))) details.open = true;
  }
  restoreFocus(mark, node);
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child);
  }
}

export function svg(tag, attributes = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (value !== undefined && value !== null) node.setAttribute(key, value);
  }
  append(node, children);
  return node;
}

export const state = { session: null, catalog: null, guild: null, csrf: "" };

// A value from the address bar or the server can be "constructor", which every plain object answers to.
export function lookup(table, key, fallback = undefined) {
  return key !== null && key !== undefined && Object.hasOwn(table, key) ? table[key] : fallback;
}

export function plural(count, one, many = `${one}s`) {
  return `${count} ${count === 1 ? one : many}`;
}

export class ApiError extends Error {
  constructor(message, data = null, signingIn = false) {
    super(message);
    this.data = data;
    this.signingIn = signingIn;  // the page is already on its way to the sign-in screen
  }
}

export async function api(path, options = {}) {
  const init = { method: options.method || "GET", credentials: "same-origin", headers: {} };
  if (init.method !== "GET") init.headers["X-CSRF-Token"] = state.csrf;
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError("AltWarden couldn't be reached. Check your connection and try again.");
  }
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (response.status === 401 && data?.login) {
    location.href = `${data.login}?next=${encodeURIComponent(location.pathname)}`;
    throw new ApiError("Sign in first.", null, true);
  }
  if (!response.ok) throw new ApiError(data?.error || "Something went wrong.", data);
  return data;
}

// Toasts stack in one column, so a second one can't sit on top of the first.
export function toast(message, isError = false) {
  const stack = document.querySelector(".toasts") ?? document.body.appendChild(h("div", { class: "toasts" }));
  for (const old of stack.children) {
    if (old.textContent === message) old.remove();
  }
  const note = h("div", { class: `toast${isError ? " error" : ""}`, role: isError ? "alert" : "status", text: message });
  stack.append(note);
  setTimeout(() => note.remove(), isError ? 7000 : 3500);
}

// Says what went wrong with a request. A bug in the page gets plain words, and its details go to the console.
export function report(error) {
  if (error?.signingIn) return;
  toast(error instanceof ApiError ? error.message : "Something went wrong.", true);
}

// A handler that talks to the server: one press at a time. The button stays enabled so the keyboard stays
// on it, and a refusal reaches the page's one handler for what nothing else caught.
export function pressed(run) {
  return async (event) => {
    const button = event.currentTarget;
    if (button.getAttribute("aria-busy") === "true") return;
    button.setAttribute("aria-busy", "true");
    try {
      await run(event);
    } finally {
      button.removeAttribute("aria-busy");
    }
  };
}

// Dialogs and the search palette stack. Only the top one takes the keyboard, and everything behind it is out of reach.
const layers = [];

export function topLayer() {
  return layers.at(-1) ?? null;
}

export function syncLayers() {
  const top = topLayer();
  for (const child of document.body.children) {
    child.inert = Boolean(top) && child !== top.node && !child.classList.contains("toasts");
  }
}

export function openLayer(node, onEscape) {
  const layer = { node, onEscape };
  layers.push(layer);
  document.body.append(node);
  return () => {
    layers.splice(layers.indexOf(layer), 1);
    node.remove();
    syncLayers();
  };
}

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || !topLayer()) return;
  event.stopImmediatePropagation();  // one press closes one thing
  topLayer().onEscape?.();
});

// What a page has floating over it goes when the visitor moves on.
const leaving = new Set();

export function whenLeaving(close) {
  leaving.add(close);
  return () => leaving.delete(close);
}

export function leavePage() {
  for (const close of [...leaving]) close();
  for (const layer of [...layers].reverse()) layer.onEscape?.(true);
}

// `sticky` is for something shown only once, like a secret: only its own button closes it.
export function dialog(title, body, { wide = false, buttons = [], onClose = null, sticky = false } = {}) {
  const opener = focusMark();
  let closeLayer = () => {};
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    closeLayer();
    onClose?.();
    restoreFocus(opener);
  };
  let busy = false;
  const foot = h("div", { class: "dialog-foot" }, buttons.map((button) => h("button", {
    class: `button ${button.kind || ""}`, text: button.label, onclick: async () => {
      // One press at a time, so a slow server can't be asked for two of something.
      if (busy) return;
      busy = true;
      let result = false;
      try {
        result = await button.onClick?.();
      } catch (error) {
        report(error);
        result = false;
      } finally {
        busy = false;
      }
      if (result !== false) close();
    },
  })));
  const overlay = h("div", { class: "overlay", onclick: (event) => { if (event.target === overlay && !sticky) close(); } },
    h("div", { class: `dialog${wide ? " wide" : ""}`, role: "dialog", "aria-modal": "true", "aria-label": title },
      h("h2", { text: title }), body, foot));
  closeLayer = openLayer(overlay, (leavingPage) => { if (!sticky || leavingPage) close(); });
  overlay.querySelector("input:not(:disabled), select:not(:disabled), textarea:not(:disabled), button:not(:disabled)")?.focus();
  syncLayers();
  return close;
}

export function confirmDialog(title, text, label, kind = "primary") {
  return new Promise((resolve) => {
    dialog(title, h("p", { text }), {
      buttons: [{ label: "Cancel" }, { label, kind, onClick: () => resolve(true) }],
      onClose: () => resolve(false),  // a promise keeps its first answer, so this only counts for Escape, the backdrop and Cancel
    });
  });
}

// Says "Copied." only when it was. When the browser refuses, the text is selected so Ctrl+C can do it.
export async function copyText(text, box = null) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied.");
  } catch {
    box?.select();
    toast(box ? "The browser refused to copy, so the text is selected. Press Ctrl+C." : "The browser refused to copy.", true);
  }
}

export function toggle(value, onChange, { disabled = false, label = "" } = {}) {
  return h("label", { class: "switch" },
    h("input", { type: "checkbox", checked: value, disabled, "aria-label": label, onchange: (event) => onChange(event.target.checked) }),
    h("span"));
}

export function segments(options, value, onChange, { disabled = false, label = "" } = {}) {
  const group = h("div", { class: "segments", role: "radiogroup", "aria-label": label });
  const mark = (button, on, id) => {
    button.setAttribute("aria-checked", String(on));
    button.className = `${on ? "on" : ""} ${id}`;
  };
  const buttons = options.map((option) => h("button", {
    type: "button", role: "radio", disabled, title: option.blurb, text: option.label,
    onclick: () => {
      onChange(option.id);
      options.forEach((other, index) => mark(buttons[index], other.id === option.id, other.id));
    },
  }));
  options.forEach((option, index) => mark(buttons[index], option.id === value, option.id));
  group.append(...buttons);
  return group;
}

// `missing` names a value that's no longer on offer, such as a deleted role, instead of showing the first option.
export function select(options, value, onChange, { disabled = false, label = "", missing = null } = {}) {
  const box = h("select", { disabled, "aria-label": label || null, onchange: (event) => onChange(event.target.value || null, event.target) });
  let found = false;
  const option = (item) => {
    const chosen = (item.id ?? "") === value;
    found ||= chosen;
    return h("option", { value: item.id ?? "", text: item.name, selected: chosen, disabled: item.disabled });
  };
  for (const item of options) {
    box.append(item.group ? h("optgroup", { label: item.group }, item.items.map(option)) : option(item));
  }
  if (!found && value && missing) box.append(h("option", { value, text: missing(value), selected: true, disabled: true }));
  return box;
}

// `given` is for a role AltWarden hands out: Discord refuses a managed role, or one above AltWarden's own.
// `managed` is for a rule that only names a role, which can be any of them.
export function rolePicker(value, onChange, { none = "Pick a role", disabled = false, label = none, given = false, managed = false } = {}) {
  const top = state.guild.bot_top_role;
  const roles = state.guild.roles.filter((role) => role.id !== state.guild.id && (managed || !role.managed || role.id === value)).map((role) => {
    const above = given && top !== undefined && top !== null && role.position >= top;
    return { id: role.id, name: above ? `${role.name} (above AltWarden's role)` : role.name, disabled: above || (given && role.managed) };
  });
  return select([{ id: "", name: none }, ...roles], value ?? "", onChange, { disabled, label, missing: (id) => `Deleted role (${id})` });
}

// `mixed` says that the things this picker sets don't agree. Picking anything sets them all, including "none".
export function channelPicker(value, onChange, { none = "Pick a channel", disabled = false, types = ["text", "news"], label = none, mixed = false } = {}) {
  const groups = new Map();
  for (const channel of state.guild.channels) {
    if (!types.includes(channel.type)) continue;
    const key = channel.category || "No category";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ id: channel.id, name: `# ${channel.name}` });
  }
  const options = [{ id: "", name: none }, ...(mixed ? [{ id: "mixed", name: "Mixed", disabled: true }] : []), ...[...groups].map(([group, items]) => ({ group, items }))];
  return select(options, mixed ? "mixed" : value ?? "", onChange, { disabled, label, missing: (id) => `Deleted channel (${id})` });
}

export function roleExists(id) {
  return state.guild.roles.some((role) => role.id === id);
}

export function channelExists(id) {
  return state.guild.channels.some((channel) => channel.id === id);
}

function textOf(label) {
  return [label].flat(Infinity).map((part) => (part instanceof Node ? part.textContent : part)).join("").trim();
}

export function field(label, control, help) {
  // A label around a picker also reads out every option, so the control carries its own name.
  if (control.matches?.("select, input, textarea")) control.setAttribute("aria-label", textOf(label));
  return h("label", { class: "field" }, h("span", {}, label), control, help ? h("span", { class: "help", text: help }) : null);
}

export function number(value, onChange, { min, max, disabled = false, label = "" } = {}) {
  return h("input", { type: "number", value, min, max, disabled, "aria-label": label || null, oninput: (event) => {
    const parsed = Number.parseInt(event.target.value, 10);
    // A box left empty can't keep showing nothing while the old value saves, so it blocks the save until it holds a number.
    event.target.setCustomValidity(Number.isNaN(parsed) ? "Enter a number." : "");
    if (!Number.isNaN(parsed)) onChange(parsed);
  } });
}

// Roles a setting ignores or uses, shown as removable chips with a picker to add one more.
export function roleList(values, onChange, { disabled = false, none = "Add a role" } = {}) {
  const box = h("div", { class: "grid" });
  const draw = () => {
    const name = (id) => state.guild.roles.find((role) => role.id === id)?.name ?? `Deleted role (${id})`;
    fill(box, h("div", { class: "chips" }, values.map((id) => h("span", { class: "chip" }, name(id),
      h("button", { type: "button", text: "×", disabled, "aria-label": `Remove ${name(id)}`, onclick: () => {
        values.splice(values.indexOf(id), 1);
        onChange();
        draw();
      } })))),
    rolePicker(null, (value) => {
      if (value && !values.includes(value)) values.push(value);
      onChange();
      draw();
    }, { none, disabled }));
  };
  draw();
  return box;
}

const UNITS = { seconds: 1, minutes: 60, hours: 3600, days: 86400 };

// A length of time in whichever unit reads best. The setting itself stays in its base unit.
// `zeroOr` is for a setting where 0 means off, and anything else has to be at least that much.
export function duration(value, onChange, { base = "seconds", min = 0, max = Infinity, zeroOr = null, disabled = false, label = "" } = {}) {
  const scale = UNITS[base];
  const names = Object.keys(UNITS).filter((name) => UNITS[name] >= scale && UNITS[name] <= max * scale);
  const seconds = value * scale;
  let unit = [...names].reverse().find((name) => seconds >= UNITS[name] && seconds % UNITS[name] === 0) ?? base;
  const judge = (total) => {
    if (zeroOr !== null && total !== 0 && total < zeroOr) return `Use 0, or between ${zeroOr} and ${max} ${base}.`;
    return total < min || total > max ? `Pick between ${min} and ${max} ${base}.` : "";
  };
  const apply = () => {
    const parsed = Number.parseFloat(amount.value);
    if (Number.isNaN(parsed)) {
      amount.setCustomValidity("Enter a number.");
      return;
    }
    const total = Math.round(parsed * UNITS[unit] / scale);
    amount.setCustomValidity(judge(total));
    onChange(total);
  };
  const amount = h("input", { type: "number", value: seconds / UNITS[unit], min: 0, step: "any", disabled, "aria-label": label || null, oninput: apply });
  amount.setCustomValidity(judge(value));  // a page that opens on a bad value still can't save it
  const picker = select(names.map((id) => ({ id, name: id })), unit, (chosen) => { unit = chosen; apply(); }, { disabled, label: `${label} unit` });
  return h("div", { class: "duration" }, amount, picker);
}

export function section(title, lead, ...children) {
  return h("section", { class: "section" }, h("h2", {}, title), lead ? h("p", { class: "lead", text: lead }) : null, children);
}

export function avatarUrl(id, hash) {
  return hash ? `https://cdn.discordapp.com/avatars/${id}/${hash}.png?size=64` : "/static/img/logo.svg";
}

export function iconUrl(id, hash) {
  return hash ? `https://cdn.discordapp.com/icons/${id}/${hash}.png?size=64` : "/static/img/logo.svg";
}

const OTHER_RESULTS = { no_email: "No verified email", cooldown: "Cooldown", role_problem: "Couldn't give the role", honeypot: "Honeypot" };

export function checkName(id) {
  if (!id) return "Unknown";
  return state.catalog.checks.find((check) => check.id === id)?.name ?? lookup(OTHER_RESULTS, id, id);
}

// The line a page shows when the visitor can look but not change anything.
export function viewOnly(page) {
  return state.guild.pages[page]?.edit ? null : h("div", { class: "notice", text: "You can view this page but not change it." });
}

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
export function when(seconds) {
  return seconds ? dateFormat.format(new Date(seconds * 1000)) : "Never";
}

export function clone(value) {
  return structuredClone(value);
}
