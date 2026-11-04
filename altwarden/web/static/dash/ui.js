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

// Replaces a node's contents, skipping empty values and flattening lists, the way h() does.
export function fill(node, ...children) {
  node.replaceChildren();
  append(node, children);
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

export class ApiError extends Error {
  constructor(message, data = null) {
    super(message);
    this.data = data;
  }
}

export async function api(path, options = {}) {
  const init = { method: options.method || "GET", credentials: "same-origin", headers: {} };
  if (init.method !== "GET") init.headers["X-CSRF-Token"] = state.csrf;
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, init);
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (response.status === 401 && data?.login) {
    location.href = `${data.login}?next=${encodeURIComponent(location.pathname)}`;
    throw new ApiError("Sign in first.");
  }
  if (!response.ok) throw new ApiError(data?.error || "Something went wrong.", data);
  return data;
}

export function toast(message, isError = false) {
  const note = h("div", { class: `toast${isError ? " error" : ""}`, role: "status", text: message });
  document.body.append(note);
  setTimeout(() => note.remove(), isError ? 7000 : 3500);
}

export function dialog(title, body, { wide = false, buttons = [] } = {}) {
  const close = () => overlay.remove();
  const foot = h("div", { class: "dialog-foot" }, buttons.map((button) => h("button", {
    class: `button ${button.kind || ""}`, text: button.label, onclick: async () => {
      if ((await button.onClick?.()) !== false) close();
    },
  })));
  const overlay = h("div", { class: "overlay", onclick: (event) => { if (event.target === overlay) close(); } },
    h("div", { class: `dialog${wide ? " wide" : ""}`, role: "dialog", "aria-modal": "true", "aria-label": title },
      h("h2", { text: title }), body, foot));
  document.body.append(overlay);
  overlay.addEventListener("keydown", (event) => { if (event.key === "Escape") close(); });
  overlay.querySelector("input, select, textarea, button")?.focus();
  return close;
}

export function confirmDialog(title, text, label, kind = "primary") {
  return new Promise((resolve) => {
    dialog(title, h("p", { text }), { buttons: [
      { label: "Cancel", onClick: () => resolve(false) },
      { label, kind, onClick: () => resolve(true) },
    ] });
  });
}

export function toggle(value, onChange, { disabled = false, label = "" } = {}) {
  return h("label", { class: "switch" },
    h("input", { type: "checkbox", checked: value, disabled, "aria-label": label, onchange: (event) => onChange(event.target.checked) }),
    h("span"));
}

export function segments(options, value, onChange, { disabled = false, label = "" } = {}) {
  const group = h("div", { class: "segments", role: "radiogroup", "aria-label": label });
  const draw = (current) => {
    group.replaceChildren(...options.map((option) => h("button", {
      type: "button", role: "radio", "aria-checked": String(option.id === current), disabled, title: option.blurb,
      class: `${option.id === current ? "on" : ""} ${option.id}`, text: option.label,
      onclick: () => { onChange(option.id); draw(option.id); },
    })));
  };
  draw(value);
  return group;
}

export function select(options, value, onChange, { disabled = false, label = "" } = {}) {
  const box = h("select", { disabled, "aria-label": label, onchange: (event) => onChange(event.target.value || null) });
  for (const option of options) {
    if (option.group) {
      box.append(h("optgroup", { label: option.group }, option.items.map((item) => h("option", { value: item.id, text: item.name, selected: item.id === value }))));
    } else {
      box.append(h("option", { value: option.id ?? "", text: option.name, selected: option.id === value }));
    }
  }
  return box;
}

export function rolePicker(value, onChange, { none = "Pick a role", disabled = false } = {}) {
  const roles = state.guild.roles.filter((role) => !role.managed && role.id !== state.guild.id);
  return select([{ id: "", name: none }, ...roles], value ?? "", onChange, { disabled, label: "Role" });
}

export function channelPicker(value, onChange, { none = "Pick a channel", disabled = false, types = ["text", "news"] } = {}) {
  const groups = new Map();
  for (const channel of state.guild.channels) {
    if (!types.includes(channel.type)) continue;
    const key = channel.category || "No category";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ id: channel.id, name: `# ${channel.name}` });
  }
  const options = [{ id: "", name: none }, ...[...groups].map(([group, items]) => ({ group, items }))];
  return select(options, value ?? "", onChange, { disabled, label: "Channel" });
}

export function field(label, control, help) {
  return h("label", { class: "field" }, h("span", {}, label), control, help ? h("span", { class: "help", text: help }) : null);
}

export function number(value, onChange, { min, max, disabled = false, label = "" } = {}) {
  return h("input", { type: "number", value, min, max, disabled, "aria-label": label, oninput: (event) => {
    const parsed = Number.parseInt(event.target.value, 10);
    if (!Number.isNaN(parsed)) onChange(parsed);
  } });
}

// Roles a setting ignores or uses, shown as removable chips with a picker to add one more.
export function roleList(values, onChange, { disabled = false, none = "Add a role" } = {}) {
  const box = h("div", { class: "grid" });
  const draw = () => {
    const name = (id) => state.guild.roles.find((role) => role.id === id)?.name ?? id;
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
export function duration(value, onChange, { base = "seconds", min = 0, max = Infinity, disabled = false, label = "" } = {}) {
  const scale = UNITS[base];
  const names = Object.keys(UNITS).filter((name) => UNITS[name] >= scale && UNITS[name] <= max * scale);
  const seconds = value * scale;
  let unit = [...names].reverse().find((name) => seconds >= UNITS[name] && seconds % UNITS[name] === 0) ?? base;
  const apply = () => {
    const parsed = Number.parseFloat(amount.value);
    if (Number.isNaN(parsed)) return;
    const total = Math.round(parsed * UNITS[unit] / scale);
    amount.setCustomValidity(total < min || total > max ? `Pick between ${min} and ${max} ${base}.` : "");
    onChange(total);
  };
  const amount = h("input", { type: "number", value: seconds / UNITS[unit], min: 0, step: "any", disabled, "aria-label": label, oninput: apply });
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

export function checkName(id) {
  if (!id) return "Unknown";
  return state.catalog.checks.find((check) => check.id === id)?.name ?? ({ no_email: "No verified email", cooldown: "Cooldown" }[id] ?? id);
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
