// Access: who can open each page and run each command. The rule order matches Discord's own.
import { dirtyKeys, draftFor, touched } from "/static/dash/drafts.js";
import { api, channelPicker, clone, dialog, fill, h, lookup, plural, pressed, rolePicker, section, select, state, toast, viewOnly } from "/static/dash/ui.js";

const PAGE_NAMES = { analytics: "Overview", settings: "Rules", members: "Members", health: "Health", permissions: "Access", appearance: "Messages", appeals: "Appeals", audit: "Audit log", integrations: "Integrations" };
const OUTCOMES = {
  saved: ["Discord's command permissions are saved.", false],
  refused: ["Discord refused part of that. You need Manage Server and Manage Roles, and access to the command and to what you changed.", true],
  declined: ["Nothing changed, because Discord's sign-in was canceled.", true],
  failed: ["Nothing changed, because Discord's sign-in didn't finish.", true],
  expired: ["Nothing changed, because that sign-in expired. Try again.", true],
  "wrong-account": ["Nothing changed, because you signed in with a different Discord account.", true],
};
// Discord's changes wait here so moving to another page keeps them. A full page load starts fresh.
let discordDraft = null;

function summary(rule) {
  const required = rule.required.length ? rule.required.map((name) => lookup(state.catalog.permission_labels, name, name)).join(", ") : "Owner and Administrators only";
  return rule.overrides.length ? `${required}, plus ${plural(rule.overrides.length, "override")}` : required;
}

function targetName(entry) {
  const guildId = state.guild.id;
  if (entry.type === "everyone" || (entry.type === "role" && entry.id === guildId)) return "Everyone";
  if (entry.type === "channel" && entry.id === String(BigInt(guildId) - 1n)) return "All channels";
  if (entry.type === "role") return `Role: ${state.guild.roles.find((role) => role.id === entry.id)?.name ?? entry.id}`;
  if (entry.type === "channel") return `Channel: ${state.guild.channels.find((channel) => channel.id === entry.id)?.name ?? entry.id}`;
  return `Member: ${entry.id}`;
}

function discordSummary(overrides) {
  if (!overrides.length) return "No overrides";
  return overrides.map((entry) => `${targetName(entry)}: ${entry.allow ? "allowed" : "blocked"}`).join(", ");
}

// The two kinds of list take members the same way, and both say why nothing was added.
function memberAdder(add) {
  const submit = () => {
    const id = box.value.trim();
    if (!/^[0-9]{15,21}$/.test(id)) {
      toast("A member ID is 15 to 21 digits. Right-click the member in Discord to copy it.", true);
      return;
    }
    if (add("user", id)) box.value = "";
  };
  const box = h("input", { type: "text", placeholder: "Member ID", "aria-label": "Member ID", onkeydown: (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    }
  } });
  return [box, h("button", { class: "button small", text: "Add member", onclick: submit })];
}

function addOnce(overrides, type, id, paint, changed = () => {}) {
  if (overrides.some((entry) => entry.type === type && entry.id === id)) {
    toast("That's already on the list.", true);
    return false;
  }
  overrides.push({ type, id, allow: true });
  changed();
  paint();
  return true;
}

export async function render(view) {
  const guildId = state.guild.id;
  const guildPath = `/api/guilds/${guildId}`;
  const canEdit = state.guild.pages.permissions.edit;
  const loaded = await api(`${guildPath}/permissions`);
  if (!view.isConnected) return;  // the visitor moved on while this was loading, maybe to another server
  const { discord } = loaded;
  const part = draftFor(guildId, "permissions", { pages: loaded.pages, commands: loaded.commands }, async (entry) => {
    const before = entry.saved;
    const result = await api(`${guildPath}/permissions`, { method: "PUT", body: { permissions: entry.draft, base: entry.revision } });
    entry.saved = clone(entry.draft);
    entry.revision = result.revision;
    offerToDiscord(before, entry.saved);
  }, loaded.revision);
  const root = h("div");
  view.append(root);
  part.redraw = () => draw();
  const changed = touched;

  const outcome = lookup(OUTCOMES, new URLSearchParams(location.search).get("discord"));
  if (outcome) {
    toast(...outcome);
    history.replaceState(null, "", location.pathname + location.hash);
  }

  const original = discord ? { all: discord.all, commands: Object.fromEntries(discord.commands.map((row) => [row.id, row.overrides])) } : null;
  // A draft can't outlive what it was drawn from, or saving it would undo a change made in Discord since.
  // If Discord is quiet this time, the draft stays for the next visit.
  const drawnFrom = original ? JSON.stringify(original) : null;
  if (original && (discordDraft?.guild !== guildId || discordDraft.from !== drawnFrom)) {
    const edited = discordDraft?.guild === guildId && JSON.stringify({ all: discordDraft.all, commands: discordDraft.commands }) !== discordDraft.from;
    if (edited) toast("Discord's command permissions changed, so your unsaved changes to them were cleared.", true);
    discordDraft = { guild: guildId, from: drawnFrom, ...clone(original) };
  }

  // An allow saved here doesn't show the command to anyone Discord still hides it from, so offer the other half.
  // Loading only fills in the Discord draft below. Writing it still takes that person's approval on Discord.
  function offerToDiscord(before, after) {
    if (!original || discordDraft?.guild !== guildId) return;
    const wanted = [];
    for (const command of discord.commands) {
      const rule = lookup(after.commands, command.name);
      if (!rule) continue;
      const earlier = lookup(before.commands, command.name)?.overrides ?? [];
      for (const entry of rule.overrides) {
        if (!entry.allow || earlier.some((old) => old.allow && old.type === entry.type && old.id === entry.id)) continue;
        const target = entry.type === "everyone" ? { type: "role", id: guildId } : { type: entry.type, id: entry.id };
        const held = discordDraft.commands[command.id];
        if (!held.some((old) => old.allow && old.type === target.type && old.id === target.id)) wanted.push({ command, target });
      }
    }
    if (!wanted.length) return;
    dialog("Allow this on Discord too?", h("div", {},
      h("p", { text: "Discord hides a command from anyone without its permission until its own settings allow them. These allows are saved here, and not yet on Discord:" }),
      h("ul", {}, wanted.map(({ command, target }) => h("li", { text: `/${command.name}: ${targetName(target)}` }))),
      h("p", { class: "muted", text: "This takes you to Discord, which asks you to approve the change with your own account." })),
    { buttons: [{ label: "Not now" }, { label: "Allow on Discord", kind: "primary", onClick: () => {
      for (const { command, target } of wanted) {
        const held = discordDraft.commands[command.id];
        held.splice(0, held.length, ...held.filter((old) => old.type !== target.type || old.id !== target.id), { ...target, allow: true });
      }
      if (part.redraw) part.redraw();
      return saveToDiscord();
    } }] });
  }

  function overrideList(overrides, onChange, disabled) {
    const list = h("div", { class: "grid" });
    const paint = () => fill(list, overrides.map((entry, index) => h("div", { class: "toolbar" },
      h("span", { class: "chip", text: targetName(entry) }),
      select([{ id: "true", name: "Allow" }, { id: "false", name: "Block" }], String(entry.allow), (value) => { entry.allow = value === "true"; onChange(); }, { disabled, label: `Allow or block ${targetName(entry)}` }),
      h("button", { class: "button small", text: "Remove", disabled, "aria-label": `Remove ${targetName(entry)}`, onclick: () => { overrides.splice(index, 1); onChange(); paint(); } }))));
    paint();
    return { list, paint };
  }

  // A picker goes back to its first line after each pick, so the same choice can be made again later.
  const addFromPicker = (type, add) => (value, box) => {
    if (value) add(type, value);
    box.value = "";
  };

  function editRule(title, rule, allowChannels) {
    const { list, paint } = overrideList(rule.overrides, changed, !canEdit);
    const add = (type, id) => addOnce(rule.overrides, type, id, paint, changed);
    const required = h("div", { class: "chips" }, state.catalog.permissions.map((name) => h("label", { class: "chip" }, h("input", { type: "checkbox", checked: rule.required.includes(name), disabled: !canEdit, onchange: (event) => {
      if (event.target.checked) rule.required.push(name);
      else rule.required.splice(rule.required.indexOf(name), 1);
      changed();
    } }), lookup(state.catalog.permission_labels, name, name))));
    dialog(title, h("div", { class: "grid" },
      h("p", { class: "muted", text: `A member override decides first, then roles, then Everyone, then these permissions. The owner and Administrators always pass.${allowChannels ? " Once you change a command's rule here, an allow on Discord's side no longer counts for it." : ""}` }),
      h("strong", { text: "Required permissions" }), required,
      h("strong", { text: "Overrides" }), list,
      canEdit ? h("div", { class: "grid two" },
        rolePicker(null, addFromPicker("role", add), { none: "Add a role", managed: true }),
        allowChannels ? channelPicker(null, addFromPicker("channel", add), { none: "Add a channel" }) : null,
        h("div", { class: "toolbar" }, memberAdder(add),
          h("button", { class: "button small", text: "Add Everyone", onclick: () => add("everyone", null) }))) : null),
    { wide: true, buttons: [{ label: "Done" }], onClose: () => draw() });
  }

  function editDiscord(title, overrides) {
    const { list, paint } = overrideList(overrides, () => {}, !canEdit);
    const add = (type, id) => addOnce(overrides, type, id, paint);
    dialog(title, h("div", { class: "grid" },
      h("p", { class: "muted", text: "These decide who sees a command in Discord. An allow for a member or role here also lets them run it, whatever the rule on this page says. Administrators always pass." }),
      list,
      canEdit ? h("div", { class: "grid two" },
        rolePicker(null, addFromPicker("role", add), { none: "Add a role", managed: true }),
        channelPicker(null, addFromPicker("channel", add), { none: "Add a channel" }),
        h("div", { class: "toolbar" }, memberAdder(add)),
        h("div", { class: "toolbar" },
          h("button", { class: "button small", text: "Add Everyone", onclick: () => add("role", guildId) }),
          h("button", { class: "button small", text: "Add All channels", onclick: () => add("channel", String(BigInt(guildId) - 1n)) }))) : null),
    { wide: true, buttons: [{ label: "Done" }], onClose: () => draw() });
  }

  function discordChanges() {
    const changes = {};
    for (const [id, overrides] of Object.entries(discordDraft.commands)) {
      if (JSON.stringify(overrides) !== JSON.stringify(original.commands[id])) changes[id] = overrides;
    }
    if (JSON.stringify(discordDraft.all) !== JSON.stringify(original.all)) changes[discord.application] = discordDraft.all;
    return changes;
  }

  async function saveToDiscord() {
    if (dirtyKeys().length) {
      toast("Save or discard your other changes first, because this leaves the page.", true);
      return;
    }
    const { authorize } = await api(`${guildPath}/permissions/discord`, { method: "POST", body: { changes: discordChanges() } });
    discordDraft = null;
    location.href = authorize;
  }

  function row(id, title, text, button) {
    return h("div", { class: "rule", id: `item-${id}` }, h("div", { class: "rule-head" },
      h("div", { class: "rule-title" }, h("strong", { text: title }), h("span", { text })), button));
  }

  function discordSection() {
    if (!original) return section("Who sees commands in Discord", null, h("div", { class: "notice warn", text: "Discord didn't answer, so its command permissions can't be shown right now." }));
    const pending = Object.keys(discordChanges()).length;
    const edit = (title, overrides) => h("button", { class: "button small", text: canEdit ? "Edit" : "View", onclick: () => editDiscord(title, overrides) });
    return section("Who sees commands in Discord",
      "Discord's own command permissions, the same ones as Server Settings, Integrations. A change made there shows here. Saving here asks you to approve it on Discord once, and that approval ends as soon as the change is saved.",
      pending ? h("div", { class: "toolbar" },
        h("span", { class: "muted", text: `${plural(pending, "unsaved change")} for Discord.` }),
        h("button", { class: "button small", text: "Discard", onclick: () => { discordDraft = { guild: guildId, from: drawnFrom, ...clone(original) }; draw(); } }),
        h("button", { class: "button small primary", text: "Save to Discord", onclick: pressed(saveToDiscord) })) : null,
      h("div", { class: "rule-list" },
        row("discord-all", "All commands", discordSummary(discordDraft.all), edit("All commands", discordDraft.all)),
        discord.commands.map((command) => row(`discord-${command.name}`, command.name === command.name.toLowerCase() ? `/${command.name}` : `${command.name} (right-click)`,
          discordSummary(discordDraft.commands[command.id]), edit(command.name, discordDraft.commands[command.id])))));
  }

  function draw() {
    const current = part.draft;
    const edit = (title, rule, channels) => h("button", { class: "button small", text: canEdit ? "Edit" : "View", onclick: () => editRule(title, rule, channels) });
    fill(root, viewOnly("permissions"),
      h("div", { class: "notice", text: "The server owner and Administrators can always open every page and run every command, so nobody gets locked out." }),
      section("Dashboard pages", null, h("div", { class: "rule-list" },
        Object.entries(current.pages).flatMap(([page, levels]) => Object.entries(levels).map(([level, rule]) => {
          const title = `${lookup(PAGE_NAMES, page, page)}: ${level}`;
          return row(`page-${page}-${level}`, title, summary(rule), edit(title, rule, false));
        })))),
      section("Who can run commands", "Discord lists each staff command only for people with the permission it needs, unless Discord's permissions below change that. These rules decide who can run them, and where. A rule you change here is final. While a rule is still its default, an allow on Discord's side also counts, so a role allowed there can use the command.", h("div", { class: "rule-list" },
        Object.entries(current.commands).map(([name, rule]) => row(`command-${name}`, `/${name}`, summary(rule), edit(`/${name}`, rule, true))))),
      discordSection());
  }
  draw();
}
