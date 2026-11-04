// Access: who can open each page and run each command. The rule order matches Discord's own.
import { dirtyKeys, draftFor, touched } from "/static/dash/drafts.js";
import { api, channelPicker, clone, dialog, fill, h, rolePicker, section, select, state, toast, viewOnly } from "/static/dash/ui.js";

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
  const required = rule.required.length ? rule.required.map((name) => state.catalog.permission_labels[name] ?? name).join(", ") : "Owner and Administrators only";
  return rule.overrides.length ? `${required}, plus ${rule.overrides.length} override${rule.overrides.length === 1 ? "" : "s"}` : required;
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

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  const canEdit = state.guild.pages.permissions.edit;
  const { discord, ...saved } = await api(`${guildPath}/permissions`);
  const part = draftFor("permissions", saved, async (entry) => {
    await api(`${guildPath}/permissions`, { method: "PUT", body: { permissions: entry.draft } });
    entry.saved = clone(entry.draft);
  });
  const root = h("div");
  view.append(root);
  part.redraw = () => draw();
  const changed = touched;

  const outcome = OUTCOMES[new URLSearchParams(location.search).get("discord")];
  if (outcome) {
    toast(...outcome);
    history.replaceState(null, "", location.pathname + location.hash);
  }

  const original = discord ? { all: discord.all, commands: Object.fromEntries(discord.commands.map((row) => [row.id, row.overrides])) } : null;
  if (discordDraft?.guild !== state.guild.id) discordDraft = original ? { guild: state.guild.id, ...clone(original) } : null;

  function overrideList(overrides, onChange, disabled) {
    const list = h("div", { class: "grid" });
    const paint = () => fill(list, overrides.map((entry, index) => h("div", { class: "toolbar" },
      h("span", { class: "chip", text: targetName(entry) }),
      select([{ id: "true", name: "Allow" }, { id: "false", name: "Block" }], String(entry.allow), (value) => { entry.allow = value === "true"; onChange(); }, { disabled }),
      h("button", { class: "button small", text: "Remove", disabled, onclick: () => { overrides.splice(index, 1); onChange(); paint(); } }))));
    paint();
    return { list, paint };
  }

  function editRule(title, rule, allowChannels) {
    const { list, paint } = overrideList(rule.overrides, changed, !canEdit);
    const addOverride = (type, id) => {
      if (rule.overrides.some((entry) => entry.type === type && entry.id === id)) return;
      rule.overrides.push({ type, id, allow: true });
      changed();
      paint();
    };
    const memberBox = h("input", { type: "text", placeholder: "Member ID" });
    const required = h("div", { class: "chips" }, state.catalog.permissions.map((name) => h("label", { class: "chip" }, h("input", { type: "checkbox", checked: rule.required.includes(name), disabled: !canEdit, onchange: (event) => {
      if (event.target.checked) rule.required.push(name);
      else rule.required.splice(rule.required.indexOf(name), 1);
      changed();
    } }), state.catalog.permission_labels[name] ?? name)));
    dialog(title, h("div", { class: "grid" },
      h("p", { class: "muted", text: "A member override decides first, then roles, then Everyone, then these permissions. The owner and Administrators always pass." }),
      h("strong", { text: "Required permissions" }), required,
      h("strong", { text: "Overrides" }), list,
      canEdit ? h("div", { class: "grid two" },
        rolePicker(null, (value) => { if (value) addOverride("role", value); }, { none: "Add a role" }),
        allowChannels ? channelPicker(null, (value) => { if (value) addOverride("channel", value); }, { none: "Add a channel" }) : null,
        h("div", { class: "toolbar" }, memberBox, h("button", { class: "button small", text: "Add member", onclick: () => { if (/^\d{15,21}$/.test(memberBox.value.trim())) { addOverride("user", memberBox.value.trim()); memberBox.value = ""; } } }),
          h("button", { class: "button small", text: "Add Everyone", onclick: () => addOverride("everyone", null) }))) : null),
    { wide: true, buttons: [{ label: "Done", onClick: () => draw() }] });
  }

  function editDiscord(title, overrides) {
    const { list, paint } = overrideList(overrides, () => {}, !canEdit);
    const add = (type, id) => {
      if (overrides.some((entry) => entry.type === type && entry.id === id)) return;
      overrides.push({ type, id, allow: true });
      paint();
    };
    const memberBox = h("input", { type: "text", placeholder: "Member ID" });
    dialog(title, h("div", { class: "grid" },
      h("p", { class: "muted", text: "Discord checks these first, and hides a command from anyone it blocks. Administrators always pass." }),
      list,
      canEdit ? h("div", { class: "grid two" },
        rolePicker(null, (value) => { if (value) add("role", value); }, { none: "Add a role" }),
        channelPicker(null, (value) => { if (value) add("channel", value); }, { none: "Add a channel" }),
        h("div", { class: "toolbar" }, memberBox, h("button", { class: "button small", text: "Add member", onclick: () => { if (/^\d{15,21}$/.test(memberBox.value.trim())) { add("user", memberBox.value.trim()); memberBox.value = ""; } } })),
        h("div", { class: "toolbar" },
          h("button", { class: "button small", text: "Add Everyone", onclick: () => add("role", state.guild.id) }),
          h("button", { class: "button small", text: "Add All channels", onclick: () => add("channel", String(BigInt(state.guild.id) - 1n)) }))) : null),
    { wide: true, buttons: [{ label: "Done", onClick: () => draw() }] });
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
    try {
      const { authorize } = await api(`${guildPath}/permissions/discord`, { method: "POST", body: { changes: discordChanges() } });
      discordDraft = null;
      location.href = authorize;
    } catch (error) {
      toast(error.message, true);
    }
  }

  function row(id, title, text, button) {
    return h("div", { class: "rule", id: `item-${id}` }, h("div", { class: "rule-head" },
      h("div", { class: "rule-title" }, h("strong", { text: title }), h("span", { text })), button));
  }

  function discordSection() {
    if (!discordDraft) return section("Who sees commands in Discord", null, h("div", { class: "notice warn", text: "Discord didn't answer, so its command permissions can't be shown right now." }));
    const pending = Object.keys(discordChanges()).length;
    const edit = (title, overrides) => h("button", { class: "button small", text: canEdit ? "Edit" : "View", onclick: () => editDiscord(title, overrides) });
    return section("Who sees commands in Discord",
      "Discord's own command permissions, the same ones as Server Settings, Integrations. A change made there shows here. Saving here asks you to approve it on Discord once, and that approval ends as soon as the change is saved.",
      pending ? h("div", { class: "toolbar" },
        h("span", { class: "muted", text: `${pending} unsaved change${pending === 1 ? "" : "s"} for Discord.` }),
        h("button", { class: "button small", text: "Discard", onclick: () => { discordDraft = { guild: state.guild.id, ...clone(original) }; draw(); } }),
        h("button", { class: "button small primary", text: "Save to Discord", onclick: saveToDiscord })) : null,
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
          const title = `${PAGE_NAMES[page]}: ${level}`;
          return row(`page-${page}-${level}`, title, summary(rule), edit(title, rule, false));
        })))),
      section("Who can run commands", "Commands show for everyone in Discord unless Discord's permissions below hide them. These rules decide who can run them, and where.", h("div", { class: "rule-list" },
        Object.entries(current.commands).map(([name, rule]) => row(`command-${name}`, `/${name}`, summary(rule), edit(`/${name}`, rule, true))))),
      discordSection());
  }
  draw();
}
