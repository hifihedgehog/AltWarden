// The Rules page. One draft document, one save bar, and a rule list you can scan top to bottom.
import { draftFor, touched } from "/static/dash/drafts.js";
import { openCountryPicker } from "/static/dash/geogate.js";
import { api, channelPicker, clone, dialog, duration, field, fill, h, number, roleList, rolePicker, section, segments, select, state, toast, toggle } from "/static/dash/ui.js";

const CONFIDENCE = [
  { id: "possible", name: "Possible: any match, including a shared connection" },
  { id: "likely", name: "Likely: a browser match, or several weaker ones" },
  { id: "confirmed", name: "Confirmed: the same browser" },
];
const MODE_OPTIONS = [
  { id: "web", label: "Web page", blurb: "Every check can run." },
  { id: "button", label: "Button", blurb: "Only account age, profile picture, attempt limit and cooldown run." },
  { id: "instant", label: "Instant", blurb: "Checks run when a member joins, with nothing to press." },
];
const LOCKED_NOTE = "You can view this page but not change it.";

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  const loaded = await api(`${guildPath}/settings`);
  const canEdit = loaded.can_edit;
  const part = draftFor("settings", loaded.settings, async (current) => {
    const result = await api(`${guildPath}/settings`, { method: "PUT", body: { settings: current.draft } });
    current.saved = result.settings;
    current.draft = clone(result.settings);
    if (result.problem) toast(result.problem, true);
  });
  let draft = part.draft;
  let filter = "";
  const root = h("div");
  const searchBox = h("input", { type: "search", placeholder: "Search rules", "aria-label": "Search rules", oninput: (event) => {
    filter = event.target.value.trim().toLowerCase();
    applyFilter();
  } });
  view.append(h("div", { class: "toolbar" }, searchBox), root);
  part.redraw = () => draw();
  part.invalid = () => root.querySelector("input:invalid");

  const edit = (apply, redraw = false) => {
    apply(draft);
    touched();
    if (redraw) draw();
  };

  function applyFilter() {
    for (const node of root.querySelectorAll(".rule, .panel")) node.hidden = Boolean(filter) && !node.textContent.toLowerCase().includes(filter);
    for (const group of root.querySelectorAll(".section")) {
      group.hidden = Boolean(filter) && ![...group.querySelectorAll(".rule, .panel")].some((node) => !node.hidden);
    }
  }

  function messageLink(name, label) {
    return h("a", { class: "button small", href: `/dashboard/${state.guild.id}/appearance#${name}`, text: label });
  }

  function actionControl(check, key = "action", options = state.catalog.actions) {
    return segments(options, check[key], (value) => edit(() => { check[key] = value; }), { disabled: !canEdit, label: "Action" });
  }

  function optionsFor(id, check) {
    if (id === "account_age") {
      return [field("Minimum age in days", number(check.days, (value) => edit(() => { check.days = value; }), { min: 1, max: 3650, disabled: !canEdit }))];
    }
    if (id === "max_attempts") {
      return [
        field("Failed attempts allowed", number(check.attempts, (value) => edit(() => { check.attempts = value; }), { min: 1, max: 100, disabled: !canEdit })),
        field("Give attempts back after", duration(check.reset_minutes, (value) => edit(() => { check.reset_minutes = value; }), { base: "minutes", min: 0, max: 43200, disabled: !canEdit, label: "Give attempts back after" }), "0 means never. Up to 30 days."),
        field("Role for members at the limit", rolePicker(check.role, (value) => edit(() => { check.role = value; }), { none: "No role", disabled: !canEdit }), "Given when the action is Watch or Deny."),
      ];
    }
    if (id === "tampering") {
      return [field("Block at score", number(check.anomaly_score, (value) => edit(() => { check.anomaly_score = value; }), { min: 1, max: 100, disabled: !canEdit }), "Rewritten browser functions add to this score.")];
    }
    if (id === "threat") {
      return [
        field("Bot score limit", number(check.bot_score, (value) => edit(() => { check.bot_score = value; }), { min: 1, max: 100, disabled: !canEdit }), "How likely the browser is automated."),
        field("Suspect score limit", number(check.suspect_score, (value) => edit(() => { check.suspect_score = value; }), { min: 1, max: 100, disabled: !canEdit }), "Many small signals added up. Free on every server."),
      ];
    }
    if (id === "alt_account") {
      const methods = check.methods;
      return [
        h("div", { class: "field wide" }, h("span", { text: "Evidence to use" }), h("div", { class: "chips" },
          [["cookie", "Same browser cookie"], ["fingerprint", "Same browser or device"], ["ip", "Same connection"]].map(([key, label]) =>
            h("label", { class: "chip" }, h("input", { type: "checkbox", checked: methods[key], disabled: !canEdit, onchange: (event) => edit(() => { methods[key] = event.target.checked; }) }), label)))),
        field("Act when the match is at least", select(CONFIDENCE, check.min_confidence, (value) => edit(() => { check.min_confidence = value; }), { disabled: !canEdit })),
        h("div", { class: "field" }, h("span", { text: "Alt of a member in good standing" }), actionControl(check, "alt_action")),
        h("div", { class: "field" }, h("span", { text: "Alt of a banned account" }), actionControl(check, "banned_alt_action")),
        h("div", { class: "field" }, h("span", { text: "The earlier account" }), actionControl(check, "main_action")),
      ];
    }
    if (id === "geogate") {
      return [h("div", { class: "field wide" },
        h("span", { text: `${check.list === "block" ? "Blocked" : "Allowed"}: ${check.countries.length} countries` }),
        h("button", { class: "button small", text: "Choose countries", disabled: !canEdit, onclick: () => openCountryPicker(check, (result) => edit(() => { Object.assign(check, result); }, true)) }))];
    }
    return [];
  }

  function ruleRow(item) {
    const check = draft.checks[item.id];
    const paused = check.enabled && !item.modes.includes(draft.core.mode);
    const options = check.enabled ? optionsFor(item.id, check) : [];
    return h("div", { class: `rule${paused ? " paused" : ""}`, id: `item-${item.id}` },
      h("div", { class: "rule-head" },
        toggle(check.enabled, (value) => edit(() => { check.enabled = value; }, true), { disabled: !canEdit, label: item.name }),
        h("div", { class: "rule-title" }, h("strong", { text: item.name }),
          h("span", { text: paused ? "Paused: this check needs the web page mode." : item.blurb })),
        check.enabled && item.id !== "alt_account" ? actionControl(check) : null),
      options.length ? h("div", { class: "rule-body" }, options) : null);
  }

  function switchRow(id, title, blurb, value, onChange, body) {
    return h("div", { class: "rule", id: `item-${id}` },
      h("div", { class: "rule-head" }, toggle(value, onChange, { disabled: !canEdit, label: title }),
        h("div", { class: "rule-title" }, h("strong", { text: title }), h("span", { text: blurb }))),
      value && body ? h("div", { class: "rule-body" }, body) : null);
  }

  // How many rows in a group are switched on, shown next to the group's name.
  function counted(title, on, total) {
    return [title, h("span", { class: "count", text: `${on}/${total}`, title: `${on} of ${total} switched on` })];
  }

  function presets() {
    const names = Object.entries(state.catalog.presets);
    return h("div", { class: "presets" }, names.map(([name, preset]) => h("button", {
      class: `preset${draft.preset === name ? " on" : ""}`, disabled: !canEdit, onclick: async () => {
        const result = await api(`${guildPath}/settings/preset`, { method: "POST", body: { settings: draft, preset: name } });
        part.draft = result.settings;
        touched();
        draw();
      } }, h("strong", {}, preset.label, draft.preset === name ? h("span", { class: "active-tag", text: "Active" }) : null), h("span", { text: preset.blurb }))),
    h("div", { class: `preset${draft.preset === "custom" ? " on" : ""}` }, h("strong", {}, "Custom", draft.preset === "custom" ? h("span", { class: "active-tag", text: "Active" }) : null), h("span", { text: "Your own mix. Set automatically when the rules match no preset." })));
  }

  async function runPreview() {
    const data = await api(`${guildPath}/settings/preview`, { method: "POST", body: { settings: draft, days: 30 } });
    const list = data.by_check.slice(0, 8).map(([id, count]) => h("li", { text: `${state.catalog.checks.find((item) => item.id === id)?.name ?? id}: ${count}` }));
    dialog("What these rules would have done", h("div", {},
      h("p", { text: `Replayed ${data.attempts} attempts from the last ${data.days} days. ${data.blocked_then} were stopped then, and ${data.blocked_now} would be stopped now.` }),
      h("p", { text: `${data.newly_blocked} members who got in would be stopped. ${data.newly_passed} who were stopped would get in.` }),
      list.length ? h("ul", {}, list) : null,
      h("p", { class: "faint", text: "A replay can only use checks that were on, in Watch or stronger, when each attempt happened." })),
    { buttons: [{ label: "Close" }] });
  }

  function logsDialog() {
    const logs = draft.core.logs;
    const modules = state.catalog.log_modules;
    const isCheck = (module) => state.catalog.checks.some((check) => check.id === module.id);
    const groups = [{ name: "Staff and events", items: modules.filter((module) => !isCheck(module)) },
      ...Object.entries(state.catalog.groups).map(([id, info]) => ({ name: info.name, items: modules.filter((module) => state.catalog.checks.find((check) => check.id === module.id)?.group === id) }))];
    const setAll = (items, value) => edit(() => {
      for (const module of items) {
        if (value) logs.modules[module.id] = value;
        else delete logs.modules[module.id];
      }
    });
    const shared = (items) => {
      const found = new Set(items.map((module) => logs.modules[module.id] ?? null));
      return found.size === 1 ? [...found][0] : null;
    };
    const body = h("div", { class: "grid" });
    const paint = () => fill(body,
      field("Every category", channelPicker(shared(modules), (value) => { setAll(modules, value); paint(); }, { none: "Not logged", disabled: !canEdit }), "Sets one channel for everything at once."),
      groups.map((group) => h("details", { class: "log-group" },
        h("summary", {}, h("span", { text: group.name }), h("small", { class: "faint", text: `${group.items.filter((module) => logs.modules[module.id]).length} of ${group.items.length}` })),
        h("div", { class: "grid two" },
          field("Whole category", channelPicker(shared(group.items), (value) => { setAll(group.items, value); paint(); }, { none: "Not logged", disabled: !canEdit })),
          group.items.map((module) => field(module.name, channelPicker(logs.modules[module.id], (value) => { setAll([module], value); paint(); }, { none: "Not logged", disabled: !canEdit })))))));
    paint();
    dialog("Logs", body, { wide: true, buttons: [{ label: "Done", onClick: () => draw() }] });
  }

  function alertsDialog() {
    const alerts = draft.core.alerts;
    const rows = state.catalog.log_modules.filter((module) => draft.core.logs.modules[module.id]).map((module) =>
      field(module.name, rolePicker(alerts.roles[module.id], (value) => edit(() => {
        if (value) alerts.roles[module.id] = value;
        else delete alerts.roles[module.id];
      }), { none: "No ping", disabled: !canEdit })));
    dialog("Alerts", rows.length ? h("div", { class: "grid two" }, rows) : h("p", { text: "Give a log module a channel first." }), { wide: true, buttons: [{ label: "Done" }] });
  }

  async function exportCode() {
    const { code } = await api(`${guildPath}/settings/export`, { method: "POST", body: {} });
    dialog("Copy these rules to another server", h("div", {}, h("p", { class: "muted", text: "Roles, channels and messages stay behind, because they belong to this server." }),
      h("textarea", { readonly: "readonly", value: code, rows: 6 })), { buttons: [
      { label: "Copy code", onClick: async () => {
        await navigator.clipboard?.writeText(code);
        toast("Copied.");
        return false;
      } },
      { label: "Download file", onClick: () => {
        const link = h("a", { href: URL.createObjectURL(new Blob([code], { type: "text/plain" })), download: "altwarden-rules.txt" });
        link.click();
        URL.revokeObjectURL(link.href);
        return false;
      } },
      { label: "Close" }] });
  }

  function importCode() {
    const box = h("textarea", { placeholder: "Paste a settings code, or pick a file", rows: 6 });
    const file = h("input", { type: "file", accept: ".txt,text/plain", onchange: async (event) => {
      const picked = event.target.files[0];
      if (picked && picked.size <= 65536) box.value = await picked.text();
      else if (picked) toast("That file is over 64 KB.", true);
    } });
    dialog("Import rules", h("div", { class: "grid" }, box, file), { buttons: [{ label: "Cancel" }, { label: "Import", kind: "primary", onClick: async () => {
      try {
        const result = await api(`${guildPath}/settings/import`, { method: "POST", body: { code: box.value } });
        part.draft = result.settings;
        touched();
        draw();
        toast("Imported. Review, then save.");
      } catch (error) {
        toast(error.message, true);
        return false;
      }
    } }] });
  }

  function draw() {
    draft = part.draft;
    const core = draft.core;
    const groups = Object.entries(state.catalog.groups);
    const paused = state.catalog.checks.filter((item) => draft.checks[item.id].enabled && !item.modes.includes(core.mode)).map((item) => item.name);
    const instant = core.mode === "instant";
    if (instant && core.unverified_enabled) paused.push("Unverified role");
    if (instant && core.notify_closed_dms.enabled) paused.push("Ping when DMs are closed");
    const coreSwitches = [core.unverified_enabled, core.auto_dm, core.notify_closed_dms.enabled, core.auto_kick.enabled, core.cooldown.enabled, core.remember_rejoin,
      core.show_reason, core.fail_open, core.direct_signin, core.external_vpn_lookup];
    const staffSwitches = [core.logs.enabled, core.alerts.enabled, core.help_desk.enabled, draft.appeals.enabled];
    const attackSwitches = [draft.raid.enabled, draft.honeypot.enabled];
    const onCount = (list) => list.filter(Boolean).length;
    fill(root,
      canEdit ? null : h("div", { class: "notice", text: LOCKED_NOTE }),
      section("Start from a preset", "A preset sets every rule below. It changes nothing until you save.", presets(),
        h("div", { class: "toolbar" }), h("div", { class: "toolbar" },
          h("button", { class: "button small", text: "Preview on the last 30 days", onclick: runPreview }),
          h("button", { class: "button small", text: "Copy to another server", onclick: exportCode }),
          h("button", { class: "button small", text: "Import rules", disabled: !canEdit, onclick: importCode }))),

      section(counted("How members verify", onCount(coreSwitches), coreSwitches.length), null, h("div", { class: "panel grid two", id: "item-core" },
        h("div", { class: "field wide" }, h("span", { text: "Verification mode" }),
          segments(MODE_OPTIONS, core.mode, (value) => edit(() => { core.mode = value; }, true), { disabled: !canEdit, label: "Verification mode" })),
        paused.length ? h("div", { class: "notice warn field wide", text: `These stay saved but can't run in this mode: ${paused.join(", ")}.` }) : null,
        field([ "Verified role ", h("span", { class: "required", text: "Required" }) ], rolePicker(core.verified_role, (value) => edit(() => { core.verified_role = value; }), { disabled: !canEdit }), "Members get this once they pass."),
        field([ "Verification channel ", h("span", { class: "required", text: "Required" }) ], channelPicker(core.channel, (value) => edit(() => { core.channel = value; }), { disabled: !canEdit }), "Members start here."),
        h("div", { class: "field wide" }, h("div", { class: "toolbar" }, messageLink("verification", "Edit the verification message")))),
      h("div", { class: "rule-list" },
        switchRow("unverified", "Unverified role", instant ? "Paused: members are checked the moment they join, so this role has no use." : "Give a role until a member verifies. Discord skips its own rules screen for anyone holding a role.", core.unverified_enabled, (value) => edit(() => { core.unverified_enabled = value; }, true),
          [field("Role", rolePicker(core.unverified_role, (value) => edit(() => { core.unverified_role = value; }), { disabled: !canEdit }))]),
        switchRow("autodm", "DM new members", "Send the link when a member joins.", core.auto_dm, (value) => edit(() => { core.auto_dm = value; })),
        switchRow("closeddms", "Ping when DMs are closed", instant ? "Paused: nothing is sent when a member joins in this mode." : core.auto_dm ? "Tell the member in the verification channel, then remove the ping." : "Waiting: turn on DM new members first.", core.notify_closed_dms.enabled, (value) => edit(() => { core.notify_closed_dms.enabled = value; }, true),
          [field("Remove the ping after", duration(core.notify_closed_dms.seconds, (value) => edit(() => { core.notify_closed_dms.seconds = value; }), { min: 30, max: 300, disabled: !canEdit, label: "Remove the ping after" }), "30 seconds to 5 minutes.")]),
        switchRow("autokick", "Auto kick", "Kick members who don't verify in time. The timer survives restarts.", core.auto_kick.enabled, (value) => edit(() => { core.auto_kick.enabled = value; }, true),
          [field("Time to verify", duration(core.auto_kick.minutes, (value) => edit(() => { core.auto_kick.minutes = value; }), { base: "minutes", min: 5, max: 10080, disabled: !canEdit, label: "Time to verify" }), "5 minutes to 7 days.")]),
        switchRow("cooldown", "Cooldown", "Make members wait after a failed attempt.", core.cooldown.enabled, (value) => edit(() => { core.cooldown.enabled = value; }, true),
          [field("Time to wait", duration(core.cooldown.seconds, (value) => edit(() => { core.cooldown.seconds = value; }), { min: 1, max: 86400, disabled: !canEdit, label: "Time to wait" }), "1 second to 24 hours.")]),
        switchRow("rejoin", "Remember verified members", "A verified member who leaves and rejoins gets the role back without verifying.", core.remember_rejoin, (value) => edit(() => { core.remember_rejoin = value; })),
        switchRow("reason", "Tell members why", "Show which check stopped them. Turn this off to give evaders less to work with.", core.show_reason, (value) => edit(() => { core.show_reason = value; })),
        switchRow("failopen", "Let members through if network data is missing", "When off, verification waits until the lists load.", core.fail_open, (value) => edit(() => { core.fail_open = value; })),
        switchRow("direct", "Skip the start page", "Send members straight to Discord's sign-in instead of showing the page that explains it first.", core.direct_signin, (value) => edit(() => { core.direct_signin = value; })),
        switchRow("external", "Outside VPN lookup", "Also ask proxycheck.io about each address. This sends members' addresses to that service, so it is off by default.", core.external_vpn_lookup, (value) => edit(() => { core.external_vpn_lookup = value; })))),

      groups.map(([group, info]) => {
        const rows = state.catalog.checks.filter((item) => item.group === group);
        return section(counted(info.name, rows.filter((item) => draft.checks[item.id].enabled).length, rows.length), info.blurb, h("div", { class: "rule-list" }, rows.map(ruleRow)));
      }),

      section(counted("Staff tools", onCount(staffSwitches), staffSwitches.length), null, h("div", { class: "rule-list" },
        switchRow("logs", "Logs", `${Object.keys(core.logs.modules).length} modules have a channel.`, core.logs.enabled, (value) => edit(() => { core.logs.enabled = value; }, true),
          [h("button", { class: "button small", text: "Choose channels", onclick: logsDialog })]),
        switchRow("alerts", "Alerts", core.logs.enabled ? `${Object.keys(core.alerts.roles).length} modules ping a role.` : "Waiting: turn on Logs first, because alerts post in the logs channels.", core.alerts.enabled, (value) => edit(() => { core.alerts.enabled = value; }, true),
          [h("button", { class: "button small", text: "Choose roles", onclick: alertsDialog })]),
        switchRow("helpdesk", "Help desk", "Add a help button that opens a private thread with staff.", core.help_desk.enabled, (value) => edit(() => { core.help_desk.enabled = value; }, true), [
          field("Support role", rolePicker(core.help_desk.support_role, (value) => edit(() => { core.help_desk.support_role = value; }), { disabled: !canEdit })),
          ...[["require_attempt", "Members must try verifying first"], ["redirect", "Add a Talk to staff button to the result page"], ["auto_close", "Close the thread when the member verifies"], ["member_close", "Members can close their own thread"]].map(([key, label]) =>
            h("label", { class: "chip" }, h("input", { type: "checkbox", checked: core.help_desk[key], disabled: !canEdit, onchange: (event) => edit(() => { core.help_desk[key] = event.target.checked; }) }), label)),
          messageLink("help_desk", "Edit the first message"),
        ]),
        switchRow("appeals", "Appeals", "Let stopped members explain themselves. Staff decide with buttons in Discord.", draft.appeals.enabled, (value) => edit(() => { draft.appeals.enabled = value; }, true), [
          field("Channel", channelPicker(draft.appeals.channel, (value) => edit(() => { draft.appeals.channel = value; }), { none: "Use the Appeals log channel", disabled: !canEdit })),
          field("Role to ping", rolePicker(draft.appeals.role, (value) => edit(() => { draft.appeals.role = value; }), { none: "No ping", disabled: !canEdit })),
        ]))),

      section(counted("Attack protection", onCount(attackSwitches), attackSwitches.length), null, h("div", { class: "rule-list" },
        switchRow("raid", "Raid mode", "When joins spike, tighten the rules for a while and alert staff.", draft.raid.enabled, (value) => edit(() => { draft.raid.enabled = value; }, true), [
          field("Joins that trigger it", number(draft.raid.joins, (value) => edit(() => { draft.raid.joins = value; }), { min: 3, max: 1000, disabled: !canEdit })),
          field("Within seconds", number(draft.raid.seconds, (value) => edit(() => { draft.raid.seconds = value; }), { min: 5, max: 3600, disabled: !canEdit })),
          field("Stay on for minutes", number(draft.raid.duration_minutes, (value) => edit(() => { draft.raid.duration_minutes = value; }), { min: 1, max: 1440, disabled: !canEdit })),
          field("Minimum account age during a raid (days)", number(draft.raid.min_account_days, (value) => edit(() => { draft.raid.min_account_days = value; }), { min: 0, max: 365, disabled: !canEdit })),
          field("Role to ping", rolePicker(draft.raid.alert_role, (value) => edit(() => { draft.raid.alert_role = value; }), { none: "No ping", disabled: !canEdit })),
          h("button", { class: "button small", text: state.guild.raid_until * 1000 > Date.now() ? "End raid mode now" : "Start raid mode now", disabled: !canEdit, onclick: async () => {
            const active = state.guild.raid_until * 1000 > Date.now();
            await api(`${guildPath}/raid`, { method: "POST", body: { active: !active } });
            state.guild = await api(guildPath);
            toast(active ? "Raid mode is off." : "Raid mode is on.");
            draw();
          } }),
        ]),
        switchRow("honeypot", "Honeypot", "A trap channel. Anything posted there is removed, and the account is acted on.", draft.honeypot.enabled, (value) => edit(() => { draft.honeypot.enabled = value; }, true), [
          field("Channel", channelPicker(draft.honeypot.channel, (value) => edit(() => { draft.honeypot.channel = value; }), { disabled: !canEdit })),
          field("Action", select(state.catalog.honeypot_actions.map((id) => ({ id, name: id[0].toUpperCase() + id.slice(1) })), draft.honeypot.action, (value) => edit(() => { draft.honeypot.action = value; }, true), { disabled: !canEdit })),
          draft.honeypot.action === "timeout" ? field("Timeout", duration(draft.honeypot.timeout_minutes, (value) => edit(() => { draft.honeypot.timeout_minutes = value; }), { base: "minutes", min: 1, max: 40320, disabled: !canEdit, label: "Timeout" }), "Up to 28 days.") : null,
          h("div", { class: "field wide" }, h("span", { text: "Roles the trap ignores" }), roleList(draft.honeypot.whitelist_roles, () => touched(), { disabled: !canEdit })),
          messageLink("honeypot", "Edit the warning"),
        ]))),

      section("Data retention", "Stored values are keyed hashes, and these limits delete even those on schedule.", h("div", { class: "panel grid two", id: "item-retention" },
        field("Keep connection hashes for (days)", number(draft.privacy.ip_days, (value) => edit(() => { draft.privacy.ip_days = value; }), { min: 1, max: 365, disabled: !canEdit })),
        field("Keep browser and device hashes for (days)", number(draft.privacy.identifier_days, (value) => edit(() => { draft.privacy.identifier_days = value; }), { min: 30, max: 730, disabled: !canEdit })),
        field("Keep attempt history for (days)", number(draft.privacy.attempt_days, (value) => edit(() => { draft.privacy.attempt_days = value; }), { min: 30, max: 730, disabled: !canEdit })),
        field("Keep banned accounts' hashes for (days)", number(draft.privacy.banned_days, (value) => edit(() => { draft.privacy.banned_days = value; }), { min: 0, max: 1825, disabled: !canEdit }), "This is how ban evasion gets caught."))),
    );
    applyFilter();
  }
  draw();
}
