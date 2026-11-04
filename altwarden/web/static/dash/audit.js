// Audit log: every settings change with before and after values, and every staff action.
import { api, h, section, state, when } from "/static/dash/ui.js";

const KINDS = { settings: "Changed settings", manual_verify: "Verified a member", reset: "Reset a member", bypass: "Created a bypass link", appeal: "Decided an appeal",
  import_members: "Imported members", command_permissions: "Changed Discord's command permissions", raid_start: "Started raid mode", raid_stop: "Ended raid mode", trust: "Trusted two accounts" };

function details(entry) {
  const detail = entry.detail;
  if (entry.kind === "settings") {
    return h("ul", {}, detail.changes.slice(0, 30).map((change) => h("li", { text: `${change.path}: ${JSON.stringify(change.before)} → ${JSON.stringify(change.after)}` })));
  }
  const parts = Object.entries(detail).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`);
  return parts.length ? h("small", { text: parts.join(", ") }) : null;
}

export async function render(view) {
  const data = await api(`/api/guilds/${state.guild.id}/audit`);
  view.append(section("Audit log", "The last 200 changes and staff actions.", data.entries.length
    ? h("ul", { class: "timeline" }, data.entries.map((entry) => h("li", {},
      h("strong", { text: KINDS[entry.kind] ?? entry.kind }),
      h("small", { text: `${entry.actor_name || entry.actor_id || "AltWarden"}, ${when(entry.at)}` }), details(entry))))
    : h("p", { class: "faint", text: "Nothing yet." })));
}
