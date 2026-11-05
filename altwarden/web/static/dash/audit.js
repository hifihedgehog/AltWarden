// Audit log: every settings change with before and after values, and every staff action.
import { api, h, lookup, section, state, when } from "/static/dash/ui.js";

const KINDS = { settings: "Changed settings", manual_verify: "Verified a member", reset: "Reset a member", bypass: "Created a bypass link", appeal: "Decided an appeal",
  import_members: "Imported members", command_permissions: "Changed Discord's command permissions", raid_start: "Started raid mode", raid_stop: "Ended raid mode", trust: "Trusted two accounts", data_deleted: "Deleted a member's data" };
const SHOWN_CHANGES = 30;

function kindName(kind) {
  const words = String(kind).replaceAll("_", " ");
  return lookup(KINDS, kind, words[0]?.toUpperCase() + words.slice(1));
}

function valueText(value) {
  if (value === true) return "yes";
  if (value === false) return "no";
  return value !== null && typeof value === "object" ? JSON.stringify(value) : String(value);
}

function details(entry) {
  const detail = entry.detail;
  if (entry.kind === "settings") {
    // An older or hand-written row may hold no list, and one row mustn't blank the page.
    const changes = Array.isArray(detail.changes) ? detail.changes : [];
    const total = detail.total ?? changes.length;
    return h("ul", {}, changes.slice(0, SHOWN_CHANGES).map((change) => h("li", { text: `${change.path}: ${JSON.stringify(change.before)} → ${JSON.stringify(change.after)}` })),
      total > Math.min(changes.length, SHOWN_CHANGES) ? h("li", { class: "faint", text: `${Math.min(changes.length, SHOWN_CHANGES)} of ${total} changes shown.` }) : null);
  }
  const parts = Object.entries(detail).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.map(valueText).join(", ") : valueText(value)}`);
  return parts.length ? h("small", { text: parts.join(", ") }) : null;
}

export async function render(view) {
  const data = await api(`/api/guilds/${state.guild.id}/audit`);
  view.append(section("Audit log", "The last 200 changes and staff actions.", data.entries.length
    ? h("ul", { class: "timeline" }, data.entries.map((entry) => h("li", {},
      h("strong", { text: kindName(entry.kind) }),
      h("small", { text: `${entry.actor_name || entry.actor_id || "AltWarden"}, ${when(entry.at)}` }), details(entry))))
    : h("p", { class: "faint", text: "Nothing yet." })));
}
