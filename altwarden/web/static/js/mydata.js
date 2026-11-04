// Lets anyone see and delete what AltWarden holds about them, with no ticket.
import { loadLanguage, t } from "/static/js/i18n.js";

const content = document.getElementById("content");
const KINDS = { ip: "Connection hash", cookie: "Browser cookie hash", fingerprint: "Browser fingerprint hash", device: "Device hash", os: "Operating system hash", browser: "Browser family hash" };

function node(tag, text, attributes = {}) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

const date = (seconds) => new Date(seconds * 1000).toLocaleDateString();

function download(data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const link = node("a", "", { href: URL.createObjectURL(blob), download: "altwarden-my-data.json" });
  link.click();
  URL.revokeObjectURL(link.href);
}

async function remove(csrf, guildId) {
  const sure = confirm(guildId ? t("Delete your records for this server? Your verified role there will be removed.") : t("Delete all your records? Your verified roles will be removed."));
  if (!sure) return;
  const response = await fetch("/api/me/delete", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(guildId ? { guild_id: guildId } : {}) });
  const result = await response.json();
  const kept = result.kept_for_ban?.length;
  alert(kept ? t("Deleted. Hashes tied to an active ban stay until the ban ends or they expire.") : t("Deleted."));
  location.reload();
}

function record(entry, csrf) {
  const section = node("section", "", { class: "record" });
  section.append(node("h2", entry.guild_name));
  const lines = node("ul");
  lines.append(node("li", `${t("Status")}: ${entry.status}${entry.verified_at ? ` (${date(entry.verified_at)})` : ""}`));
  for (const kind of entry.stored_hashes) {
    lines.append(node("li", `${t(KINDS[kind.kind] ?? kind.kind)}: ${kind.count}, ${t("deleted by")} ${date(kind.expires_at)}`));
  }
  lines.append(node("li", `${t("Attempts on record")}: ${entry.attempts.length}`));
  if (entry.appeals.length) lines.append(node("li", `${t("Appeals on record")}: ${entry.appeals.length}`));
  if (entry.linked_accounts) lines.append(node("li", `${t("Links to another account")}: ${entry.linked_accounts}`));
  section.append(lines);
  const button = node("button", t("Delete for this server"), { class: "button small danger" });
  button.addEventListener("click", () => remove(csrf, entry.guild_id));
  section.append(button);
  return section;
}

async function main() {
  await loadLanguage();
  const response = await fetch("/api/me/data", { credentials: "same-origin" });
  if (response.status === 401) {
    content.replaceChildren(node("h1", t("See and delete your data")),
      node("p", t("Sign in with Discord to see everything AltWarden holds about you. The sign-in reads your username, then ends.")),
      node("a", t("Continue with Discord"), { class: "button discord", href: "/login?for=member&next=/my-data" }));
    return;
  }
  const data = await response.json();
  const header = [node("h1", t("Your data")), node("p", `${t("Signed in as")} ${data.user.name}`, { class: "muted" })];
  if (!data.records.length) {
    content.replaceChildren(...header, node("p", t("AltWarden holds nothing about you.")));
    return;
  }
  const actions = node("div", "", { class: "toolbar" });
  const save = node("button", t("Download a copy"), { class: "button small" });
  save.addEventListener("click", () => download(data.records));
  const all = node("button", t("Delete everything"), { class: "button small danger" });
  all.addEventListener("click", () => remove(data.csrf));
  actions.append(save, all);
  content.replaceChildren(...header, ...data.records.map((entry) => record(entry, data.csrf)), node("p"), actions,
    node("p", t("Hashes can't be turned back into your address or fingerprint. There's nothing readable to show."), { class: "faint" }));
}

main();
