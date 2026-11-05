// Lets anyone see and delete what AltWarden holds about them, with no ticket.
import { loadLanguage, t } from "/static/js/i18n.js";

window.pageStarted = true;  // tells loading-guard.js this script loaded
const content = document.getElementById("content");
const REQUEST_TIMEOUT = 20000;
// Long enough for a slow browser to start the download. FileSaver.js waits this long for the same reason.
const DOWNLOAD_URL_SECONDS = 40;
const KINDS = { ip: "Connection hash", cookie: "Browser cookie hash", fingerprint: "Browser fingerprint hash", device: "Device hash", os: "Operating system hash", browser: "Browser family hash" };

function node(tag, text, attributes = {}) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

const date = (seconds) => new Date(seconds * 1000).toLocaleDateString();

function render(...nodes) {
  const hadFocus = content.contains(document.activeElement);
  content.replaceChildren(...nodes);
  if (hadFocus) {
    const heading = content.querySelector("h1");
    heading?.setAttribute("tabindex", "-1");
    heading?.focus();
  }
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;  // a proxy's error page, which says nothing the member can use
  }
}

function download(data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  // Some browsers ignore a click on a link that isn't in the page, or drop a download whose address is already gone.
  const link = node("a", "", { href: url, download: "altwarden-my-data.json", hidden: "" });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), DOWNLOAD_URL_SECONDS * 1000);
}

// Whether the request went through, after telling the member if it didn't.
async function sendDelete(csrf, guildId) {
  let response;
  try {
    response = await fetch("/api/me/delete", { method: "POST", credentials: "same-origin", signal: AbortSignal.timeout?.(REQUEST_TIMEOUT),
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(guildId ? { guild_id: guildId } : {}) });
  } catch {
    alert(t("We couldn't reach the server, so this may not have gone through. Reload the page to see what's still here."));
    return null;
  }
  if (response.status === 403) {
    alert(t("Nothing was deleted. Your sign-in may have ended, so sign in again and retry."));
    location.reload();
    return null;
  }
  if (response.status === 429) {
    alert(t("Too many tries. Wait a minute, then try again."));
    return null;
  }
  const result = response.ok ? await readJson(response) : null;
  if (!result) alert(t("Something went wrong. Please try again."));
  return result;
}

async function remove(csrf, guildId, button) {
  const sure = confirm(guildId ? t("Delete your records for this server? Your verified role there will be removed.") : t("Delete all your records? Your verified roles will be removed."));
  if (!sure) return;
  // Disabling a button drops the keyboard's focus, so this has to be read first.
  const hadFocus = document.activeElement === button;
  button.disabled = true;
  const result = await sendDelete(csrf, guildId);
  button.disabled = false;
  if (hadFocus) button.focus();
  if (!result) return;
  alert(result.kept_for_ban?.length ? t("Deleted. Hashes tied to an active ban stay until the ban ends or they expire.") : t("Deleted."));
  location.reload();
}

function statusWord(status) {
  return new Map([["pending", t("Not verified")], ["verified", t("Verified")], ["approved", t("Approved by staff")]]).get(status) ?? status;
}

function record(entry, csrf) {
  const section = node("section", "", { class: "record" });
  section.append(node("h2", entry.guild_name));
  const lines = node("ul");
  const line = (label, value) => lines.append(node("li", `${t(label)}: ${value}`));
  if (entry.status) line("Status", `${statusWord(entry.status)}${entry.verified_at ? ` (${date(entry.verified_at)})` : ""}`);
  if (entry.banned) lines.append(node("li", t("Banned on {date}. Your hashes for this server stay until the ban ends or they expire.", { date: date(entry.banned_at) })));
  if (entry.username) line("Name on record", entry.username);
  if (entry.avatar) lines.append(node("li", t("Your profile picture's ID is on record.")));
  if (entry.first_verified_at) line("First verified", date(entry.first_verified_at));
  if (entry.joined_at) line("Joined", date(entry.joined_at));
  if (entry.kick_at) line("Time to verify ends", date(entry.kick_at));
  if (entry.fails) line("Failed attempts counted", entry.fails);
  if (entry.last_fail_at) line("Last failed attempt", date(entry.last_fail_at));
  if (entry.limit_reached_at) line("Reached the attempt limit", date(entry.limit_reached_at));
  if (entry.help_thread_id) lines.append(node("li", t("Help thread on record.")));
  for (const kind of entry.stored_hashes) {
    lines.append(node("li", `${t(KINDS[kind.kind] ?? kind.kind)}: ${kind.count}, ${t("deleted by")} ${date(kind.expires_at)}`));
  }
  line("Attempts on record", entry.attempt_count);
  if (entry.attempt_count > entry.attempts.length) lines.append(node("li", t("The download holds the latest {count}.", { count: entry.attempts.length })));
  if (entry.appeals.length) line("Appeals on record", entry.appeals.length);
  if (entry.linked_accounts) line("Links to another account", entry.linked_accounts);
  if (entry.trusted_pairs) line("Accounts staff marked as different people", entry.trusted_pairs);
  if (entry.audit_about) line("Staff records that mention you", entry.audit_about);
  if (entry.staff_actions) line("Actions you took as staff", entry.staff_actions);
  if (entry.live_links) line("Links to verify", entry.live_links);
  section.append(lines);
  const button = node("button", t("Delete for this server"), { class: "button small danger" });
  button.addEventListener("click", () => remove(csrf, entry.guild_id, button));
  section.append(button);
  return section;
}

async function main() {
  await loadLanguage();
  document.title = `${t("Your data")} | AltWarden`;
  const response = await fetch("/api/me/data", { credentials: "same-origin", signal: AbortSignal.timeout?.(REQUEST_TIMEOUT) });
  if (response.status === 401) {
    render(node("h1", t("See and delete your data")),
      node("p", t("Sign in with Discord to see everything AltWarden holds about you. The sign-in reads your account details once, then ends.")),
      node("a", t("Continue with Discord"), { class: "button discord", href: "/login?for=member&next=/my-data" }));
    return;
  }
  const data = response.ok ? await readJson(response) : null;
  if (!data) throw new Error("the server didn't answer");
  const header = [node("h1", t("Your data")), node("p", `${t("Signed in as")} ${data.user.name}`, { class: "muted" })];
  if (!data.records.length) {
    render(...header, node("p", t("AltWarden holds no records about you.")));
    return;
  }
  const actions = node("div", "", { class: "toolbar" });
  const save = node("button", t("Download a copy"), { class: "button small" });
  save.addEventListener("click", () => download(data.records));
  const all = node("button", t("Delete everything"), { class: "button small danger" });
  all.addEventListener("click", () => remove(data.csrf, undefined, all));
  actions.append(save, all);
  render(...header, ...data.records.map((entry) => record(entry, data.csrf)), node("p"), actions,
    node("p", t("Hashes can't be turned back into your address or fingerprint. There's nothing readable to show."), { class: "faint" }),
    node("p", t("Deleting here doesn't reach backups, which keep a copy for up to 14 days. Messages AltWarden posted in a server, such as logs, appeals and help threads, stay in Discord. Ask that server's staff to delete them."), { class: "faint" }));
}

main().catch(() => {
  render(node("p", t("Something went wrong. Please try again.")), node("a", t("Reload"), { class: "button", href: location.pathname }));
});
