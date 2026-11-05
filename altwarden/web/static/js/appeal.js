// Lets a stopped member explain themselves to the server's staff, and shows what staff decided.
import { loadLanguage, t } from "/static/js/i18n.js";

window.pageStarted = true;  // tells loading-guard.js this script loaded
const content = document.getElementById("content");
const guildId = location.pathname.split("/")[2];
const REQUEST_TIMEOUT = 20000;
const DATE_FORMAT = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

function node(tag, text, attributes = {}) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

// Replacing the card would drop a keyboard user's focus to the top of the page, so it moves to the new heading.
function focusHeading() {
  const heading = content.querySelector("h1");
  heading?.setAttribute("tabindex", "-1");
  heading?.focus();
}

function render(...nodes) {
  const hadFocus = content.contains(document.activeElement);
  content.replaceChildren(...nodes.filter(Boolean));
  if (hadFocus) focusHeading();
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;  // a proxy's error page, which says nothing the member can use
  }
}

// The decision also goes by DM, and Discord won't deliver one to someone who left the server, so the page has to say it.
function decision(latest) {
  if (!latest) return [];
  const date = DATE_FORMAT.format(new Date(latest.decided_at * 1000));
  const said = latest.status === "approved"
    ? t("Staff approved your appeal on {date}. If you're not in the server, rejoin it to get access.", { date })
    : t("Staff turned down your appeal on {date}.", { date });
  return [node("p", said), latest.note ? node("p", t("Note from staff: {note}", { note: latest.note }), { class: "muted" }) : null];
}

function sendFailure(status, body) {
  if (status === 429) return t("Too many tries. Wait a minute, then try again.");
  if (status === 403) return t("Your sign-in ended. Copy what you wrote, then reload the page to sign in again.");
  if (status >= 500 || !body?.error) return t("Something went wrong. Please try again.");
  return t(body.error);
}

function showForm(data) {
  const box = node("textarea", "", { maxlength: "1500", "aria-label": t("What happened?") });
  const note = node("p", "", { class: "faint" });
  const send = node("button", t("Send to staff"), { class: "button primary" });
  send.addEventListener("click", async () => {
    // Disabling a button drops the keyboard's focus, so this has to be read first.
    const hadFocus = document.activeElement === send;
    send.disabled = true;
    note.textContent = "";
    let problem;
    try {
      const reply = await fetch(`/api/me/appeal/${guildId}`, { method: "POST", credentials: "same-origin", signal: AbortSignal.timeout?.(REQUEST_TIMEOUT),
        headers: { "Content-Type": "application/json", "X-CSRF-Token": data.csrf }, body: JSON.stringify({ text: box.value }) });
      const body = await readJson(reply);
      if (reply.ok && body) {
        render(node("h1", t("Sent")), node("p", t("Staff will reply by DM if they can. The decision also shows on this page.")));
        if (hadFocus) focusHeading();
        return;
      }
      problem = sendFailure(reply.status, body);
    } catch {
      problem = t("We couldn't reach the server. Check your connection, then try again.");
    }
    send.disabled = false;
    if (hadFocus) send.focus();
    note.textContent = problem;
  });
  render(node("h1", t("Appeal to {server}", { server: data.guild.name })), ...decision(data.latest),
    node("p", t("Tell staff what happened. If you share a home or a computer with someone in this server, or someone else used your account, say so."), { class: "muted" }),
    box, note, send);
}

async function main() {
  await loadLanguage();
  document.title = `${t("Appeal to staff")} | AltWarden`;
  const response = await fetch(`/api/me/appeal/${guildId}`, { credentials: "same-origin", signal: AbortSignal.timeout?.(REQUEST_TIMEOUT) });
  if (response.status === 401) {
    render(node("h1", t("Appeal to staff")),
      node("p", t("Sign in with Discord so staff know who is asking. The sign-in reads your account details once, then ends.")),
      node("a", t("Continue with Discord"), { class: "button discord", href: `/login?for=member&next=/appeal/${guildId}` }));
    return;
  }
  const data = response.ok ? await readJson(response) : null;
  if (!data) throw new Error("the server didn't answer");
  if (data.open) {
    render(node("h1", t("Your appeal is waiting")), node("p", t("Staff will reply by DM if they can. The decision also shows on this page.")));
  } else if (data.check) {
    showForm(data);
  } else if (!data.present && (data.enabled || !data.problem)) {
    // The same answer during an outage and after the bot was removed, because a member can't tell those apart and neither can this page.
    render(node("h1", t("This server can't take appeals right now")), ...decision(data.latest), node("p", t("AltWarden can't reach it at the moment. Try again later, or ask the server's staff.")));
  } else if (data.present && !data.enabled) {
    render(node("h1", t("This server doesn't take appeals")), ...decision(data.latest), node("p", t("Ask the server's staff if you think a result is wrong.")));
  } else {
    render(node("h1", data.latest ? t("Staff decided your appeal") : t("Nothing to appeal")), ...decision(data.latest), node("p", t(data.problem)));
  }
}

main().catch(() => {
  render(node("p", t("Something went wrong. Please try again.")), node("a", t("Reload"), { class: "button", href: location.pathname }));
});
