// Lets a stopped member explain themselves to the server's staff.
import { loadLanguage, t } from "/static/js/i18n.js";

const content = document.getElementById("content");
const guildId = location.pathname.split("/")[2];

function node(tag, text, attributes = {}) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

async function main() {
  await loadLanguage();
  const response = await fetch(`/api/me/appeal/${guildId}`, { credentials: "same-origin" });
  if (response.status === 401) {
    content.replaceChildren(node("h1", t("Appeal to staff")),
      node("p", t("Sign in with Discord so staff know who is asking. The sign-in reads your username, then ends.")),
      node("a", t("Continue with Discord"), { class: "button discord", href: `/login?for=member&next=/appeal/${guildId}` }));
    return;
  }
  const data = await response.json();
  if (data.open) {
    content.replaceChildren(node("h1", t("Your appeal is waiting")), node("p", t("Staff will reply by DM.")));
    return;
  }
  if (!data.check) {
    content.replaceChildren(node("h1", t("Nothing to appeal")), node("p", t("There is no recent failed attempt on this account.")));
    return;
  }
  const box = node("textarea", "", { maxlength: "1500", "aria-label": t("What happened?") });
  const note = node("p", "", { class: "faint" });
  const send = node("button", t("Send to staff"), { class: "button primary" });
  send.addEventListener("click", async () => {
    send.disabled = true;
    const reply = await fetch(`/api/me/appeal/${guildId}`, { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": data.csrf }, body: JSON.stringify({ text: box.value }) });
    if (reply.ok) {
      content.replaceChildren(node("h1", t("Sent")), node("p", t("Staff will reply by DM.")));
      return;
    }
    send.disabled = false;
    note.textContent = (await reply.json()).error ?? t("Something went wrong. Please try again.");
  });
  content.replaceChildren(node("h1", t("Appeal to {server}").replace("{server}", data.guild.name)),
    node("p", t("Tell staff what happened. If you share a home or a computer with someone in this server, say so."), { class: "muted" }),
    box, note, send);
}

main();
