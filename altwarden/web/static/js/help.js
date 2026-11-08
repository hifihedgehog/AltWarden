// Help for members, one page per thing that can stop them. Each check with a fix gets its page from the server, which
// gives the verify page and the DM the same steps.
import { loadLanguage, t } from "/static/js/i18n.js";

window.pageStarted = true;  // tells loading-guard.js this script loaded
const STAFF = "If that doesn't work, press Appeal to staff if the page shows it, or ask the server's staff. They can verify you themselves or send you a link that skips this check.";

const PAGES = {
  "how-to-verify": ["How to verify", "This server uses AltWarden to keep out bots, raiders and alt accounts. Verifying takes less than a minute.", ["Open the link AltWarden sent you by DM. No DM? Press Verify in the server's verification channel to get one.", "Press Continue with Discord. Some servers skip this page and go straight to Discord.", "Keep the tab open for a few seconds until you see the result, then go back to Discord.", "Some servers check you as you join, with nothing to press. You get a DM if something went wrong.", "Use your own device and a normal browser window, with any VPN or iCloud Private Relay turned off.", "Discord's sign-in page is always on discord.com, so check the address bar before you type anything. AltWarden never asks for your password or two-factor codes."]],
  verification: ["You weren't verified", "This server's rules stopped this attempt, and it chose not to show which one.", ["Try again in a normal browser on your home connection.", STAFF]],
  "account-age": ["Your account is too new", "This server only accepts accounts older than a set age. Brand new accounts are the easiest way to dodge a ban.", ["Try again once your account is old enough.", STAFF]],
  "max-attempts": ["You're out of attempts", "This server limits how many times someone can fail.", ["If attempts come back after a while, the message said when. Fix what stopped you, then try again.", STAFF]],
  cooldown: ["Please wait", "This server makes members wait after a failed attempt. Being asked to wait doesn't count against you.", ["Use the time to fix what stopped you, then try again."]],
  geogate: ["Your country isn't accepted here", "This server chooses which countries can verify, based on your connection.", ["If you're traveling, try again from your usual connection.", STAFF]],
  "link-expired": ["This link has expired", "Links are personal and stop working after a while, or when a newer link replaces them.", ["Go to the server's verification channel and press Verify for a new link.", "If your browser blocks cookies, allow them for this site, then try again.", "If you were removed from the server, contact its staff."]],
  "security-check": ["Your browser couldn't finish the check", "The check needs scripts on this page to run.", ["Turn off anything blocking scripts on this site. Ad blockers are fine.", "Open the link once, and don't go back while it's checking.", "Try another browser if it keeps happening."]],
  "connection-check": ["The connection check isn't available", "This is usually temporary and has nothing to do with your account.", ["Wait a minute and try again."]],
  "wrong-account": ["That's a different Discord account", "Each link belongs to the account that joined the server.", ["Go back to the verification page and press Continue with Discord. AltWarden asks Discord to show its screen, where you can switch accounts.", "If Discord signs you in as the wrong account again, log out of Discord in this browser, then try again."]],
  "sign-in": ["Discord sign-in didn't finish", "Discord didn't share your account details. This is usually a short hiccup on Discord's side.", ["Press Verify in the server for a new link and try again.", "When Discord asks, press Authorize without changing anything."]],
  "left-server": ["You're not in the server", "The role can only be given to someone in the server.", ["Rejoin the server and verify again."]],
  "not-set-up": ["This server isn't ready", "The server added AltWarden but hasn't finished setting it up. There's nothing you can fix on your side.", ["Let the server's staff know.", "Staff: finish the setup screen on the dashboard, or run /setup."]],
  "app-removed": ["AltWarden isn't in this server any more", "AltWarden has to be in the server to give you the role. There's nothing you can fix on your side.", ["Let the server's staff know.", "Staff: ask the owner of AltWarden to add it back within 30 days, or your settings are deleted."]],
  "server-loading": ["Discord is still loading this server", "Discord can take a few minutes to make a server available again, usually after an outage.", ["Wait a few minutes, then press Try again.", "You can see outages at discordstatus.com."]],
  timeout: ["The check took too long", "Your browser didn't get an answer in time, which is usually a browser or network problem.", ["Reload the page.", "Try another browser or network."]],
  "something-went-wrong": ["Something went wrong on our side", "An unexpected error stopped the check. It has nothing to do with your account.", ["Wait a minute, then reload the page.", "If it keeps happening, press Verify in the server for a new link, or ask the server's staff."]],
  "role-problem": ["You passed, but the role couldn't be given", "Nothing is wrong with your account. The server's roles need fixing.", ["Let the server's staff know, then try again once they've fixed it.", "Staff: run /health. It names the missing permission or deleted role."]],
  "role-too-low": ["AltWarden's role is too low", "You passed, but Discord only lets an app give roles below its own, and this server's order is wrong. Nothing is wrong with your account.", ["Let the server's staff know, then verify again once they've fixed it.", "Staff: in Server Settings, Roles, drag the AltWarden role above the role it gives."]],
};

const titles = Object.entries(PAGES).filter(([slug]) => slug !== "verification");

function node(tag, text, attributes = {}) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

async function fromServer(path) {
  const response = await fetch(path, { signal: AbortSignal.timeout?.(20000) });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error("the server had a problem");
  return response.json();
}

function showFix(content, page) {
  document.title = `${t(page.title)} | AltWarden`;
  const nodes = [node("h1", t(page.title)), node("p", t(page.why), { class: "muted" })];
  const many = page.ways.length > 1;
  for (const way of page.ways) {
    nodes.push(node("h2", many ? t(way.heading) : t("What to do")));
    if (many && way.why) nodes.push(node("p", t(way.why), { class: "muted" }));
    const list = node("ol", "", { class: "help-steps" });
    for (const step of way.steps) list.append(node("li", t(step)));
    nodes.push(list);
  }
  nodes.push(node("p", t(STAFF)), node("p", t("AltWarden will never ask for your password or two-factor codes."), { class: "note" }));
  content.replaceChildren(...nodes);
}

async function showIndex(content) {
  const list = node("ul", "", { class: "help-index" });
  const add = (key, title) => {
    const item = node("li");
    item.append(node("a", t(title), { href: `/help/${key}` }));
    list.append(item);
  };
  const [first, ...rest] = titles;
  add(first[0], first[1][0]);
  let served = [];
  try {
    served = (await fromServer("/api/help"))?.pages ?? [];
  } catch {
    served = [];  // the pages help.js holds still list
  }
  for (const page of served) if (!Object.hasOwn(PAGES, page.slug)) add(page.slug, page.title);
  for (const [key, [title]] of rest) add(key, title);
  content.replaceChildren(node("h1", t("Help with verifying")), node("p", t("Pick what you saw.")), list);
}

async function main() {
  await loadLanguage();
  const content = document.getElementById("content");
  const slug = location.pathname.split("/")[2];
  // A plain object also answers to "constructor", which the address can ask for.
  const page = Object.hasOwn(PAGES, slug ?? "") ? PAGES[slug] : null;
  if (!page && slug) {
    const fix = await fromServer(`/api/help/${encodeURIComponent(slug)}`);
    if (fix) {
      showFix(content, fix);
      return;
    }
  }
  if (!page) {
    await showIndex(content);
    return;
  }
  const [title, why, steps] = page;
  document.title = `${t(title)} | AltWarden`;
  const list = node("ol", "", { class: "help-steps" });
  for (const step of steps) list.append(node("li", t(step)));
  content.replaceChildren(node("h1", t(title)), node("p", t(why), { class: "muted" }), node("h2", t("What to do")), list,
    node("p", t("AltWarden will never ask for your password or two-factor codes."), { class: "note" }));
}

main().catch(() => {
  document.getElementById("content").replaceChildren(node("p", t("Something went wrong. Please try again.")), node("a", t("Reload"), { class: "button", href: location.pathname }));
});
