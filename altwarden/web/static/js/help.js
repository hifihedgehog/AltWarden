// Help for members, one page per thing that can stop them.
import { loadLanguage, t } from "/static/js/i18n.js";

const STAFF = "If that doesn't work, press Appeal, or ask the server's staff. They can verify you themselves or send you a link that skips this check.";

const PAGES = {
  verification: ["You weren't verified", "This server's rules stopped this attempt, and it chose not to show which one.", ["Try again in a normal browser on your home connection.", STAFF]],
  "account-age": ["Your account is too new", "This server only accepts accounts older than a set age. Brand new accounts are the easiest way to dodge a ban.", ["Try again once your account is old enough.", STAFF]],
  avatar: ["You need a profile picture", "Throwaway accounts rarely set one, so this server requires it.", ["In Discord, open User Settings, then Profiles, and upload a picture.", "Press Verify in the server to try again."]],
  mfa: ["You need two-factor login", "Accounts with two-factor login are much harder to steal or mass-produce.", ["In Discord, open User Settings, then Account, and enable an authenticator app.", "Save your backup codes somewhere safe, and never share them with anyone.", "Press Verify in the server to try again."]],
  "no-email": ["Your account has no verified email", "This server checks that accounts use a real email address, and Discord says yours isn't verified.", ["In Discord, open User Settings, then Account, and add or confirm your email.", "Press Verify in the server to try again."]],
  "disposable-email": ["Your account uses a throwaway email", "Temporary inboxes make it easy to create accounts in bulk, so this server turns them away.", ["In Discord, change your email to a regular provider and confirm it.", "Press Verify in the server to try again."]],
  "alt-account": ["This account looks linked to another", "Something about this browser or connection matches another account in this server. That can happen to people who share a home or a computer.", ["If it's a mistake, press Appeal and explain. Saying that you share a home or computer helps.", "Staff decide, and they can mark the two accounts as different people."]],
  "max-attempts": ["You're out of attempts", "This server limits how many times someone can fail.", ["If attempts come back after a while, the message said when. Fix what stopped you, then try again.", STAFF]],
  cooldown: ["Please wait", "This server makes members wait after a failed attempt. Being asked to wait doesn't count against you.", ["Use the time to fix what stopped you, then try again."]],
  vpn: ["Your connection looks like a VPN", "VPNs and proxies make it easy to dodge bans, so this server limits them. Data centers, Tor and iCloud Private Relay count too.", ["Turn off your VPN or proxy while you verify. You can turn it back on afterwards.", "On an Apple device, turn off iCloud Private Relay for now.", "Use your home connection if you can. School and work networks can look like a VPN.", STAFF]],
  "mobile-data": ["Mobile data isn't accepted here", "Mobile networks hand out new addresses all the time, so this server asks for another connection.", ["Connect to Wi-Fi and try again.", STAFF]],
  geogate: ["Your country isn't accepted here", "This server chooses which countries can verify, based on your connection.", ["If you're traveling, try again from your usual connection.", STAFF]],
  automation: ["Your browser looks automated", "Scripts that drive a browser are used to verify accounts in bulk.", ["Open the link in a normal browser such as Chrome, Edge, Safari or Firefox.", "Turn off extensions that automate pages.", STAFF]],
  antidetect: ["Your browser hides what device it's on", "Tools that invent a new device for every profile let one person run many accounts. Some privacy tools can look like one by mistake.", ["Use a normal browser with its default settings.", "Turn off extensions that change what your browser reports.", STAFF]],
  tampering: ["Your browser looks modified", "Built-in browser functions were rewritten, usually by an extension.", ["Turn off extensions that change or hide browser details, or try a browser with none.", STAFF]],
  "fake-ua": ["Your browser is reporting the wrong identity", "It claims to be a different browser or system than it is, usually because of an extension.", ["Turn off user agent switchers.", "On a phone, turn off Request desktop site.", "Try again in a normal browser.", STAFF]],
  devtools: ["Developer tools are open", "This server doesn't accept verification with developer tools open.", ["Close the developer tools panel. F12 usually toggles it.", "Reload the page."]],
  incognito: ["This is a private window", "Private windows throw away cookies, which helps people dodge alt detection.", ["Copy the link, paste it in a normal window, and finish there. You can go back to private browsing afterwards."]],
  privacy: ["Your browser is blocking device details", "Strict privacy settings hide what this server uses to tell devices apart. There's nothing wrong with using them.", ["Try a browser with default settings for this one step.", STAFF]],
  threat: ["This attempt scored too high on risk", "Several small signs added up, such as a VPN, extensions or an unusual setup.", ["Try a normal browser with no extensions on your home connection.", STAFF]],
  vm: ["This looks like a virtual machine", "Virtual machines can be reset in seconds, which makes them an easy way to look like a new device. Remote desktops and turned-off graphics acceleration can look like one too.", ["Open the link on your own device.", STAFF]],
  rooted: ["This phone looks emulated or modified", "Emulators and modified phones let one person look like many. Custom firmware, or a phone reporting a model that doesn't fit its hardware, can trigger this.", ["Verify from a regular phone or computer.", STAFF]],
  "link-expired": ["This link has expired", "Links are personal and stop working after a while, or when a newer link replaces them.", ["Go to the server's verification channel and press Verify for a new link."]],
  "security-check": ["Your browser couldn't finish the check", "The check needs scripts on this page to run.", ["Turn off anything blocking scripts on this site. Ad blockers are fine.", "Open the link once, and don't go back while it's checking.", "Try another browser if it keeps happening."]],
  "connection-check": ["The connection check isn't available", "This is usually temporary and has nothing to do with your account.", ["Wait a minute and try again."]],
  "wrong-account": ["That's a different Discord account", "Each link belongs to the account that joined the server.", ["Press Verify in the server for a new link.", "When Discord asks you to authorize, check the account shown. If it's wrong, choose Not you and sign in with the right one."]],
  "sign-in": ["Discord sign-in didn't finish", "Discord didn't share your account details. This is usually a short hiccup on Discord's side.", ["Press Verify in the server for a new link and try again.", "When Discord asks, press Authorize without changing anything."]],
  "left-server": ["You're not in the server", "The role can only be given to someone in the server.", ["Rejoin the server and verify again."]],
  "not-set-up": ["This server isn't ready", "The server added AltWarden but hasn't finished setting it up. There's nothing you can fix on your side.", ["Let the server's staff know.", "Staff: finish the setup screen on the dashboard, or run /setup."]],
  "app-removed": ["AltWarden isn't in this server any more", "AltWarden has to be in the server to give you the role. There's nothing you can fix on your side.", ["Let the server's staff know.", "Staff: add AltWarden back from the dashboard. Your settings are kept."]],
  "server-loading": ["Discord is still loading this server", "Discord can take a few minutes to make a server available again, usually after an outage.", ["Wait a few minutes, then press Try again.", "You can see outages at discordstatus.com."]],
  timeout: ["The check took too long", "Your browser didn't get an answer in time, which is usually a browser or network problem.", ["Reload the page.", "Try another browser or network."]],
  "something-went-wrong": ["Something went wrong on our side", "An unexpected error stopped the check. It has nothing to do with your account.", ["Wait a minute, then reload the page.", "If it keeps happening, press Verify in the server for a new link, or ask the server's staff."]],
  "role-problem": ["You passed, but the role couldn't be given", "Nothing is wrong with your account. The server's roles need fixing, and staff have been told.", ["Try again once staff have fixed it.", "Staff: run /health. It names the missing permission or deleted role."]],
  "role-too-low": ["AltWarden's role is too low", "You passed, but Discord only lets an app give roles below its own, and this server's order is wrong. Nothing is wrong with your account.", ["Let the server's staff know, then verify again once they've fixed it.", "Staff: in Server Settings, Roles, drag the AltWarden role above the role it gives."]],
};

const titles = Object.entries(PAGES).filter(([slug]) => slug !== "verification");

function node(tag, text, attributes = {}) {
  const element = document.createElement(tag);
  if (text) element.textContent = text;
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

async function main() {
  await loadLanguage();
  const content = document.getElementById("content");
  const slug = location.pathname.split("/")[2];
  const page = PAGES[slug];
  if (!page) {
    const list = node("ul", "", { class: "help-index" });
    for (const [key, [title]] of titles) {
      const item = node("li");
      item.append(node("a", t(title), { href: `/help/${key}` }));
      list.append(item);
    }
    content.replaceChildren(node("h1", t("Help with verifying")), node("p", t("Pick what you saw.")), list);
    return;
  }
  const [title, why, steps] = page;
  document.title = `${t(title)} | AltWarden`;
  const list = node("ol", "", { class: "help-steps" });
  for (const step of steps) list.append(node("li", t(step)));
  content.replaceChildren(node("h1", t(title)), node("p", t(why), { class: "muted" }), node("h2", t("What to do")), list,
    node("p", t("AltWarden will never ask for your password or two-factor codes."), { class: "note" }));
}

main();
