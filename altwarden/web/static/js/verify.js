// The member's page. All text goes in through textContent, so nothing here can inject markup.
import { collect, solvePuzzle } from "/static/js/collector.js";
import { loadLanguage, t } from "/static/js/i18n.js";

const token = location.pathname.split("/")[2];
const card = document.getElementById("card");
const CHECK_TIMEOUT = 60000;
const DATE_FORMAT = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function el(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  node.append(...children.filter(Boolean));
  return node;
}

function iconUrl(guild) {
  return guild.icon ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png?size=128` : "/static/img/logo.svg";
}

function header(state) {
  return el("div", { class: "verify-who" }, el("img", { src: iconUrl(state.guild), alt: "" }));
}

function privacyLine() {
  const line = el("p", { class: "privacy-line" });
  line.append(t("No ads, no trackers, and nothing readable about you is stored. "));
  line.append(el("a", { href: "/privacy", text: t("How this works") }));
  return line;
}

function render(...nodes) {
  card.replaceChildren(...nodes.filter(Boolean));
}

function showExpired() {
  render(
    el("h1", { text: t("This link has expired") }),
    el("p", { text: t("Press Verify in the server's verification channel to get a new one.") }),
    el("div", { class: "verify-actions" }, el("a", { class: "button", href: "/help/link-expired", text: t("Get help") })),
  );
}

function showSignIn(state) {
  const problem = new URLSearchParams(location.search).get("signin");
  if (state.direct && !problem) {
    location.replace(`/v/${token}/signin`);
    return;
  }
  const notes = {
    declined: t("Discord sign-in was canceled. You need to sign in to verify."),
    failed: t("Discord didn't answer. Please try again."),
    wrong: t("You signed in with a different Discord account than the one that joined. Use the right account."),
  };
  const guides = { failed: "/help/sign-in", wrong: "/help/wrong-account" };
  render(
    header(state),
    el("h1", { text: t("Verify for {server}", { server: state.guild.name }) }),
    el("p", { text: t("Sign in with Discord so we can confirm it's you. AltWarden only reads your account details, and ends the sign-in straight away.") }),
    state.member.name ? el("p", { class: "verify-for", text: t("This link is for {name}. If Discord shows a different account, choose Not you.", { name: state.member.name }) }) : null,
    problem && notes[problem] ? el("div", { class: "verify-note", text: notes[problem] }) : null,
    el("div", { class: "verify-actions" },
      el("a", { class: "button discord", href: `/v/${token}/signin`, text: t("Continue with Discord") }),
      guides[problem] ? el("a", { class: "button", href: guides[problem], text: t("What to do") }) : null),
    privacyLine(),
  );
}

function stepRow(label) {
  return el("li", {}, el("span", { class: "dot" }), el("span", { text: label }));
}

async function runCheck(state) {
  const rows = [stepRow(t("Signed in")), stepRow(t("Checking your browser")), stepRow(t("Checking your connection"))];
  rows[0].className = "done";
  rows[1].className = "active";
  render(header(state), el("h1", { text: t("Checking…") }), el("ul", { class: "steps" }, ...rows), privacyLine());
  let finished = false;
  const timer = setTimeout(() => {
    if (!finished) showProblem(state, t("This took too long. Your browser or network didn't get an answer in time."), "/help/timeout");
  }, CHECK_TIMEOUT);
  const stop = () => { finished = true; clearTimeout(timer); };
  try {
    const challengeResponse = await fetch(`/api/verify/${token}/challenge`, { method: "POST", credentials: "same-origin" });
    if (!challengeResponse.ok) {
      stop();
      showProblem(state, t("This link can't be used right now. Reload the page or get a new link."));
      return;
    }
    const challenge = await challengeResponse.json();
    const [report, counter] = await Promise.all([collect(), solvePuzzle(challenge.salt, challenge.bits)]);
    if (finished) return;
    rows[1].className = "done";
    rows[2].className = "active";
    const response = await fetch(`/api/verify/${token}/submit`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nonce: challenge.nonce, counter, report }),
    });
    const result = await response.json();
    if (finished) return;
    stop();
    if (!response.ok) {
      showProblem(state, result.error || t("Something went wrong. Please try again."), response.status >= 500 ? "/help/something-went-wrong" : "/help/security-check");
      return;
    }
    showResult(state, result);
  } catch {
    if (finished) return;
    stop();
    showProblem(state, t("Your browser couldn't finish the check. Turn off anything blocking scripts on this page, then reload."));
  }
}

function showProblem(state, message, guide = "/help/security-check") {
  render(
    header(state),
    el("div", { class: "result-mark wait", text: "!" }),
    el("h1", { text: t("Please try again") }),
    el("p", { text: message }),
    el("div", { class: "verify-actions" },
      el("a", { class: "button primary", href: location.pathname, text: t("Reload") }),
      el("a", { class: "button", href: guide, text: t("Get help") })),
  );
}

function showResult(state, result) {
  if (result.status === "verified" || result.status === "already") {
    render(
      header(state),
      el("div", { class: "result-mark good", text: "✓" }),
      el("h1", { text: t("You're verified") }),
      el("p", { text: t("You now have access to {server}. You can close this tab.", { server: state.guild.name }) }),
    );
    return;
  }
  if (result.status === "cooldown") {
    showCooldown(state, result.seconds_left);
    return;
  }
  const actions = el("div", { class: "verify-actions" });
  if (result.retry) actions.append(el("a", { class: "button primary", href: location.pathname, text: t("Try again") }));
  if (result.help) actions.append(el("a", { class: "button", href: `/help/${result.help}`, text: t("What to do") }));
  if (result.staff_help) actions.append(talkToStaff());
  if (result.appeal) actions.append(el("a", { class: "button", href: `/appeal/${state.guild.id}`, text: t("Appeal to staff") }));
  const removed = { kick: t("You were removed from the server."), ban: t("You were banned from the server.") }[result.action];
  render(
    header(state),
    el("div", { class: `result-mark ${result.status === "problem" ? "wait" : "bad"}`, text: result.status === "problem" ? "!" : "×" }),
    el("h1", { text: t(result.status === "problem" ? result.title : "You weren't verified") }),
    el("p", { text: t(result.template ?? result.message, result.args ?? {}) }),
    result.retry_on ? el("p", { text: t("You can try again after {date}.", { date: DATE_FORMAT.format(new Date(result.retry_on * 1000)) }) }) : null,
    removed ? el("div", { class: "verify-note", text: removed }) : null,
    actions,
  );
}

function talkToStaff() {
  const button = el("button", { class: "button", type: "button", text: t("Talk to staff") });
  button.addEventListener("click", async () => {
    button.disabled = true;
    const response = await fetch(`/api/verify/${token}/help`, { method: "POST", credentials: "same-origin" });
    const data = await response.json();
    if (response.ok) {
      location.href = data.url;
      return;
    }
    button.disabled = false;
    button.textContent = data.error || t("Something went wrong. Please try again.");
  });
  return button;
}

function showCooldown(state, seconds) {
  const line = el("p");
  const retry = el("a", { class: "button primary", href: location.pathname, text: t("Try again") });
  retry.hidden = true;
  let left = Math.ceil(seconds);
  const tick = () => {
    line.textContent = t("Please wait {seconds} seconds before trying again.", { seconds: left });
    if (left-- <= 0) {
      clearInterval(timer);
      line.textContent = t("You can try again now.");
      retry.hidden = false;
    }
  };
  const timer = setInterval(tick, 1000);
  tick();
  render(header(state), el("div", { class: "result-mark wait", text: "…" }), el("h1", { text: t("Please wait") }), line,
    el("div", { class: "verify-actions" }, retry));
}

async function main() {
  await loadLanguage();
  document.title = t("Verify your account") + " | AltWarden";
  const response = await fetch(`/api/verify/${token}`, { credentials: "same-origin" });
  if (!response.ok) {
    showExpired();
    return;
  }
  const state = await response.json();
  if (state.step === "expired") showExpired();
  else if (state.step === "signin") showSignIn(state);
  else if (state.step === "check") runCheck(state);
  else showResult(state, { status: "verified" });
}

main();
