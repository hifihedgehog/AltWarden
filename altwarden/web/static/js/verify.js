// The member's page. All text goes in through textContent, so nothing here can inject markup.
import { collect, solvePuzzle } from "/static/js/collector.js";
import { loadLanguage, t } from "/static/js/i18n.js";

window.pageStarted = true;  // tells loading-guard.js this script loaded, however long the server takes to answer
const token = location.pathname.split("/")[2];
const card = document.getElementById("card");
const CHECK_TIMEOUT = 60000;
const STATE_TIMEOUT = 20000;
// A problem result the help desk can't do anything about: the member has left, or the bot isn't in the server.
const NO_STAFF_HELP = new Set(["left_server", "app_removed", "not_set_up"]);
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
  line.append(t("No ads, no trackers, and your IP address and email are never stored in readable form. "));
  line.append(el("a", { href: "/privacy", text: t("How this works") }));
  return line;
}

function render(...nodes) {
  // Replacing the card would drop a keyboard user's focus to the top of the page, so it moves to the new heading.
  const hadFocus = card.contains(document.activeElement);
  card.replaceChildren(...nodes.filter(Boolean));
  if (hadFocus) {
    const heading = card.querySelector("h1");
    heading?.setAttribute("tabindex", "-1");
    heading?.focus();
  }
}

function showExpired() {
  render(
    el("h1", { text: t("This link has expired") }),
    el("p", { text: t("If you're still in the server, press Verify in its verification channel to get a new one. If you were removed, contact the server's staff.") }),
    el("div", { class: "verify-actions" }, el("a", { class: "button", href: "/help/link-expired", text: t("Get help") })),
  );
}

function showSignIn(state, again) {
  const problem = new URLSearchParams(location.search).get("signin");
  // Maps, because the value comes from the address, and a plain object would also answer to "constructor".
  const notes = new Map([
    ["declined", t("Discord sign-in was canceled. You need to sign in to verify.")],
    ["failed", t("Discord didn't answer. Please try again.")],
    ["wrong", t("You signed in with a different Discord account than the one that joined. Press Continue with Discord to switch. If Discord picks the same account, log out of Discord in this browser and try again.")],
  ]);
  const guides = new Map([["failed", "/help/sign-in"], ["wrong", "/help/wrong-account"]]);
  // After a failed try the page waits to be asked, or each reload would sign in and spend another attempt.
  if (state.direct && !notes.has(problem) && (!state.tried || again)) {
    location.replace(`/v/${token}/signin`);
    return;
  }
  render(
    header(state),
    el("h1", { text: t("Verify for {server}", { server: state.guild.name }) }),
    el("p", { text: t("Sign in with Discord so we can confirm it's you. AltWarden only reads your account details, and ends the sign-in straight away.") }),
    state.member.name ? el("p", { class: "verify-for", text: t("This link is for {name}.", { name: state.member.name }) }) : null,
    notes.has(problem) ? el("div", { class: "verify-note", text: notes.get(problem) }) : null,
    el("div", { class: "verify-actions" },
      // Discord skips its screen for an account it already knows, so after the wrong account the next sign-in has to ask.
      el("a", { class: "button discord", href: `/v/${token}/signin${problem === "wrong" ? "?switch=1" : ""}`, text: t("Continue with Discord") }),
      guides.has(problem) ? el("a", { class: "button", href: guides.get(problem), text: t("What to do") }) : null),
    privacyLine(),
  );
}

// A reload mustn't spend an attempt, so after a failure the page waits to be asked. The last attempt's fixes come back with it.
function showTried(state) {
  const fixes = Array.isArray(state.fixes) ? state.fixes : [];
  render(
    header(state),
    el("h1", { text: t("You weren't verified") }),
    el("p", { text: t("Your last attempt didn't pass. Press Try again when you're ready.") }),
    ...fixSection(fixes, true),
    el("div", { class: "verify-actions" },
      el("a", { class: "button primary", href: retryUrl(), text: t("Try again") }),
      el("a", { class: "button", href: "/help/verification", text: fixes.length ? t("Get help") : t("What to do") }),
      state.staff_help ? talkToStaff() : null,
      state.appeal ? el("a", { class: "button", href: `/appeal/${state.guild.id}`, text: t("Appeal to staff") }) : null),
  );
}

function retryUrl() {
  return `${location.pathname}?again=1`;
}

function stepList(steps) {
  const list = el("ol", { class: "fix-steps" });
  for (const step of steps) list.append(el("li", { text: t(step) }));
  return list;
}

// What to do about each check that stopped an attempt. The steps for this device come first, and the others wait behind their headings.
function fixSection(fixes, retry) {
  const nodes = [];
  if (fixes.length > 1) nodes.push(el("p", { class: "fix-intro", text: t("{count} things stopped this attempt. Fix each one, then try again.", { count: fixes.length }) }));
  for (const fix of fixes) {
    const [first, ...others] = fix.ways;
    const block = el("section", { class: "fix" }, el("h2", { text: t(fix.title) }), el("p", { class: "fix-why", text: t(fix.why) }));
    if (others.length) block.append(el("h3", { text: t(first.heading) }));
    block.append(stepList(first.steps));
    for (const way of others) block.append(el("details", { class: "fix-other" }, el("summary", { text: t(way.heading) }), stepList(way.steps)));
    nodes.push(block);
  }
  if (retry && fixes.some((fix) => fix.after)) {
    nodes.push(el("p", { class: "fix-after", text: fixes.some((fix) => fix.after === "signin")
      ? t("When you're done, press Try again and sign in with Discord again, so this server can see the change.")
      : t("When you're done, press Try again.") }));
  }
  return nodes;
}

function stepRow(label) {
  return el("li", {}, el("span", { class: "dot" }), el("span", { text: label }));
}

// The dot's color says which step this is, so a screen reader gets the same in words.
function markStep(row, status) {
  row.className = status;
  if (status === "active") {
    row.setAttribute("aria-current", "step");
  } else {
    row.removeAttribute("aria-current");
    row.append(el("span", { class: "visually-hidden", text: t("Done") }));
  }
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;  // a proxy's error page, which says nothing the member can use
  }
}

// The server or a proxy refused. None of this is the member's browser, so it never sends them to their extensions.
function showRefused(state, response, body, message) {
  if (response.status === 429) {
    showProblem(state, t("Too many tries. Wait a minute, then reload the page."), "/help/something-went-wrong");
  } else if (response.status >= 500 || !body) {
    showProblem(state, t("Something went wrong. Please try again."), "/help/something-went-wrong");
  } else {
    showProblem(state, message ?? (body.error ? t(body.error) : t("Something went wrong. Please try again.")));
  }
}

async function runCheck(state) {
  const rows = [stepRow(t("Signed in")), stepRow(t("Checking your browser")), stepRow(t("Checking your connection"))];
  markStep(rows[0], "done");
  markStep(rows[1], "active");
  render(header(state), el("h1", { text: t("Checking…") }), el("ul", { class: "steps" }, ...rows), privacyLine());
  let finished = false;
  const requests = new AbortController();
  const timer = setTimeout(() => {
    // Nothing more goes out after this, so a member who presses Reload can't run into this attempt still in progress.
    finished = true;
    requests.abort();
    showProblem(state, t("This took too long. Your browser or network didn't get an answer in time."), "/help/timeout");
  }, CHECK_TIMEOUT);
  const stop = () => { finished = true; clearTimeout(timer); };
  let inBrowser = false;
  try {
    const challengeResponse = await fetch(`/api/verify/${token}/challenge`, { method: "POST", credentials: "same-origin", signal: requests.signal });
    const challenge = await readJson(challengeResponse);
    if (finished) return;
    if (!challengeResponse.ok || !challenge) {
      stop();
      showRefused(state, challengeResponse, challenge, t("This link can't be used right now. Reload the page or get a new link."));
      return;
    }
    inBrowser = true;
    const [report, counter] = await Promise.all([collect(), solvePuzzle(challenge.salt, challenge.bits)]);
    inBrowser = false;
    if (finished) return;
    markStep(rows[1], "done");
    markStep(rows[2], "active");
    const response = await fetch(`/api/verify/${token}/submit`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nonce: challenge.nonce, counter, report }),
      signal: requests.signal,
    });
    const result = await readJson(response);
    if (finished) return;
    stop();
    if (!response.ok || !result) {
      showRefused(state, response, result);
      return;
    }
    showResult(state, result);
  } catch {
    if (finished) return;
    stop();
    if (inBrowser) showProblem(state, t("Your browser couldn't finish the check. Turn off anything blocking scripts on this page, then reload."));
    else showProblem(state, t("We couldn't reach the server. Check your connection, then reload."), "/help/timeout");
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
      el("a", { class: "button", href: guide, text: t("Get help") }),
      state.staff_help ? talkToStaff() : null),
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
  const fixes = Array.isArray(result.fixes) ? result.fixes : [];
  const actions = el("div", { class: "verify-actions" });
  if (result.retry) actions.append(el("a", { class: "button primary", href: retryUrl(), text: t("Try again") }));
  if (result.help) actions.append(el("a", { class: "button", href: `/help/${result.help}`, text: fixes.length ? t("Get help") : t("What to do") }));
  if (result.staff_help || (result.status === "problem" && state.staff_help && !NO_STAFF_HELP.has(result.reason))) actions.append(talkToStaff());
  if (result.appeal) actions.append(el("a", { class: "button", href: `/appeal/${state.guild.id}`, text: t("Appeal to staff") }));
  const removed = { kick: t("You were removed from the server."), ban: t("You were banned from the server.") }[result.action];
  const left = result.attempts_left;
  render(
    header(state),
    el("div", { class: `result-mark ${result.status === "problem" ? "wait" : "bad"}`, text: result.status === "problem" ? "!" : "×" }),
    el("h1", { text: t(result.status === "problem" ? result.title : "You weren't verified") }),
    el("p", { text: t(result.template ?? result.message, result.args ?? {}) }),
    Number.isInteger(left) && left > 0 ? el("p", { text: left === 1 ? t("1 try left.") : t("{count} tries left.", { count: left }) }) : null,
    result.retry_on ? el("p", { text: t("You can try again after {date}.", { date: DATE_FORMAT.format(new Date(result.retry_on * 1000)) }) }) : null,
    removed ? el("div", { class: "verify-note", text: removed }) : null,
    ...fixSection(fixes, result.retry),
    actions,
  );
}

function talkToStaff() {
  const button = el("button", { class: "button", type: "button", text: t("Talk to staff") });
  button.addEventListener("click", async () => {
    button.disabled = true;
    let problem = null;
    try {
      const response = await fetch(`/api/verify/${token}/help`, { method: "POST", credentials: "same-origin" });
      const data = await response.json();
      if (response.ok) {
        location.href = data.url;
        return;
      }
      problem = data.error;
    } catch {
      problem = null;
    }
    button.disabled = false;
    button.textContent = problem ? t(problem) : t("Something went wrong. Please try again.");
  });
  return button;
}

function showCooldown(state, seconds) {
  const line = el("p");
  const retry = el("a", { class: "button primary", href: retryUrl(), text: t("Try again") });
  retry.hidden = true;
  let left = Math.ceil(seconds);
  const tick = () => {
    line.textContent = left === 1 ? t("Please wait 1 second before trying again.") : t("Please wait {seconds} seconds before trying again.", { seconds: left });
    if (left-- <= 0) {
      clearInterval(timer);
      line.setAttribute("aria-live", "polite");  // the one thing worth saying aloud after the first line
      line.textContent = t("You can try again now.");
      retry.hidden = false;
    }
  };
  // The card reads changes aloud, so the count goes quiet after its first line, or a screen reader says it every second.
  const timer = setInterval(() => { line.setAttribute("aria-live", "off"); tick(); }, 1000);
  tick();
  render(header(state), el("div", { class: "result-mark wait", text: "…" }), el("h1", { text: t("Please wait") }), line,
    el("div", { class: "verify-actions" }, retry));
}

async function main() {
  await loadLanguage();
  document.title = t("Verify your account") + " | AltWarden";
  const again = new URLSearchParams(location.search).has("again");
  if (again) history.replaceState(null, "", location.pathname);
  // Without a limit, a request a proxy holds open leaves the member on Loading, because the guard stands down once this script runs.
  const response = await fetch(`/api/verify/${token}`, { credentials: "same-origin", signal: AbortSignal.timeout?.(STATE_TIMEOUT) });
  if (response.status >= 500 || response.status === 429) throw new Error("the server had a problem");
  if (!response.ok) {
    showExpired();
    return;
  }
  const state = await response.json();
  if (state.step === "expired") showExpired();
  else if (state.step === "signin") showSignIn(state, again);
  else if (state.step === "check" && state.tried && !again) showTried(state);
  else if (state.step === "check") runCheck(state);
  else showResult(state, { status: "verified" });
}

main().catch(() => {
  render(
    el("h1", { text: t("Please try again") }),
    el("p", { text: t("Something went wrong. Please try again.") }),
    el("div", { class: "verify-actions" }, el("a", { class: "button primary", href: location.pathname, text: t("Reload") })),
  );
});
