// Members: search, history, and every staff action in one place.
import { api, avatarUrl, checkName, confirmDialog, dialog, field, fill, h, number, select, state, toast, when } from "/static/dash/ui.js";

const STATUS = { verified: ["Verified", "good"], pending: ["Waiting", "warn"], approved: ["Approved", "good"] };

function statusPill(row) {
  const [label, kind] = STATUS[row.status] ?? [row.status, ""];
  return h("span", { class: `pill ${kind}`, text: label });
}

// Every result on record, counted, in the same words the logs use.
function results(row) {
  const pills = row.results.slice(0, 4).map((entry) => {
    const name = { passed: "Verified", manual: "Verified by staff", auto_kick: "Auto kicked", honeypot: "Honeypot" }[entry.outcome] ?? checkName(entry.check);
    const good = entry.outcome === "passed" || entry.outcome === "manual";
    return h("span", { class: `pill ${good ? "good" : "bad"}`, text: entry.count > 1 ? `${entry.count} × ${name}` : name });
  });
  return pills.length ? h("div", { class: "chips" }, pills) : h("span", { class: "faint", text: "No attempts yet" });
}

function drawer(guildPath, userId, refresh) {
  const panel = h("aside", { class: "drawer", role: "dialog", "aria-label": "Member" });
  const close = () => panel.remove();
  document.body.append(panel);
  const act = async (action, body, message) => {
    try {
      const result = await api(`${guildPath}/members/${userId}/${action}`, { method: "POST", body: body ?? {} });
      toast(message);
      await draw();
      refresh();
      return result;
    } catch (error) {
      toast(error.message, true);
      return null;
    }
  };
  function bypassDialog(checks) {
    const chosen = new Set();
    let hours = 1;
    let notify = "both";
    if (!checks.length) {
      toast("No checks are on, so there is nothing to skip.", true);
      return;
    }
    const body = h("div", {},
      h("p", { class: "muted", text: "The link belongs to this member. Every check you don't tick still runs, and the link is never posted in a log." }),
      h("div", { class: "chips" }, checks.map((check) => h("label", { class: "chip" }, h("input", { type: "checkbox", onchange: (event) => {
        if (event.target.checked) chosen.add(check.id);
        else chosen.delete(check.id);
      } }), check.name))),
      h("div", { class: "grid two" },
        field("Hours it lasts", number(hours, (value) => { hours = value; }, { min: 1, max: 168 })),
        field("Tell the member", select([{ id: "both", name: "By DM and in the verification channel" }, { id: "dm", name: "By DM" },
          { id: "channel", name: "In the verification channel" }, { id: "none", name: "I'll send it myself" }], notify, (value) => { notify = value; }))));
    dialog("Bypass link", body, { buttons: [{ label: "Cancel" }, { label: "Create link", kind: "primary", onClick: async () => {
      const result = await act("bypass", { skip: [...chosen], hours, notify }, "Link created.");
      if (result) {
        dialog(result.delivered ? "The member was told" : "Send this link yourself", h("div", { class: "grid" },
          h("p", { class: "muted", text: "This is the only time the link is shown." }),
          h("input", { type: "text", readonly: "readonly", value: result.url })), { buttons: [{ label: "Close" }] });
      }
    } }] });
  }
  async function draw() {
    let data;
    try {
      data = await api(`${guildPath}/members/${userId}`);
    } catch (error) {
      fill(panel, h("button", { class: "button small", text: "Close", onclick: close }), h("p", { text: error.message }));
      return;
    }
    const member = data.member;
    fill(panel,
      h("div", { class: "toolbar" }, h("button", { class: "button small", text: "Close", onclick: close })),
      h("div", { class: "who" }, h("img", { src: avatarUrl(userId, member.avatar), alt: "" }),
        h("div", {}, h("strong", { text: member.username || userId }),
          h("small", { text: userId, title: "Copy this ID", onclick: () => navigator.clipboard?.writeText(userId).then(() => toast("Copied.")) }))),
      h("p", {}, statusPill(member), data.banned ? h("span", { class: "pill bad", text: "Banned" }) : null),
      h("div", { class: "toolbar" },
        h("button", { class: "button small", text: "Verify", onclick: () => act("verify", null, "Verified.") }),
        h("button", { class: "button small", text: "Bypass link", onclick: () => bypassDialog(data.bypass_options) }),
        h("button", { class: "button small danger", text: "Reset", onclick: async () => {
          if (await confirmDialog("Reset this member?", "This deletes their records here and removes the verified role, so they verify again.", "Reset", "danger")) act("reset", null, "Reset.");
        } })),
      data.links.length ? h("div", {}, h("h3", { text: "Linked accounts" }), h("ul", { class: "timeline" }, data.links.map((link) => {
        const other = link.main_id === userId ? link.alt_id : link.main_id;
        return h("li", {}, h("span", { text: `${other} (${link.main_id === userId ? "alt" : "main"}): ${link.confidence}, ${link.methods.join(", ")}` }),
          h("button", { class: "button small", text: "Not the same person", onclick: () => act("trust", { other }, "They won't be linked again.") }));
      }))) : null,
      h("h3", { text: "History" }),
      data.attempts.length ? h("ul", { class: "timeline" }, data.attempts.filter((row) => row.outcome !== "started").map((row) => {
        const findings = row.detail.findings ?? [];
        const title = { passed: "Verified", failed: `Stopped: ${checkName(row.check_id)}`, manual: "Verified by staff", auto_kick: "Auto kicked", honeypot: "Posted in the honeypot" }[row.outcome] ?? row.outcome;
        return h("li", {}, h("strong", { text: title }), h("small", { text: `${when(row.at)}${row.action ? `, ${row.action}` : ""}${row.bypassed ? ", bypass link" : ""}` }),
          findings.length ? h("small", { text: `Noted: ${findings.map((finding) => checkName(finding.check)).join(", ")}` }) : null);
      })) : h("p", { class: "faint", text: "No attempts yet." }));
  }
  draw();
}

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  let page = 1;
  let query = "";
  let status = "";
  let size = 20;
  const table = h("div");
  const load = async () => {
    const params = new URLSearchParams({ page: String(page), size: String(size), q: query, status });
    const data = await api(`${guildPath}/members?${params}`);
    const pages = Math.max(1, Math.ceil(data.total / size));
    fill(table,
      h("div", { class: "panel table-wrap" }, h("table", { class: "list" },
        h("thead", {}, h("tr", {}, ["Member", "Status", "Results", "Last activity"].map((text) => h("th", { text })))),
        h("tbody", {}, data.members.map((row) => h("tr", { class: "click", tabindex: "0", onclick: () => drawer(guildPath, row.user_id, load), onkeydown: (event) => { if (event.key === "Enter") drawer(guildPath, row.user_id, load); } },
          h("td", {}, h("div", { class: "who" }, h("img", { src: avatarUrl(row.user_id, row.avatar), alt: "" }), h("div", {}, h("span", { text: row.username || "Unknown" }), h("small", { text: row.user_id })))),
          h("td", {}, statusPill(row)),
          h("td", {}, results(row)),
          h("td", { text: when(row.last_at) })))))),
      data.members.length ? null : h("p", { class: "faint", text: "Nobody matches." }),
      h("div", { class: "pager" }, h("span", { text: `${data.total} members, page ${page} of ${pages}` }),
        h("button", { class: "button small", text: "Previous", disabled: page <= 1, onclick: () => { page--; load(); } }),
        h("button", { class: "button small", text: "Next", disabled: page >= pages, onclick: () => { page++; load(); } })));
  };
  let timer = null;
  view.append(h("div", { class: "toolbar" },
    h("input", { type: "search", placeholder: "Search by name or user ID", "aria-label": "Search members", oninput: (event) => {
      clearTimeout(timer);
      timer = setTimeout(() => { query = event.target.value.trim(); page = 1; load(); }, 250);
    } }),
    select([{ id: "", name: "Everyone" }, { id: "verified", name: "Verified" }, { id: "pending", name: "Waiting" }], "", (value) => { status = value ?? ""; page = 1; load(); }, { label: "Status" }),
    select([10, 20, 30, 50].map((count) => ({ id: String(count), name: `${count} per page` })), "20", (value) => { size = Number(value); page = 1; load(); }, { label: "Page size" })),
  table);
  await load();
}
