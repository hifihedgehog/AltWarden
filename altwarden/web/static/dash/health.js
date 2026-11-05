// Health: what would stop verification, how to fix it, and which permissions are really needed.
import { api, fill, h, lookup, plural, report, section, state, when } from "/static/dash/ui.js";

function listLine(list) {
  if (list.age_days === null || list.age_days === undefined) return `${list.name}: not downloaded yet`;
  const age = list.age_days === 0 ? "updated today" : `${plural(list.age_days, "day")} old`;
  return `${list.name}: ${list.rows.toLocaleString("en-US")} ${list.rows === 1 ? "row" : "rows"}, ${age}`;
}

export async function render(view) {
  const body = h("div");
  const load = async () => {
    const data = await api(`/api/guilds/${state.guild.id}/health`);
    const groups = new Map();
    for (const item of data.ok) groups.set(item.area, [...(groups.get(item.area) ?? []), item]);
    fill(body,
      h("div", { class: `notice ${data.healthy ? "" : "bad"}`, text: data.healthy ? "Everything AltWarden needs is in place." : `${plural(data.issues.length, "thing")} ${data.issues.length === 1 ? "needs" : "need"} fixing.` }),
      data.public_bot ? h("div", { class: "notice bad", text: "Public Bot is on in the Discord Developer Portal, so anyone can add this bot to their server. Turn it off there." }) : null,
      data.lookup_without_key ? h("div", { class: "notice", text: "Outside VPN lookup has no key, so proxycheck.io allows it 100 lookups a day. Save a free key on the Rules page to raise that to 1,000." }) : null,
      (data.notices ?? []).map((notice) => h("div", { class: "notice warn" }, h("strong", { text: notice.title }), ` ${notice.fix}`)),
      data.issues.length ? section("To fix", null, h("div", { class: "rule-list" }, data.issues.map((issue) => h("div", { class: "rule" },
        h("div", { class: "rule-head" }, h("div", { class: "rule-title" }, h("strong", { text: issue.title }), h("span", { text: issue.fix }))))))) : null,
      section("Permissions these settings need", data.has_administrator ? "AltWarden has Administrator, which covers these. Without it, it needs these server-wide." : "AltWarden needs these server-wide.", h("div", { class: "rule-list" },
        Object.entries(data.needs).map(([name, features]) => h("div", { class: "rule" }, h("div", { class: "rule-head" },
          h("div", { class: "rule-title" }, h("strong", { text: lookup(state.catalog.permission_labels, name, name) }), h("span", { text: features.join(", ") }))))))),
      [...groups].filter(([area]) => area !== "permissions").map(([area, items]) => section(area[0].toUpperCase() + area.slice(1).replace("_", " "), null,
        h("div", { class: "chips" }, items.map((item) => h("span", { class: "chip", text: `${item.label}: ${item.value}` }))))),
      data.lists?.length ? section("Network lists", null, h("div", { class: "chips" }, data.lists.map((list) => h("span", { class: "chip", text: listLine(list) })))) : null,
      h("p", { class: "faint", text: `Checked ${when(data.checked_at)}.` }));
  };
  // Discord data is cached for 30 seconds, so a faster check would only repeat the same answer.
  const again = h("button", { class: "button small", text: "Check again", onclick: async () => {
    again.disabled = true;
    const timer = setTimeout(() => { again.disabled = false; }, 30000);
    try {
      await load();
    } catch (error) {
      clearTimeout(timer);  // nothing was checked, so there's no reason to wait
      again.disabled = false;
      report(error);
    }
  } });
  view.append(h("div", { class: "toolbar" }, again), body);
  await load();
}
