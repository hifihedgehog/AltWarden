// Health: what would stop verification, how to fix it, and which permissions are really needed.
import { api, fill, h, section, state, when } from "/static/dash/ui.js";

export async function render(view) {
  const body = h("div");
  const load = async () => {
    const data = await api(`/api/guilds/${state.guild.id}/health`);
    const groups = {};
    for (const item of data.ok) (groups[item.area] ??= []).push(item);
    fill(body,
      h("div", { class: `notice ${data.healthy ? "" : "bad"}`, text: data.healthy ? "Everything AltWarden needs is in place." : `${data.issues.length} things need fixing.` }),
      data.public_bot ? h("div", { class: "notice bad", text: "Public Bot is on in the Discord Developer Portal, so anyone can add this bot to their server. Turn it off there." }) : null,
      data.vpn_lookup_idle ? h("div", { class: "notice warn", text: "Outside VPN lookup is on, but this copy of AltWarden has no proxycheck.io key, so it isn't running." }) : null,
      data.lists_loaded ? null : h("div", { class: "notice warn", text: "The network lists haven't loaded yet, so VPN and country checks can't run." }),
      data.lists_loaded && data.lists_missing.length ? h("div", { class: "notice warn", text: `${data.lists_missing.length} network lists haven't downloaded yet, so VPN and country checks may miss some connections. AltWarden tries again every hour.` }) : null,
      data.issues.length ? section("To fix", null, h("div", { class: "rule-list" }, data.issues.map((issue) => h("div", { class: "rule" },
        h("div", { class: "rule-head" }, h("div", { class: "rule-title" }, h("strong", { text: issue.title }), h("span", { text: issue.fix }))))))) : null,
      section("Permissions these settings need", data.has_administrator ? "AltWarden has Administrator, which covers these. Without it, it needs these server-wide." : "AltWarden needs these server-wide.", h("div", { class: "rule-list" },
        Object.entries(data.needs).map(([name, features]) => h("div", { class: "rule" }, h("div", { class: "rule-head" },
          h("div", { class: "rule-title" }, h("strong", { text: state.catalog.permission_labels[name] ?? name }), h("span", { text: features.join(", ") }))))))),
      Object.entries(groups).filter(([area]) => area !== "permissions").map(([area, items]) => section(area[0].toUpperCase() + area.slice(1).replace("_", " "), null,
        h("div", { class: "chips" }, items.map((item) => h("span", { class: "chip", text: `${item.label}: ${item.value}` }))))),
      h("p", { class: "faint", text: `Checked ${when(data.checked_at)}.` }));
  };
  // Discord data is cached for 30 seconds, so a faster check would only repeat the same answer.
  const again = h("button", { class: "button small", text: "Check again", onclick: async () => {
    again.disabled = true;
    setTimeout(() => { again.disabled = false; }, 30000);
    await load();
  } });
  view.append(h("div", { class: "toolbar" }, again), body);
  await load();
}
