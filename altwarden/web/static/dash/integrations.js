// Signed webhooks and read-only API keys, so other bots can use verification results.
import { api, confirmDialog, dialog, fill, h, section, state, toast, viewOnly, when } from "/static/dash/ui.js";

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  const canEdit = state.guild.pages.integrations.edit;
  const body = h("div");
  const showSecret = (title, value, note) => dialog(title, h("div", {}, h("p", { class: "muted", text: note }), h("input", { type: "text", readonly: "readonly", value })), { buttons: [{ label: "I saved it" }] });

  const load = async () => {
    const data = await api(`${guildPath}/integrations`);
    const urlBox = h("input", { type: "url", placeholder: "https://example.com/altwarden" });
    const labelBox = h("input", { type: "text", placeholder: "What this key is for", maxlength: 40 });
    const example = `curl -H "Authorization: Bearer YOUR_KEY" ${location.origin}/api/v1/guilds/${state.guild.id}/members/USER_ID`;
    fill(body, viewOnly("integrations"),
      section("Webhooks", "AltWarden posts events to these addresses. Each request is signed, so your receiver can trust it.",
        data.webhooks.length ? h("div", { class: "rule-list" }, data.webhooks.map((hook) => h("div", { class: "rule" }, h("div", { class: "rule-head" },
          h("div", { class: "rule-title" }, h("strong", { text: hook.url }), h("span", { text: `Last sent ${when(hook.last_sent_at)}${hook.last_status ? `, status ${hook.last_status}` : ""}` })),
          h("button", { class: "button small danger", text: "Remove", disabled: !canEdit, onclick: async () => {
            if (await confirmDialog("Remove this webhook?", hook.url, "Remove", "danger")) { await api(`${guildPath}/webhooks/${hook.id}`, { method: "DELETE" }); load(); }
          } }))))) : null,
        canEdit ? h("div", { class: "toolbar" }, urlBox, h("button", { class: "button small primary", text: "Add webhook", onclick: async () => {
          try {
            const result = await api(`${guildPath}/webhooks`, { method: "POST", body: { url: urlBox.value } });
            showSecret("Signing secret", result.secret, "Shown once. The X-AltWarden-Signature header is t=time,v1=HMAC-SHA256 of time.body with this secret.");
            load();
          } catch (error) {
            toast(error.message, true);
          }
        } })) : null,
        h("p", { class: "faint", text: `Events: ${data.events.join(", ")}.` })),
      section("API keys", "A key can only ask whether a member of this server is verified.",
        data.api_keys.length ? h("div", { class: "rule-list" }, data.api_keys.map((key) => h("div", { class: "rule" }, h("div", { class: "rule-head" },
          h("div", { class: "rule-title" }, h("strong", { text: key.label }), h("span", { text: `Last used ${when(key.last_used_at)}` })),
          h("button", { class: "button small danger", text: "Revoke", disabled: !canEdit, onclick: async () => { await api(`${guildPath}/keys/${key.id}`, { method: "DELETE" }); load(); } }))))) : null,
        canEdit ? h("div", { class: "toolbar" }, labelBox, h("button", { class: "button small primary", text: "Create key", onclick: async () => {
          const result = await api(`${guildPath}/keys`, { method: "POST", body: { label: labelBox.value || "Key" } });
          showSecret("API key", result.key, "Shown once, because only a hash of it is stored.");
          load();
        } })) : null,
        h("pre", {}, h("code", { text: example }))));
  };
  view.append(body);
  await load();
}
