// Signed webhooks and read-only API keys, so other bots can use verification results.
import { api, confirmDialog, copyText, dialog, fill, h, pressed, section, state, toast, viewOnly, when } from "/static/dash/ui.js";

// A delivery that got no answer is stored as status 0, and it mustn't read like one that worked.
function deliveryLine(hook) {
  if (!hook.last_sent_at) return "Last sent Never";
  const sent = when(hook.last_sent_at);
  if (!hook.last_status) return `Failed ${sent}, no answer`;
  return hook.last_status >= 200 && hook.last_status < 300 ? `Last sent ${sent}, status ${hook.last_status}` : `Failed ${sent}, status ${hook.last_status}`;
}

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  const body = h("div");
  let asked = 0;  // only the newest list may draw, because an older one can answer last
  // Shown once, so a stray click or Escape can't lose it.
  const showSecret = (title, value, note) => {
    const box = h("input", { type: "text", readonly: "readonly", value, "aria-label": title });
    dialog(title, h("div", {}, h("p", { class: "muted", text: note }), box), { sticky: true, buttons: [
      { label: "Copy", onClick: async () => { await copyText(value, box); return false; } },
      { label: "I saved it" }] });
  };

  const load = async () => {
    const turn = ++asked;
    const data = await api(`${guildPath}/integrations`);
    if (turn !== asked) return;
    const canEdit = data.can_edit ?? state.guild.pages.integrations.edit;
    const urlBox = h("input", { type: "url", placeholder: "https://example.com/altwarden", "aria-label": "Webhook address" });
    const labelBox = h("input", { type: "text", placeholder: "What this key is for", "aria-label": "What this key is for", maxlength: 40 });
    const example = `curl -H "Authorization: Bearer YOUR_KEY" ${location.origin}/api/v1/guilds/${state.guild.id}/members/USER_ID`;
    fill(body, viewOnly("integrations"),
      section("Webhooks", "AltWarden posts events to these addresses. Each request is signed, so your receiver can trust it.",
        data.webhooks.length ? h("div", { class: "rule-list" }, data.webhooks.map((hook) => h("div", { class: "rule" }, h("div", { class: "rule-head" },
          h("div", { class: "rule-title" }, h("strong", { text: hook.url }), h("span", { text: deliveryLine(hook) })),
          h("button", { class: "button small danger", text: "Remove", disabled: !canEdit, onclick: pressed(async () => {
            if (await confirmDialog("Remove this webhook?", hook.url, "Remove", "danger")) {
              await api(`${guildPath}/webhooks/${hook.id}`, { method: "DELETE" });
              await load();
            }
          }) }))))) : null,
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
          h("button", { class: "button small danger", text: "Revoke", disabled: !canEdit, onclick: pressed(async () => {
            if (await confirmDialog("Revoke this key?", `Anything using "${key.label}" stops working right away.`, "Revoke", "danger")) {
              await api(`${guildPath}/keys/${key.id}`, { method: "DELETE" });
              await load();
            }
          }) }))))) : null,
        canEdit ? h("div", { class: "toolbar" }, labelBox, h("button", { class: "button small primary", text: "Create key", onclick: pressed(async () => {
          const result = await api(`${guildPath}/keys`, { method: "POST", body: { label: labelBox.value || "Key" } });
          showSecret("API key", result.key, "Shown once, because only a hash of it is stored.");
          await load();
        }) })) : null,
        h("pre", {}, h("code", { text: example }))));
  };
  view.append(body);
  await load();
}
