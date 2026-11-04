// Appeals queue. The same decisions are available as buttons in Discord.
import { api, avatarUrl, checkName, fill, h, section, select, state, toast, viewOnly, when } from "/static/dash/ui.js";

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  const list = h("div", { class: "grid" });
  let status = "open";
  const canEdit = state.guild.pages.appeals.edit;
  const decide = async (id, decision, note) => {
    try {
      await api(`${guildPath}/appeals/${id}`, { method: "POST", body: { decision, note } });
      toast("Decided. The member has been told.");
      await load();
    } catch (error) {
      toast(error.message, true);
    }
  };
  const load = async () => {
    const data = await api(`${guildPath}/appeals?status=${status}`);
    fill(list, (data.appeals.length ? data.appeals.map((appeal) => {
      const note = h("input", { type: "text", placeholder: "Note to the member (optional)", maxlength: 500 });
      return h("div", { class: "panel" },
        h("div", { class: "who" }, h("img", { src: avatarUrl(appeal.user_id, appeal.avatar), alt: "" }),
          h("div", {}, h("strong", { text: appeal.username || appeal.user_id }), h("small", { text: `${when(appeal.created_at)}, stopped by ${checkName(appeal.check_id)}` }))),
        h("p", { text: appeal.text }),
        appeal.status === "open" && canEdit ? h("div", {}, note, h("div", { class: "toolbar" },
          h("button", { class: "button small primary", text: "Approve", onclick: () => decide(appeal.id, "approve", note.value) }),
          h("button", { class: "button small", text: "Approve and trust the link", title: "Also stops these accounts matching again", onclick: () => decide(appeal.id, "trust", note.value) }),
          h("button", { class: "button small danger", text: "Turn down", onclick: () => decide(appeal.id, "deny", note.value) })))
          : h("p", { class: "faint", text: `${appeal.status} ${appeal.decided_at ? when(appeal.decided_at) : ""}` }));
    }) : [h("p", { class: "faint", text: "Nothing here." })]));
  };
  view.append(section("Appeals", "Members who were stopped can explain themselves here.", viewOnly("appeals"),
    h("div", { class: "toolbar" }, select([{ id: "open", name: "Waiting" }, { id: "approved", name: "Approved" }, { id: "denied", name: "Turned down" }], status, (value) => { status = value; load(); }, { label: "Status" })),
    list));
  await load();
}
