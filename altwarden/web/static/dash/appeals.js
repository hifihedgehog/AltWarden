// Appeals queue. The same decisions are available as buttons in Discord.
import { api, avatarUrl, checkName, fill, h, lookup, section, select, state, toast, viewOnly, when } from "/static/dash/ui.js";

const STATUS_WORDS = { open: "Waiting", approved: "Approved", denied: "Turned down" };
const PAGE_LIMIT = 100;  // the server sends this many of the newest for each status

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  const list = h("div", { class: "grid" });
  let status = "open";
  let asked = 0;  // only the newest filter may draw, because an older one can answer last
  const canEdit = state.guild.pages.appeals.edit;
  const decide = async (id, decision, note) => {
    try {
      const result = await api(`${guildPath}/appeals/${id}`, { method: "POST", body: { decision, note } });
      toast(result.told === true ? "Decided. The member has been told." : result.told === false ? "Decided, but the member couldn't be told." : "Decided.");
      await load();
    } catch (error) {
      toast(error.message, true);
    }
  };
  const load = async () => {
    const turn = ++asked;
    const data = await api(`${guildPath}/appeals?status=${status}`);
    if (turn !== asked) return;
    fill(list, data.appeals.length >= PAGE_LIMIT ? h("p", { class: "faint", text: `Showing the newest ${PAGE_LIMIT}.` }) : null, (data.appeals.length ? data.appeals.map((appeal) => {
      const note = h("input", { type: "text", placeholder: "Note to the member (optional)", maxlength: 500 });
      return h("div", { class: "panel" },
        h("div", { class: "who" }, h("img", { src: avatarUrl(appeal.user_id, appeal.avatar), alt: "" }),
          h("div", {}, h("strong", { text: appeal.username || appeal.user_id }), h("small", { text: `${when(appeal.created_at)}, stopped by ${checkName(appeal.check_id)}` }))),
        h("p", { text: appeal.text }),
        appeal.status === "open" && canEdit ? h("div", {}, appeal.check_id === "alt_account" ? h("p", { class: "faint", text: "Approve lets them in now, and the link still stands if they rejoin. Approve and trust the link is for two different people." }) : null, note, h("div", { class: "toolbar" },
          h("button", { class: "button small primary", text: "Approve", onclick: () => decide(appeal.id, "approve", note.value) }),
          h("button", { class: "button small", text: "Approve and trust the link", title: "Also stops these accounts matching again", onclick: () => decide(appeal.id, "trust", note.value) }),
          h("button", { class: "button small danger", text: "Turn down", onclick: () => decide(appeal.id, "deny", note.value) })))
          : h("div", {},
            h("p", { class: "faint", text: `${lookup(STATUS_WORDS, appeal.status, appeal.status)}${appeal.decided_at ? ` ${when(appeal.decided_at)}` : ""}${appeal.decided_by ? `, by ${appeal.decided_by}` : ""}` }),
            appeal.note ? h("p", { class: "faint", text: `Note to the member: ${appeal.note}` }) : null));
    }) : [h("p", { class: "faint", text: "Nothing here." })]));
  };
  view.append(section("Appeals", "Members who were stopped can explain themselves here.", viewOnly("appeals"),
    h("div", { class: "toolbar" }, select([{ id: "open", name: "Waiting" }, { id: "approved", name: "Approved" }, { id: "denied", name: "Turned down" }], status, (value) => { status = value; load(); }, { label: "Status" })),
    list));
  await load();
}
