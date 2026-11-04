// First-run screen: two choices, then the Standard rules apply.
import { api, channelPicker, field, h, rolePicker, section, state, toast } from "/static/dash/ui.js";

export function render(view, done) {
  const choice = { verified_role: null, channel: null };
  const start = h("button", { class: "button primary", text: "Finish setup", onclick: async () => {
    try {
      await api(`/api/guilds/${state.guild.id}/setup`, { method: "POST", body: choice });
      toast("Verification is on.");
      done();
    } catch (error) {
      toast(error.message, true);
    }
  } });
  view.append(section("Two choices to start", "New members verify in the channel you pick and get the role you pick. You can tune everything afterwards.",
    h("div", { class: "panel grid two" },
      field("Verified role", rolePicker(null, (value) => { choice.verified_role = value; }), "Members get this after they pass. AltWarden's role must sit above it."),
      field("Verification channel", channelPicker(null, (value) => { choice.channel = value; }), "New members start here."))),
  h("div", { class: "notice", text: "Your server starts on the Standard rules. Checks that could catch honest members only watch until you say otherwise." }),
  start);
}
