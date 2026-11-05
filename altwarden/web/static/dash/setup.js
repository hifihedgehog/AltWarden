// First-run screen: two choices, then the Standard rules apply.
import { api, channelPicker, field, h, rolePicker, section, state, toast } from "/static/dash/ui.js";

export function render(view, done) {
  // Only someone who can run /setup gets the server's roles and channels to pick from.
  if (!state.guild.can_setup) {
    view.append(h("div", { class: "notice", text: "AltWarden isn't set up on this server yet. Someone who can run /setup has to finish that first." }));
    return;
  }
  const choice = { verified_role: null, channel: null };
  const start = h("button", { class: "button primary", text: "Finish setup", onclick: async () => {
    try {
      const result = await api(`/api/guilds/${state.guild.id}/setup`, { method: "POST", body: choice });
      toast(result.problem ?? "Verification is on.", Boolean(result.problem));
      done();
    } catch (error) {
      toast(error.message, true);
    }
  } });
  view.append(section("Two choices to start", "New members verify in the channel you pick and get the role you pick. You can tune everything afterward.",
    h("div", { class: "panel grid two" },
      field("Verified role", rolePicker(null, (value) => { choice.verified_role = value; }, { given: true }), "Members get this after they pass. AltWarden's role must sit above it."),
      field("Verification channel", channelPicker(null, (value) => { choice.channel = value; }), "New members start here."))),
  h("div", { class: "notice", text: "Your server starts on the Standard rules, which stop anyone who fails a check." }),
  h("div", { class: "notice", text: "Switching from another bot? After this, press Import members on the Members page." }),
  start);
}
