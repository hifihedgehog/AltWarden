// Messages and per-server profile, with a live preview of what members will see.
import { draftFor, touched } from "/static/dash/drafts.js";
import { api, clone, field, fill, h, iconUrl, section, segments, select, state, toast, viewOnly } from "/static/dash/ui.js";

const NAMES = { verification: "Verification message", help_desk: "Help desk message", honeypot: "Honeypot warning" };
const STYLES = ["primary", "secondary", "success", "danger"].map((id) => ({ id, name: { primary: "Blue", secondary: "Gray", success: "Green", danger: "Red" }[id] }));
const NAME_CHOICES = ["", "Verification"];
const GUMMY = 8;

function hex(value) {
  return `#${value.toString(16).padStart(6, "0")}`;
}

function pick(list) {
  return list[Math.floor(Math.random() * list.length)];
}

// A name in its font and effect. Gummy moves letter by letter, so each letter gets its own node.
function styledName(text, look) {
  const node = h("strong", { class: `name-style${look.font ? ` font-${look.font}` : ""}${look.effect ? ` effect-${look.effect}` : ""}` });
  look.colors.forEach((color, index) => node.style.setProperty(`--c${index + 1}`, hex(color)));
  if (look.effect !== GUMMY) {
    node.textContent = text;
    return node;
  }
  [...text].forEach((letter, index) => {
    const span = h("span", { text: letter });
    span.style.color = hex(look.colors[index % look.colors.length]);
    span.style.animationDelay = `${index * 80}ms`;
    node.append(span);
  });
  return node;
}

function preview(message, name, light, you) {
  // The verification message falls back to the server's icon, as it does in Discord.
  const thumbnail = message.thumbnail || (name === "verification" && state.guild.icon ? iconUrl(state.guild.id, state.guild.icon) : "");
  const embed = h("div", { class: "embed" }, thumbnail ? h("img", { class: "thumb", src: thumbnail, alt: "" }) : null,
    message.title ? h("strong", { text: message.title }) : null, h("p", { text: message.description.replaceAll("{server}", state.guild.name) }),
    message.image ? h("img", { src: message.image, alt: "" }) : null, message.footer ? h("small", { text: message.footer }) : null,
    you ? h("span", { class: "subtext", text: `Written by ${you} on this server's staff. Report it` }) : null);
  embed.style.borderLeftColor = hex(message.color);
  return h("div", { class: `preview${light ? " light" : ""}` }, message.content ? h("p", { text: message.content }) : null, embed,
    name === "verification" ? h("div", { class: "buttons" },
      h("span", { class: `fake-button ${message.verify_style}`, text: message.verify_label }),
      state.guild.help_desk ? h("span", { class: `fake-button ${message.help_style}`, text: message.help_label }) : null) : null);
}

function profilePreview(look, light) {
  const picture = look.avatar ? `/static/img/avatars/${look.avatar}.png` : "/static/img/logo-128.png";
  const name = look.nickname || "AltWarden";
  return h("div", { class: `profile-preview${light ? " preview-light" : ""}` },
    h("div", { class: "profile-card" }, h("div", { class: "banner" }), h("img", { src: picture, alt: "" }), styledName(name, look),
      h("small", { text: "AltWarden" }), look.bio ? h("p", { text: look.bio }) : null),
    h("div", { class: "preview-side" },
      h("div", { class: "member-row" }, h("img", { src: picture, alt: "" }), styledName(name, look), h("span", { class: "tag", text: "APP" })),
      h("div", { class: "message-row" }, h("img", { src: picture, alt: "" }), h("div", {},
        h("div", { class: "line" }, styledName(name, look), h("span", { class: "tag", text: "APP" }), h("small", { text: "Today at 12:00" })),
        h("p", { text: "Press Verify to get started." })))));
}

export async function render(view) {
  const guildPath = `/api/guilds/${state.guild.id}`;
  const canEdit = state.guild.pages.appearance.edit;
  const { settings } = await api(`${guildPath}/settings`);
  const part = draftFor("appearance", { messages: settings.messages, appearance: settings.appearance }, async (entry) => {
    const result = await api(`${guildPath}/appearance`, { method: "PUT", body: entry.draft });
    entry.saved = { messages: result.messages, appearance: result.appearance };
    entry.draft = clone(entry.saved);
    if (result.problem) toast(result.problem, true);
  });
  let current = NAMES[location.hash.slice(1)] ? location.hash.slice(1) : "verification";
  let light = false;
  let colorSlot = 0;
  const root = h("div");
  view.append(root);
  part.redraw = () => draw();
  part.invalid = () => root.querySelector("input:invalid");

  const customized = (message) => {
    const { author, ...words } = message;
    const { author: none, ...standard } = state.catalog.default_messages[current];
    return JSON.stringify(Object.entries(words).sort()) !== JSON.stringify(Object.entries(standard).sort());
  };

  function text(label, key, { area = false, limit = 256, help } = {}) {
    const message = part.draft.messages[current];
    const control = h(area ? "textarea" : "input", { value: message[key], maxlength: limit, disabled: !canEdit, oninput: (event) => { message[key] = event.target.value; touched(); refresh(); } });
    return field(label, control, help);
  }

  const previewBox = h("div");
  const profileBox = h("div");
  const refresh = () => {
    const message = part.draft.messages[current];
    previewBox.replaceChildren(preview(message, current, light, customized(message) ? state.session.user.name : null));
    profileBox.replaceChildren(profilePreview(part.draft.appearance, light));
  };

  // The same rules the server applies: a style has a font, an effect, and the colors that effect needs.
  function fixStyle(look) {
    if (!look.font && !look.effect) {
      look.font = null;
      look.effect = null;
      look.colors = [];
      return;
    }
    look.font ||= state.catalog.name_fonts[0].id;
    look.effect ||= state.catalog.name_effects[0].id;
    const wanted = state.catalog.name_effects.find((effect) => effect.id === look.effect).colors;
    const palette = Object.values(state.catalog.avatar_hex).filter((color) => !look.colors.includes(color));
    look.colors = [...look.colors, ...palette].slice(0, wanted);
    colorSlot = Math.min(colorSlot, wanted - 1);
  }

  function surprise() {
    const look = part.draft.appearance;
    look.avatar = pick(state.guild.avatar_colors);
    look.nickname = pick(NAME_CHOICES);
    look.font = pick(state.catalog.name_fonts).id;
    look.effect = pick(state.catalog.name_effects).id;
    look.colors = Object.values(state.catalog.avatar_hex).sort(() => Math.random() - 0.5);
    fixStyle(look);
    touched();
    draw();
  }

  function styleControls(look) {
    const change = (key) => (value) => {
      look[key] = value ? Number(value) : null;
      fixStyle(look);
      touched();
      draw();
    };
    return [
      field("Font", select([{ id: "", name: "No style" }, ...state.catalog.name_fonts], look.font ?? "", change("font"), { disabled: !canEdit, label: "Font" })),
      field("Effect", select([{ id: "", name: "No style" }, ...state.catalog.name_effects], look.effect ?? "", change("effect"), { disabled: !canEdit, label: "Effect" })),
      look.effect ? h("div", { class: "field wide" }, h("span", { text: look.colors.length > 1 ? "Colors" : "Color" }),
        h("div", { class: "chips" }, look.colors.map((color, index) => h("input", { type: "color", value: hex(color), disabled: !canEdit, "aria-label": `Color ${index + 1}`,
          onfocus: () => { colorSlot = index; },
          oninput: (event) => { look.colors[index] = Number.parseInt(event.target.value.slice(1), 16); touched(); refresh(); } }))),
        h("div", { class: "chips swatches" }, Object.entries(state.catalog.avatar_hex).map(([name, color]) => {
          const swatch = h("button", { type: "button", class: "swatch", title: `Match the ${name} picture`, "aria-label": `Use ${name}`, disabled: !canEdit, onclick: () => {
            look.colors[colorSlot] = color;
            touched();
            draw();
          } });
          swatch.style.background = hex(color);
          return swatch;
        })),
        h("span", { class: "help", text: "Discord's apps draw name styles a little differently, and a colored role can take over the color. The preview uses a similar font for Medieval and Vampyre." })) : null,
    ];
  }

  function draw() {
    const draft = part.draft;
    const message = draft.messages[current];
    const colorInput = h("input", { type: "color", value: hex(message.color), disabled: !canEdit, oninput: (event) => {
      message.color = Number.parseInt(event.target.value.slice(1), 16);
      touched();
      refresh();
    } });
    refresh();
    fill(root, viewOnly("appearance"),
      section("Profile in this server", "Discord shows these only here. Custom names and name styles need Change Nickname.", h("div", { class: "editor" },
        h("div", { class: "panel grid" },
          h("div", { class: "field wide" }, h("span", { text: "Profile picture" }), h("div", { class: "chips" },
            ["", ...state.guild.avatar_colors].map((color) => h("button", {
              class: `button small${draft.appearance.avatar === color ? " primary" : ""}`, disabled: !canEdit, title: color || "Default",
              onclick: () => { draft.appearance.avatar = color; touched(); draw(); },
            }, color ? h("img", { src: `/static/img/avatars/${color}.png`, alt: color, width: 22, height: 22 }) : "Default")))),
          field("Name", h("input", { value: draft.appearance.nickname, maxlength: 32, minlength: 2, placeholder: "AltWarden", disabled: !canEdit, oninput: (event) => { draft.appearance.nickname = event.target.value; touched(); refresh(); } }), "Leave empty for AltWarden. 2 to 32 characters."),
          h("div", { class: "toolbar" }, NAME_CHOICES.map((choice) => h("button", { class: "button small", text: choice || "AltWarden", disabled: !canEdit, onclick: () => { draft.appearance.nickname = choice; touched(); draw(); } })),
            h("button", { class: "button small", text: "Surprise me", disabled: !canEdit, onclick: surprise })),
          styleControls(draft.appearance),
          field("Bio", h("input", { value: draft.appearance.bio, maxlength: 190, disabled: !canEdit, oninput: (event) => { draft.appearance.bio = event.target.value; touched(); refresh(); } }))),
        h("div", {}, h("div", { class: "preview-tools" }, h("span", { class: "muted", text: "As members see it" }),
          segments([{ id: "dark", label: "Dark" }, { id: "light", label: "Light" }], light ? "light" : "dark", (value) => { light = value === "light"; refresh(); }, { label: "Preview theme" })), profileBox))),
      section("Messages", "Use {server} for your server's name. A changed message names who wrote it, so nobody can pass off a scam as AltWarden's own words.",
        h("div", { class: "toolbar" }, segments(Object.entries(NAMES).map(([id, label]) => ({ id, label })), current, (value) => { current = value; draw(); }, { label: "Message" })),
        h("div", { class: "editor" },
          h("div", { class: "panel grid" },
            text("Text above the embed", "content", { area: true, limit: 2000, help: "This shows even for members who turned embeds off." }),
            text("Title", "title"),
            text("Description", "description", { area: true, limit: 4000 }),
            field("Color", colorInput),
            text("Thumbnail link", "thumbnail", { limit: 2000, help: "An https link." }),
            text("Image link", "image", { limit: 2000, help: "An https link." }),
            text("Footer", "footer", { limit: 2048 }),
            current === "verification" ? [text("Verify button text", "verify_label", { limit: 80 }),
              field("Verify button color", select(STYLES, message.verify_style, (value) => { message.verify_style = value; touched(); refresh(); }, { disabled: !canEdit })),
              text("Verify button emoji", "verify_emoji", { limit: 64, help: "A standard emoji, or a custom one as <:name:id>." }),
              text("Help button text", "help_label", { limit: 80 }),
              field("Help button color", select(STYLES, message.help_style, (value) => { message.help_style = value; touched(); refresh(); }, { disabled: !canEdit })),
              text("Help button emoji", "help_emoji", { limit: 64 })] : null,
            h("button", { class: "button small", text: "Restore defaults", disabled: !canEdit, onclick: () => {
              draft.messages[current] = clone(state.catalog.default_messages[current]);
              touched();
              draw();
            } })),
          h("div", {}, previewBox, current !== "help_desk" ? h("div", { class: "toolbar" }, h("button", { class: "button small", text: "Post it again", disabled: !canEdit, onclick: async () => {
            try {
              await api(`${guildPath}/post-message`, { method: "POST", body: { message: current } });
              toast("Posted.");
            } catch (error) {
              toast(error.message, true);
            }
          } })) : null))));
  }
  draw();
}
