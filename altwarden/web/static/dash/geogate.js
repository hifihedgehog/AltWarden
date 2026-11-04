// Country rules: pick on a flat map, a globe, or a list, with an action per continent, region or country.
import { clone, dialog, h, segments, state, svg } from "/static/dash/ui.js";

const ACTIONS = ["", "watch", "deny", "kick", "ban"];
const LABELS = { "": "Default", watch: "Watch", deny: "Deny", kick: "Kick", ban: "Ban" };
let cache = null;

async function loadData() {
  if (!cache) {
    const [countries, world] = await Promise.all([
      fetch("/static/countries.json").then((response) => response.json()),
      fetch("/static/world.json").then((response) => response.json()),
    ]);
    cache = { countries, world };
  }
  return cache;
}

function flatPath(ring) {
  return `M${ring.map(([lon, lat]) => `${((lon + 180) * 2.5).toFixed(1)} ${((90 - lat) * 2.5).toFixed(1)}`).join("L")}Z`;
}

const RADIUS = 200;

function toVector([lon, lat], rotation) {
  const lambda = (lon + rotation.lon) * Math.PI / 180;
  const phi = lat * Math.PI / 180;
  const tilt = rotation.lat * Math.PI / 180;
  const x = Math.cos(phi) * Math.sin(lambda);
  const y = Math.sin(phi);
  const z = Math.cos(phi) * Math.cos(lambda);
  return [x, y * Math.cos(tilt) - z * Math.sin(tilt), y * Math.sin(tilt) + z * Math.cos(tilt)];
}

function limbPoint(a, b) {
  const t = a[2] / (a[2] - b[2]);
  const x = a[0] + (b[0] - a[0]) * t;
  const y = a[1] + (b[1] - a[1]) * t;
  const length = Math.hypot(x, y) || 1;
  return [x / length, y / length, 0];
}

// Clips a ring to the near side of the globe. Pieces that leave and re-enter follow the limb.
function globePath(ring, rotation) {
  const vectors = ring.map((point) => toVector(point, rotation));
  const output = [];
  for (let index = 0; index < vectors.length; index++) {
    const current = vectors[index];
    const next = vectors[(index + 1) % vectors.length];
    if (current[2] >= 0) output.push(current);
    if ((current[2] >= 0) !== (next[2] >= 0)) output.push(limbPoint(current, next));
  }
  if (output.length < 3) return "";
  const parts = [];
  output.forEach((vector, index) => {
    const previous = output[index - 1];
    if (previous && previous[2] === 0 && vector[2] === 0) {
      const start = Math.atan2(previous[1], previous[0]);
      let sweep = Math.atan2(vector[1], vector[0]) - start;
      if (sweep > Math.PI) sweep -= 2 * Math.PI;
      if (sweep < -Math.PI) sweep += 2 * Math.PI;
      for (let step = 1; step < 8; step++) {
        const angle = start + sweep * step / 8;
        parts.push([Math.cos(angle), Math.sin(angle)]);
      }
    }
    parts.push(vector);
  });
  return `M${parts.map(([x, y]) => `${(RADIUS + 10 + x * RADIUS).toFixed(1)} ${(RADIUS + 10 - y * RADIUS).toFixed(1)}`).join("L")}Z`;
}

export async function openCountryPicker(check, onDone) {
  const { countries, world } = await loadData();
  const draft = clone({ list: check.list, countries: check.countries, overrides: check.overrides, action: check.action });
  const picked = new Set(draft.countries);
  const byNumber = Object.fromEntries(countries.map((country) => [country.num, country]));
  let shape = "flat";
  const rotation = { lon: -10, lat: -20 };
  const mapBox = h("div", { class: "map-wrap" });
  const treeBox = h("div", { class: "tree" });
  const count = h("p", { class: "muted" });

  const actionOf = (country) => draft.overrides[country.code] || draft.overrides[`region:${country.region}`] || draft.overrides[`continent:${country.continent}`] || draft.action;

  function toggleCountry(code) {
    if (picked.has(code)) picked.delete(code);
    else picked.add(code);
    drawMap();
    drawTree();
  }

  function landClass(country) {
    if (!country || !picked.has(country.code)) return "land";
    const action = actionOf(country);
    return `land picked ${action === "deny" ? "" : action}`;
  }

  let shapes = [];
  function drawMap() {
    count.textContent = `${picked.size} countries picked.`;
    const flat = shape === "flat";
    shapes = [];
    const canvas = flat
      ? svg("svg", { viewBox: "0 0 900 450", role: "img", "aria-label": "World map" })
      : svg("svg", { viewBox: `0 0 ${RADIUS * 2 + 20} ${RADIUS * 2 + 20}`, role: "img", "aria-label": "Globe. Drag to turn it." },
        svg("circle", { cx: RADIUS + 10, cy: RADIUS + 10, r: RADIUS, fill: "var(--bg-hover)" }));
    for (const [number, rings] of Object.entries(world)) {
      const country = byNumber[number];
      const path = rings.map((ring) => (flat ? flatPath(ring) : globePath(ring, rotation))).join("");
      const node = svg("path", { d: path, class: landClass(country), "fill-rule": "evenodd" }, svg("title", {}, country?.name ?? ""));
      if (country) node.addEventListener("click", () => { if (!dragged) toggleCountry(country.code); });
      shapes.push([node, rings]);
      canvas.append(node);
    }
    if (!flat) attachDrag(canvas);
    mapBox.replaceChildren(canvas);
  }

  let dragged = false;
  let frame = 0;
  function turnGlobe() {
    frame = 0;
    for (const [node, rings] of shapes) node.setAttribute("d", rings.map((ring) => globePath(ring, rotation)).join(""));
  }
  function attachDrag(canvas) {
    let start = null;
    canvas.addEventListener("pointerdown", (event) => { start = [event.clientX, event.clientY, rotation.lon, rotation.lat]; dragged = false; });
    canvas.addEventListener("pointermove", (event) => {
      if (!start) return;
      const dx = event.clientX - start[0], dy = event.clientY - start[1];
      if (!dragged && Math.abs(dx) + Math.abs(dy) <= 4) return;
      // Capture only once this is a drag. A captured pointer sends its click to the globe, not the country.
      if (!dragged) canvas.setPointerCapture(event.pointerId);
      dragged = true;
      rotation.lon = start[2] + dx * 0.4;
      rotation.lat = Math.max(-80, Math.min(80, start[3] + dy * 0.4));
      frame ||= requestAnimationFrame(turnGlobe);
    });
    for (const name of ["pointerup", "pointercancel"]) canvas.addEventListener(name, () => { start = null; });
  }

  function overridePicker(key) {
    return h("select", { "aria-label": "Action", onclick: (event) => event.stopPropagation(), onchange: (event) => {
      if (event.target.value) draft.overrides[key] = event.target.value;
      else delete draft.overrides[key];
      drawMap();
    } }, ACTIONS.map((action) => h("option", { value: action, text: LABELS[action], selected: (draft.overrides[key] ?? "") === action })));
  }

  function groupCheckbox(items) {
    const all = items.every((country) => picked.has(country.code));
    const some = items.some((country) => picked.has(country.code));
    const box = h("input", { type: "checkbox", checked: all, onclick: (event) => {
      event.stopPropagation();
      for (const country of items) {
        if (event.target.checked) picked.add(country.code);
        else picked.delete(country.code);
      }
      drawMap();
      drawTree();
    } });
    box.indeterminate = some && !all;
    return box;
  }

  let filter = "";
  function drawTree() {
    const wanted = countries.filter((country) => country.name.toLowerCase().includes(filter));
    const continents = [...new Set(wanted.map((country) => country.continent))].sort();
    treeBox.replaceChildren(...continents.map((continent) => {
      const inContinent = wanted.filter((country) => country.continent === continent);
      const regions = [...new Set(inContinent.map((country) => country.region))].sort();
      return h("details", { open: Boolean(filter) },
        h("summary", {}, groupCheckbox(inContinent), h("span", { text: continent }), overridePicker(`continent:${continent}`)),
        h("div", { class: "inner" }, regions.map((region) => {
          const inRegion = inContinent.filter((country) => country.region === region);
          return h("details", { open: Boolean(filter) },
            h("summary", {}, groupCheckbox(inRegion), h("span", { text: region }), overridePicker(`region:${region}`)),
            h("div", { class: "inner" }, inRegion.map((country) => h("label", { class: "country" },
              h("input", { type: "checkbox", checked: picked.has(country.code), onchange: () => toggleCountry(country.code) }),
              h("span", { text: country.name }), overridePicker(country.code)))));
        })));
    }));
  }

  const body = h("div", {},
    h("div", { class: "toolbar" },
      segments([{ id: "block", label: "Block these" }, { id: "allow", label: "Allow only these" }], draft.list, (value) => { draft.list = value; }, { label: "List type" }),
      segments([{ id: "flat", label: "Map" }, { id: "globe", label: "Globe" }], shape, (value) => { shape = value; drawMap(); }, { label: "View" })),
    h("div", { class: "toolbar" }, h("span", { class: "muted", text: "Default action" }),
      segments(state.catalog.actions, draft.action, (value) => { draft.action = value; drawMap(); }, { label: "Default action" })),
    mapBox, count,
    h("input", { type: "search", placeholder: "Search countries", "aria-label": "Search countries", oninput: (event) => { filter = event.target.value.toLowerCase(); drawTree(); } }),
    treeBox,
    h("p", { class: "faint", text: "The most specific action wins: a country's own, then its region's, then its continent's. Logs never show a member's country." }));
  drawMap();
  drawTree();
  dialog("Country rules", body, { wide: true, buttons: [
    { label: "Cancel" },
    { label: "Done", kind: "primary", onClick: () => onDone({ list: draft.list, countries: [...picked].sort(), overrides: draft.overrides, action: draft.action }) },
  ] });
}
