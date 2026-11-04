// Overview page. Two fixed series, verified and stopped, use the first two validated palette slots.
import { api, checkName, fill, h, section, select, state, svg } from "/static/dash/ui.js";

const DAY = 86400;
const RANGES = [{ id: "month", name: "This month" }, { id: "7", name: "Last 7 days" }, { id: "30", name: "Last 30 days" }, { id: "90", name: "Last 90 days" }, { id: "365", name: "Last 12 months" }, { id: "custom", name: "Pick dates" }];
const COMPARE = [{ id: "", name: "No comparison" }, { id: "period", name: "Compare with the previous period" }, { id: "month", name: "Compare with the previous month" }];
const CHART_MODES = [{ id: "area", name: "Area" }, { id: "bars", name: "Bars" }, { id: "rate", name: "Pass rate" }];
const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const OUTCOME_NAMES = { web: "Web page", button: "Button", instant: "Instant", staff: "By staff", deny: "Denied", kick: "Kicked", ban: "Banned", auto_kick: "Auto kicked" };

function delta(now, before) {
  if (before === undefined || before === null || now === null) return null;
  const change = now - before;
  if (change === 0) return "No change";
  return `${change > 0 ? "+" : ""}${Number.isInteger(change) ? change : change.toFixed(1)} vs previous`;
}

function kpi(label, value, compare) {
  return h("div", { class: "panel kpi" }, h("div", { class: "label", text: label }), h("div", { class: "value", text: value }),
    compare ? h("div", { class: "delta", text: compare }) : null);
}

function formatSeconds(value) {
  if (value === null || value === undefined) return "No data";
  return value < 60 ? `${Math.round(value)}s` : `${Math.round(value / 60)}m`;
}

function dailyChart(days, mode, hidden) {
  const width = 900, height = 240, left = 34, right = 10, top = 10, bottom = 24;
  const stopped = days.map((day) => Object.entries(day.checks).reduce((sum, [id, count]) => sum + (hidden.has(id) ? 0 : count), 0));
  const rate = days.map((day, index) => {
    const total = day.verified + stopped[index];
    return total ? day.verified / total * 100 : null;
  });
  const peak = mode === "rate" ? 100 : Math.max(1, ...days.map((day, index) => Math.max(day.verified, stopped[index])));
  const x = (index) => left + (days.length > 1 ? index * (width - left - right) / (days.length - 1) : 0);
  const y = (value) => height - bottom - value * (height - top - bottom) / peak;
  const line = (values) => {
    let path = "";
    let pen = "M";
    values.forEach((value, index) => {
      if (value === null) { pen = "M"; return; }
      path += `${pen}${x(index).toFixed(1)} ${y(value).toFixed(1)} `;
      pen = "L";
    });
    return path;
  };
  const ticks = [0, Math.round(peak / 2), peak];
  const marks = [];
  if (mode === "bars") {
    const slot = (width - left - right) / Math.max(1, days.length);
    const bar = Math.max(1, Math.min(10, slot / 2 - 2));
    days.forEach((day, index) => {
      const center = left + slot * (index + 0.5);
      marks.push(svg("rect", { x: center - bar - 1, y: y(day.verified), width: bar, height: height - bottom - y(day.verified), rx: 2, fill: "var(--series-1)" }));
      marks.push(svg("rect", { x: center + 1, y: y(stopped[index]), width: bar, height: height - bottom - y(stopped[index]), rx: 2, fill: "var(--series-2)" }));
    });
  } else if (mode === "rate") {
    marks.push(svg("path", { class: "series-a", d: line(rate), "stroke-linejoin": "round" }));
  } else {
    const area = (values, kind) => {
      const path = line(values);
      if (days.length > 1) marks.push(svg("path", { class: `area-${kind}`, d: `${path}L${x(days.length - 1).toFixed(1)} ${y(0).toFixed(1)} L${x(0).toFixed(1)} ${y(0).toFixed(1)} Z` }));
      marks.push(svg("path", { class: `series-${kind}`, d: path, "stroke-linejoin": "round" }));
    };
    area(days.map((day) => day.verified), "a");
    area(stopped, "b");
  }
  const chart = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Verification activity per day" },
    ticks.map((tick) => [svg("line", { class: "grid-line", x1: left, x2: width - right, y1: y(tick), y2: y(tick) }),
      svg("text", { x: left - 6, y: y(tick) + 4, "text-anchor": "end" }, mode === "rate" ? `${tick}%` : String(tick))]),
    [0, Math.floor((days.length - 1) / 2), days.length - 1].filter((value, index, list) => list.indexOf(value) === index).map((index) =>
      svg("text", { x: x(index), y: height - 6, "text-anchor": "middle" }, days[index].day.slice(5))),
    marks);
  const wrap = h("div", { class: "chart" }, chart);
  const cross = svg("line", { class: "cross", y1: top, y2: height - bottom, opacity: 0 });
  chart.append(cross);
  const tip = h("div", { class: "tip", hidden: true });
  wrap.append(tip);
  chart.addEventListener("pointermove", (event) => {
    const box = chart.getBoundingClientRect();
    const position = (event.clientX - box.left) / box.width * width;
    const index = Math.max(0, Math.min(days.length - 1, Math.round((position - left) / Math.max(1, (width - left - right) / Math.max(1, days.length - 1)))));
    cross.setAttribute("x1", x(index));
    cross.setAttribute("x2", x(index));
    cross.setAttribute("opacity", 1);
    tip.hidden = false;
    tip.textContent = mode === "rate"
      ? `${days[index].day}: ${rate[index] === null ? "no attempts" : `${rate[index].toFixed(0)}% passed`}`
      : `${days[index].day}: ${days[index].verified} verified, ${stopped[index]} stopped`;
    tip.style.left = `${Math.min(event.clientX - box.left + 12, box.width - 220)}px`;
    tip.style.top = "6px";
  });
  chart.addEventListener("pointerleave", () => { tip.hidden = true; cross.setAttribute("opacity", 0); });
  return wrap;
}

function bars(rows, kind = "") {
  const peak = Math.max(1, ...rows.map((row) => row.value));
  return h("div", { class: "bars" }, rows.map((row) => {
    const fill = h("div", { class: `bar-fill ${kind}` });
    fill.style.width = `${row.value / peak * 100}%`;
    return h("div", { class: "bar-row", title: `${row.label}: ${row.value}` }, h("span", { text: row.label }),
      h("div", { class: "bar-track" }, fill), h("strong", { text: String(row.value) }));
  }));
}

function funnel(data) {
  const steps = [["Started", data.started], ["Finished", data.finished], ["Verified", data.verified]];
  const peak = Math.max(1, data.started);
  return h("div", {}, steps.map(([label, value]) => {
    const fill = h("div", { class: "bar-fill" });
    fill.style.width = `${value / peak * 100}%`;
    return h("div", { class: "funnel-row" }, h("span", { text: label }), h("strong", { text: String(value) }), h("div", { class: "bar-track" }, fill));
  }), h("p", { class: "faint", text: `${data.unfinished} didn't finish. ${data.retried} tried more than once.` }));
}

function heatmap(grid) {
  const peak = Math.max(1, ...grid.flat());
  const cells = [h("span")];
  for (let hour = 0; hour < 24; hour++) cells.push(h("span", { text: hour % 6 === 0 ? String(hour) : "" }));
  grid.forEach((row, day) => {
    cells.push(h("span", { text: WEEKDAYS[day] }));
    row.forEach((count, hour) => {
      const cell = h("div", { class: "cell", title: `${WEEKDAYS[day]} ${hour}:00: ${count}` });
      if (count) {
        cell.style.background = "var(--series-1)";
        cell.style.opacity = String(0.25 + 0.75 * count / peak);
      }
      cells.push(cell);
    });
  });
  return h("div", { class: "heat", role: "img", "aria-label": "Verifications by weekday and hour" }, cells);
}

function checkFilter(hidden, reload) {
  const seen = state.catalog.checks;
  return h("details", { class: "check-filter" }, h("summary", { class: "button small", text: hidden.size ? `Checks: ${seen.length - hidden.size} of ${seen.length}` : "Every check" }),
    h("div", { class: "panel chips" }, seen.map((check) => h("label", { class: "chip" }, h("input", { type: "checkbox", checked: !hidden.has(check.id), onchange: (event) => {
      if (event.target.checked) hidden.delete(check.id);
      else hidden.add(check.id);
      reload();
    } }), check.name))));
}

function busiest(days) {
  const top = days.reduce((best, day) => (day.verified + day.blocked > best.verified + best.blocked ? day : best), { verified: 0, blocked: 0 });
  return top.day ? `The busiest day was ${top.day}, with ${top.verified + top.blocked} attempts.` : "No attempts in this period.";
}

function dataTable(days) {
  return h("details", {}, h("summary", { class: "faint", text: "Show as a table" }),
    h("div", { class: "table-wrap" }, h("table", { class: "list" },
      h("thead", {}, h("tr", {}, h("th", { text: "Day" }), h("th", { text: "Verified" }), h("th", { text: "Stopped" }))),
      h("tbody", {}, days.filter((day) => day.verified || day.blocked).map((day) => h("tr", {},
        h("td", { text: day.day }), h("td", { text: String(day.verified) }), h("td", { text: String(day.blocked) })))))));
}

export async function render(view) {
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const body = h("div");
  let days = "month";
  let compare = "";
  let mode = "area";
  const hidden = new Set();
  const fromBox = h("input", { type: "date", "aria-label": "From", hidden: true, onchange: () => load() });
  const toBox = h("input", { type: "date", "aria-label": "To", hidden: true, onchange: () => load() });
  const period = () => {
    if (days === "custom" && fromBox.value && toBox.value) {
      return [new Date(`${fromBox.value}T00:00`).getTime() / 1000, new Date(`${toBox.value}T23:59:59`).getTime() / 1000];
    }
    const end = Date.now() / 1000;
    if (days === "month") {
      const now = new Date();
      return [new Date(now.getFullYear(), now.getMonth(), 1).getTime() / 1000, end];
    }
    return [end - Number(days === "custom" ? 30 : days) * DAY, end];
  };
  const load = async () => {
    const [start, end] = period();
    const query = new URLSearchParams({ from: String(start), to: String(end), tz: zone, compare: compare ? "1" : "0" });
    if (compare === "month") {
      const first = new Date(start * 1000);
      query.set("compare_from", String(new Date(first.getFullYear(), first.getMonth() - 1, first.getDate()).getTime() / 1000));
      query.set("compare_to", String(new Date(new Date(end * 1000).getFullYear(), new Date(end * 1000).getMonth() - 1, new Date(end * 1000).getDate() + 1).getTime() / 1000));
    }
    const data = await api(`/api/guilds/${state.guild.id}/analytics?${query}`);
    const previous = data.previous ?? {};
    const cards = data.cards;
    fill(body,
      h("div", { class: "grid kpis section" },
        kpi("Verified", String(cards.verified), delta(cards.verified, previous.verified)),
        kpi("Stopped", String(cards.blocked), delta(cards.blocked, previous.blocked)),
        kpi("Pass rate", cards.pass_rate === null ? "No data" : `${cards.pass_rate}%`, delta(cards.pass_rate, previous.pass_rate)),
        kpi("Members tried", String(cards.members), delta(cards.members, previous.members)),
        kpi("Median time", formatSeconds(cards.median_seconds), cards.median_seconds === null || previous.median_seconds === null ? null : delta(cards.median_seconds, previous.median_seconds)),
        kpi("Verifying now", String(data.verifying_now))),
      section("Daily activity", busiest(data.daily), h("div", { class: "panel" },
        h("div", { class: "toolbar" },
          select(CHART_MODES, mode, (value) => { mode = value; load(); }, { label: "Chart type" }),
          checkFilter(hidden, load)),
        mode === "rate" ? null : h("div", { class: "legend" }, h("span", {}, h("i", { class: "a" }), "Verified"), h("span", {}, h("i", { class: "b" }), "Stopped")),
        dailyChart(data.daily, mode, hidden), dataTable(data.daily))),
      h("div", { class: "grid two section" },
        h("div", { class: "panel" }, h("h3", { text: "Why attempts were stopped" }),
          data.reasons.length ? bars(data.reasons.map(([id, value]) => ({ label: checkName(id), value })), "b") : h("p", { class: "faint", text: "Nothing stopped in this period." })),
        h("div", { class: "panel" }, h("h3", { text: "Funnel" }), funnel(data.funnel))),
      h("div", { class: "grid two section" },
        h("div", { class: "panel" }, h("h3", { text: "Busiest times" }), heatmap(data.heatmap)),
        h("div", { class: "panel" }, h("h3", { text: "Time to verify" }), bars(data.durations.map((row) => ({ label: row.label, value: row.count }))))),
      section("Outcomes", null, h("div", { class: "panel" },
        bars([...Object.entries(data.outcomes.modes), ...Object.entries(data.outcomes.actions)].map(([id, value]) => ({ label: OUTCOME_NAMES[id] ?? id, value }))),
        h("p", { class: "faint", text: `${data.outcomes.bypassed} used a bypass link.` }))));
  };
  view.append(h("div", { class: "toolbar" },
    select(RANGES, days, (value) => {
      days = value;
      fromBox.hidden = toBox.hidden = value !== "custom";
      if (value !== "custom") load();
    }, { label: "Date range" }),
    fromBox, toBox,
    select(COMPARE, compare, (value) => { compare = value ?? ""; load(); }, { label: "Compare" })),
  body);
  await load();
}
