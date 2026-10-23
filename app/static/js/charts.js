// Mirror bar chart: allowed above the baseline, refused below it.
// Position carries the meaning as well as colour (colour-blind safe), with a
// legend, a hover tooltip per day, and a screen-reader table.
import { h } from "./core.js";

const NS = "http://www.w3.org/2000/svg";
const s = (name, attrs = {}) => {
  const e = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
};

function roundedBar(x, y, w, hgt, up) {
  // 4px rounded data-end, square at the baseline
  const r = Math.min(4, w / 2, hgt);
  if (hgt <= 0) return "";
  if (up) return `M${x} ${y + hgt}V${y + r}Q${x} ${y} ${x + r} ${y}H${x + w - r}Q${x + w} ${y} ${x + w} ${y + r}V${y + hgt}Z`;
  return `M${x} ${y}V${y + hgt - r}Q${x} ${y + hgt} ${x + r} ${y + hgt}H${x + w - r}Q${x + w} ${y + hgt} ${x + w} ${y + hgt - r}V${y}Z`;
}

export function mirrorChart(series, { height = 240, labelEvery = 2, title = "Audit events per day" } = {}) {
  const W = 720, H = height, padL = 40, padR = 8, top = 14, bottom = 30;
  const maxUp = Math.max(1, ...series.map((d) => d.allowed));
  const maxDown = Math.max(1, ...series.map((d) => d.refused));
  const plotH = H - top - bottom;
  const upH = plotH * 0.68, downH = plotH * 0.32;
  const base = top + upH;
  const band = (W - padL - padR) / series.length;
  const bw = Math.max(4, band * 0.56);

  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "chart", role: "img",
    "aria-label": `${title}: allowed above the line, refused below.` });
  const grid = s("g", { class: "grid" });
  const axis = s("g", { class: "axis" });
  [0.5, 1].forEach((f) => {
    const y = base - upH * f;
    grid.append(s("line", { x1: padL, x2: W - padR, y1: y, y2: y }));
    const t = s("text", { x: padL - 6, y: y + 4, "text-anchor": "end" });
    t.textContent = Math.round(maxUp * f);
    axis.append(t);
  });
  const tDown = s("text", { x: padL - 6, y: base + downH + 2, "text-anchor": "end" });
  tDown.textContent = maxDown;
  axis.append(tDown);
  svg.append(grid, axis);

  const tip = h("div", { class: "chart-tip", hidden: true });
  document.body.append(tip);

  series.forEach((d, i) => {
    const x = padL + i * band + (band - bw) / 2;
    const ha = (d.allowed / maxUp) * upH;
    const hr = (d.refused / maxDown) * downH;
    if (ha > 0) svg.append(s("path", { d: roundedBar(x, base - ha - 1, bw, ha, true), class: "bar-allowed" }));
    if (hr > 0) svg.append(s("path", { d: roundedBar(x, base + 1, bw, hr, false), class: "bar-refused" }));
    if ((series.length - 1 - i) % labelEvery === 0) {
      const lbl = s("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle", class: "axis" });
      const dt = new Date(d.day + "T00:00:00");
      lbl.textContent = dt.toLocaleDateString(undefined, { day: "numeric", month: "short" });
      svg.append(lbl);
    }
    const hit = s("rect", { x: padL + i * band, y: top, width: band, height: plotH, class: "hit", tabindex: 0,
      "aria-label": `${d.day}: ${d.allowed} allowed, ${d.refused} refused` });
    const show = (ev) => {
      tip.textContent = `${new Date(d.day + "T00:00:00").toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" })}: ${d.allowed} allowed, ${d.refused} refused`;
      tip.hidden = false;
      const r = ev.currentTarget.getBoundingClientRect();
      tip.style.left = Math.min(window.innerWidth - 220, r.left + r.width / 2 - 80) + "px";
      tip.style.top = r.top - 36 + "px";
    };
    hit.addEventListener("mouseenter", show);
    hit.addEventListener("focus", show);
    hit.addEventListener("mouseleave", () => { tip.hidden = true; });
    hit.addEventListener("blur", () => { tip.hidden = true; });
    svg.append(hit);
  });
  svg.append(s("line", { x1: padL, x2: W - padR, y1: base, y2: base, class: "base" }));

  const table = h("table", { class: "sr-only" },
    h("caption", null, title),
    h("thead", null, h("tr", null, h("th", null, "Day"), h("th", null, "Allowed"), h("th", null, "Refused"))),
    h("tbody", null, series.map((d) => h("tr", null, h("td", null, d.day), h("td", null, d.allowed), h("td", null, d.refused)))));

  const wrap = h("div", null,
    h("div", { class: "legend" }, h("span", null, h("i", { class: "allowed" }), "Allowed (above the line)"),
      h("span", null, h("i", { class: "refused" }), "Refused (below the line)")),
    svg, table);
  // remove stray tooltip when the chart leaves the page
  const obs = new MutationObserver(() => { if (!document.body.contains(svg)) { tip.remove(); obs.disconnect(); } });
  obs.observe(document.body, { childList: true, subtree: true });
  return wrap;
}

/** A labelled horizontal meter list (ranking). */
export function meterList(items, { refused = false } = {}) {
  const max = Math.max(1, ...items.map((i) => i.n));
  return h("ul", { class: "bars-list" }, items.map((i) => {
    const bar = h("div", { class: refused ? "refused" : "" });
    bar.style.width = Math.max(3, (i.n / max) * 100) + "%";
    return h("li", null, h("span", null, i.label), h("strong", null, i.n), h("div", { class: "meter" }, bar));
  }));
}


/** Per-day allowed/refused series from audit-style rows, for the last `days` days. */
export function dailySeries(rows, days = 30) {
  const start = new Date(); start.setHours(0, 0, 0, 0); start.setDate(start.getDate() - (days - 1));
  const out = Array.from({ length: days }, (_, i) => {
    const d = new Date(start); d.setDate(start.getDate() + i);
    return { day: d.toISOString().slice(0, 10), allowed: 0, refused: 0, _t: d.getTime() };
  });
  for (const r of rows) {
    const t = new Date(r.ts); t.setHours(0, 0, 0, 0);
    const i = Math.round((t.getTime() - start.getTime()) / 86400000);
    if (i >= 0 && i < days) out[i][r.outcome === "denied" ? "refused" : "allowed"] += 1;
  }
  return out;
}

/**
 * Access timeline: one bar per person, from when access was granted to when
 * it ends. Open-ended access runs off the right edge (and is drawn as such:
 * that is the point - it never ends). A vertical line marks today.
 */
export function accessTimeline(grants) {
  const DAY = 86400000;
  const now = Date.now();
  const starts = grants.map((g) => new Date(g.created_at).getTime());
  const ends = grants.filter((g) => g.expires_at).map((g) => new Date(g.expires_at).getTime());
  const from = Math.min(now - 7 * DAY, ...starts) - DAY;
  const to = Math.max(now + 30 * DAY, ...ends.map((e) => e + 3 * DAY));
  const pct = (t) => Math.max(0, Math.min(100, ((t - from) / (to - from)) * 100));

  const axis = h("div", { class: "tl-axis", "aria-hidden": "true" });
  for (let k = 0; k <= 4; k++) {
    const t = from + ((to - from) * k) / 4;
    const tick = h("span", null, new Date(t).toLocaleDateString(undefined, { day: "numeric", month: "short" }));
    tick.style.left = (k * 25) + "%";
    axis.append(tick);
  }
  const rows = grants.map((g) => {
    const s = new Date(g.created_at).getTime();
    const e = g.expires_at ? new Date(g.expires_at).getTime() : to;
    const soon = g.expires_at && e - now < 7 * DAY && e > now;
    const bar = h("div", {
      class: `tl-bar ${g.permission}${g.expires_at ? "" : " open"}${soon ? " soon" : ""}${g.expired ? " expired" : ""}`,
      title: `${g.user.name}: ${g.permission === "edit" ? "can edit" : "can read"} from ${new Date(s).toLocaleDateString()} ${g.expires_at ? "until " + new Date(e).toLocaleDateString() : "with no end date"}`,
    });
    bar.style.left = pct(s) + "%";
    bar.style.width = Math.max(1.5, pct(e) - pct(s)) + "%";
    const today = h("div", { class: "tl-today", "aria-hidden": "true" });
    today.style.left = pct(now) + "%";
    return h("div", { class: "tl-row", role: "listitem" },
      h("div", { class: "tl-who" }, h("strong", null, g.user.name),
        h("span", { class: "sub" }, g.expires_at ? (g.expired ? "expired " : "until ") + new Date(e).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "no end date")),
      h("div", { class: "tl-track" }, bar, today));
  });
  const nowLabel = h("span", { class: "tl-now" }, "Today");
  nowLabel.style.left = pct(now) + "%";
  return h("div", { class: "timeline" },
    h("div", { class: "tl-row tl-head" }, h("div"), h("div", { class: "tl-track tl-scale" }, axis, nowLabel)),
    h("div", { role: "list", "aria-label": "When each person's access starts and ends" }, rows),
    h("div", { class: "legend small" },
      h("span", null, h("i", { class: "allowed" }), "Can edit"), h("span", null, h("i", { class: "read" }), "Can read"),
      h("span", null, h("i", { class: "open" }), "No end date"), h("span", null, h("i", { class: "soon" }), "Ends within 7 days")));
}
