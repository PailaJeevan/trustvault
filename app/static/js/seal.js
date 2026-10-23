// The custody seal: a guilloche rosette generated deterministically from a
// SHA-256. Same file -> same seal; one changed byte -> a visibly different seal.
// It is a recognition aid, not a security control: the hash itself (shown
// beside it) is what proves integrity.
const NS = "http://www.w3.org/2000/svg";

function bytesOf(hex) {
  const clean = (hex || "").replace(/[^0-9a-f]/gi, "").padEnd(64, "0").slice(0, 64);
  const out = [];
  for (let i = 0; i < 64; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return out;
}

function el(name, attrs) {
  const e = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

/**
 * @param {string} hash  hex SHA-256 (or any hex string)
 * @param {object} opt   { label: true|false, draw: false, title: "" }
 */
export function seal(hash, opt = {}) {
  const b = bytesOf(hash);
  const size = 200, c = size / 2;
  const svg = el("svg", { viewBox: `0 0 ${size} ${size}`, class: "seal" + (opt.draw ? " draw" : ""), role: "img" });
  const title = el("title", {});
  title.textContent = opt.title || `Custody seal for SHA-256 ${hash ? hash.slice(0, 16) + "…" : "unknown"}`;
  svg.append(title);

  // outer rim with micro-ticks: one tick per bit of the first 12 bytes
  svg.append(el("circle", { cx: c, cy: c, r: 96, class: "rim", "stroke-width": 0.8 }));
  svg.append(el("circle", { cx: c, cy: c, r: 90, class: "rim", "stroke-width": 0.5 }));
  let ticks = "";
  for (let i = 0; i < 96; i++) {
    const bit = (b[i >> 3] >> (i & 7)) & 1;
    const a = (i / 96) * Math.PI * 2;
    const r1 = 90, r2 = bit ? 95.5 : 92.5;
    ticks += `M${(c + r1 * Math.cos(a)).toFixed(2)} ${(c + r1 * Math.sin(a)).toFixed(2)}L${(c + r2 * Math.cos(a)).toFixed(2)} ${(c + r2 * Math.sin(a)).toFixed(2)}`;
  }
  svg.append(el("path", { d: ticks, class: "tick", "stroke-width": 0.7 }));

  // six layered rose / hypotrochoid rings, each parameterised by hash bytes
  const layers = 6;
  for (let L = 0; L < layers; L++) {
    const k = 5 + (b[12 + L] % 9);                 // lobes
    const m = 2 + (b[18 + L] % 5);                 // secondary frequency
    const amp = 0.10 + (b[24 + L] / 255) * 0.16;    // lobe depth
    const amp2 = 0.03 + (b[(30 + L) % 32] / 255) * 0.06;
    const phase = (b[L] / 255) * Math.PI * 2;
    const R = 84 - L * 9.5;
    let d = "";
    const steps = 720;
    for (let i = 0; i <= steps; i++) {
      const t = (i / steps) * Math.PI * 2;
      const r = R * (1 - amp + amp * Math.cos(k * t + phase) + amp2 * Math.sin(m * k * t));
      const x = c + r * Math.cos(t), y = c + r * Math.sin(t);
      d += (i ? "L" : "M") + x.toFixed(2) + " " + y.toFixed(2);
    }
    svg.append(el("path", {
      d: d + "Z", class: "ring" + (L % 2 ? " alt" : ""), "stroke-width": L === 0 ? 1.1 : 0.8,
      pathLength: 1, "stroke-linejoin": "round",
    }));
  }

  svg.append(el("circle", { cx: c, cy: c, r: 26, class: "core", "stroke-width": 0.8 }));
  if (opt.label !== false && hash) {
    const t1 = el("text", { x: c, y: c - 2, "text-anchor": "middle", "font-size": 11 });
    t1.textContent = hash.slice(0, 4);
    const t2 = el("text", { x: c, y: c + 11, "text-anchor": "middle", "font-size": 11 });
    t2.textContent = hash.slice(4, 8);
    svg.append(t1, t2);
  }
  return svg;
}
