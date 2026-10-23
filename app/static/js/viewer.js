// Safe in-app viewer.
// Nothing from a file is ever interpreted as HTML or script:
//   - text and Markdown are rendered by building DOM nodes with textContent
//     (Markdown gets headings, lists and bold - nothing else);
//   - CSV becomes a table of textContent cells;
//   - PNG/JPEG are shown from a blob: URL in an <img> (raster only; SVG is
//     not an accepted upload type, and CSP allows blob: for images only);
//   - everything else (PDF, Office) is offered as a download instead.
// Every view goes through the same authorisation as a download and is
// recorded in the audit trail with purpose "view".
import { api, download, fmtSize, h, icon, openOverlay, put, toast } from "./core.js";
import { seal } from "./seal.js";

const TEXT = ["txt", "md"];
const IMAGE = ["png", "jpg", "jpeg"];
const MAX_TEXT = 512 * 1024;
const MAX_ROWS = 500;
const MAX_COLS = 40;

export const canView = (filename) => {
  const ext = (filename || "").split(".").pop().toLowerCase();
  return [...TEXT, ...IMAGE, "csv"].includes(ext);
};

async function fetchForView(docId, version) {
  const q = new URLSearchParams({ purpose: "view" });
  if (version) q.set("version", version);
  const res = await api("GET", `/api/documents/${encodeURIComponent(docId)}/download?${q}`, undefined, { raw: true });
  return { blob: await res.blob(), receipt: res.headers.get("X-TrustVault-Receipt") };
}

// ---------------------------------------------------------------- renderers
function renderText(text) {
  return h("pre", { class: "viewer-text" }, text);
}

function inline(line) {
  // **bold** and `code`, built as nodes - never innerHTML.
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(line))) {
    if (m.index > last) out.push(line.slice(last, m.index));
    const tok = m[0];
    out.push(tok.startsWith("**") ? h("strong", null, tok.slice(2, -2)) : h("code", null, tok.slice(1, -1)));
    last = m.index + tok.length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

function renderMarkdown(text) {
  const root = h("article", { class: "viewer-md" });
  let list = null, para = [];
  const flushPara = () => { if (para.length) { root.append(h("p", null, inline(para.join(" ")))); para = []; } };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    const head = /^(#{1,4})\s+(.*)$/.exec(line);
    const item = /^\s*[-*]\s+(.*)$/.exec(line);
    if (head) { flushPara(); list = null; root.append(h("h" + Math.min(4, head[1].length + 1), null, inline(head[2]))); }
    else if (item) { flushPara(); if (!list) { list = h("ul"); root.append(list); } list.append(h("li", null, inline(item[1]))); }
    else if (!line.trim()) { flushPara(); list = null; }
    else { list = null; para.push(line.trim()); }
  }
  flushPara();
  return root;
}

function parseCsv(text) {
  const rows = [];
  let row = [], cell = "", quoted = false;
  for (let i = 0; i < text.length && rows.length <= MAX_ROWS; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); rows.push(row); row = []; cell = "";
    } else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((c) => c !== ""));
}

function renderCsv(text) {
  const rows = parseCsv(text);
  if (!rows.length) return h("p", { class: "muted" }, "The file is empty.");
  const [head, ...body] = rows;
  const cols = Math.min(MAX_COLS, Math.max(...rows.map((r) => r.length)));
  const pad = (r) => Array.from({ length: cols }, (_, i) => r[i] ?? "");
  return h("div", { class: "viewer-table table-wrap" }, h("table", null,
    h("thead", null, h("tr", null, h("th", { class: "rownum" }, "#"), pad(head).map((c) => h("th", null, c)))),
    h("tbody", null, body.slice(0, MAX_ROWS).map((r, i) => h("tr", null, h("td", { class: "rownum" }, i + 1), pad(r).map((c) => h("td", null, c)))))),
  body.length >= MAX_ROWS ? h("p", { class: "small muted" }, `Showing the first ${MAX_ROWS} rows. Download for the full file.`) : null);
}

// ---------------------------------------------------------------- the overlay
export function openViewer(doc, version) {
  const v = version ? doc.versions.find((x) => x.version_no === version) : null;
  const filename = v ? v.filename : doc.filename;
  const sha = v ? v.sha256 : doc.sha256;
  const ext = (filename || "").split(".").pop().toLowerCase();
  let objectUrl = null;

  openOverlay((close) => {
    const body = h("div", { class: "viewer-body", "aria-busy": "true" }, h("div", { class: "skel h" }));
    const foot = h("div", { class: "viewer-foot small muted" }, "Opening…");
    const done = () => { if (objectUrl) URL.revokeObjectURL(objectUrl); close(); };
    const frame = h("section", { class: "viewer", role: "dialog", "aria-modal": "true", "aria-label": `Viewing ${doc.title}` },
      h("header", { class: "viewer-head" },
        seal(sha, { label: false }),
        h("div", { class: "viewer-title" }, h("strong", null, doc.title),
          h("span", { class: "sub" }, `${filename}${v ? `, version ${v.version_no}` : ""}`)),
        h("button", { class: "btn secondary small", onclick: () => download(doc.id, version, filename).catch((ex) => toast(ex.message, true)) }, icon("download"), "Download"),
        h("button", { class: "icon-btn", "aria-label": "Close viewer", onclick: done }, icon("x"))),
      body, foot);

    (async () => {
      try {
        const { blob, receipt } = await fetchForView(doc.id, version);
        let node;
        if (IMAGE.includes(ext)) {
          objectUrl = URL.createObjectURL(new Blob([blob], { type: ext === "png" ? "image/png" : "image/jpeg" }));
          node = h("div", { class: "viewer-image" }, h("img", { src: objectUrl, alt: doc.title }));
        } else {
          const text = new TextDecoder("utf-8", { fatal: false }).decode(await blob.slice(0, MAX_TEXT).arrayBuffer());
          node = ext === "csv" ? renderCsv(text) : ext === "md" ? renderMarkdown(text) : renderText(text);
          if (blob.size > MAX_TEXT) node = h("div", null, node, h("p", { class: "small muted" }, `Showing the first ${fmtSize(MAX_TEXT)}. Download for the full file.`));
        }
        body.removeAttribute("aria-busy");
        put(body, node);
        put(foot, icon("history"), receipt ? ` This view is in the custody record as receipt #${receipt}.` : " This view was recorded.");
      } catch (ex) {
        put(body, h("div", { class: "note error" }, ex.message));
        put(foot);
      }
    })();
    return frame;
  });
}
