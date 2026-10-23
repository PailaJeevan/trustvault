import { api, confirmDialog, errorNote, expiryChip, fmtDate, fmtSize, h, icon, levelChip, put, skeleton, state, toast, upload, ago } from "../core.js";
import { seal } from "../seal.js";
import { shell } from "../shell.js";

function getView() { try { return localStorage.getItem("tv-view") || "grid"; } catch (_) { return "grid"; } }
function setView(v) { try { localStorage.setItem("tv-view", v); } catch (_) { /* fine */ } }

export async function viewDocuments(render, query) {
  const p = new URLSearchParams(query || "");
  const page = Number(p.get("page") || 1);
  const go = (changes) => {
    const q = new URLSearchParams(p);
    for (const [k, v] of Object.entries(changes)) { if (v) q.set(k, v); else q.delete(k); }
    if (!("page" in changes)) q.delete("page");
    location.hash = "#/documents" + (q.toString() ? "?" + q : "");
  };

  const q = h("input", { id: "f-q", type: "search", value: p.get("q") || "", placeholder: "Title or description" });
  const owner = h("input", { id: "f-owner", value: p.get("owner") || "", placeholder: "Name or email" });
  const scope = h("select", { id: "f-scope" }, [["all", "Everything I can open"], ["mine", "I own"], ["shared", "Shared with me"]]
    .map(([v, l]) => h("option", { value: v, selected: (p.get("scope") || "all") === v }, l)));
  const sort = h("select", { id: "f-sort" }, [["newest", "Newest first"], ["updated", "Recently changed"], ["oldest", "Oldest first"], ["title", "Title A–Z"]]
    .map(([v, l]) => h("option", { value: v, selected: (p.get("sort") || "newest") === v }, l)));
  const tag = h("input", { id: "f-tag", value: p.get("tag") || "", list: "f-tags", placeholder: "Any tag" });
  const from = h("input", { id: "f-from", type: "date", value: p.get("from") || "" });
  const to = h("input", { id: "f-to", type: "date", value: p.get("to") || "" });
  const tagList = h("datalist", { id: "f-tags" });
  const apply = (e) => { if (e) e.preventDefault(); go({ q: q.value.trim(), owner: owner.value.trim(), scope: scope.value === "all" ? "" : scope.value, sort: sort.value === "newest" ? "" : sort.value, tag: tag.value.trim(), from: from.value, to: to.value }); };
  [scope, sort].forEach((el) => el.addEventListener("change", apply));
  const fld = (el, label) => h("div", null, h("label", { for: el.id }, label), el);

  const view = getView();
  const toggle = h("div", { class: "view-toggle", role: "group", "aria-label": "Layout" },
    h("button", { "aria-pressed": String(view === "grid"), "aria-label": "Cards", onclick: () => { setView("grid"); viewDocuments(render, query); } }, icon("grid")),
    h("button", { "aria-pressed": String(view === "list"), "aria-label": "Table", onclick: () => { setView("list"); viewDocuments(render, query); } }, icon("list")));
  const activeCat = p.get("category") || "";
  const cats = h("div", { class: "cat-tabs", role: "group", "aria-label": "Category" },
    ["", ...state.categories].map((c) => h("button", { "aria-pressed": String(activeCat === c), onclick: () => go({ category: c }) }, c || "All categories")));

  const results = h("div", null, skeleton(2));
  render(shell("documents",
    h("div", { class: "page-head" },
      h("div", null, h("h1", null, "Documents"),
        h("p", null, state.user.role === "admin"
          ? "Administrators only see documents someone has shared with them. Oversight lives under Administration."
          : "Everything here is something you own or someone shared with you by name.")),
      h("div", { class: "row" }, toggle, state.user.role === "owner" ? h("a", { class: "btn", href: "#/upload" }, icon("upload"), "Upload") : null)),
    h("form", { class: "panel", role: "search", onsubmit: apply },
      h("div", { class: "filters" }, fld(q, "Search"), fld(owner, "Owner"), fld(scope, "Show"), fld(sort, "Sort")),
      h("div", { class: "filters more" }, fld(tag, "Tag"), tagList, fld(from, "Added from"), fld(to, "Added to"),
        h("div", null, h("button", { class: "btn", type: "submit" }, icon("search"), "Search")))),
    cats, results));

  try {
    p.set("page", page); p.set("page_size", 24);
    const r = await api("GET", "/api/documents?" + p.toString());
    tagList.replaceChildren(...(r.tags || []).map((t) => h("option", { value: t })));
    if (!r.documents.length) {
      const filtered = [...p.keys()].some((k) => !["page", "page_size"].includes(k));
      put(results, h("div", { class: "panel empty" }, icon("docs"),
        h("p", null, filtered ? "No documents match these filters." : state.user.role === "owner" ? "No documents yet. Upload one; it stays private until you share it." : "Nobody has shared a document with you yet."),
        filtered ? h("a", { class: "btn secondary", href: "#/documents" }, "Clear filters") : null));
      return;
    }
    const pages = Math.max(1, Math.ceil(r.total / r.page_size));
    const pager = h("div", { class: "pager" },
      `${r.total} document${r.total === 1 ? "" : "s"}, page ${page} of ${pages}`,
      h("button", { class: "btn secondary small", disabled: page <= 1, onclick: () => go({ page: page - 1 }) }, "Previous"),
      h("button", { class: "btn secondary small", disabled: page >= pages, onclick: () => go({ page: page + 1 }) }, "Next"));
    const content = view === "grid"
      ? h("div", { class: "doc-grid" }, r.documents.map((d) => h("a", { class: "doc-card", href: "#/doc/" + d.id },
        h("div", { class: "top" }, seal(d.sha256, { label: false }), levelChip(d.my_access)),
        h("h3", null, d.title),
        h("div", { class: "chips" }, h("span", { class: "chip cat" }, d.category), d.legal_hold ? h("span", { class: "chip hold" }, "Legal hold") : null,
          expiryChip(d.my_expires_at),
          (d.tags || []).slice(0, 3).map((t) => h("span", { class: "chip tag" }, t))),
        h("div", { class: "meta" }, h("span", null, d.owner.name), h("span", null, ago(d.updated_at))))))
      : h("div", { class: "panel" }, h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Document", "Category", "Owner", "Your access", "Size", "Added"].map((t) => h("th", null, t)))),
        h("tbody", null, r.documents.map((d) => h("tr", { class: "clickable", tabindex: "0",
          onclick: () => { location.hash = "#/doc/" + d.id; }, onkeydown: (e) => { if (e.key === "Enter") location.hash = "#/doc/" + d.id; } },
        h("td", null, h("div", { class: "cell-doc" }, seal(d.sha256, { label: false }), h("div", null, h("strong", null, d.title), h("span", { class: "sub" }, d.filename)))),
        h("td", null, h("span", { class: "chip cat" }, d.category)),
        h("td", null, d.owner.name),
        h("td", null, levelChip(d.my_access)),
        h("td", { class: "nowrap small" }, fmtSize(d.size_bytes)),
        h("td", { class: "nowrap small" }, fmtDate(d.created_at))))))));
    put(results, content, pager);
  } catch (ex) { put(results, errorNote(ex)); }
}

// ------------------------------------------------------------------ upload (one or many)
const ALLOWED = ["pdf", "png", "jpg", "jpeg", "txt", "csv", "md", "docx", "xlsx", "pptx"];
const MAX = 10 * 1024 * 1024;
const MAX_FILES = 20;

function precheck(f) {
  const ext = (f.name.split(".").pop() || "").toLowerCase();
  if (!f.name.includes(".") || !ALLOWED.includes(ext)) return `.${ext} files are not accepted`;
  if (!f.size) return "The file is empty";
  if (f.size > MAX) return "Larger than 10 MB";
  return null;
}

export function viewUpload(render) {
  let queue = [];               // {file, title, problem, state, bar, status, row}
  const err = h("div");
  const input = h("input", { type: "file", id: "file", class: "sr-only", multiple: true, accept: ALLOWED.map((e) => "." + e).join(",") });
  const list = h("ul", { class: "upload-queue", "aria-live": "polite" });
  const cat = h("select", { id: "cat" }, state.categories.map((c) => h("option", { value: c }, c)));
  const tags = h("input", { id: "tags", placeholder: "payroll, 2026" });
  const desc = h("textarea", { id: "desc", maxlength: 2000, placeholder: "What is this, and who is it for?" });
  const btn = h("button", { class: "btn", type: "submit", disabled: true }, icon("lock"), "Upload privately");
  const summary = h("p", { class: "small muted" });

  const refresh = () => {
    const ok = queue.filter((q) => !q.problem && q.state === "ready");
    btn.disabled = !ok.length;
    put(btn, icon("lock"), ok.length > 1 ? `Upload ${ok.length} files privately` : "Upload privately");
    put(summary, queue.length ? `${queue.length} file${queue.length === 1 ? "" : "s"} selected` +
      (queue.some((q) => q.problem) ? `, ${queue.filter((q) => q.problem).length} cannot be uploaded` : "") : "");
  };
  const drawRow = (q) => {
    const titleIn = h("input", { "aria-label": `Name for ${q.file.name}`, value: q.title, maxlength: 200,
      oninput: (e) => { q.title = e.target.value; } });
    q.bar = h("div");
    q.status = h("span", { class: "small" + (q.problem ? " bad" : " muted") }, q.problem || fmtSize(q.file.size));
    q.row = h("li", { class: "upload-item" + (q.problem ? " invalid" : "") },
      icon(q.problem ? "alert" : "file"),
      h("div", { class: "grow" }, q.problem ? h("strong", null, q.file.name) : titleIn,
        h("div", { class: "row between" }, h("span", { class: "sub" }, q.file.name), q.status),
        q.problem ? null : h("div", { class: "progress" }, q.bar)),
      q.state === "ready" ? h("button", { type: "button", class: "icon-btn", "aria-label": `Remove ${q.file.name}`,
        onclick: () => { queue = queue.filter((x) => x !== q); q.row.remove(); refresh(); } }, icon("x")) : null);
    return q.row;
  };
  const add = (files) => {
    const room = MAX_FILES - queue.length;
    [...files].slice(0, room).forEach((f) => {
      const q = { file: f, title: f.name.replace(/\.[^.]+$/, "").replace(/[-_]+/g, " ").trim(), problem: precheck(f), state: "ready" };
      queue.push(q);
      list.append(drawRow(q));
    });
    if (files.length > room) toast(`Only ${MAX_FILES} files at a time.`, true);
    refresh();
  };
  input.addEventListener("change", () => { add(input.files); input.value = ""; });
  const zone = h("label", { class: "dropzone", for: "file", tabindex: "0",
    onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } } },
  icon("upload"), h("strong", null, "Drop files here"),
  h("span", { class: "muted small" }, "or click to choose. Up to 20 at once: PDF, images, text, CSV, Markdown or Office, 10 MB each."));
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("over"); }));
  zone.addEventListener("drop", (e) => add(e.dataTransfer.files));

  const form = h("form", { class: "grid-2", onsubmit: async (e) => {
    e.preventDefault(); put(err);
    const todo = queue.filter((q) => !q.problem && q.state === "ready");
    if (!todo.length) return;
    btn.disabled = true;
    const uploaded = [];
    for (const q of todo) {
      q.state = "uploading";
      q.row.querySelectorAll("input, button").forEach((x) => { x.disabled = true; });
      put(q.status, "Uploading…");
      const fd = new FormData();
      fd.append("title", q.title.trim() || q.file.name); fd.append("category", cat.value); fd.append("tags", tags.value);
      fd.append("description", desc.value); fd.append("file", q.file);
      try {
        const r = await upload("/api/documents", fd, (f) => { q.bar.style.width = Math.round(f * 100) + "%"; });
        q.state = "done"; q.row.classList.add("done");
        put(q.status, h("a", { href: "#/doc/" + r.document.id }, "Uploaded, open it"));
        uploaded.push(r.document);
      } catch (ex) {
        q.state = "failed"; q.row.classList.add("invalid");
        q.status.className = "small bad";
        put(q.status, ex.message);
      }
    }
    if (uploaded.length === 1 && todo.length === 1) { toast("Uploaded privately", false, "Nobody else can open it until you share it."); location.hash = "#/doc/" + uploaded[0].id; return; }
    toast(`${uploaded.length} of ${todo.length} uploaded privately`, uploaded.length !== todo.length, "Nobody else can open them until you share them.");
    refresh();
  } },
  h("section", { class: "panel stack" }, zone, input, summary, list,
    h("ul", { class: "checklist" },
      h("li", { class: "ok" }, icon("shield"), "Checked here first, then again on the server: real file contents, no scripts, no macros"),
      h("li", { class: "ok" }, icon("lock"), "Encrypted when stored, each file with its own key"))),
  h("section", { class: "panel" },
    h("p", { class: "small muted" }, "These apply to every file in this upload. You can change any of them later."),
    h("div", { class: "row" }, h("div", { class: "grow field" }, h("label", { for: "cat" }, "Category"), cat),
      h("div", { class: "grow field" }, h("label", { for: "tags" }, "Tags"), tags)),
    h("p", { class: "hint" }, "Tags help you find things. They never give anyone access."),
    h("div", { class: "field" }, h("label", { for: "desc" }, "Description"), desc),
    err, btn));

  render(shell("upload",
    h("div", { class: "page-head" }, h("div", null, h("h1", null, "Upload documents"),
      h("p", null, "Each file is encrypted as it is stored, and stays private to you until you share it with someone by name."))),
    form));
}

// ------------------------------------------------------------------ trash
export async function viewTrash(render) {
  const body = h("div", null, skeleton(2));
  render(shell("trash", h("div", { class: "page-head" }, h("div", null, h("h1", null, "Trash"),
    h("p", null, "Nobody, including you, can open a document while it is here."))), body));
  try {
    const r = await api("GET", "/api/documents/trash");
    if (!r.documents.length) { put(body, h("div", { class: "panel empty" }, icon("trash"), h("p", null, "The trash is empty."))); return; }
    put(body, h("div", { class: "panel" },
      h("p", { class: "small muted" }, `Documents are destroyed ${r.retention_days} days after they are moved here, unless they are under legal hold. Their audit record is kept.`),
      h("div", { class: "table-wrap" }, h("table", null, h("tbody", null, r.documents.map((d) => h("tr", null,
        h("td", null, h("div", { class: "cell-doc" }, seal(d.sha256, { label: false }), h("div", null, h("strong", null, d.title), h("span", { class: "sub" }, "Moved " + ago(d.deleted_at))))),
        h("td", null, d.legal_hold ? h("span", { class: "chip hold" }, "Legal hold") : null),
        h("td", { class: "nowrap" }, h("button", { class: "btn secondary small", onclick: async () => {
          if (!(await confirmDialog({ title: "Restore this document?", body: "Everyone who had access before will have it again.", confirm: "Restore" }))) return;
          try { await api("POST", `/api/documents/${d.id}/restore`); toast("Restored"); location.hash = "#/doc/" + d.id; }
          catch (ex) { toast(ex.message, true); }
        } }, icon("restore"), "Restore")))))))));
  } catch (ex) { put(body, errorNote(ex)); }
}
