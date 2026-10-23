import { ago, api, avatar, confirmDialog, copyText, describe, download, errorNote, expiryChip, fmtDate, fmtDateTime, fmtSize, h, icon, levelChip, put, skeleton, state, toast, upload } from "../core.js";
import { accessTimeline, dailySeries, mirrorChart } from "../charts.js";
import { seal } from "../seal.js";
import { canView, openViewer } from "../viewer.js";
import { shell } from "../shell.js";

export async function viewDocument(render, id, tabWanted) {
  render(shell("documents", skeleton(3)));
  let doc;
  try { doc = (await api("GET", "/api/documents/" + encodeURIComponent(id))).document; }
  catch (ex) {
    render(shell("documents", h("div", { class: "panel empty" }, icon("lock"),
      h("h2", null, ex.status === 404 ? "Document not found" : "Can't open this document"),
      h("p", null, ex.status === 404 ? "It does not exist, or it has not been shared with you. Those two cases look the same on purpose." : ex.message),
      h("a", { class: "btn secondary", href: "#/documents" }, "Back to documents"))));
    return;
  }
  const lvl = doc.my_access;
  const isOwner = lvl === "owner";
  const canEdit = isOwner || lvl === "edit";
  const canWiden = isOwner && state.user.role === "owner";

  const tabs = [["versions", "Versions", icon("history"), doc.versions.length]];
  if (isOwner) tabs.push(["sharing", "Sharing", icon("share")], ["custody", "Custody record", icon("chain")]);
  if (canEdit) tabs.push(["details", "Edit details", icon("edit")]);
  let current = tabs.some((t) => t[0] === tabWanted) ? tabWanted : (isOwner ? "sharing" : "versions");
  const tabBar = h("div", { class: "tabs", role: "tablist" });
  const pane = h("div", { role: "tabpanel" });
  const showTab = (key) => {
    current = key;
    put(tabBar, tabs.map(([k, label, ic, n]) => h("button", { role: "tab", "aria-selected": String(k === key), onclick: () => showTab(k) },
      ic, label, n ? h("span", { class: "n" }, n) : null)));
    put(pane, skeleton(1));
    const builder = { versions: versionsTab, sharing: sharingTab, custody: custodyTab, details: detailsTab }[key];
    builder(doc, pane, { canWiden, reload: (t) => viewDocument(render, id, t || current) });
  };

  const hero = h("section", { class: "panel doc-hero" },
    h("div", null, h("div", { class: "seal-wrap" }, seal(doc.sha256, { title: `Custody seal of version ${doc.current_version}` })),
      h("div", { class: "seal-caption" }, "Seal of the current file. A different file can never draw this seal.")),
    h("div", null,
      h("div", { class: "chips" }, levelChip(lvl), expiryChip(doc.my_expires_at), h("span", { class: "chip cat" }, doc.category),
        doc.legal_hold ? h("span", { class: "chip hold" }, icon("hold"), "Legal hold") : null,
        (doc.tags || []).map((t) => h("span", { class: "chip tag" }, icon("tag"), t))),
      h("h1", null, doc.title),
      doc.description ? h("p", { class: "muted" }, doc.description) : null,
      h("div", { class: "facts" },
        h("span", null, icon("user"), "Owner: " + doc.owner.name),
        h("span", null, icon("file"), `${doc.filename}, ${fmtSize(doc.size_bytes)}`),
        h("span", null, icon("history"), `Version ${doc.current_version}, changed ${ago(doc.updated_at)}`)),
      h("div", { class: "row" },
        canView(doc.filename) ? h("button", { class: "btn", onclick: () => openViewer(doc) }, icon("eye"), "Open") : null,
        h("button", { class: canView(doc.filename) ? "btn secondary" : "btn", onclick: () => download(doc.id, null, doc.filename).catch((ex) => toast(ex.message, true)) }, icon("download"), "Download"),
        isOwner ? h("button", { class: "btn danger", disabled: doc.legal_hold, title: doc.legal_hold ? "Under legal hold" : null, onclick: async () => {
          if (!(await confirmDialog({ title: "Move to trash?", body: "Nobody, including you, can open it while it is in the trash. You can restore it for 30 days.", confirm: "Move to trash", danger: true }))) return;
          try { await api("DELETE", "/api/documents/" + doc.id); toast("Moved to trash"); location.hash = "#/documents"; }
          catch (ex) { toast(ex.message, true); }
        } }, icon("trash"), "Move to trash") : null),
      doc.legal_hold ? h("p", { class: "note warn small" }, "An administrator has placed this document under legal hold. It cannot be deleted until the hold is released.") : null));

  render(shell("documents",
    h("div", { class: "crumbs" }, h("a", { href: "#/documents" }, "Documents"), " / ", doc.title),
    h("div", { class: "stack" }, hero, h("section", { class: "panel" }, tabBar, pane))));
  showTab(current);
}

// ------------------------------------------------------------------ versions
function versionsTab(doc, pane, { reload }) {
  put(pane,
    h("ul", { class: "versions" }, doc.versions.map((v) => h("li", null,
      seal(v.sha256, { label: false }),
      h("div", null,
        h("div", null, h("span", { class: "v" }, "v" + v.version_no), " ", v.filename, v.version_no === doc.current_version ? h("span", { class: "chip edit" }, "Current") : null),
        h("div", { class: "small muted" }, `${fmtDateTime(v.created_at)} by ${v.uploaded_by}, ${fmtSize(v.size_bytes)}`),
        h("div", { class: "hash-row" }, h("span", { class: "hash" }, "SHA-256 " + v.sha256),
          h("button", { class: "linkish xs", "aria-label": `Copy SHA-256 of version ${v.version_no}`, onclick: () => copyText(v.sha256, "Hash copied") }, "Copy"))),
      h("div", { class: "row" },
        canView(v.filename) ? h("button", { class: "btn ghost small", onclick: () => openViewer(doc, v.version_no === doc.current_version ? null : v.version_no) }, icon("eye"), "Open") : null,
        h("button", { class: "btn secondary small", onclick: () => download(doc.id, v.version_no, v.filename).catch((ex) => toast(ex.message, true)) }, icon("download"), "Download"))))),
    (doc.my_access === "owner" || doc.my_access === "edit") ? newVersionForm(doc, reload) : null);
}

function newVersionForm(doc, reload) {
  const input = h("input", { type: "file", id: "vfile" });
  const bar = h("div");
  const prog = h("div", { class: "progress", hidden: true }, bar);
  const err = h("div");
  return h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault(); put(err);
    if (!input.files[0]) return;
    const fd = new FormData(); fd.append("file", input.files[0]);
    prog.hidden = false;
    try { await upload(`/api/documents/${doc.id}/versions`, fd, (f) => { bar.style.width = f * 100 + "%"; }); toast("New version uploaded", false, "The old version is kept."); reload("versions"); }
    catch (ex) { put(err, errorNote(ex)); prog.hidden = true; }
  } },
  h("hr", { class: "divider" }),
  h("div", { class: "row" }, h("div", { class: "grow" }, h("label", { for: "vfile" }, "Upload a new version"), input),
    h("button", { class: "btn secondary", type: "submit" }, icon("upload"), "Upload version")), prog, err);
}

// ------------------------------------------------------------------ sharing
const PRESETS = [["7", "7 days"], ["30", "30 days"], ["90", "90 days"], ["", "No end date"]];
const plusDays = (n) => { const d = new Date(); d.setDate(d.getDate() + Number(n)); return d.toISOString().slice(0, 10); };

async function sharingTab(doc, pane, { canWiden, reload }) {
  let data;
  try { data = await api("GET", `/api/documents/${doc.id}/grants`); } catch (ex) { put(pane, errorNote(ex)); return; }

  const people = data.grants.length
    ? h("ul", { class: "people" }, data.grants.map((g) => h("li", null, avatar(g.user.name),
      h("div", null, h("strong", null, g.user.name), h("span", { class: "sub" }, g.user.email),
        h("span", { class: "sub" }, g.expires_at ? (g.expired ? "Expired " : "Until ") + fmtDate(g.expires_at) : "No end date",
          g.source === "suggestion" ? ", added from a suggestion" : "")),
      h("select", { "aria-label": `Access for ${g.user.name}`, onchange: async (e) => {
        try { await api("PATCH", `/api/documents/${doc.id}/grants/${g.id}`, { permission: e.target.value }); toast("Access changed"); }
        catch (ex) { toast(ex.message, true); e.target.value = g.permission; }
      } }, ["read", "edit"].map((p) => h("option", { value: p, selected: g.permission === p }, p === "read" ? "Can read" : "Can edit"))),
      h("button", { class: "btn danger small", onclick: async () => {
        if (!(await confirmDialog({ title: `Remove ${g.user.name}?`, body: "Their access stops on their very next click, including any page they already have open.", confirm: "Remove access", danger: true }))) return;
        try { await api("DELETE", `/api/documents/${doc.id}/grants/${g.id}`); toast("Access removed", false, `${g.user.name} can no longer open this document.`); reload("sharing"); }
        catch (ex) { toast(ex.message, true); }
      } }, "Remove"))))
    : h("p", { class: "muted" }, "Only you can open this document.");

  const blocks = [h("h2", null, "People with access"),
    data.grants.length ? h("div", { class: "panel-sub" }, h("h3", null, "When access starts and ends"), accessTimeline(data.grants)) : null,
    people];
  if (!canWiden) {
    blocks.push(h("p", { class: "note warn small" }, "Your role no longer allows sharing. You can still remove access."));
  } else {
    blocks.push(h("hr", { class: "divider" }), h("h2", null, "Share with someone"), shareForm(doc, reload), suggestionsBlock(doc, reload));
  }
  put(pane, blocks);
}

function shareForm(doc, reload) {
  let picked = null, perm = "read", preset = "30";
  const err = h("div");
  const search = h("input", { id: "who", placeholder: "Search by name or email", autocomplete: "off", role: "combobox", "aria-expanded": "false", "aria-controls": "who-list" });
  const list = h("ul", { class: "combo-list", id: "who-list", role: "listbox", hidden: true });
  const pickedBox = h("div");
  const custom = h("input", { type: "date", id: "until", "aria-label": "Custom end date", min: plusDays(1), hidden: true });
  let results = [], sel = 0, timer;

  const renderList = () => {
    list.hidden = !results.length;
    search.setAttribute("aria-expanded", String(!list.hidden));
    put(list, results.map((u, i) => h("li", { role: "option", "aria-selected": String(i === sel), onmousedown: (e) => { e.preventDefault(); choose(u); } },
      avatar(u.name), h("div", null, h("strong", null, u.name), h("span", { class: "sub" }, u.email)))));
  };
  const choose = (u) => {
    picked = u; results = []; renderList(); search.value = "";
    put(pickedBox, h("div", { class: "picked" }, avatar(u.name), h("div", null, h("strong", null, u.name), h("span", { class: "sub" }, u.email)),
      h("button", { type: "button", class: "icon-btn", "aria-label": "Clear", onclick: () => { picked = null; put(pickedBox); search.focus(); } }, icon("x"))));
  };
  search.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!search.value.trim()) { results = []; renderList(); return; }
      try { results = (await api("GET", "/api/users/directory?q=" + encodeURIComponent(search.value))).users.filter((u) => u.id !== doc.owner.id); sel = 0; renderList(); }
      catch (ex) { toast(ex.message, true); }
    }, 180);
  });
  search.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(results.length - 1, sel + 1); renderList(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); renderList(); }
    else if (e.key === "Enter" && results[sel]) { e.preventDefault(); choose(results[sel]); }
    else if (e.key === "Escape") { results = []; renderList(); }
  });
  search.addEventListener("blur", () => setTimeout(() => { results = []; renderList(); }, 120));

  const permGroup = h("div", { class: "presets", role: "group", "aria-label": "Access level" });
  const drawPerm = () => put(permGroup, [["read", "Can read"], ["edit", "Can edit"]].map(([v, l]) =>
    h("button", { type: "button", "aria-pressed": String(perm === v), onclick: () => { perm = v; drawPerm(); } }, l)));
  const presetGroup = h("div", { class: "presets", role: "group", "aria-label": "Access ends" });
  const drawPreset = () => {
    put(presetGroup, [...PRESETS, ["custom", "Pick a date"]].map(([v, l]) =>
      h("button", { type: "button", "aria-pressed": String(preset === v), onclick: () => { preset = v; drawPreset(); } }, l)));
    custom.hidden = preset !== "custom";
  };
  drawPerm(); drawPreset();

  return h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault(); put(err);
    if (!picked) { put(err, errorNote(new Error("Choose a person first."))); return; }
    const expires = preset === "custom" ? custom.value : preset ? plusDays(preset) : null;
    if (preset === "custom" && !expires) { put(err, errorNote(new Error("Pick an end date."))); return; }
    try {
      await api("POST", `/api/documents/${doc.id}/grants`, { user_id: picked.id, permission: perm, expires_at: expires });
      toast(`Shared with ${picked.name}`, false, expires ? `Access ends ${fmtDate(expires)}.` : "Access has no end date.");
      reload("sharing");
    } catch (ex) { put(err, errorNote(ex)); }
  } },
  h("div", { class: "combo" }, h("label", { for: "who" }, "Person"), search, list), pickedBox,
  h("div", { class: "row" }, h("div", null, h("span", { class: "label" }, "Access"), permGroup),
    h("div", { class: "grow" }, h("span", { class: "label" }, "Access ends"), presetGroup, custom)),
  err, h("div", null, h("button", { class: "btn", type: "submit" }, icon("share"), "Share")));
}

function suggestionsBlock(doc, reload) {
  const box = h("div");
  const btn = h("button", { class: "btn ghost", type: "button", onclick: async () => {
    btn.disabled = true;
    try {
      const r = await api("POST", `/api/documents/${doc.id}/suggestions`);
      if (!r.suggestions.length) { put(box, h("p", { class: "small muted" }, "No suggestions for this document.")); return; }
      put(box, h("p", { class: "small muted" }, r.note), h("ul", { class: "people" }, r.suggestions.map((s) => h("li", null, avatar(s.user.name),
        h("div", null, h("strong", null, s.user.name), h("span", { class: "sub" }, s.reason)),
        h("button", { class: "btn small", onclick: async () => {
          try { await api("POST", `/api/documents/${doc.id}/suggestions/${s.id}/accept`, { permission: "read", expires_at: plusDays(30) }); toast(`Shared with ${s.user.name}`, false, "Read access for 30 days. You made this decision; it is recorded."); reload("sharing"); }
          catch (ex) { toast(ex.message, true); }
        } }, "Give read access"),
        h("button", { class: "btn secondary small", onclick: async () => {
          try { await api("POST", `/api/documents/${doc.id}/suggestions/${s.id}/dismiss`); toast("Suggestion dismissed"); btn.disabled = false; put(box); }
          catch (ex) { toast(ex.message, true); }
        } }, "Dismiss")))));
    } catch (ex) { toast(ex.message, true); btn.disabled = false; }
  } }, icon("sparkle"), "Suggest people");
  return h("div", null, h("hr", { class: "divider" }), h("div", { class: "row between" },
    h("div", null, h("h2", null, "Suggestions"), h("p", { class: "small muted" }, "Based on who can already open your other documents in this category. Nothing is shared unless you choose to.")), btn), box);
}

// ------------------------------------------------------------------ custody
async function custodyTab(doc, pane) {
  try {
    const r = await api("GET", `/api/documents/${doc.id}/activity`);
    if (!r.activity.length) { put(pane, h("p", { class: "muted" }, "No activity yet.")); return; }
    const refused = r.activity.filter((a) => a.outcome === "denied").length;
    put(pane,
      h("div", { class: "panel-sub" }, h("h3", null, "Last 30 days"),
        mirrorChart(dailySeries(r.activity, 30), { height: 150, labelEvery: 7, title: "Actions on this document per day" })),
      h("p", { class: "small muted" }, `Every action on this document, newest first. ${refused ? refused + " refused attempt" + (refused === 1 ? "" : "s") + " shown in red." : "No refused attempts."} Each line is a record in the hash-chained audit trail.`),
      h("ol", { class: "custody" }, r.activity.map((a) => {
        let d = {}; try { d = JSON.parse(a.details); } catch (_) { /* ignore */ }
        const extra = d.grantee || (d.version ? "v" + d.version : "") || (d.reason ? d.reason.replace(/_/g, " ") : "");
        if (d.purpose === "view" && a.action === "document.download") a = { ...a, action: "document.view" };
        return h("li", { class: a.outcome === "denied" ? "denied" : "" },
          h("div", { class: "when" }, `#${a.seq}, ${fmtDateTime(a.ts)}`),
          h("div", { class: "what" }, h("span", { class: "who" }, a.actor_email || "System"), " ", describe(a).replace(/ of$| to$/, ""), extra ? h("span", { class: "muted" }, ` (${extra})`) : null));
      })));
  } catch (ex) { put(pane, errorNote(ex)); }
}

// ------------------------------------------------------------------ details
function detailsTab(doc, pane, { reload }) {
  const err = h("div");
  const title = h("input", { id: "etitle", value: doc.title, maxlength: 200 });
  const cat = h("select", { id: "ecat" }, state.categories.map((c) => h("option", { value: c, selected: c === doc.category }, c)));
  const tags = h("input", { id: "etags", value: (doc.tags || []).join(", ") });
  const desc = h("textarea", { id: "edesc", maxlength: 2000 });
  desc.value = doc.description || "";
  put(pane, h("form", { onsubmit: async (e) => {
    e.preventDefault(); put(err);
    try {
      await api("PATCH", "/api/documents/" + doc.id, { title: title.value, category: cat.value, description: desc.value,
        tags: tags.value.split(",").map((t) => t.trim()).filter(Boolean) });
      toast("Changes saved", false, "Recorded in the custody record.");
      reload("details");
    } catch (ex) { put(err, errorNote(ex)); }
  } },
  h("div", { class: "field" }, h("label", { for: "etitle" }, "Name"), title),
  h("div", { class: "row" }, h("div", { class: "grow field" }, h("label", { for: "ecat" }, "Category"), cat),
    h("div", { class: "grow field" }, h("label", { for: "etags" }, "Tags, comma separated"), tags)),
  h("div", { class: "field" }, h("label", { for: "edesc" }, "Description"), desc),
  err, h("button", { class: "btn", type: "submit" }, "Save changes")));
}
