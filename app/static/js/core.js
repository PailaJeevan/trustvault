// Core helpers. Nothing in the front end is a security control: the server
// decides every access. These helpers only make the UI honest and pleasant.
// User data is only ever inserted with textContent (via h), never as HTML.
import { icon } from "./icons.js";

export const state = { user: null, csrf: null, unread: 0, categories: ["HR", "Legal", "Finance", "Engineering", "Audit", "General"] };

/** Create an element. `style` takes an object and is applied through the CSSOM
 *  (allowed by our CSP); a style *attribute* would be blocked. */
export function h(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else if (k === "style" && typeof v === "object") Object.assign(e.style, v);
    else if (k === "value") e.value = v;
    else e.setAttribute(k, v === true ? "" : v);
  }
  append(e, children);
  return e;
}

export function append(parent, children) {
  for (const c of [children].flat(Infinity)) {
    if (c === null || c === undefined || c === false || c === "") continue;
    parent.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return parent;
}

/** Replace children, ignoring null/false (so `cond && node` is safe). */
export function put(parent, ...children) {
  parent.replaceChildren();
  return append(parent, children);
}

export { icon };

// ------------------------------------------------------------------ formatting
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const dateTimeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
export const fmtDate = (ts) => (ts ? dateFmt.format(new Date(ts)) : "");
export const fmtDateTime = (ts) => (ts ? dateTimeFmt.format(new Date(ts)) : "");
export function ago(ts) {
  if (!ts) return "";
  const s = (Date.now() - new Date(ts).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)} d ago`;
  return fmtDate(ts);
}
export function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}
export const initials = (name) => (name || "?").split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join("");
export const levelName = { owner: "Owner", edit: "Can edit", read: "Can read" };
export function levelChip(level) {
  return h("span", { class: "chip " + level }, icon(level === "owner" ? "key" : level === "edit" ? "edit" : "eye"), levelName[level] || level);
}
/** "Your access ends in N days" for grantees; nothing for owners or open-ended access. */
export function expiryChip(ts) {
  if (!ts) return null;
  const days = Math.ceil((new Date(ts).getTime() - Date.now()) / 86400000);
  const label = days <= 0 ? "Your access ends today" : days === 1 ? "Your access ends tomorrow" : `Your access ends in ${days} days`;
  return h("span", { class: "chip" + (days <= 7 ? " hold" : ""), title: "Until " + fmtDateTime(ts) }, icon("clock"), label);
}

export async function copyText(text, what = "Copied") {
  try { await navigator.clipboard.writeText(text); toast(what); }
  catch (_) { toast("Copy is not available in this browser.", true); }
}

export function avatar(name) { return h("span", { class: "avatar", "aria-hidden": "true" }, initials(name)); }

// ------------------------------------------------------------------ API
export class ApiError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}

export async function api(method, path, body, opts = {}) {
  const init = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET" && state.csrf) init.headers["X-CSRF-Token"] = state.csrf;
  if (body !== undefined) {
    if (body instanceof FormData) init.body = body;
    else { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
  }
  const res = await fetch(path, init);
  if (opts.raw && res.ok) return res;
  let data = null;
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (res.status === 401 && !path.startsWith("/api/auth/login")) {
    state.user = null;
    if (location.hash !== "#/login") location.hash = "#/login";
    throw new ApiError(401, "Your session has ended. Please sign in again.");
  }
  if (res.status === 403 && data && data.error === "reauth_required" && !opts.noReauth) {
    // Step-up: the server wants the password again before a sensitive action
    // (sharing, deleting, admin powers). Ask, confirm, then retry once.
    if (await reauthDialog()) return api(method, path, body, { ...opts, noReauth: true });
    throw new ApiError(403, "Cancelled. That action needs you to confirm your password.", "reauth_cancelled");
  }
  if (!res.ok) throw new ApiError(res.status, (data && data.message) || `Request failed (${res.status}).`, data && data.error);
  return data;
}

let reauthOpen = null;
/** Ask for the password (and a code with MFA) and unlock sensitive actions for a few minutes. */
export function reauthDialog() {
  if (reauthOpen) return reauthOpen;           // several requests at once share one prompt
  reauthOpen = overlay((close) => {
    const err = h("div");
    const pw = h("input", { id: "reauth-pw", type: "password", autocomplete: "current-password", required: true });
    const code = state.user && state.user.mfa_enabled
      ? h("input", { id: "reauth-code", class: "otp", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code", required: true }) : null;
    const btn = h("button", { type: "submit", class: "btn" }, icon("lock"), "Confirm");
    return h("form", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": "Confirm it's you",
      onsubmit: async (e) => {
        e.preventDefault(); put(err); btn.disabled = true;
        try {
          await api("POST", "/api/auth/reauth", code ? { password: pw.value, code: code.value } : { password: pw.value }, { noReauth: true });
          close(true);
        } catch (ex) { put(err, errorNote(ex)); btn.disabled = false; pw.select(); }
      } },
    h("div", { class: "reauth-head" }, icon("shield"), h("h2", null, "Confirm it's you")),
    h("p", { class: "muted" }, "This action changes who can reach documents or accounts, so it needs your password again. You won't be asked again for a few minutes."),
    h("div", { class: "field" }, h("label", { for: "reauth-pw" }, "Password"), pw),
    code ? h("div", { class: "field" }, h("label", { for: "reauth-code" }, "Code from your authenticator app"), code) : null,
    err,
    h("div", { class: "actions" }, h("button", { type: "button", class: "btn secondary", onclick: () => close(false) }, "Cancel"), btn));
  }).then((v) => { reauthOpen = null; return !!v; });
  return reauthOpen;
}

/** Upload with progress (fetch cannot report upload progress). */
export function upload(path, formData, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", path);
    x.withCredentials = true;
    if (state.csrf) x.setRequestHeader("X-CSRF-Token", state.csrf);
    x.upload.addEventListener("progress", (e) => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); });
    x.addEventListener("load", () => {
      let data = null;
      try { data = JSON.parse(x.responseText); } catch (_) { /* ignore */ }
      if (x.status >= 200 && x.status < 300) resolve(data);
      else reject(new ApiError(x.status, (data && data.message) || `Upload failed (${x.status}).`));
    });
    x.addEventListener("error", () => reject(new ApiError(0, "Network error during upload.")));
    x.send(formData);
  });
}

/** Download through fetch so we can read the audit receipt the server returns. */
export async function download(docId, version, filename) {
  const res = await api("GET", `/api/documents/${encodeURIComponent(docId)}/download${version ? "?version=" + version : ""}`, undefined, { raw: true });
  const receipt = res.headers.get("X-TrustVault-Receipt");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: filename || "document" });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
  toast(`Downloaded ${filename || "file"}`, false, receipt ? `Recorded in the audit trail as receipt #${receipt}` : "");
  return receipt;
}

// ------------------------------------------------------------------ feedback
export function toast(message, bad = false, detail = "") {
  const root = document.getElementById("toasts");
  const t = h("div", { class: "toast" + (bad ? " bad" : "") }, icon(bad ? "alert" : "check"),
    h("div", null, message, detail ? h("small", null, detail) : null));
  root.append(t);
  setTimeout(() => t.remove(), bad ? 6000 : 4200);
}

export function errorNote(err) {
  return h("div", { class: "note error", role: "alert" }, err && err.message ? err.message : String(err));
}

export function skeleton(lines = 3) {
  return h("div", { class: "stack", "aria-busy": "true" }, Array.from({ length: lines }, (_, i) => h("div", { class: "skel" + (i === 0 ? " h" : "") })));
}

// ------------------------------------------------------------------ dialogs (no window.confirm/prompt)
function overlay(build) {
  const root = document.getElementById("overlay-root");
  const prev = document.activeElement;
  return new Promise((resolve) => {
    const close = (v) => { scrim.remove(); document.removeEventListener("keydown", onKey); if (prev) prev.focus(); resolve(v); };
    const onKey = (e) => { if (e.key === "Escape") close(null); };
    const scrim = h("div", { class: "scrim", onclick: (e) => { if (e.target === scrim) close(null); } });
    scrim.append(build(close));
    root.append(scrim);
    document.addEventListener("keydown", onKey);
    const f = scrim.querySelector("input, button.btn:not(.secondary), button");
    if (f) f.focus();
  });
}

export function confirmDialog({ title, body, confirm = "Confirm", danger = false }) {
  return overlay((close) => h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title },
    h("h2", null, title), h("p", { class: "muted" }, body),
    h("div", { class: "actions" },
      h("button", { class: "btn secondary", onclick: () => close(false) }, "Cancel"),
      h("button", { class: "btn" + (danger ? " danger" : ""), onclick: () => close(true) }, confirm))));
}

export function promptDialog({ title, body, label, confirm = "Save", type = "text", minlength }) {
  return overlay((close) => {
    const input = h("input", { id: "dlg-input", type, minlength, autocomplete: type === "password" ? "new-password" : "off" });
    return h("form", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title,
      onsubmit: (e) => { e.preventDefault(); if (input.value.trim()) close(input.value); } },
    h("h2", null, title), body ? h("p", { class: "muted" }, body) : null,
    h("label", { for: "dlg-input" }, label), input,
    h("div", { class: "actions" },
      h("button", { type: "button", class: "btn secondary", onclick: () => close(null) }, "Cancel"),
      h("button", { type: "submit", class: "btn" }, confirm)));
  });
}

export function openOverlay(build) { return overlay(build); }

// ------------------------------------------------------------------ theme
export function currentTheme() {
  const set = document.documentElement.getAttribute("data-theme");
  if (set) return set;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}
export function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("tv-theme", next); } catch (_) { /* fine */ }
  return next;
}

// ------------------------------------------------------------------ labels for audit actions
export const ACTION = {
  "document.upload": "uploaded", "document.download": "downloaded", "document.view": "viewed", "document.read": "opened",
  "document.update": "changed the details of", "document.new_version": "uploaded a new version of",
  "document.delete": "moved to trash", "document.restore": "restored", "document.edit": "tried to edit",
  "document.share": "tried to share", "document.manage": "tried to manage access to",
  "document.view_activity": "tried to view the record of", "document.purge": "destroyed the content of",
  "permission.grant": "gave access to", "permission.change": "changed access to", "permission.revoke": "removed access to",
  "admin.ownership_transfer": "transferred ownership of", "admin.legal_hold": "placed a legal hold on",
  "admin.legal_hold_release": "released the legal hold on",
};
export function describe(e) {
  let action = e.action;
  try { if (action === "document.download" && JSON.parse(e.details || "{}").purpose === "view") action = "document.view"; } catch (_) { /* not JSON */ }
  const verb = ACTION[action] || action;
  return e.outcome === "denied" ? `was refused: ${verb.replace(/^tried to /, "")}` : verb;
}
