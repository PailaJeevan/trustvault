import { ago, api, avatar, confirmDialog, errorNote, fmtDate, h, icon, levelChip, put, skeleton, state, toast } from "../core.js";
import { shell, roleName } from "../shell.js";

// ------------------------------------------------------------------ access review
export async function viewReview(render) {
  const body = h("div", null, skeleton(2));
  render(shell("review",
    h("div", { class: "page-head" }, h("div", null, h("h1", null, "Access review"),
      h("p", null, "Everyone who can open a document you own. Access that is never reviewed only ever grows."))),
    body));
  try {
    const r = await api("GET", "/api/review/grants");
    if (!r.grants.length) { put(body, h("div", { class: "panel empty" }, icon("shield"), h("p", null, "Nobody else can open any of your documents."))); return; }
    const picked = new Set();
    let filter = "all";
    const serious = new Set(["inactive", "external", "sensitive_edit"]);
    const counts = {};
    r.grants.forEach((g) => g.flags.forEach((f) => { counts[f.code] = (counts[f.code] || 0) + 1; }));
    const flagged = r.grants.filter((g) => g.flags.length).length;

    const revokeBtn = h("button", { class: "btn danger", disabled: true, onclick: async () => {
      if (!(await confirmDialog({ title: `Remove ${picked.size} grant${picked.size === 1 ? "" : "s"}?`, body: "Access stops on each person's next click. All of them are removed, or none if any one is refused.", confirm: "Remove access", danger: true }))) return;
      try { const x = await api("POST", "/api/review/revoke", { grant_ids: [...picked] }); toast(`Removed ${x.revoked} grant${x.revoked === 1 ? "" : "s"}`); viewReview(render); }
      catch (ex) { toast(ex.message, true); }
    } }, icon("ban"), "Remove selected");
    const sync = () => { revokeBtn.disabled = !picked.size; put(revokeBtn, icon("ban"), picked.size ? `Remove ${picked.size} selected` : "Remove selected"); };

    const filterBar = h("div", { class: "cat-tabs" });
    const tbody = h("tbody");
    let mode = (() => { try { return localStorage.getItem("tv-review-mode") || "table"; } catch (_) { return "table"; } })();
    const view = h("div");
    const table = h("table", null,
      h("thead", null, h("tr", null, ["", "Person", "Document", "Access", "Last download", "Worth a look"].map((t) => h("th", null, t)))), tbody);

    const matching = () => r.grants.filter((g) => filter === "all" || (filter === "flagged" ? g.flags.length : g.flags.some((f) => f.code === filter)));

    // People x documents. Each cell is one grant; click to select it for revoking.
    const accessMap = (rows) => {
      const people = [...new Map(rows.map((g) => [g.user.id, g.user])).values()].sort((a, b) => a.name.localeCompare(b.name));
      const docs = [...new Map(rows.map((g) => [g.document.id, g.document])).values()].sort((a, b) => a.title.localeCompare(b.title));
      const at = new Map(rows.map((g) => [g.user.id + "|" + g.document.id, g]));
      return h("div", { class: "table-wrap" }, h("table", { class: "access-map" },
        h("thead", null, h("tr", null, h("th", { class: "corner" }, `${people.length} people × ${docs.length} documents`),
          docs.map((d) => h("th", { class: "doc-col", title: d.title }, h("a", { href: "#/doc/" + d.id + "/sharing" }, d.title), h("span", { class: "sub" }, d.category))))),
        h("tbody", null, people.map((p) => h("tr", null,
          h("th", { scope: "row" }, h("div", { class: "cell-doc" }, avatar(p.name), h("div", null, h("strong", null, p.name), h("span", { class: "sub" }, p.email)))),
          docs.map((d) => {
            const g = at.get(p.id + "|" + d.id);
            if (!g) return h("td", { class: "empty-cell", "aria-label": `${p.name} has no access to ${d.title}` }, "");
            const serious_ = g.flags.some((f) => serious.has(f.code));
            const cell = h("button", {
              class: `map-cell ${g.permission}${g.flags.length ? " flagged" : ""}${serious_ ? " serious" : ""}`,
              "aria-pressed": String(picked.has(g.grant_id)),
              "aria-label": `${p.name}, ${g.permission === "edit" ? "can edit" : "can read"} ${d.title}${g.flags.length ? ". " + g.flags.map((f) => f.text).join(", ") : ""}. Select to remove.`,
              title: [g.permission === "edit" ? "Can edit" : "Can read", g.expires_at ? "until " + fmtDate(g.expires_at) : "no end date", ...g.flags.map((f) => f.text)].join(", "),
              onclick: (e) => { picked.has(g.grant_id) ? picked.delete(g.grant_id) : picked.add(g.grant_id); e.currentTarget.setAttribute("aria-pressed", String(picked.has(g.grant_id))); sync(); },
            }, g.permission === "edit" ? "Edit" : "Read", g.flags.length ? icon("alert") : null);
            return h("td", null, cell);
          }))))),
      h("div", { class: "legend small" }, h("span", null, h("i", { class: "allowed" }), "Can edit"), h("span", null, h("i", { class: "read" }), "Can read"),
        h("span", null, h("i", { class: "soon" }), "Worth a look"), h("span", null, "Click cells to select them, then remove.")));
    };

    const modeBar = h("div", { class: "view-toggle", role: "group", "aria-label": "Layout" });
    const draw = () => {
      put(filterBar, [["all", `All ${r.grants.length}`], ["flagged", `Flagged ${flagged}`], ...Object.entries(counts).map(([k, n]) => [k, `${labelFor(k)} ${n}`])]
        .map(([k, l]) => h("button", { "aria-pressed": String(filter === k), onclick: () => { filter = k; draw(); } }, l)));
      put(modeBar,
        h("button", { "aria-pressed": String(mode === "table"), "aria-label": "Table", title: "Table", onclick: () => { mode = "table"; try { localStorage.setItem("tv-review-mode", mode); } catch (_) { /* fine */ } draw(); } }, icon("list")),
        h("button", { "aria-pressed": String(mode === "map"), "aria-label": "Access map", title: "Access map", onclick: () => { mode = "map"; try { localStorage.setItem("tv-review-mode", mode); } catch (_) { /* fine */ } draw(); } }, icon("grid")));
      const rows = matching();
      if (mode === "map") { put(view, accessMap(rows)); return; }
      put(tbody, rows.map((g) => {
        const cb = h("input", { type: "checkbox", "aria-label": `Select ${g.user.name} on ${g.document.title}`,
          onchange: (e) => { e.target.checked ? picked.add(g.grant_id) : picked.delete(g.grant_id); sync(); } });
        cb.checked = picked.has(g.grant_id);
        return h("tr", null,
          h("td", null, cb),
          h("td", null, h("div", { class: "cell-doc" }, avatar(g.user.name), h("div", null, h("strong", null, g.user.name), h("span", { class: "sub" }, g.user.email)))),
          h("td", null, h("a", { href: "#/doc/" + g.document.id + "/sharing" }, g.document.title), h("span", { class: "sub" }, g.document.category)),
          h("td", null, levelChip(g.permission), h("span", { class: "sub" }, g.expires_at ? "Until " + fmtDate(g.expires_at) : "No end date")),
          h("td", { class: "small nowrap" }, g.last_download ? ago(g.last_download) : "Never"),
          h("td", null, g.flags.length ? g.flags.map((f) => h("span", { class: "flag" + (serious.has(f.code) ? " serious" : "") }, icon("alert"), f.text)) : h("span", { class: "small muted" }, "Looks fine")));
      }));
      put(view, h("div", { class: "table-wrap" }, table));
    };
    draw();
    put(body, h("section", { class: "panel" },
      h("div", { class: "row between" }, filterBar, h("div", { class: "row" }, modeBar, revokeBtn)),
      view));
  } catch (ex) { put(body, errorNote(ex)); }
}

function labelFor(code) {
  return { no_expiry: "Never expires", external: "External", unused: "Unused", sensitive_edit: "Sensitive edit", inactive: "Deactivated", expiring: "Expiring" }[code] || code;
}

// ------------------------------------------------------------------ account
export async function viewAccount(render) {
  const mfa = h("section", { class: "panel" }, skeleton(1));
  const sessions = h("section", { class: "panel" }, skeleton(1));
  const pwBox = h("section", { class: "panel" });
  render(shell("account",
    h("div", { class: "page-head" }, h("div", { class: "row" }, avatar(state.user.name),
      h("div", null, h("h1", null, state.user.name), h("p", null, `${state.user.email}, ${roleName(state.user.role).toLowerCase()}`)))),
    h("div", { class: "grid-2" }, h("div", { class: "stack" }, mfa, sessions), pwBox)));
  drawMfa(mfa, () => drawSessions(sessions));
  drawSessions(sessions);
  drawPassword(pwBox);
}

async function drawMfa(box, onChange) {
  const me = (await api("GET", "/api/auth/me")).user;
  state.user = me;
  const err = h("div");
  if (me.mfa_enabled) {
    const pw = h("input", { id: "mfa-pw", type: "password", autocomplete: "current-password" });
    const code = h("input", { id: "mfa-code", class: "otp", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code" });
    put(box, h("div", { class: "panel-head" }, h("h2", null, "Two-step sign-in"), h("span", { class: "chip edit" }, icon("check"), "On")),
      h("p", { class: "muted" }, "Signing in needs your password and a code from your phone. A stolen password alone is not enough."),
      h("details", null, h("summary", { class: "small" }, "Turn two-step sign-in off"),
        h("form", { class: "stack", onsubmit: async (e) => {
          e.preventDefault(); put(err);
          try { await api("POST", "/api/auth/mfa/disable", { current_password: pw.value, code: code.value }); toast("Two-step sign-in turned off"); drawMfa(box, onChange); }
          catch (ex) { put(err, errorNote(ex)); }
        } },
        h("p", { class: "small muted" }, "You need both your password and a current code, so a stolen session can't do this."),
        h("div", { class: "row" }, h("div", { class: "grow" }, h("label", { for: "mfa-pw" }, "Password"), pw), h("div", { class: "grow" }, h("label", { for: "mfa-code" }, "Code"), code)),
        err, h("button", { class: "btn danger", type: "submit" }, "Turn off"))));
    return;
  }
  const pw = h("input", { id: "mfa-pw", type: "password", autocomplete: "current-password" });
  put(box, h("div", { class: "panel-head" }, h("h2", null, "Two-step sign-in"), h("span", { class: "chip" }, "Off")),
    h("p", { class: "muted" }, "Add a 6-digit code from your phone to every sign-in."),
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); put(err);
      try {
        const r = await api("POST", "/api/auth/mfa/setup", { current_password: pw.value });
        const code = h("input", { id: "mfa-code", class: "otp", inputmode: "numeric", maxlength: 6, autocomplete: "one-time-code" });
        const err2 = h("div");
        put(box, h("h2", null, "Set up two-step sign-in"),
          h("ol", { class: "steps" },
            h("li", null, "Open an authenticator app: Google Authenticator, Microsoft Authenticator, Authy or 1Password."),
            h("li", null, "Choose ", h("strong", null, "Enter a setup key"), ", name it TrustVault, choose time-based, and type:",
              h("div", { class: "setup-key" }, r.secret.replace(/(.{4})/g, "$1 ").trim())),
            h("li", null, "Enter the 6-digit code the app shows.",
              h("form", { class: "row", onsubmit: async (ev) => {
                ev.preventDefault(); put(err2);
                try { await api("POST", "/api/auth/mfa/enable", { code: code.value }); toast("Two-step sign-in is on", false, "Your other sessions were signed out."); drawMfa(box, onChange); if (onChange) onChange(); }
                catch (ex) { put(err2, errorNote(ex)); }
              } }, h("div", { class: "grow" }, code), h("button", { class: "btn", type: "submit" }, "Turn on")), err2)));
        code.focus();
      } catch (ex) { put(err, errorNote(ex)); }
    } },
    h("div", { class: "row" }, h("div", { class: "grow" }, h("label", { for: "mfa-pw" }, "Confirm your password to start"), pw),
      h("button", { class: "btn", type: "submit" }, icon("key"), "Set up")), err));
}

async function drawSessions(box) {
  try {
    const r = await api("GET", "/api/auth/sessions");
    put(box, h("div", { class: "panel-head" }, h("h2", null, "Where you're signed in"),
      r.sessions.length > 1 ? h("button", { class: "btn secondary small", onclick: async () => {
        try { const x = await api("POST", "/api/auth/sessions/end-others"); toast(`Signed out of ${x.ended} other device${x.ended === 1 ? "" : "s"}`); drawSessions(box); }
        catch (ex) { toast(ex.message, true); }
      } }, "Sign out everywhere else") : null),
    h("ul", { class: "people" }, r.sessions.map((x) => h("li", null,
      h("span", { class: "avatar" }, icon("device")),
      h("div", null, h("strong", null, browserName(x.user_agent)), h("span", { class: "sub" }, `${x.ip || "unknown address"}, signed in ${ago(x.created_at)}, active ${ago(x.last_seen_at)}`)),
      x.current ? h("span", { class: "chip edit" }, "This device") : h("button", { class: "btn secondary small", onclick: async () => {
        try { await api("DELETE", "/api/auth/sessions/" + x.public_id); toast("Signed out of that device"); drawSessions(box); }
        catch (ex) { toast(ex.message, true); }
      } }, "Sign out"), h("span")))));
  } catch (ex) { put(box, errorNote(ex)); }
}

function browserName(ua) {
  if (!ua) return "Unknown device";
  const b = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${b} on ${os}` : b;
}

function drawPassword(box) {
  const err = h("div");
  const cur = h("input", { id: "pw-cur", type: "password", autocomplete: "current-password" });
  const nw = h("input", { id: "pw-new", type: "password", autocomplete: "new-password", minlength: 12 });
  const meter = h("div"); const meterWrap = h("div", { class: "meter" }, meter);
  const hint = h("p", { class: "hint" }, "At least 12 characters. A short sentence is easy to remember and hard to guess.");
  nw.addEventListener("input", () => {
    const v = nw.value, score = Math.min(4, Math.floor(v.length / 5) + (/[A-Z]/.test(v) && /[a-z]/.test(v) ? 1 : 0) + (/\d|\W/.test(v) ? 1 : 0) - (v.length < 12 ? 2 : 0));
    meter.style.width = Math.max(5, score * 25) + "%";
  });
  put(box, h("h2", null, "Change password"),
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); put(err);
      try { await api("POST", "/api/auth/password", { current_password: cur.value, new_password: nw.value }); toast("Password changed", false, "Your other sessions were signed out."); cur.value = nw.value = ""; }
      catch (ex) { put(err, errorNote(ex)); }
    } },
    h("div", { class: "field" }, h("label", { for: "pw-cur" }, "Current password"), cur),
    h("div", { class: "field" }, h("label", { for: "pw-new" }, "New password"), nw, meterWrap, hint),
    err, h("button", { class: "btn", type: "submit" }, "Change password")),
    h("hr", { class: "divider" }),
    h("h2", null, "Your record"),
    h("p", { class: "small muted" }, "Every sign-in, download and change you make is written to the audit trail. Owners can see who opened their documents; administrators can see everything except document contents."));
}
