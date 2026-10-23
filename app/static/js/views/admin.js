import { ago, api, avatar, confirmDialog, errorNote, fmtDateTime, h, icon, promptDialog, put, skeleton, state, toast } from "../core.js";
import { mirrorChart, meterList } from "../charts.js";
import { seal } from "../seal.js";
import { shell, roleName } from "../shell.js";

const TABS = [["overview", "Overview"], ["alerts", "Alerts"], ["approvals", "Approvals"], ["audit", "Audit trail"], ["chain", "Integrity chain"], ["users", "People"], ["documents", "Documents"]];

function frame(render, tab, ...content) {
  render(shell("admin",
    h("div", { class: "page-head" }, h("div", null, h("h1", null, "Administration"),
      h("p", null, "Accounts, oversight and evidence. Administrators never see document contents."))),
    h("div", { class: "tabs", role: "tablist" }, TABS.map(([k, l]) => h("button", { role: "tab", "aria-selected": String(k === tab),
      onclick: () => { location.hash = "#/admin/" + k; } }, l))),
    ...content));
}

export async function viewAdmin(render, tab = "overview", query = "") {
  const fn = { overview: adminOverview, alerts, approvals, audit, chain, users, documents }[tab] || adminOverview;
  return fn(render, query);
}

// ------------------------------------------------------------------ overview
export async function adminOverview(render) {
  const body = h("div", null, skeleton(3));
  frame(render, "overview", body);
  try {
    const [st, al] = await Promise.all([api("GET", "/api/admin/stats"), api("GET", "/api/admin/alerts")]);
    const t = st.totals, c = al.audit_chain;
    const urgent = al.alerts.filter((a) => a.severity === "critical" || a.severity === "high");
    const integ = integrityPanel(c, () => adminOverview(render));
    put(body, h("div", { class: "stack" },
      h("div", { class: "ledger" },
        h("div", null, h("div", { class: "n" }, t.users_active), h("div", { class: "l" }, `active people, ${t.users_with_mfa} with two-step`)),
        h("div", null, h("div", { class: "n" }, t.documents), h("div", { class: "l" }, `documents, ${t.on_legal_hold} on legal hold`)),
        h("div", null, h("div", { class: "n" }, t.live_grants), h("div", { class: "l" }, "live access grants")),
        h("div", null, h("div", { class: "n" + (urgent.length ? " refused" : "") }, urgent.length), h("div", { class: "l" }, "alerts that need attention"))),
      h("div", { class: "grid-2" },
        h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", null, "Last 14 days"), h("a", { class: "small", href: "#/admin/audit" }, "Open audit trail")),
          mirrorChart(st.series)),
        integ),
      h("div", { class: "grid-3" },
        h("section", { class: "panel" }, h("div", { class: "panel-head" }, h("h2", null, "Needs attention"), h("a", { class: "small", href: "#/admin/alerts" }, "All alerts")),
          urgent.length ? urgent.slice(0, 4).map((a) => alertNote(a)) : h("p", { class: "muted small" }, "Nothing urgent in the last 24 hours.")),
        h("section", { class: "panel" }, h("h2", null, "Most refused, 7 days"),
          st.top_refused.length ? meterList(st.top_refused.map((x) => ({ label: x.who, n: x.n })), { refused: true }) : h("p", { class: "muted small" }, "No refusals this week.")),
        h("section", { class: "panel" }, h("h2", null, "Activity by area, 7 days"),
          st.action_mix.length ? meterList(st.action_mix.map((x) => ({ label: areaName(x.area), n: x.n }))) : h("p", { class: "muted small" }, "No activity.")))));
  } catch (ex) { put(body, errorNote(ex)); }
}

const areaName = (a) => ({ document: "Documents", permission: "Sharing", auth: "Sign-ins", admin: "Administration", security: "Forged requests", suggestion: "Suggestions", review: "Access review", access: "Role refusals" }[a] || a);

function integrityPanel(c, onVerify) {
  const s = seal(c.head_hash || "", { draw: true, label: false, title: "Seal of the latest audit record" });
  return h("section", { class: "panel" },
    h("div", { class: "panel-head" }, h("h2", null, "Audit trail integrity")),
    h("div", { class: "integrity" }, s,
      h("div", null,
        h("div", { class: "state " + (c.valid ? "ok" : "bad") }, c.valid ? "Intact" : "Broken"),
        h("p", { class: "small muted" }, c.valid
          ? `All ${c.count} records re-verified just now. Each one's HMAC covers the record before it, so no record can be edited, removed or inserted without this turning red.`
          : `Record #${c.broken_at}: ${c.reason}. Something changed the audit trail outside the application.`),
        c.valid ? h("div", { class: "hash" }, "Head " + c.head_hash.slice(0, 32) + "…") : null,
        h("div", { class: "row" },
          h("button", { class: "btn secondary small", onclick: onVerify }, icon("verify"), "Verify again"),
          h("a", { class: "btn ghost small", href: "/api/admin/audit/export" }, icon("export"), "Export with hashes")))));
}

function alertNote(a) {
  const cls = a.severity === "critical" || a.severity === "high" ? "error" : a.severity === "medium" ? "warn" : "ok";
  return h("div", { class: "note " + cls }, h("strong", null, a.title), a.detail);
}

/** Dangerous admin powers go through the two-person rule: the server answers
 *  202 "pending" until a different administrator approves. Say so honestly. */
function doneToast(r, msg, detail) {
  if (r && r.status === "pending") toast("Sent for approval", false, "Another administrator must approve it before it takes effect. It is waiting under Approvals.");
  else toast(msg, false, detail);
}

const REQUEST_LABEL = {
  reset_password: "Reset the password of", reset_mfa: "Reset two-step sign-in of",
  transfer_ownership: "Transfer ownership of", promote_admin: "Make an administrator:",
};

// ------------------------------------------------------------------ approvals (two-person rule)
async function approvals(render) {
  const body = h("div", null, skeleton(2));
  frame(render, "approvals", body);
  try {
    const r = await api("GET", "/api/admin/requests");
    const pending = r.requests.filter((x) => x.status === "pending");
    const past = r.requests.filter((x) => x.status !== "pending");
    const decide = async (x, verb) => {
      if (verb === "approve" && !(await confirmDialog({ title: "Approve this request?", body: `${REQUEST_LABEL[x.action] || x.action} ${x.target || x.document || ""}. It takes effect immediately and is recorded with your name.`, confirm: "Approve", danger: true }))) return;
      try { const res = await api("POST", `/api/admin/requests/${x.id}/${verb}`); toast(res.status === "approved" ? "Approved and carried out" : res.status === "cancelled" ? "Request withdrawn" : "Request rejected"); approvals(render); }
      catch (ex) { toast(ex.message, true); }
    };
    const card = (x) => {
      const mine = x.requested_by_id === state.user.id;
      return h("li", { class: "request" + (x.status === "pending" ? " pending" : "") },
        h("div", { class: "request-main" },
          h("div", null, h("strong", null, `${REQUEST_LABEL[x.action] || x.action} `), x.target || "", x.document ? h("em", null, ` "${x.document}"`) : null),
          h("div", { class: "small muted" }, `Requested by ${mine ? "you" : x.requested_by}, ${ago(x.requested_at)}`,
            x.status === "pending" ? `, expires ${fmtDateTime(x.expires_at)}` : `, ${x.status} by ${x.decided_by || "nobody"}${x.decided_at ? " " + ago(x.decided_at) : ""}`),
          x.reason ? h("div", { class: "small" }, "Reason: ", x.reason) : null),
        x.status === "pending"
          ? h("div", { class: "row" }, mine
            ? [h("span", { class: "chip hold" }, icon("people"), "Waiting for another administrator"),
              h("button", { class: "btn secondary small", onclick: () => decide(x, "reject") }, "Withdraw")]
            : [h("button", { class: "btn small", onclick: () => decide(x, "approve") }, icon("check"), "Approve"),
              h("button", { class: "btn danger small", onclick: () => decide(x, "reject") }, "Reject")])
          : h("span", { class: "chip" + (x.status === "approved" ? " edit" : x.status === "rejected" ? " refused" : "") }, x.status));
    };
    put(body, h("div", { class: "grid-2" },
      h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", null, "Waiting for a decision"), pending.length ? h("span", { class: "chip hold" }, `${pending.length} pending`) : null),
        pending.length ? h("ul", { class: "requests" }, pending.map(card))
          : h("div", { class: "empty" }, icon("check"), h("p", null, "Nothing is waiting for approval."))),
      h("section", { class: "panel" },
        h("h2", null, "The two-person rule"),
        h("p", { class: "small muted" }, "Resetting someone's password or two-step sign-in, transferring a document and making someone an administrator are the powers that could be used to read a document without being given it. Each one is requested by one administrator and only happens when a different administrator approves it. Requests expire if nobody decides."),
        h("p", { class: "small" }, `${r.active_admins} active administrator${r.active_admins === 1 ? "" : "s"}.`,
          r.active_admins < 2 ? h("strong", null, " With only one, these requests cannot be approved. Add a second administrator.") : null),
        past.length ? [h("h3", null, "Decided"), h("ul", { class: "requests" }, past.slice(0, 20).map(card))] : null)));
  } catch (ex) { put(body, errorNote(ex)); }
}

// ------------------------------------------------------------------ alerts
async function alerts(render) {
  const body = h("div", null, skeleton(2));
  frame(render, "alerts", body);
  try {
    const r = await api("GET", "/api/admin/alerts");
    const order = { critical: 0, high: 1, medium: 2, info: 3 };
    const list = r.alerts.sort((a, b) => order[a.severity] - order[b.severity]);
    put(body, h("div", { class: "grid-2" },
      h("section", { class: "panel stack" }, h("h2", null, "What counts as worth noticing"),
        list.length ? list.map(alertNote) : h("div", { class: "empty" }, icon("check"), h("p", null, "Nothing unusual right now."))),
      integrityPanel(r.audit_chain, () => alerts(render))));
  } catch (ex) { put(body, errorNote(ex)); }
}

// ------------------------------------------------------------------ audit trail
async function audit(render, query) {
  const p = new URLSearchParams(query || "");
  const page = Number(p.get("page") || 1);
  const f = {
    actor: h("input", { id: "a-actor", value: p.get("actor") || "", placeholder: "Email contains" }),
    action: h("select", { id: "a-action" }, [["", "Anything"], ["document.*", "Document activity"], ["document.download", "Downloads"], ["permission.*", "Permission changes"],
      ["auth.*", "Sign-ins"], ["admin.*", "Administrator actions"], ["suggestion.*", "Suggestions"], ["security.*", "Forged requests"]]
      .map(([v, l]) => h("option", { value: v, selected: (p.get("action") || "") === v }, l))),
    outcome: h("select", { id: "a-outcome" }, [["", "Allowed and refused"], ["success", "Allowed"], ["denied", "Refused"]]
      .map(([v, l]) => h("option", { value: v, selected: (p.get("outcome") || "") === v }, l))),
    from: h("input", { id: "a-from", type: "date", value: p.get("from") || "" }),
    to: h("input", { id: "a-to", type: "date", value: p.get("to") || "" }),
  };
  const go = (pg) => {
    const q = new URLSearchParams();
    for (const [k, el] of Object.entries(f)) if (el.value) q.set(k, el.value);
    if (pg) q.set("page", pg);
    location.hash = "#/admin/audit" + (q.toString() ? "?" + q : "");
  };
  const fld = (el, l) => h("div", null, h("label", { for: el.id }, l), el);
  const body = h("div", null, skeleton(2));
  frame(render, "audit",
    h("form", { class: "panel", onsubmit: (e) => { e.preventDefault(); go(); } },
      h("div", { class: "filters" }, fld(f.actor, "Who"), fld(f.action, "What"), fld(f.outcome, "Result"), fld(f.from, "From")),
      h("div", { class: "filters more" }, fld(f.to, "To"), h("div"), h("div"),
        h("div", { class: "row" }, h("button", { class: "btn", type: "submit" }, "Filter"), h("a", { class: "btn secondary", href: "/api/admin/audit/export" }, icon("export"), "Export")))),
    body);
  try {
    p.set("page", page); p.set("page_size", 50);
    const r = await api("GET", "/api/admin/audit?" + p.toString());
    const pages = Math.max(1, Math.ceil(r.total / r.page_size));
    put(body, h("section", { class: "panel" },
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, ["#", "When", "Who", "Action", "Result", "Document or person", "Details"].map((t) => h("th", null, t)))),
        h("tbody", null, r.entries.map((e) => h("tr", { class: e.outcome === "denied" ? "refused" : "" },
          h("td", { class: "small" }, e.seq),
          h("td", { class: "small nowrap" }, fmtDateTime(e.ts), h("span", { class: "sub" }, e.ip || "")),
          h("td", { class: "small" }, e.actor_email || "System"),
          h("td", { class: "small" }, e.action),
          h("td", null, e.outcome === "denied" ? h("span", { class: "chip refused" }, "Refused") : h("span", { class: "chip" }, "Allowed")),
          h("td", { class: "small" }, e.document_title || "", e.target_email ? h("span", { class: "sub" }, "to " + e.target_email) : null),
          h("td", { class: "hash" }, e.details === "{}" ? "" : e.details)))))),
      h("div", { class: "pager" }, `${r.total} records, page ${page} of ${pages}`,
        h("button", { class: "btn secondary small", disabled: page <= 1, onclick: () => go(page - 1) }, "Newer"),
        h("button", { class: "btn secondary small", disabled: page >= pages, onclick: () => go(page + 1) }, "Older"))));
  } catch (ex) { put(body, errorNote(ex)); }
}

// ------------------------------------------------------------------ chain explorer
async function chain(render) {
  const body = h("div", null, skeleton(2));
  frame(render, "chain", body);
  try {
    const [r, v] = await Promise.all([api("GET", "/api/admin/audit?page_size=10"), api("GET", "/api/admin/audit/verify")]);
    const blocks = r.entries.slice().reverse();
    const row = h("div", { class: "chain", role: "list", "aria-label": "The ten most recent audit records, oldest on the left" });
    blocks.forEach((b, i) => {
      const linked = i > 0 && b.prev_hash === blocks[i - 1].hash;
      if (i > 0) row.append(h("div", { class: "link-arrow", "aria-hidden": "true" }, icon(linked ? "chain" : "alert")));
      row.append(h("div", { class: "chain-block" + (b.outcome === "denied" ? " denied" : "") + (linked ? " match" : ""), role: "listitem" },
        h("div", { class: "row between" }, h("span", { class: "seq" }, "#" + b.seq), b.outcome === "denied" ? h("span", { class: "chip refused" }, "Refused") : null),
        h("div", { class: "act" }, b.action),
        h("div", { class: "muted" }, b.actor_email || "System"),
        h("div", { class: "hash prev" }, "prev " + b.prev_hash.slice(0, 16)),
        h("div", { class: "hash" }, "hash " + b.hash.slice(0, 16))));
    });
    put(body, h("div", { class: "stack" },
      integrityPanel(v, () => chain(render)),
      h("section", { class: "panel" }, h("h2", null, "How the chain works"),
        h("p", { class: "small muted" }, "Each record stores the hash of the record before it, and its own HMAC computed with a key that lives outside the database. Change any field of any record and every hash after it stops matching. The ten most recent records are shown below, oldest on the left; the link icon means the record correctly points to its neighbour."),
        row)));
  } catch (ex) { put(body, errorNote(ex)); }
}

// ------------------------------------------------------------------ people
async function users(render) {
  const body = h("div", null, skeleton(2));
  frame(render, "users", body);
  try {
    const r = await api("GET", "/api/admin/users");
    const act = async (fn, msg, detail) => { try { doneToast(await fn(), msg, detail); users(render); } catch (ex) { toast(ex.message, true); } };
    const err = h("div");
    const nu = {
      name: h("input", { id: "nu-name", required: true }), email: h("input", { id: "nu-email", type: "email", required: true }),
      role: h("select", { id: "nu-role" }, ["viewer", "owner", "admin"].map((x) => h("option", { value: x }, roleName(x)))),
      password: h("input", { id: "nu-pw", type: "password", required: true, minlength: 12, autocomplete: "new-password" }),
    };
    put(body, h("div", { class: "stack" },
      h("section", { class: "panel" }, h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Person", "Role", "Status", "Two-step", "Actions"].map((t) => h("th", null, t)))),
        h("tbody", null, r.users.map((u) => {
          const self = u.id === state.user.id;
          const locked = u.locked_until && new Date(u.locked_until) > new Date();
          return h("tr", null,
            h("td", null, h("div", { class: "cell-doc" }, avatar(u.name), h("div", null, h("strong", null, u.name), h("span", { class: "sub" }, u.email)))),
            h("td", null, self ? roleName(u.role) : h("select", { "aria-label": "Role for " + u.name,
              onchange: (e) => act(() => api("PATCH", "/api/admin/users/" + u.id, { role: e.target.value }), "Role changed", "Their sessions were ended, so it applies now.") },
            ["viewer", "owner", "admin"].map((x) => h("option", { value: x, selected: x === u.role }, roleName(x))))),
            h("td", { class: "small nowrap" }, h("span", { class: "status-dot" + (u.active ? "" : " off") + (locked ? " bad" : "") }), locked ? "Locked" : u.active ? "Active" : "Deactivated"),
            h("td", { class: "small" }, u.mfa_enabled ? h("span", { class: "chip edit" }, "On") : h("span", { class: "chip" }, "Off")),
            h("td", null, self ? h("span", { class: "small muted" }, "You") : h("div", { class: "row" },
              h("button", { class: "btn secondary small", onclick: () => act(() => api("PATCH", "/api/admin/users/" + u.id, { active: !u.active }), u.active ? "Deactivated" : "Reactivated", u.active ? "Their sessions ended immediately." : "") }, u.active ? "Deactivate" : "Reactivate"),
              locked ? h("button", { class: "btn secondary small", onclick: () => act(() => api("POST", `/api/admin/users/${u.id}/unlock`), "Unlocked") }, "Unlock") : null,
              h("button", { class: "btn ghost small", onclick: async () => {
                const pw = await promptDialog({ title: `Reset password for ${u.name}`, body: "They will be signed out everywhere. This is recorded and shown in alerts.", label: "New password (at least 12 characters)", type: "password", confirm: "Reset password", minlength: 12 });
                if (pw) act(() => api("POST", `/api/admin/users/${u.id}/reset-password`, { new_password: pw }), "Password reset", "Their sessions were ended.");
              } }, "Reset password"),
              u.mfa_enabled ? h("button", { class: "btn ghost small", onclick: async () => {
                if (await confirmDialog({ title: "Reset two-step sign-in?", body: "Only for a lost phone. It is recorded and flagged as a privileged action.", confirm: "Reset two-step", danger: true }))
                  act(() => api("POST", `/api/admin/users/${u.id}/reset-mfa`), "Two-step sign-in reset");
              } }, "Reset two-step") : null,
              u.active ? h("button", { class: "btn danger small", onclick: async () => {
                if (!(await confirmDialog({ title: `Offboard ${u.name}?`, body: "Deactivates the account, ends every session and removes every access grant they hold. If they are reactivated later, they come back with no access.", confirm: "Offboard", danger: true }))) return;
                try { const x = await api("POST", `/api/admin/users/${u.id}/offboard`); toast(`${u.name} offboarded`, false, `${x.grants_revoked} grant(s) removed.` + (x.documents_to_transfer.length ? ` Transfer their ${x.documents_to_transfer.length} document(s) on the Documents tab.` : "")); users(render); }
                catch (ex) { toast(ex.message, true); }
              } }, "Offboard") : null)));
        }))))),
      h("section", { class: "panel" }, h("h2", null, "Add a person"),
        h("form", { onsubmit: (e) => {
          e.preventDefault(); put(err);
          api("POST", "/api/admin/users", { name: nu.name.value, email: nu.email.value, role: nu.role.value, password: nu.password.value })
            .then(() => { toast("Account created"); users(render); }).catch((ex) => put(err, errorNote(ex)));
        } },
        h("div", { class: "filters" },
          h("div", null, h("label", { for: "nu-name" }, "Name"), nu.name), h("div", null, h("label", { for: "nu-email" }, "Email"), nu.email),
          h("div", null, h("label", { for: "nu-role" }, "Role"), nu.role), h("div", null, h("label", { for: "nu-pw" }, "First password"), nu.password)),
        err, h("div", { class: "row" }, h("button", { class: "btn", type: "submit" }, "Create account"))))));
  } catch (ex) { put(body, errorNote(ex)); }
}

// ------------------------------------------------------------------ documents (metadata only)
async function documents(render) {
  const body = h("div", null, skeleton(2));
  frame(render, "documents", body);
  try {
    const [r, us] = await Promise.all([api("GET", "/api/admin/documents"), api("GET", "/api/admin/users")]);
    const owners = us.users.filter((u) => u.role === "owner" && u.active);
    put(body, h("section", { class: "panel" },
      h("p", { class: "note" }, h("strong", null, "Details only"), "Administrators cannot open or download a document unless its owner shares it with them. Placing a legal hold does not change that."),
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, ["Document", "Owner", "People", "State", "Legal hold", "Transfer to"].map((t) => h("th", null, t)))),
        h("tbody", null, r.documents.map((d) => h("tr", null,
          h("td", null, h("strong", null, d.title), h("span", { class: "sub" }, `${d.category}, version ${d.current_version}`)),
          h("td", { class: "small" }, d.owner_name,
            !d.owner_active ? h("span", { class: "sub" }, h("span", { class: "chip refused" }, "Owner deactivated")) :
              d.owner_role !== "owner" ? h("span", { class: "sub" }, h("span", { class: "chip hold" }, "Owner is now " + roleName(d.owner_role).toLowerCase())) : null),
          h("td", null, d.live_grants),
          h("td", { class: "small" }, d.purged_at ? "Destroyed" : d.deleted_at ? "In trash" : "Active"),
          h("td", { class: "small" }, d.purged_at ? "" : d.legal_hold
            ? h("div", null, h("span", { class: "chip hold" }, icon("hold"), "Held"), h("span", { class: "sub" }, d.legal_hold_reason),
              h("button", { class: "linkish small", onclick: async () => {
                if (!(await confirmDialog({ title: "Release the legal hold?", body: "The owner will be able to delete it again. This is flagged in alerts.", confirm: "Release hold" }))) return;
                try { await api("POST", `/api/admin/documents/${d.id}/legal-hold`, { hold: false }); toast("Hold released"); documents(render); } catch (ex) { toast(ex.message, true); }
              } }, "Release"))
            : h("button", { class: "btn secondary small", onclick: async () => {
              const reason = await promptDialog({ title: "Place a legal hold", body: "While held, nobody can delete this document and it will not be purged.", label: "Reason or case reference", confirm: "Place hold" });
              if (!reason) return;
              try { await api("POST", `/api/admin/documents/${d.id}/legal-hold`, { hold: true, reason }); toast("Legal hold placed"); documents(render); } catch (ex) { toast(ex.message, true); }
            } }, icon("hold"), "Hold")),
          h("td", null, d.purged_at ? "" : h("select", { "aria-label": "Transfer " + d.title, onchange: async (e) => {
            const to = owners.find((o) => o.id === e.target.value);
            if (!to) return;
            if (!(await confirmDialog({ title: `Transfer to ${to.name}?`, body: "The current owner loses access. This is recorded and flagged.", confirm: "Transfer" }))) { e.target.value = ""; return; }
            try { doneToast(await api("POST", `/api/admin/documents/${d.id}/transfer`, { new_owner_id: to.id }), "Ownership transferred"); documents(render); }
            catch (ex) { toast(ex.message, true); e.target.value = ""; }
          } }, h("option", { value: "" }, "Choose…"), owners.filter((o) => o.email !== d.owner_email).map((o) => h("option", { value: o.id }, o.name)))))))))));
  } catch (ex) { put(body, errorNote(ex)); }
}
