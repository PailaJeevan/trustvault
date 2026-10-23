import { api, errorNote, h, icon, put, state } from "../core.js";
import { seal } from "../seal.js";

// Shown ONLY when the server reports demo mode. These are the public demo
// credentials already printed in README.md; they exist only on seeded demo data.
const DEMO = [
  ["admin@trustvault.test", "Admin-Demo-2026!", "Administrator"],
  ["admin2@trustvault.test", "Arjun-Demo-2026!", "Second administrator"],
  ["olivia@trustvault.test", "Olivia-Demo-2026!", "Owner"],
  ["oscar@trustvault.test", "Oscar-Demo-2026!", "Owner"],
  ["maya@trustvault.test", "Maya-Demo-2026!", "Owner, two-step"],
  ["vera@trustvault.test", "Vera-Demo-2026!", "Viewer"],
  ["victor@trustvault.test", "Victor-Demo-2026!", "Viewer"],
  ["ext@partner.test", "Partner-Demo-2026!", "External viewer"],
];

function frame(card) {
  const art = h("section", { class: "auth-art" },
    h("div", null,
      h("h1", null, "Every document has a custody record."),
      h("p", null, "Shared with named people only. Taken back the moment you say so. Every opening, download and refusal written into a chain that cannot be quietly rewritten.")),
    seal("c0ffee1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d", { draw: true, label: false, title: "" }),
    h("ul", { class: "promises" },
      h("li", null, icon("lock"), "Nobody can open a document they were not given, including administrators."),
      h("li", null, icon("history"), "Refused attempts are recorded too, with who, when and from where."),
      h("li", null, icon("chain"), "The audit trail is hash-chained: any edit or deletion is detected.")));
  art.querySelector("svg.seal").classList.add("big-seal");
  return h("div", { class: "auth" }, art, h("main", { class: "auth-form", id: "main" }, card));
}

export async function viewLogin(render) {
  const err = h("div");
  const email = h("input", { id: "email", type: "email", autocomplete: "username", required: true });
  const pw = h("input", { id: "pw", type: "password", autocomplete: "current-password", required: true });
  const btn = h("button", { type: "submit", class: "btn block" }, "Sign in");
  const submit = async (e) => {
    if (e) e.preventDefault();
    put(err); btn.disabled = true;
    try {
      const r = await api("POST", "/api/auth/login", { email: email.value, password: pw.value });
      if (r.mfa_required) { viewMfa(render, r.challenge, email.value); return; }
      state.user = r.user; state.csrf = r.csrfToken;
      location.hash = "#/home";
    } catch (ex) { put(err, errorNote(ex)); btn.disabled = false; pw.select(); }
  };
  const demoBox = h("div");
  const card = h("div", { class: "auth-card" },
    h("h2", null, "Sign in"),
    h("p", { class: "muted" }, "Use your work email and password."),
    h("form", { onsubmit: submit },
      h("div", { class: "field" }, h("label", { for: "email" }, "Email"), email),
      h("div", { class: "field" }, h("label", { for: "pw" }, "Password"), pw),
      err, btn),
    demoBox);
  render(frame(card));
  email.focus();
  try {
    const cfg = await api("GET", "/api/auth/config");
    if (cfg.demo_mode) {
      put(demoBox, h("details", { class: "demo-list" },
        h("summary", null, "Demo accounts for reviewers"),
        h("ul", null, DEMO.map(([e, p, role]) => h("li", null, h("button", { type: "button", onclick: () => { email.value = e; pw.value = p; submit(); } },
          h("span", null, e), h("span", { class: "muted" }, role)))))));
    }
  } catch (_) { /* no demo list */ }
}

export function viewMfa(render, challenge, email) {
  const err = h("div");
  const code = h("input", { id: "code", class: "otp", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, pattern: "[0-9]{6}", required: true });
  const btn = h("button", { type: "submit", class: "btn block" }, "Verify and sign in");
  const submit = async (e) => {
    if (e) e.preventDefault();
    put(err); btn.disabled = true;
    try {
      const r = await api("POST", "/api/auth/login/mfa", { challenge, code: code.value });
      state.user = r.user; state.csrf = r.csrfToken;
      location.hash = "#/home";
    } catch (ex) {
      put(err, errorNote(ex)); btn.disabled = false; code.select();
      if (/expired/.test(ex.message)) setTimeout(() => viewLogin(render), 1600);
    }
  };
  code.addEventListener("input", () => { if (/^\d{6}$/.test(code.value)) submit(); });
  render(frame(h("div", { class: "auth-card" },
    h("h2", null, "Two-step sign-in"),
    h("p", { class: "muted" }, `Password accepted for ${email}. Enter the 6-digit code from your authenticator app.`),
    h("form", { onsubmit: submit },
      h("div", { class: "field" }, h("label", { for: "code" }, "Code"), code),
      err, btn),
    h("p", { class: "small" }, h("button", { class: "linkish", onclick: () => viewLogin(render) }, "Use a different account")))));
  code.focus();
}
