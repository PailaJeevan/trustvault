import { api, state } from "./core.js";
import { bindGlobalKeys, startBadgePolling } from "./shell.js";
import { viewLogin } from "./views/auth.js";
import { viewHome } from "./views/home.js";
import { viewDocuments, viewUpload, viewTrash } from "./views/documents.js";
import { viewDocument } from "./views/document.js";
import { viewReview, viewAccount } from "./views/account.js";
import { viewAdmin } from "./views/admin.js";

const app = document.getElementById("app");

function render(node) {
  app.replaceChildren(node);
  window.scrollTo(0, 0);
  const target = app.querySelector("h1, #main");
  if (target) { target.setAttribute("tabindex", "-1"); target.focus({ preventScroll: true }); }
}

async function ensureUser() {
  if (state.user) return true;
  try {
    const r = await api("GET", "/api/auth/me");
    state.user = r.user; state.csrf = r.csrfToken;
    try { state.unread = (await api("GET", "/api/activity?limit=1")).unread; } catch (_) { state.unread = 0; }
    return true;
  } catch (_) { return false; }
}

async function route() {
  document.querySelectorAll(".scrim, .chart-tip").forEach((e) => e.remove());
  const [path, query] = (location.hash || "#/home").slice(1).split("?");
  const parts = path.split("/").filter(Boolean);
  if (parts[0] === "login") {
    if (await ensureUser()) { location.hash = "#/home"; return; }
    return viewLogin(render);
  }
  if (!(await ensureUser())) { location.hash = "#/login"; return; }
  startBadgePolling();
  switch (parts[0]) {
    case "home": return viewHome(render);
    case "documents": return viewDocuments(render, query);
    case "upload": return viewUpload(render);
    case "trash": return viewTrash(render);
    case "doc": return viewDocument(render, parts[1], parts[2]);
    case "review": return viewReview(render);
    case "account": return viewAccount(render);
    case "admin": return state.user.role === "admin" ? viewAdmin(render, parts[1], query) : (location.hash = "#/home");
    default: location.hash = "#/home";
  }
}

bindGlobalKeys();
window.addEventListener("hashchange", route);
route();
