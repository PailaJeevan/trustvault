import { ACTION, ago, api, avatar, currentTheme, describe, h, icon, openOverlay, put, state, toggleTheme } from "./core.js";
import { seal } from "./seal.js";

const NAV = [
  { key: "home", href: "#/home", label: "Overview", icon: "home", roles: ["owner", "viewer"] },
  { key: "documents", href: "#/documents", label: "Documents", icon: "docs" },
  { key: "upload", href: "#/upload", label: "Upload", icon: "upload", roles: ["owner"] },
  { key: "review", href: "#/review", label: "Access review", icon: "shield", roles: ["owner"] },
  { key: "trash", href: "#/trash", label: "Trash", icon: "trash", roles: ["owner"] },
  { key: "admin", href: "#/admin", label: "Administration", icon: "admin", roles: ["admin"], group: "Oversight" },
  { key: "account", href: "#/account", label: "Account & security", icon: "user", group: "You" },
];

export function navItems() {
  return NAV.filter((n) => !n.roles || n.roles.includes(state.user.role));
}

let shellEl = null;

/** Render the app frame once; views fill `.content`. */
export function shell(active, ...content) {
  const u = state.user;
  const main = h("div", { class: "content", id: "main", tabindex: "-1" });
  put(main, content);

  let lastGroup = null;
  const links = [];
  for (const n of navItems()) {
    if (n.group && n.group !== lastGroup) { links.push(h("div", { class: "nav-group" }, n.group)); lastGroup = n.group; }
    links.push(h("a", { href: n.href, "aria-current": active === n.key ? "page" : null,
      onclick: () => shellEl && shellEl.classList.remove("nav-open") }, icon(n.icon), n.label));
  }

  const bell = h("button", { class: "icon-btn", "data-bell": "", "aria-label": "Activity on your documents", onclick: openFeed },
    icon("bell"), state.unread ? h("span", { class: "badge" }, state.unread > 99 ? "99+" : state.unread) : null);
  const themeBtn = h("button", { class: "icon-btn", "aria-label": "Switch light or dark theme",
    onclick: () => { toggleTheme(); put(themeBtn, icon(currentTheme() === "dark" ? "sun" : "moon")); } },
  icon(currentTheme() === "dark" ? "sun" : "moon"));

  const brandSeal = seal("7a1c9e04b3f2d8865c0a4e19f3b7d2c6a8e5f10b4d9c3a7e2f6b8d1c5a9e3f70", { label: false, title: "TrustVault" });
  shellEl = h("div", { class: "shell" },
    h("aside", { class: "rail", "aria-label": "Main navigation" },
      h("a", { class: "brand", href: "#/home" }, brandSeal,
        h("span", { class: "brand-name" }, "TrustVault", h("span", { class: "brand-sub" }, "Documents with a custody record"))),
      h("nav", { class: "nav" }, links),
      h("div", { class: "me" }, avatar(u.name),
        h("div", null, h("div", { class: "me-name" }, u.name), h("div", { class: "me-role" }, roleName(u.role) + (u.mfa_enabled ? ", two-step on" : ""))),
        h("button", { class: "icon-btn", "aria-label": "Sign out", title: "Sign out", onclick: logout }, icon("logout")))),
    h("div", { class: "main" },
      h("header", { class: "topbar" },
        h("button", { class: "icon-btn menu-btn", "aria-label": "Open navigation", onclick: () => shellEl.classList.toggle("nav-open") }, icon("menu")),
        h("button", { class: "search-trigger", onclick: openPalette, "aria-label": "Search documents and pages" },
          icon("search"), h("span", null, "Search documents, people, pages"), h("span", { class: "kbd" }, navigator.platform.includes("Mac") ? "⌘ K" : "Ctrl K")),
        h("div", { class: "topbar-spacer" }),
        state.user.role !== "admin" ? bell : null,
        h("button", { class: "icon-btn", "aria-label": "Keyboard shortcuts", title: "Keyboard shortcuts (?)", onclick: openShortcuts }, h("span", { class: "kbd-q" }, "?")),
        themeBtn),
      main));
  shellEl.addEventListener("click", (e) => { if (e.target === shellEl) shellEl.classList.remove("nav-open"); });
  return shellEl;
}

export const roleName = (r) => ({ admin: "Administrator", owner: "Document owner", viewer: "Viewer" }[r] || r);

export async function logout() {
  try { await api("POST", "/api/auth/logout"); } catch (_) { /* already gone */ }
  stopBadgePolling();
  state.user = null; state.csrf = null; state.unread = 0;
  location.hash = "#/login";
}

// ------------------------------------------------------------------ command palette
export function openPalette() {
  if (document.querySelector(".palette")) return;
  openOverlay((close) => {
    const input = h("input", { type: "search", placeholder: "Type a document name, a page, or a command", "aria-label": "Search",
      autocomplete: "off", "aria-controls": "pal-list", "aria-expanded": "true", role: "combobox" });
    const list = h("ul", { id: "pal-list", role: "listbox" });
    let items = [], sel = 0, timer = null, reqId = 0;

    const pages = navItems().map((n) => ({ kind: "Pages", label: n.label, icon: n.icon, run: () => { location.hash = n.href; } }));
    const commands = [
      { kind: "Commands", label: "Switch light or dark theme", icon: "moon", run: () => toggleTheme() },
      { kind: "Commands", label: "Show activity on my documents", icon: "bell", run: () => setTimeout(openFeed, 50), when: () => state.user.role !== "admin" },
      { kind: "Commands", label: "Show keyboard shortcuts", icon: "sparkle", run: () => setTimeout(openShortcuts, 50) },
    { kind: "Commands", label: "Sign out", icon: "logout", run: logout },
    ].filter((c) => !c.when || c.when());

    const render = () => {
      list.replaceChildren();
      let group = null;
      items.forEach((it, i) => {
        if (it.kind !== group) { list.append(h("li", { class: "group", role: "presentation" }, it.kind)); group = it.kind; }
        list.append(h("li", { class: "item", role: "option", id: "pal-" + i, "aria-selected": String(i === sel),
          onmousemove: () => { if (sel !== i) { sel = i; render(); } }, onclick: () => { close(); it.run(); } },
        it.seal ? seal(it.seal, { label: false }) : icon(it.icon), h("span", null, it.label), it.sub ? h("span", { class: "sub" }, it.sub) : null));
      });
      if (!items.length) list.append(h("li", { class: "group" }, "Nothing matches. Documents you cannot open never appear here."));
      input.setAttribute("aria-activedescendant", items.length ? "pal-" + sel : "");
    };
    const filterLocal = (q) => [...pages, ...commands].filter((p) => p.label.toLowerCase().includes(q.toLowerCase()));
    const update = () => {
      const q = input.value.trim();
      items = filterLocal(q);
      sel = 0; render();
      clearTimeout(timer);
      if (q.length >= 1) {
        const my = ++reqId;
        timer = setTimeout(async () => {
          try {
            const r = await api("GET", "/api/documents?page_size=8&q=" + encodeURIComponent(q));
            if (my !== reqId) return;
            const docs = r.documents.map((d) => ({ kind: "Documents", label: d.title, seal: d.sha256, sub: d.owner.name,
              run: () => { location.hash = "#/doc/" + d.id; } }));
            items = [...docs, ...filterLocal(q)];
            sel = 0; render();
          } catch (_) { /* ignore while typing */ }
        }, 160);
      }
    };
    input.addEventListener("input", update);
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); render(); scrollSel(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); render(); scrollSel(); }
      else if (e.key === "Enter" && items[sel]) { e.preventDefault(); const it = items[sel]; close(); it.run(); }
    });
    const scrollSel = () => { const el = list.querySelector('[aria-selected="true"]'); if (el) el.scrollIntoView({ block: "nearest" }); };
    items = [...pages, ...commands]; render();
    return h("div", { class: "palette", role: "dialog", "aria-modal": "true", "aria-label": "Search" },
      h("div", { class: "palette-input" }, icon("search"), input), list,
      h("div", { class: "foot" }, h("span", null, "↑ ↓ to move"), h("span", null, "Enter to open"), h("span", null, "Esc to close")));
  });
}

// ------------------------------------------------------------------ activity drawer
export function openFeed() {
  openOverlay((close) => {
    const body = h("div", { class: "drawer-body" }, h("p", { class: "muted" }, "Loading…"));
    (async () => {
      try {
        const r = await api("GET", "/api/activity?limit=50");
        if (!r.events.length) {
          put(body, h("div", { class: "empty" }, icon("bell"), h("p", null, "Nothing yet. When someone opens, downloads or is refused one of your documents, it appears here.")));
        } else {
          put(body, h("ul", { class: "feed" }, r.events.map((e) => {
            const denied = e.outcome === "denied";
            return h("li", { class: (denied ? "denied " : "") + (e.unread ? "unread" : "") },
              h("span", { class: "ico" }, icon(denied ? "ban" : e.action === "document.download" ? "download" : e.action.startsWith("permission") ? "share" : "history")),
              h("div", null,
                h("div", { class: "t" }, h("strong", null, e.actor_email || "System"), " ", describe(e), " ",
                  h("a", { href: "#/doc/" + e.document_id, onclick: () => close() }, e.title)),
                h("div", { class: "when" }, ago(e.ts))));
          })));
        }
        await api("POST", "/api/activity/seen");
        state.unread = 0;
        document.querySelectorAll(".topbar .badge").forEach((b) => b.remove());
      } catch (ex) { put(body, h("div", { class: "note error" }, ex.message)); }
    })();
    return h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": "Activity on your documents" },
      h("div", { class: "drawer-head" }, h("h2", null, "Activity on your documents"),
        h("button", { class: "icon-btn", "aria-label": "Close", onclick: () => close() }, icon("x"))),
      body);
  });
}

// ------------------------------------------------------------------ live badge
let badgeTimer = null;
export function startBadgePolling() {
  if (badgeTimer || !state.user || state.user.role === "admin") return;
  badgeTimer = setInterval(async () => {
    if (!state.user || document.hidden) return;
    try {
      const r = await api("GET", "/api/activity?limit=1");
      if (r.unread === state.unread) return;
      state.unread = r.unread;
      const bell = document.querySelector('.topbar [data-bell]');
      if (!bell) return;
      bell.querySelectorAll(".badge").forEach((b) => b.remove());
      if (r.unread) bell.append(h("span", { class: "badge" }, r.unread > 99 ? "99+" : r.unread));
    } catch (_) { /* signed out or offline; the next route change handles it */ }
  }, 45000);
}
export function stopBadgePolling() { clearInterval(badgeTimer); badgeTimer = null; }

// ------------------------------------------------------------------ keyboard
const SHORTCUTS = [
  ["Ctrl K  or  /", "Search documents, pages and commands"],
  ["g  then  o", "Overview"], ["g  then  d", "Documents"], ["g  then  u", "Upload"],
  ["g  then  r", "Access review"], ["g  then  a", "Account and security"], ["g  then  m", "Administration"],
  ["?", "Show this list"], ["Esc", "Close any dialog"],
];
const GOTO = { o: "#/home", d: "#/documents", u: "#/upload", r: "#/review", a: "#/account", m: "#/admin" };

export function openShortcuts() {
  if (document.querySelector(".shortcuts")) return;
  openOverlay((close) => h("div", { class: "modal shortcuts", role: "dialog", "aria-modal": "true", "aria-label": "Keyboard shortcuts" },
    h("h2", null, "Keyboard shortcuts"),
    h("dl", { class: "kv" }, SHORTCUTS.flatMap(([k, what]) => [h("dt", null, h("span", { class: "kbd" }, k)), h("dd", null, what)])),
    h("div", { class: "actions" }, h("button", { class: "btn", onclick: () => close() }, "Done"))));
}

export function bindGlobalKeys() {
  let pendingG = 0;
  document.addEventListener("keydown", (e) => {
    if (!state.user) return;
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) || document.activeElement.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey || document.querySelector(".scrim")) return;
    if (e.key === "/") { e.preventDefault(); openPalette(); }
    else if (e.key === "?") { e.preventDefault(); openShortcuts(); }
    else if (e.key === "g") { pendingG = Date.now(); }
    else if (pendingG && Date.now() - pendingG < 1200 && GOTO[e.key]) {
      pendingG = 0;
      const target = GOTO[e.key];
      const allowed = navItems().some((n) => n.href === target) || (target === "#/home");
      if (allowed) location.hash = target;
    } else pendingG = 0;
  });
}

export { ACTION };
