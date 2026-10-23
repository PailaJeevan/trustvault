import { ago, api, describe, errorNote, h, icon, put, skeleton, state } from "../core.js";
import { seal } from "../seal.js";
import { shell, roleName } from "../shell.js";
import { adminOverview } from "./admin.js";

function greeting() {
  const hr = new Date().getHours();
  return hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";
}

export async function viewHome(render) {
  if (state.user.role === "admin") return adminOverview(render);
  const body = h("div", null, skeleton(3));
  render(shell("home",
    h("div", { class: "page-head" }, h("div", null,
      h("h1", null, `${greeting()}, ${state.user.name.split(" ")[0]}`),
      h("p", null, roleName(state.user.role) + ". Here is what is happening with your documents."))),
    body));
  try {
    const [d, feed] = await Promise.all([
      api("GET", "/api/dashboard"),
      api("GET", "/api/activity?limit=8").catch(() => ({ events: [] })),
    ]);
    state.unread = d.unread;
    const o = d.owner;
    const ledger = h("div", { class: "ledger" },
      h("div", null, h("div", { class: "n" }, d.counts.owned), h("div", { class: "l" }, "documents you own")),
      h("div", null, h("div", { class: "n" }, d.counts.shared_with_me), h("div", { class: "l" }, "shared with you")),
      o ? h("div", null, h("div", { class: "n" }, o.people_with_access), h("div", { class: "l" }, "people can open your documents")) : null,
      o ? h("div", null, h("div", { class: "n" + (o.refused_on_mine_7d ? " refused" : "") }, o.refused_on_mine_7d),
        h("div", { class: "l" }, "refused attempts on your documents this week")) : null);

    const recent = h("section", { class: "panel" },
      h("div", { class: "panel-head" }, h("h2", null, "Recently changed"), h("a", { href: "#/documents", class: "small" }, "All documents")),
      d.recent.length
        ? h("div", { class: "doc-grid" }, d.recent.map((r) => h("a", { class: "doc-card", href: "#/doc/" + r.id },
          h("div", { class: "top" }, seal(r.sha256, { label: false }), h("span", { class: "chip cat" }, r.category)),
          h("h3", null, r.title),
          h("div", { class: "meta" }, h("span", null, r.mine ? "Yours" : r.owner_name), h("span", null, ago(r.updated_at))))))
        : h("div", { class: "empty" }, icon("docs"),
          h("p", null, state.user.role === "owner" ? "You have no documents yet. Upload one; only you can see it until you share it." : "Nobody has shared a document with you yet."),
          state.user.role === "owner" ? h("a", { class: "btn", href: "#/upload" }, icon("upload"), "Upload a document") : null));

    const side = h("div", { class: "stack" });
    if (o) {
      side.append(h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", null, "Access health")),
        o.open_ended_grants
          ? h("div", { class: "note warn" }, h("strong", null, `${o.open_ended_grants} grant${o.open_ended_grants === 1 ? "" : "s"} never expire${o.open_ended_grants === 1 ? "s" : ""}`),
            "Access that never ends is the most common way people keep documents after they leave.")
          : h("div", { class: "note ok" }, h("strong", null, "Every grant has an end date"), "Nice. Access will lapse on its own."),
        h("p", { class: "small muted" }, `${o.downloads_by_others_7d} download${o.downloads_by_others_7d === 1 ? "" : "s"} of your documents by other people in the last 7 days.`),
        h("a", { class: "btn secondary", href: "#/review" }, icon("shield"), "Review who has access")));
      side.append(h("section", { class: "panel" },
        h("div", { class: "panel-head" }, h("h2", null, "Latest activity"),
          d.unread ? h("span", { class: "chip refused" }, `${d.unread} new`) : null),
        feed.events.length
          ? h("ul", { class: "custody" }, feed.events.map((e) => h("li", { class: e.outcome === "denied" ? "denied" : "" },
            h("div", { class: "when" }, ago(e.ts)),
            h("div", { class: "what" }, h("span", { class: "who" }, e.actor_email || "System"), " ", describe(e), " ",
              h("a", { href: "#/doc/" + e.document_id }, e.title)))))
          : h("p", { class: "muted small" }, "No one else has touched your documents yet.")));
    } else {
      side.append(h("section", { class: "panel" }, h("h2", null, "How access works here"),
        h("ol", { class: "steps small" },
          h("li", null, "An owner shares a document with you by name, to read or to edit."),
          h("li", null, "Every time you open or download it, that is recorded."),
          h("li", null, "When the owner removes your access, it stops working on your next click."))));
    }
    put(body, h("div", { class: "stack" }, ledger, h("div", { class: "grid-2" }, recent, side)));
  } catch (ex) { put(body, errorNote(ex)); }
}
