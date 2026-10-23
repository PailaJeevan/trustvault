"""Access review: one page where an owner sees everyone who can reach any of
their documents, with flags for grants that deserve a second look, and can
revoke several at once.

This is the answer to "someone left and their link still works" from the
owner's side: access that is never reviewed only ever grows.

Bulk revoke does not bypass anything. For each grant it looks up the grant's
document and calls the same authorize(document_id, "manage") as the single
revoke route, inside one transaction: all of them are revoked, or none.
"""
from datetime import timedelta

from flask import Blueprint, g, jsonify

from .. import audit
from ..auth import login_required
from ..authz import authorize
from ..db import get_db, iso, now_iso, transaction, utcnow
from ..errors import ApiError
from . import id_param, json_body

bp = Blueprint("review", __name__, url_prefix="/api/review")

UNUSED_DAYS = 30
MAX_BULK = 100


def _domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower()


@bp.get("/grants")
@login_required
def review_grants():
    db = get_db()
    now = utcnow()
    stale_before = iso(now - timedelta(days=UNUSED_DAYS))
    soon = iso(now + timedelta(days=7))
    my_domain = _domain(g.user["email"])
    rows = db.execute(
        """SELECT gr.id, gr.document_id, gr.permission, gr.created_at, gr.expires_at, gr.source,
                  d.title, d.category, u.id AS user_id, u.name, u.email, u.is_active, u.role,
                  (SELECT MAX(a.ts) FROM audit_log a
                    WHERE a.document_id = gr.document_id AND a.actor_id = gr.user_id
                      AND a.action = 'document.download' AND a.outcome = 'success') AS last_download
             FROM grants gr
             JOIN documents d ON d.id = gr.document_id
             JOIN users u ON u.id = gr.user_id
            WHERE d.owner_id = ? AND d.deleted_at IS NULL AND d.purged_at IS NULL
              AND gr.revoked_at IS NULL AND (gr.expires_at IS NULL OR gr.expires_at > ?)
            ORDER BY u.name, d.title""",
        (g.user["id"], now_iso())).fetchall()

    out = []
    for r in rows:
        flags = []
        if not r["is_active"]:
            flags.append({"code": "inactive", "text": "Account deactivated"})
        if _domain(r["email"]) != my_domain:
            flags.append({"code": "external", "text": "Outside your organisation"})
        if r["expires_at"] is None:
            flags.append({"code": "no_expiry", "text": "Never expires"})
        elif r["expires_at"] <= soon:
            flags.append({"code": "expiring", "text": "Expires within 7 days"})
        if r["created_at"] < stale_before and (r["last_download"] is None or r["last_download"] < stale_before):
            flags.append({"code": "unused", "text": f"Not downloaded in {UNUSED_DAYS} days"})
        if r["permission"] == "edit" and r["category"] in ("HR", "Legal"):
            flags.append({"code": "sensitive_edit", "text": f"Can edit a {r['category']} document"})
        out.append({
            "grant_id": r["id"], "document": {"id": r["document_id"], "title": r["title"], "category": r["category"]},
            "user": {"id": r["user_id"], "name": r["name"], "email": r["email"], "active": bool(r["is_active"])},
            "permission": r["permission"], "created_at": r["created_at"], "expires_at": r["expires_at"],
            "source": r["source"], "last_download": r["last_download"], "flags": flags,
        })
    return jsonify(grants=out, unused_days=UNUSED_DAYS)


@bp.post("/revoke")
@login_required
def bulk_revoke():
    data = json_body({"grant_ids"}, {"grant_ids"})
    ids = data["grant_ids"]
    if not isinstance(ids, list) or not ids or len(ids) > MAX_BULK:
        raise ApiError(400, f"grant_ids must be a list of 1 to {MAX_BULK} ids.")
    ids = sorted({id_param(i, "grant id") for i in ids})
    db = get_db()
    with transaction(db):
        for gid in ids:
            gr = db.execute("SELECT * FROM grants WHERE id = ? AND revoked_at IS NULL", (gid,)).fetchone()
            if gr is None:
                raise ApiError(404, "One of those grants does not exist or is already revoked. Nothing was changed.")
            doc = authorize(gr["document_id"], "manage")  # the same decision as a single revoke
            db.execute("UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ?",
                       (now_iso(), g.user["id"], gid))
            grantee = db.execute("SELECT email FROM users WHERE id = ?", (gr["user_id"],)).fetchone()
            audit.append("permission.revoke", document_id=doc["id"], target_user_id=gr["user_id"],
                         details={"grantee": grantee["email"], "permission": gr["permission"],
                                  "via": "access_review"})
        audit.append("review.bulk_revoke", details={"count": len(ids)})
    return jsonify(revoked=len(ids))
