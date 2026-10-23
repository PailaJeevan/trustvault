"""Dashboard and activity feed.

Everything here is computed from the same two rules as the rest of the app:
  - a document counts for you only if VISIBLE_DOCUMENTS_SQL says you can open it;
  - you only see activity on documents you currently OWN (the same audience as
    the per-document custody record), never on documents merely shared with you.
"""
from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from ..auth import login_required
from ..authz import VISIBLE_DOCUMENTS_SQL
from ..db import get_db, iso, now_iso, transaction, utcnow
from ..errors import ApiError

bp = Blueprint("insights", __name__, url_prefix="/api")

# Activity on documents I own, by anyone other than me. Parameters: (me, me).
_MY_DOCS_ACTIVITY = """
    FROM audit_log a
    JOIN documents d ON d.id = a.document_id
   WHERE d.owner_id = ?                                   -- AUTHZ-CHECK:feed-owner
     AND (a.actor_id IS NULL OR a.actor_id != ?)
     AND a.action NOT LIKE 'suggestion.%'
"""


def _unread(db, uid: str) -> int:
    seen = db.execute("SELECT feed_seen_at FROM users WHERE id = ?", (uid,)).fetchone()["feed_seen_at"]
    return db.execute(f"SELECT COUNT(*) {_MY_DOCS_ACTIVITY} AND a.ts > ?",
                      (uid, uid, seen or "")).fetchone()[0]


@bp.get("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid, now = g.user["id"], now_iso()
    week = iso(utcnow() - timedelta(days=7))
    visible = (uid, uid, now)

    owned = db.execute(f"SELECT COUNT(*) FROM documents d WHERE {VISIBLE_DOCUMENTS_SQL} AND d.owner_id = ?",
                       visible + (uid,)).fetchone()[0]
    shared = db.execute(f"SELECT COUNT(*) FROM documents d WHERE {VISIBLE_DOCUMENTS_SQL} AND d.owner_id != ?",
                        visible + (uid,)).fetchone()[0]
    recent = db.execute(
        f"""SELECT d.id, d.title, d.category, d.updated_at, d.owner_id, u.name AS owner_name, v.sha256
              FROM documents d JOIN users u ON u.id = d.owner_id
              JOIN document_versions v ON v.document_id = d.id AND v.version_no = d.current_version
             WHERE {VISIBLE_DOCUMENTS_SQL} ORDER BY d.updated_at DESC LIMIT 6""", visible).fetchall()

    out = {
        "counts": {"owned": owned, "shared_with_me": shared},
        "recent": [{**dict(r), "mine": r["owner_id"] == uid} for r in recent],
        "unread": _unread(db, uid),
    }
    if owned:
        my = (uid, uid)
        out["owner"] = {
            "people_with_access": db.execute(
                """SELECT COUNT(DISTINCT gr.user_id) FROM grants gr JOIN documents d ON d.id = gr.document_id
                    WHERE d.owner_id = ? AND d.deleted_at IS NULL AND gr.revoked_at IS NULL
                      AND (gr.expires_at IS NULL OR gr.expires_at > ?)""", (uid, now)).fetchone()[0],
            "open_ended_grants": db.execute(
                """SELECT COUNT(*) FROM grants gr JOIN documents d ON d.id = gr.document_id
                    WHERE d.owner_id = ? AND d.deleted_at IS NULL AND gr.revoked_at IS NULL
                      AND gr.expires_at IS NULL""", (uid,)).fetchone()[0],
            "downloads_by_others_7d": db.execute(
                f"SELECT COUNT(*) {_MY_DOCS_ACTIVITY} AND a.action = 'document.download' "
                f"AND a.outcome = 'success' AND a.ts >= ?", my + (week,)).fetchone()[0],
            "refused_on_mine_7d": db.execute(
                f"SELECT COUNT(*) {_MY_DOCS_ACTIVITY} AND a.outcome = 'denied' AND a.ts >= ?",
                my + (week,)).fetchone()[0],
        }
    return jsonify(out)


@bp.get("/activity")
@login_required
def activity():
    db = get_db()
    uid = g.user["id"]
    try:
        limit = min(100, max(1, int(request.args.get("limit", 40))))
    except ValueError:
        raise ApiError(400, "limit must be a number.") from None
    rows = db.execute(
        f"""SELECT a.seq, a.ts, a.actor_email, a.action, a.outcome, a.document_id, a.details, d.title
             {_MY_DOCS_ACTIVITY} ORDER BY a.seq DESC LIMIT ?""", (uid, uid, limit)).fetchall()
    seen = db.execute("SELECT feed_seen_at FROM users WHERE id = ?", (uid,)).fetchone()["feed_seen_at"] or ""
    return jsonify(events=[{**dict(r), "unread": r["ts"] > seen} for r in rows], unread=_unread(db, uid))


@bp.post("/activity/seen")
@login_required
def activity_seen():
    db = get_db()
    with transaction(db):
        db.execute("UPDATE users SET feed_seen_at = ? WHERE id = ?", (now_iso(), g.user["id"]))
    return jsonify(unread=0)
