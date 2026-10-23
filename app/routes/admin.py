"""Administration: accounts, ownership transfer, the audit trail and alerts.

The administrator manages people and watches activity. The administrator does
NOT read documents: there is no admin route that returns file content, and
authorize() ignores roles. An admin can see document metadata (title, owner,
category, grant count), because overseeing sharing is impossible without it.
"""
import json
from datetime import timedelta

from flask import Blueprint, Response, current_app, g, jsonify, request

from .. import audit
from ..auth import cfg, recent_auth, revoke_user_sessions, roles_required
from ..db import get_db, iso, now_iso, transaction, utcnow
from ..errors import ApiError
from ..security import hash_password, new_id, password_problem
from . import id_param, json_body, like_escape, page_params, parse_date, text_field

bp = Blueprint("admin", __name__, url_prefix="/api/admin")

ROLES = ("admin", "owner", "viewer")


def _user_json(u):
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
            "active": bool(u["is_active"]), "locked_until": u["locked_until"],
            "failed_logins": u["failed_logins"], "created_at": u["created_at"],
            "mfa_enabled": bool(u["mfa_enabled"]), "demo": bool(u["is_demo"])}


def _protect_demo(u, what: str):
    """On the public demo, one judge must not be able to lock the others out
    of the shared accounts. Reversible changes (role, deactivate) stay allowed."""
    if cfg().DEMO_MODE and u["is_demo"]:
        raise ApiError(403, f"{what} is disabled for the shared demo accounts. "
                            "Create your own account on the Users tab to try it.")


def _get_user(db, user_id):
    u = db.execute("SELECT * FROM users WHERE id = ?", (id_param(user_id, "user id"),)).fetchone()
    if u is None:
        raise ApiError(404, "No such user.")
    return u


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
@bp.get("/users")
@roles_required("admin")
def list_users():
    db = get_db()
    rows = db.execute("SELECT * FROM users ORDER BY role, name").fetchall()
    return jsonify(users=[_user_json(u) for u in rows])


@bp.post("/users")
@roles_required("admin")
@recent_auth
def create_user():
    data = json_body({"email", "name", "role", "password"}, {"email", "name", "role", "password"})
    email = text_field(data["email"], "email", 254).lower()
    if "@" not in email or " " in email:
        raise ApiError(400, "email is not valid.")
    name = text_field(data["name"], "name", 120)
    if data["role"] not in ROLES:
        raise ApiError(400, "role must be admin, owner or viewer.")
    problem = password_problem(data["password"], email, name)
    if problem:
        raise ApiError(400, problem)
    db = get_db()
    uid = new_id()
    now = now_iso()
    with transaction(db):
        if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise ApiError(409, "A user with that email already exists.")
        db.execute("INSERT INTO users (id, email, name, role, password_hash, created_at, updated_at) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (uid, email, name, data["role"], hash_password(data["password"]), now, now))
        audit.append("admin.user_create", target_user_id=uid, details={"email": email, "role": data["role"]})
    return jsonify(user=_user_json(_get_user(db, uid))), 201


@bp.patch("/users/<user_id>")
@roles_required("admin")
@recent_auth
def update_user(user_id):
    data = json_body({"role", "active", "name"})
    if not data:
        raise ApiError(400, "Nothing to change.")
    db = get_db()
    with transaction(db):
        u = _get_user(db, user_id)
        if u["id"] == g.user["id"] and ("role" in data or "active" in data):
            raise ApiError(400, "You cannot change your own role or deactivate yourself.")
        changes, diff = {}, {}
        if "role" in data:
            if data["role"] not in ROLES:
                raise ApiError(400, "role must be admin, owner or viewer.")
            if data["role"] == "admin" and u["role"] != "admin":
                # Widening to the most powerful role: two administrators must agree.
                if len(data) > 1:
                    raise ApiError(400, "Promote to administrator on its own, without other changes.")
                _check_promote(db, u, g.user["id"])
                return _request_or_run("promote_admin", target_user_id=u["id"], payload={})
            changes["role"] = data["role"]
        if "active" in data:
            if not isinstance(data["active"], bool):
                raise ApiError(400, "active must be true or false.")
            changes["is_active"] = 1 if data["active"] else 0
        if "name" in data:
            changes["name"] = text_field(data["name"], "name", 120)
        for k, v in changes.items():
            if u[k] != v:
                diff[k] = {"from": u[k], "to": v}
        if diff:
            sets = ", ".join(f"{k} = ?" for k in changes)
            db.execute(f"UPDATE users SET {sets}, updated_at = ? WHERE id = ?", (*changes.values(), now_iso(), u["id"]))
            ended = 0
            # Any change to what a person is allowed to be ends their sessions now.
            if "role" in diff or "is_active" in diff:
                ended = revoke_user_sessions(db, u["id"])
            audit.append("admin.user_update", target_user_id=u["id"],
                         details={"email": u["email"], "changes": diff, "sessions_ended": ended})
    return jsonify(user=_user_json(_get_user(db, user_id)))


@bp.post("/users/<user_id>/reset-password")
@roles_required("admin")
@recent_auth
def reset_password(user_id):
    data = json_body({"new_password", "reason"}, {"new_password"})
    db = get_db()
    u = _get_user(db, user_id)
    problem = password_problem(data["new_password"], u["email"], u["name"])
    if problem:
        raise ApiError(400, problem)
    _check_reset_password(db, u, g.user["id"])
    return _request_or_run("reset_password", target_user_id=u["id"], reason=data.get("reason"),
                           payload={"password_hash": hash_password(data["new_password"])})


@bp.post("/users/<user_id>/reset-mfa")
@roles_required("admin")
@recent_auth
def reset_mfa(user_id):
    """For a lost phone. Turns MFA off and ends their sessions; the person
    signs in with their password and sets MFA up again. Flagged in alerts."""
    data = request.get_json(silent=True) or {}
    db = get_db()
    u = _get_user(db, user_id)
    _check_reset_mfa(db, u, g.user["id"])
    reason = data.get("reason") if isinstance(data, dict) else None
    return _request_or_run("reset_mfa", target_user_id=u["id"], reason=reason, payload={})


@bp.post("/users/<user_id>/offboard")
@roles_required("admin")
@recent_auth
def offboard_user(user_id):
    """A leaver, in one step: deactivate, end every session, revoke every grant
    they hold, and list the documents they own so they can be transferred.
    Revoking the grants (not just deactivating) means that if the account is
    ever reactivated - by mistake or for a returning employee - it comes back
    with no access, not with everything it had."""
    db = get_db()
    with transaction(db):
        u = _get_user(db, user_id)
        if u["id"] == g.user["id"]:
            raise ApiError(400, "You cannot offboard yourself.")
        _protect_demo(u, "Offboarding")
        db.execute("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?", (now_iso(), u["id"]))
        ended = revoke_user_sessions(db, u["id"])
        grants = db.execute("SELECT id, document_id, permission FROM grants WHERE user_id = ? AND revoked_at IS NULL",
                            (u["id"],)).fetchall()
        for gr in grants:
            db.execute("UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ?",
                       (now_iso(), g.user["id"], gr["id"]))
            audit.append("permission.revoke", document_id=gr["document_id"], target_user_id=u["id"],
                         details={"grantee": u["email"], "permission": gr["permission"], "via": "offboarding"})
        owned = db.execute("SELECT id, title FROM documents WHERE owner_id = ? AND purged_at IS NULL",
                           (u["id"],)).fetchall()
        audit.append("admin.offboard", target_user_id=u["id"],
                     details={"email": u["email"], "sessions_ended": ended, "grants_revoked": len(grants),
                              "documents_owned": len(owned)})
    return jsonify(grants_revoked=len(grants), sessions_ended=ended,
                   documents_to_transfer=[{"id": d["id"], "title": d["title"]} for d in owned])


@bp.post("/users/<user_id>/unlock")
@roles_required("admin")
@recent_auth
def unlock_user(user_id):
    db = get_db()
    with transaction(db):
        u = _get_user(db, user_id)
        db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (u["id"],))
        audit.append("admin.user_unlock", target_user_id=u["id"], details={"email": u["email"]})
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Documents (metadata only) and ownership transfer
# ---------------------------------------------------------------------------
@bp.get("/documents")
@roles_required("admin")
def list_documents():
    db = get_db()
    now = now_iso()
    rows = db.execute(
        """SELECT d.id, d.title, d.category, d.created_at, d.deleted_at, d.purged_at, d.current_version,
                  d.legal_hold, d.legal_hold_reason, u.role AS owner_role,
                  u.name AS owner_name, u.email AS owner_email, u.is_active AS owner_active,
                  (SELECT COUNT(*) FROM grants gr WHERE gr.document_id = d.id AND gr.revoked_at IS NULL
                      AND (gr.expires_at IS NULL OR gr.expires_at > ?)) AS live_grants
             FROM documents d JOIN users u ON u.id = d.owner_id
            ORDER BY d.created_at DESC LIMIT 500""", (now,)).fetchall()
    return jsonify(documents=[dict(r) for r in rows])


@bp.post("/documents/<doc_id>/transfer")
@roles_required("admin")
@recent_auth
def transfer_ownership(doc_id):
    """For when an owner leaves. Guard rails: an admin cannot transfer a
    document to themselves (that would be a quiet way to read it), the new
    owner must be an active 'owner'-role user, and it is flagged in alerts."""
    data = json_body({"new_owner_id", "reason"}, {"new_owner_id"})
    db = get_db()
    doc, new_owner = _check_transfer(db, id_param(doc_id, "document id"), data["new_owner_id"], g.user["id"])
    return _request_or_run("transfer_ownership", target_user_id=new_owner["id"], document_id=doc["id"],
                           reason=data.get("reason"), payload={})


@bp.post("/documents/<doc_id>/legal-hold")
@roles_required("admin")
@recent_auth
def legal_hold(doc_id):
    """Place or lift a legal hold. While held, nobody - including the owner -
    can delete the document, and the retention job will not purge it if it was
    already in the trash. Holding does not give the admin any access."""
    data = json_body({"hold", "reason"}, {"hold"})
    if not isinstance(data["hold"], bool):
        raise ApiError(400, "hold must be true or false.")
    reason = text_field(data.get("reason"), "reason", 300, required=data["hold"])
    db = get_db()
    with transaction(db):
        doc = db.execute("SELECT * FROM documents WHERE id = ? AND purged_at IS NULL",
                         (id_param(doc_id, "document id"),)).fetchone()
        if doc is None:
            raise ApiError(404, "Document not found.")
        if bool(doc["legal_hold"]) == data["hold"]:
            raise ApiError(409, "The document is already " + ("under hold." if data["hold"] else "not under hold."))
        if data["hold"]:
            db.execute("UPDATE documents SET legal_hold = 1, legal_hold_reason = ?, legal_hold_by = ?, "
                       "legal_hold_at = ? WHERE id = ?", (reason, g.user["id"], now_iso(), doc["id"]))
        else:
            db.execute("UPDATE documents SET legal_hold = 0, legal_hold_reason = NULL, legal_hold_by = NULL, "
                       "legal_hold_at = NULL WHERE id = ?", (doc["id"],))
        audit.append("admin.legal_hold" if data["hold"] else "admin.legal_hold_release", document_id=doc["id"],
                     details={"title": doc["title"], "reason": reason or doc["legal_hold_reason"]})
    return jsonify(ok=True)


@bp.post("/purge-expired")
@roles_required("admin")
@recent_auth
def purge_expired():
    """Destroy the content of documents that have been in the trash longer than
    the retention period. Metadata and the audit trail are kept."""
    from ..retention import purge_expired as do_purge
    purged = do_purge(get_db(), current_app.config["TV"].TRASH_RETENTION_DAYS)
    return jsonify(purged=purged)


# ---------------------------------------------------------------------------
# Two-person rule ("dual control")
#
# Password reset, MFA reset, ownership transfer and promotion to admin are the
# powers that let one administrator quietly become someone else or reach a
# document (THREATS AC-3b). Each is now a REQUEST. It is carried out only when
# a DIFFERENT administrator approves it, and every check is run again at
# approval time, because things may have changed since the request.
# ---------------------------------------------------------------------------
def _check_reset_password(db, u, actor_id):
    if u["id"] == actor_id:
        raise ApiError(400, "Use 'change password' for your own account.")
    _protect_demo(u, "Resetting passwords")


def _check_reset_mfa(db, u, actor_id):
    if u["id"] == actor_id:
        raise ApiError(400, "Turn off your own two-step sign-in from your Account page.")
    _protect_demo(u, "Resetting two-step sign-in")
    if not u["mfa_enabled"]:
        raise ApiError(400, "That person does not have two-step sign-in turned on.")


def _check_promote(db, u, actor_id):
    if u["id"] == actor_id:
        raise ApiError(400, "You cannot change your own role.")
    if not u["is_active"]:
        raise ApiError(400, "Reactivate the account first.")


def _check_transfer(db, doc_id, new_owner_id, actor_id):
    doc = db.execute("SELECT * FROM documents WHERE id = ? AND purged_at IS NULL", (doc_id,)).fetchone()
    if doc is None:
        raise ApiError(404, "Document not found.")
    new_owner = _get_user(db, new_owner_id)
    if new_owner["id"] == actor_id:  # AUTHZ-CHECK:transfer-self
        audit.append("admin.ownership_transfer", "denied", document_id=doc["id"], details={"reason": "self_transfer"})
        raise ApiError(403, "An administrator cannot transfer a document to themselves.")
    if not new_owner["is_active"] or new_owner["role"] != "owner":
        raise ApiError(400, "The new owner must be an active user with the 'owner' role.")
    if new_owner["id"] == doc["owner_id"]:
        raise ApiError(400, "That user already owns this document.")
    return doc, new_owner


def _execute(db, req, approver_id):
    """Carry out an approved request. Runs inside the caller's transaction."""
    action, payload = req["action"], json.loads(req["payload"])
    by = {"requested_by": req["requested_by"], "approved_by": approver_id, "request_id": req["id"]}
    if action == "transfer_ownership":
        for who in (req["requested_by"], approver_id):  # neither admin may end up owning it
            _check_transfer(db, req["document_id"], req["target_user_id"], who)
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (req["document_id"],)).fetchone()
        old = db.execute("SELECT email FROM users WHERE id = ?", (doc["owner_id"],)).fetchone()
        new = db.execute("SELECT email FROM users WHERE id = ?", (req["target_user_id"],)).fetchone()
        db.execute("UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE document_id = ? AND user_id = ? "
                   "AND revoked_at IS NULL", (now_iso(), approver_id, doc["id"], req["target_user_id"]))
        db.execute("UPDATE documents SET owner_id = ?, updated_at = ? WHERE id = ?",
                   (req["target_user_id"], now_iso(), doc["id"]))
        audit.append("admin.ownership_transfer", document_id=doc["id"], target_user_id=req["target_user_id"],
                     details={"from": old["email"], "to": new["email"], "title": doc["title"], **by})
        return
    u = _get_user(db, req["target_user_id"])
    if u["id"] == approver_id:
        raise ApiError(403, "You cannot approve a request about your own account.")
    if action == "reset_password":
        _check_reset_password(db, u, req["requested_by"])
        db.execute("UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL, updated_at = ? "
                   "WHERE id = ?", (payload["password_hash"], now_iso(), u["id"]))
        ended = revoke_user_sessions(db, u["id"])
        audit.append("admin.password_reset", target_user_id=u["id"],
                     details={"email": u["email"], "sessions_ended": ended, **by})
    elif action == "reset_mfa":
        _check_reset_mfa(db, u, req["requested_by"])
        db.execute("UPDATE users SET mfa_enabled = 0, mfa_secret_enc = NULL, mfa_last_step = 0, updated_at = ? "
                   "WHERE id = ?", (now_iso(), u["id"]))
        ended = revoke_user_sessions(db, u["id"])
        audit.append("admin.mfa_reset", target_user_id=u["id"], details={"email": u["email"], "sessions_ended": ended, **by})
    elif action == "promote_admin":
        _check_promote(db, u, req["requested_by"])
        db.execute("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?", (now_iso(), u["id"]))
        ended = revoke_user_sessions(db, u["id"])
        audit.append("admin.user_update", target_user_id=u["id"],
                     details={"email": u["email"], "changes": {"role": {"from": u["role"], "to": "admin"}},
                              "sessions_ended": ended, **by})


def _request_or_run(action, *, target_user_id=None, document_id=None, payload=None, reason=None):
    db = get_db()
    reason = text_field(reason, "reason", 300, required=False) if reason else ""
    rid = new_id()
    now = utcnow()
    with transaction(db):
        db.execute("INSERT INTO admin_requests (id, action, target_user_id, document_id, payload, reason, "
                   "requested_by, requested_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (rid, action, target_user_id, document_id, json.dumps(payload or {}), reason, g.user["id"],
                    iso(now), iso(now + timedelta(hours=cfg().ADMIN_REQUEST_HOURS))))
        audit.append("admin.request_created", target_user_id=target_user_id, document_id=document_id,
                     details={"request_id": rid, "action": action, "reason": reason})
        if not cfg().DUAL_CONTROL:
            # Single-administrator deployments: recorded as a request, run at once.
            req = db.execute("SELECT * FROM admin_requests WHERE id = ?", (rid,)).fetchone()
            _execute(db, req, g.user["id"])
            db.execute("UPDATE admin_requests SET status = 'approved', decided_by = ?, decided_at = ?, payload = '{}', "
                       "outcome = 'done (dual control off)' WHERE id = ?", (g.user["id"], now_iso(), rid))
            return jsonify(status="done", request_id=rid)
    return jsonify(status="pending", request_id=rid,
                   message="Request created. Another administrator must approve it before it takes effect."), 202


def _request_json(db, r):
    def email(uid):
        row = db.execute("SELECT email FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
        return row["email"] if row else None
    doc = db.execute("SELECT title FROM documents WHERE id = ?", (r["document_id"],)).fetchone() if r["document_id"] else None
    return {"id": r["id"], "action": r["action"], "status": r["status"], "reason": r["reason"],
            "target": email(r["target_user_id"]), "document": doc["title"] if doc else None,
            "requested_by": email(r["requested_by"]), "requested_by_id": r["requested_by"],
            "requested_at": r["requested_at"], "expires_at": r["expires_at"],
            "decided_by": email(r["decided_by"]), "decided_at": r["decided_at"], "outcome": r["outcome"]}


@bp.get("/requests")
@roles_required("admin")
def list_requests():
    db = get_db()
    with transaction(db):
        db.execute("UPDATE admin_requests SET status = 'expired', payload = '{}' WHERE status = 'pending' AND expires_at < ?",
                   (now_iso(),))
    rows = db.execute("SELECT * FROM admin_requests ORDER BY (status = 'pending') DESC, requested_at DESC LIMIT 100").fetchall()
    return jsonify(requests=[_request_json(db, r) for r in rows],
                   active_admins=db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1").fetchone()[0])


def _pending(db, request_id):
    r = db.execute("SELECT * FROM admin_requests WHERE id = ?", (id_param(request_id, "request id"),)).fetchone()
    if r is None:
        raise ApiError(404, "No such request.")
    if r["status"] != "pending" or r["expires_at"] < now_iso():
        raise ApiError(409, "That request is no longer pending.")
    return r


@bp.post("/requests/<request_id>/approve")
@roles_required("admin")
@recent_auth
def approve_request(request_id):
    db = get_db()
    with transaction(db):
        r = _pending(db, request_id)
        if r["requested_by"] == g.user["id"]:  # AUTHZ-CHECK:dual-control
            audit.defer(action="admin.request_approve", outcome="denied",
                        details={"request_id": r["id"], "reason": "self_approval"})
            raise ApiError(403, "You cannot approve your own request. Another administrator must.")
        _execute(db, r, g.user["id"])
        db.execute("UPDATE admin_requests SET status = 'approved', decided_by = ?, decided_at = ?, payload = '{}', "
                   "outcome = 'done' WHERE id = ?", (g.user["id"], now_iso(), r["id"]))
        audit.append("admin.request_approved", target_user_id=r["target_user_id"], document_id=r["document_id"],
                     details={"request_id": r["id"], "action": r["action"], "requested_by": r["requested_by"]})
    return jsonify(status="approved")


@bp.post("/requests/<request_id>/reject")
@roles_required("admin")
@recent_auth
def reject_request(request_id):
    """Another admin rejects it, or the requester withdraws it."""
    db = get_db()
    with transaction(db):
        r = _pending(db, request_id)
        status = "cancelled" if r["requested_by"] == g.user["id"] else "rejected"
        db.execute("UPDATE admin_requests SET status = ?, decided_by = ?, decided_at = ?, payload = '{}' WHERE id = ?",
                   (status, g.user["id"], now_iso(), r["id"]))
        audit.append("admin.request_" + status, target_user_id=r["target_user_id"], document_id=r["document_id"],
                     details={"request_id": r["id"], "action": r["action"]})
    return jsonify(status=status)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------
def _audit_filters():
    where, params = [], []
    for arg, col in (("action", "action"), ("outcome", "outcome"), ("document_id", "document_id"),
                     ("actor_id", "actor_id"), ("target_user_id", "target_user_id")):
        v = request.args.get(arg)
        if v:
            if arg == "action" and v.endswith("*"):
                where.append("action LIKE ? ESCAPE '\\'")
                params.append(like_escape(v[:-1][:60]) + "%")
            else:
                where.append(f"{col} = ?")
                params.append(v[:100])
    actor = request.args.get("actor")
    if actor:
        where.append("actor_email LIKE ? ESCAPE '\\'")
        params.append(f"%{like_escape(actor[:100])}%")
    f = parse_date(request.args.get("from"), "from")
    t = parse_date(request.args.get("to"), "to", end_of_day=True)
    if f:
        where.append("ts >= ?")
        params.append(f)
    if t:
        where.append("ts <= ?")
        params.append(t)
    return (" WHERE " + " AND ".join(where)) if where else "", params


@bp.get("/audit")
@roles_required("admin")
def audit_list():
    db = get_db()
    where, params = _audit_filters()
    page, size = page_params(200)
    total = db.execute(f"SELECT COUNT(*) FROM audit_log{where}", params).fetchone()[0]
    rows = db.execute(
        f"""SELECT a.seq, a.ts, a.actor_id, a.actor_email, a.action, a.outcome, a.document_id,
                   a.target_user_id, a.ip, a.details, a.prev_hash, a.hash,
                   d.title AS document_title, tu.email AS target_email
              FROM (SELECT * FROM audit_log{where}) a
              LEFT JOIN documents d ON d.id = a.document_id
              LEFT JOIN users tu ON tu.id = a.target_user_id
             ORDER BY a.seq DESC LIMIT ? OFFSET ?""", params + [size, (page - 1) * size]).fetchall()
    return jsonify(entries=[dict(r) for r in rows], total=total, page=page, page_size=size)


@bp.get("/audit/verify")
@roles_required("admin")
def audit_verify():
    result = audit.verify_chain(get_db(), current_app.config["TV"].AUDIT_KEY)
    return jsonify(result)


@bp.get("/audit/export")
@roles_required("admin")
def audit_export():
    """Full log as JSON lines, including hashes, so a copy can be kept off the
    server and later compared against it."""
    db = get_db()
    audit.append("admin.audit_export")
    lines = (json.dumps(dict(r)) + "\n" for r in db.execute("SELECT * FROM audit_log ORDER BY seq").fetchall())
    return Response(lines, mimetype="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="trustvault-audit-{now_iso()[:10]}.jsonl"'})


@bp.get("/stats")
@roles_required("admin")
def stats():
    """Numbers for the admin overview. Counts and audit metadata only."""
    db = get_db()
    now = utcnow()
    days = 14
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    rows = db.execute(
        """SELECT substr(ts, 1, 10) AS day,
                  SUM(outcome = 'success') AS allowed, SUM(outcome = 'denied') AS refused
             FROM audit_log WHERE ts >= ? GROUP BY day""", (iso(start),)).fetchall()
    by_day = {r["day"]: r for r in rows}
    series = []
    for i in range(days):
        d = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        r = by_day.get(d)
        series.append({"day": d, "allowed": (r["allowed"] if r else 0) or 0, "refused": (r["refused"] if r else 0) or 0})
    week = iso(now - timedelta(days=7))
    users = db.execute("SELECT COUNT(*) total, SUM(is_active) active, SUM(is_active AND mfa_enabled) mfa "
                       "FROM users").fetchone()
    return jsonify(
        series=series,
        totals={
            "users_active": users["active"] or 0,
            "users_with_mfa": users["mfa"] or 0,
            "documents": db.execute("SELECT COUNT(*) FROM documents WHERE deleted_at IS NULL AND purged_at IS NULL"
                                    ).fetchone()[0],
            "live_grants": db.execute("SELECT COUNT(*) FROM grants WHERE revoked_at IS NULL AND "
                                      "(expires_at IS NULL OR expires_at > ?)", (now_iso(),)).fetchone()[0],
            "on_legal_hold": db.execute("SELECT COUNT(*) FROM documents WHERE legal_hold = 1").fetchone()[0],
            "audit_records": db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        },
        top_refused=[dict(r) for r in db.execute(
            """SELECT COALESCE(actor_email, ip, 'unknown') AS who, COUNT(*) AS n FROM audit_log
                WHERE outcome = 'denied' AND ts >= ? GROUP BY who ORDER BY n DESC LIMIT 5""", (week,))],
        action_mix=[dict(r) for r in db.execute(
            """SELECT substr(action, 1, instr(action, '.') - 1) AS area, COUNT(*) AS n FROM audit_log
                WHERE ts >= ? GROUP BY area ORDER BY n DESC""", (week,))],
    )


@bp.get("/alerts")
@roles_required("admin")
def alerts():
    """Things worth a human's attention, computed from the audit log."""
    db = get_db()
    now = utcnow()
    day = iso(now - timedelta(hours=24))
    hour = iso(now - timedelta(hours=1))
    week = iso(now - timedelta(days=7))
    out = []

    chain = audit.verify_chain(db, current_app.config["TV"].AUDIT_KEY)
    if not chain["valid"]:
        out.append({"severity": "critical", "title": "Audit trail integrity check failed",
                    "detail": f"Record {chain['broken_at']}: {chain['reason']}"})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n, COUNT(DISTINCT document_id) docs FROM audit_log
                WHERE outcome = 'denied' AND action LIKE 'document.%' AND ts >= ? AND actor_id IS NOT NULL
                GROUP BY actor_id HAVING n >= 5 ORDER BY n DESC""", (day,)):
        out.append({"severity": "high", "title": "Repeated refused document access",
                    "detail": f"{r['actor_email']} was refused {r['n']} times on {r['docs']} document id(s) "
                              "in 24h - possible probing.", "actor": r["actor_email"]})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n FROM audit_log
                WHERE action = 'auth.login' AND outcome = 'denied' AND ts >= ?
                GROUP BY actor_email HAVING n >= 5 ORDER BY n DESC""", (day,)):
        out.append({"severity": "medium", "title": "Repeated failed sign-ins",
                    "detail": f"{r['n']} failed sign-ins for {r['actor_email']} in 24h.", "actor": r["actor_email"]})

    for r in db.execute(
            """SELECT ip, COUNT(DISTINCT actor_email) accounts, COUNT(*) n FROM audit_log
                WHERE action = 'auth.login' AND outcome = 'denied' AND ts >= ?
                GROUP BY ip HAVING accounts >= 3 ORDER BY n DESC""", (day,)):
        out.append({"severity": "high", "title": "One address trying many accounts",
                    "detail": f"{r['ip']} failed to sign in to {r['accounts']} different accounts in 24h."})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n, COUNT(DISTINCT document_id) docs FROM audit_log
                WHERE action = 'document.download' AND outcome = 'success' AND ts >= ?
                GROUP BY actor_id HAVING n >= 20 ORDER BY n DESC""", (hour,)):
        out.append({"severity": "high", "title": "Unusual download volume",
                    "detail": f"{r['actor_email']} downloaded {r['n']} times ({r['docs']} documents) in the last hour.",
                    "actor": r["actor_email"]})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n FROM audit_log
                WHERE action = 'permission.grant' AND outcome = 'success' AND ts >= ?
                GROUP BY actor_id HAVING n >= 10""", (hour,)):
        out.append({"severity": "medium", "title": "Burst of sharing",
                    "detail": f"{r['actor_email']} granted access {r['n']} times in the last hour."})

    for r in db.execute(
            """SELECT ts, actor_email, action, details FROM audit_log
                WHERE (action IN ('admin.ownership_transfer', 'admin.password_reset', 'admin.mfa_reset',
                                  'admin.offboard', 'admin.legal_hold_release', 'admin.request_rejected')
                       OR (action = 'admin.user_update' AND details LIKE '%"role"%'))
                  AND outcome = 'success' AND ts >= ? ORDER BY seq DESC LIMIT 20""", (week,)):
        out.append({"severity": "info", "title": "Privileged administrator action",
                    "detail": f"{r['ts'][:16].replace('T', ' ')} - {r['actor_email']}: {r['action']} {r['details']}"})

    for r in db.execute(
            """SELECT action, COUNT(*) n FROM audit_log
                WHERE action IN ('security.csrf_rejected', 'security.bad_origin') AND ts >= ? GROUP BY action""",
            (day,)):
        out.append({"severity": "medium", "title": "Forged-request attempts",
                    "detail": f"{r['n']} request(s) refused by {r['action']} in 24h."})

    stale = db.execute(
        """SELECT COUNT(*) FROM documents d JOIN users u ON u.id = d.owner_id
            WHERE u.is_active = 0 AND d.deleted_at IS NULL""").fetchone()[0]
    if stale:
        out.append({"severity": "medium", "title": "Documents owned by deactivated users",
                    "detail": f"{stale} document(s) have no active owner. Transfer them so someone can manage access."})

    demoted = db.execute(
        """SELECT COUNT(*) FROM documents d JOIN users u ON u.id = d.owner_id
            WHERE u.is_active = 1 AND u.role != 'owner' AND d.deleted_at IS NULL AND d.purged_at IS NULL""").fetchone()[0]
    if demoted:
        out.append({"severity": "medium", "title": "Documents owned by people who are no longer owners",
                    "detail": f"{demoted} document(s) belong to someone whose role changed. They can still revoke "
                              "access but cannot share. Consider transferring them."})

    inactive_grants = db.execute(
        """SELECT COUNT(*) FROM grants gr JOIN users u ON u.id = gr.user_id
            WHERE gr.revoked_at IS NULL AND u.is_active = 0""").fetchone()[0]
    if inactive_grants:
        out.append({"severity": "medium", "title": "Live grants held by deactivated accounts",
                    "detail": f"{inactive_grants} grant(s) would come back if those accounts were reactivated. "
                              "Use Offboard to revoke them."})

    pending = db.execute("SELECT COUNT(*) FROM admin_requests WHERE status = 'pending' AND expires_at >= ?",
                         (now_iso(),)).fetchone()[0]
    if pending:
        out.append({"severity": "medium", "title": "Requests waiting for a second administrator",
                    "detail": f"{pending} sensitive request(s) need approval. Check them on the Approvals tab."})
    if cfg().DUAL_CONTROL and db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1").fetchone()[0] < 2:
        out.append({"severity": "high", "title": "Only one active administrator",
                    "detail": "The two-person rule needs a second administrator, or sensitive requests can never be approved."})

    no_mfa_admins = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1 AND mfa_enabled = 0"
                               ).fetchone()[0]
    if no_mfa_admins:
        out.append({"severity": "info", "title": "Administrators without two-step sign-in",
                    "detail": f"{no_mfa_admins} active administrator account(s) sign in with a password only."})

    return jsonify(alerts=out, audit_chain=chain)
