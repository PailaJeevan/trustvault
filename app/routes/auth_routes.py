from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from .. import audit, totp
from ..auth import (cfg, clear_session_cookie, create_session, login_limiter, login_required,
                    revoke_user_sessions, set_session_cookie)
from ..db import get_db, iso, now_iso, transaction, utcnow
from ..errors import ApiError
from ..security import (decrypt_secret, encrypt_secret, hash_password, new_token, password_problem,
                        token_hash, verify_password)
from . import json_body

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

GENERIC_FAILURE = "Email or password is incorrect, or the account is temporarily locked."
MFA_FAILURE = "That code is not valid. Check your authenticator app and try again."
MFA_CHALLENGE_MINUTES = 5
MFA_MAX_ATTEMPTS = 5


def _public_user(u):
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
            "mfa_enabled": bool(u["mfa_enabled"])}


def _rate_limit():
    if not login_limiter.allow(request.remote_addr or "?", cfg().LOGIN_RATE_PER_IP):
        audit.append("auth.login", "denied", details={"reason": "ip_rate_limited", "path": request.path})
        raise ApiError(429, "Too many sign-in attempts from this address. Try again in a few minutes.")


def _record_failure(db, user, reason: str, **extra):
    """A failed password OR a failed MFA code counts towards the same lockout."""
    c = cfg()
    with transaction(db):
        failures = user["failed_logins"] + 1
        locked = failures >= c.LOGIN_MAX_FAILURES
        db.execute(
            "UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?",
            (0 if locked else failures,
             iso(utcnow() + timedelta(minutes=c.LOGIN_LOCK_MINUTES)) if locked else user["locked_until"],
             now_iso(), user["id"]),
        )
        audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                     details={"reason": reason, "failures": failures, "locked": locked, **extra})


def _start_session(db, user, mfa: bool):
    with transaction(db):
        db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        token, csrf = create_session(db, user)
        audit.append("auth.login", "success", actor=user, details={"mfa": mfa})
    resp = jsonify(user=_public_user(user), csrfToken=csrf)
    set_session_cookie(resp, token)
    return resp


def _user_secret(user) -> str:
    return decrypt_secret(cfg().MASTER_KEY, f"mfa:{user['id']}", user["mfa_secret_enc"])


# ---------------------------------------------------------------------------
# Sign in
# ---------------------------------------------------------------------------
@bp.post("/login")
def login():
    _rate_limit()
    data = json_body({"email", "password"}, {"email", "password"})
    email, password = data["email"], data["password"]
    if not isinstance(email, str) or not isinstance(password, str) or len(email) > 254 or len(password) > 256:
        raise ApiError(400, "Invalid email or password format.")
    email = email.strip()

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    # Always run the password check, even for unknown emails (timing).
    ok = verify_password(user["password_hash"] if user else None, password)

    if user is None:
        audit.append("auth.login", "denied", actor_email=email[:254], details={"reason": "unknown_email"})
        raise ApiError(401, GENERIC_FAILURE)
    if user["locked_until"] and user["locked_until"] > now_iso():
        audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                     details={"reason": "locked"})
        raise ApiError(401, GENERIC_FAILURE)
    if not user["is_active"]:
        audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                     details={"reason": "deactivated"})
        raise ApiError(401, GENERIC_FAILURE)
    if not ok:
        _record_failure(db, user, "bad_password")
        raise ApiError(401, GENERIC_FAILURE)

    if user["mfa_enabled"]:  # AUTHZ-CHECK:mfa-required
        # Password was right, but no session yet: issue a short-lived, single-
        # purpose challenge that can only be exchanged for a session with a code.
        challenge = new_token()
        now = utcnow()
        with transaction(db):
            db.execute("DELETE FROM mfa_challenges WHERE user_id = ? OR expires_at < ?", (user["id"], iso(now)))
            db.execute("INSERT INTO mfa_challenges (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                       (token_hash(challenge), user["id"], iso(now),
                        iso(now + timedelta(minutes=MFA_CHALLENGE_MINUTES))))
            audit.append("auth.mfa_challenge", target_user_id=user["id"], actor_email=user["email"])
        return jsonify(mfa_required=True, challenge=challenge)

    return _start_session(db, user, mfa=False)


@bp.post("/login/mfa")
def login_mfa():
    _rate_limit()
    data = json_body({"challenge", "code"}, {"challenge", "code"})
    if not isinstance(data["challenge"], str) or len(data["challenge"]) > 128:
        raise ApiError(400, "Invalid challenge.")
    db = get_db()
    ch = db.execute("SELECT * FROM mfa_challenges WHERE token_hash = ?", (token_hash(data["challenge"]),)).fetchone()
    if ch is None or ch["expires_at"] <= now_iso() or ch["attempts"] >= MFA_MAX_ATTEMPTS:
        audit.append("auth.login", "denied", details={"reason": "mfa_challenge_invalid"})
        raise ApiError(401, "This sign-in has expired. Start again with your email and password.")
    user = db.execute("SELECT * FROM users WHERE id = ?", (ch["user_id"],)).fetchone()
    if (not user["is_active"] or not user["mfa_enabled"]
            or (user["locked_until"] and user["locked_until"] > now_iso())):
        with transaction(db):
            db.execute("DELETE FROM mfa_challenges WHERE token_hash = ?", (ch["token_hash"],))
        audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                     details={"reason": "mfa_user_not_allowed"})
        raise ApiError(401, GENERIC_FAILURE)

    step = totp.verify(_user_secret(user), str(data["code"]), user["mfa_last_step"])
    if step is None:  # AUTHZ-CHECK:mfa-code
        with transaction(db):
            db.execute("UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash = ?", (ch["token_hash"],))
        _record_failure(db, user, "bad_mfa_code", challenge_attempts=ch["attempts"] + 1)
        raise ApiError(401, MFA_FAILURE)

    with transaction(db):
        # Conditional update: if two requests race with the same code, only one wins.
        cur = db.execute("UPDATE users SET mfa_last_step = ? WHERE id = ? AND mfa_last_step < ?",
                         (step, user["id"], step))
        db.execute("DELETE FROM mfa_challenges WHERE token_hash = ?", (ch["token_hash"],))
        won = cur.rowcount == 1
        if not won:  # recorded inside the transaction, which commits - then refuse
            audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                         details={"reason": "mfa_code_replayed"})
    if not won:
        raise ApiError(401, MFA_FAILURE)
    return _start_session(db, user, mfa=True)


@bp.post("/logout")
@login_required
def logout():
    db = get_db()
    with transaction(db):
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (g.session["token_hash"],))
        audit.append("auth.logout")
    resp = jsonify(ok=True)
    clear_session_cookie(resp)
    return resp


@bp.get("/me")
@login_required
def me():
    return jsonify(user=_public_user(g.user), csrfToken=g.session["csrf_token"])


@bp.post("/password")
@login_required
def change_password():
    if cfg().DEMO_MODE and g.user["is_demo"]:
        raise ApiError(403, "Shared demo accounts cannot change their password.")
    data = json_body({"current_password", "new_password"}, {"current_password", "new_password"})
    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if not verify_password(row["password_hash"], str(data["current_password"])):
        audit.append("auth.password_change", "denied", details={"reason": "bad_current_password"})
        raise ApiError(403, "Current password is incorrect.")
    problem = password_problem(data["new_password"])
    if problem:
        raise ApiError(400, problem)
    with transaction(db):
        db.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                   (hash_password(data["new_password"]), now_iso(), g.user["id"]))
        ended = revoke_user_sessions(db, g.user["id"], except_token_hash=g.session["token_hash"])
        audit.append("auth.password_change", details={"other_sessions_ended": ended})
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# MFA enrolment
# ---------------------------------------------------------------------------
def _check_password(db, password, action):
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if not isinstance(password, str) or not verify_password(row["password_hash"], password):
        audit.append(action, "denied", details={"reason": "bad_current_password"})
        raise ApiError(403, "Current password is incorrect.")


@bp.post("/mfa/setup")
@login_required
def mfa_setup():
    """Step 1: re-enter password, receive a new secret. Not active until confirmed."""
    if cfg().DEMO_MODE and g.user["is_demo"]:
        raise ApiError(403, "Shared demo accounts cannot change sign-in settings. "
                            "Sign in as maya@trustvault.test to try MFA, or create your own account as admin.")
    data = json_body({"current_password"}, {"current_password"})
    db = get_db()
    _check_password(db, data["current_password"], "auth.mfa_setup")
    if g.user["mfa_enabled"]:
        raise ApiError(409, "Two-step sign-in is already on. Turn it off first to set up a new device.")
    secret = totp.new_secret()
    with transaction(db):
        db.execute("UPDATE users SET mfa_secret_enc = ?, mfa_last_step = 0, updated_at = ? WHERE id = ?",
                   (encrypt_secret(cfg().MASTER_KEY, f"mfa:{g.user['id']}", secret), now_iso(), g.user["id"]))
        audit.append("auth.mfa_setup")
    return jsonify(secret=secret, otpauth_uri=totp.provisioning_uri(secret, g.user["email"]))


@bp.post("/mfa/enable")
@login_required
def mfa_enable():
    """Step 2: prove the authenticator works by entering a current code."""
    data = json_body({"code"}, {"code"})
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if user["mfa_enabled"]:
        raise ApiError(409, "Two-step sign-in is already on.")
    if user["mfa_secret_enc"] is None:
        raise ApiError(400, "Start setup first.")
    step = totp.verify(_user_secret(user), str(data["code"]), user["mfa_last_step"])
    if step is None:
        audit.append("auth.mfa_enable", "denied", details={"reason": "bad_code"})
        raise ApiError(400, MFA_FAILURE)
    with transaction(db):
        db.execute("UPDATE users SET mfa_enabled = 1, mfa_last_step = ?, updated_at = ? WHERE id = ?",
                   (step, now_iso(), user["id"]))
        ended = revoke_user_sessions(db, user["id"], except_token_hash=g.session["token_hash"])
        audit.append("auth.mfa_enable", details={"other_sessions_ended": ended})
    return jsonify(ok=True)


@bp.post("/mfa/disable")
@login_required
def mfa_disable():
    """Needs BOTH the password and a current code: a stolen session alone
    cannot remove the second factor."""
    data = json_body({"current_password", "code"}, {"current_password", "code"})
    db = get_db()
    _check_password(db, data["current_password"], "auth.mfa_disable")
    user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if not user["mfa_enabled"]:
        raise ApiError(400, "Two-step sign-in is not on.")
    step = totp.verify(_user_secret(user), str(data["code"]), user["mfa_last_step"])
    if step is None:  # AUTHZ-CHECK:mfa-disable-code
        audit.append("auth.mfa_disable", "denied", details={"reason": "bad_code"})
        raise ApiError(403, MFA_FAILURE)
    with transaction(db):
        db.execute("UPDATE users SET mfa_enabled = 0, mfa_secret_enc = NULL, mfa_last_step = 0, updated_at = ? "
                   "WHERE id = ?", (now_iso(), user["id"]))
        audit.append("auth.mfa_disable")
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Your own sessions
# ---------------------------------------------------------------------------
@bp.get("/sessions")
@login_required
def list_sessions():
    rows = get_db().execute(
        "SELECT public_id, created_at, last_seen_at, expires_at, ip, user_agent FROM sessions "
        "WHERE user_id = ? ORDER BY last_seen_at DESC", (g.user["id"],)).fetchall()
    return jsonify(sessions=[{**dict(r), "current": r["public_id"] == g.session["public_id"]} for r in rows])


@bp.delete("/sessions/<public_id>")
@login_required
def end_session(public_id):
    if not isinstance(public_id, str) or len(public_id) > 32:
        raise ApiError(404, "No such session.")
    db = get_db()
    with transaction(db):
        cur = db.execute("DELETE FROM sessions WHERE public_id = ? AND user_id = ?",  # AUTHZ-CHECK:session-owner
                         (public_id, g.user["id"]))
        if cur.rowcount == 0:
            raise ApiError(404, "No such session.")
        audit.append("auth.session_end", details={"session": public_id,
                                                  "own": public_id == g.session["public_id"]})
    return jsonify(ok=True)


@bp.post("/sessions/end-others")
@login_required
def end_other_sessions():
    db = get_db()
    with transaction(db):
        ended = revoke_user_sessions(db, g.user["id"], except_token_hash=g.session["token_hash"])
        audit.append("auth.session_end", details={"other_sessions_ended": ended})
    return jsonify(ended=ended)
