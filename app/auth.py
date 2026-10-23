"""Authentication: server-side sessions, CSRF protection, role checks.

Sessions live in the database and are looked up on every request. That is the
whole of "revocation is immediate": deactivating a user, changing their role,
resetting their password or logging out deletes their session rows, and the
very next request finds nothing.
"""
import secrets
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import current_app, g, request

from . import audit
from .db import get_db, iso, transaction, utcnow
from .errors import ApiError
from .security import constant_time_equal, new_token, token_hash

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def cfg():
    return current_app.config["TV"]


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=utcnow().tzinfo)


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------
def create_session(db, user_row) -> tuple[str, str]:
    """Create a new session. Returns (token, csrf_token). Always a fresh token,
    so a token planted before login (session fixation) is never upgraded."""
    token = new_token()
    csrf = new_token()
    now = utcnow()
    db.execute(
        "INSERT INTO sessions (token_hash, public_id, user_id, csrf_token, created_at, last_seen_at, reauth_at, "
        "expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (token_hash(token), secrets.token_hex(8), user_row["id"], csrf, iso(now), iso(now), iso(now),
         iso(now + timedelta(hours=cfg().SESSION_ABSOLUTE_HOURS)),
         request.remote_addr, request.headers.get("User-Agent", "")[:300]),
    )
    return token, csrf


def revoke_user_sessions(db, user_id: str, except_token_hash: str | None = None) -> int:
    if except_token_hash:
        cur = db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, except_token_hash))
    else:
        cur = db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM mfa_challenges WHERE user_id = ?", (user_id,))  # half-finished sign-ins too
    return cur.rowcount


def set_session_cookie(response, token: str):
    c = cfg()
    response.set_cookie(
        c.cookie_name, token,
        max_age=c.SESSION_ABSOLUTE_HOURS * 3600,
        secure=c.SECURE_COOKIES, httponly=True, samesite="Strict", path="/",
    )


def clear_session_cookie(response):
    c = cfg()
    response.delete_cookie(c.cookie_name, path="/", secure=c.SECURE_COOKIES, httponly=True, samesite="Strict")


def load_session():
    """before_request: resolve the cookie to a user, or to nobody."""
    g.user = None
    g.session = None
    token = request.cookies.get(cfg().cookie_name)
    if not token or len(token) > 128:
        return
    th = token_hash(token)
    db = get_db()
    row = db.execute(
        """SELECT s.token_hash, s.public_id, s.csrf_token, s.last_seen_at, s.expires_at, s.reauth_at,
                  u.id, u.email, u.name, u.role, u.is_active, u.is_demo, u.mfa_enabled
             FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?""",
        (th,),
    ).fetchone()
    if row is None:
        return
    now = utcnow()
    idle_limit = _parse(row["last_seen_at"]) + timedelta(minutes=cfg().SESSION_IDLE_MINUTES)
    if not row["is_active"] or _parse(row["expires_at"]) <= now or idle_limit <= now:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
        return
    if now - _parse(row["last_seen_at"]) > timedelta(seconds=60):
        db.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (iso(now), th))
    g.user = {k: row[k] for k in ("id", "email", "name", "role", "is_demo", "mfa_enabled")}
    g.session = {"token_hash": th, "public_id": row["public_id"], "csrf_token": row["csrf_token"],
                 "reauth_at": row["reauth_at"], "expires_at": row["expires_at"]}


# ---------------------------------------------------------------------------
# CSRF and origin checks
# ---------------------------------------------------------------------------
def _same_origin(origin: str) -> bool:
    if origin == "null":
        return False
    o = urlsplit(origin)
    h = urlsplit(request.host_url)
    return (o.scheme, o.netloc) == (h.scheme, h.netloc)


def refuse_head():
    """before_request. Flask answers HEAD by running the GET handler and
    dropping the body. For /api/documents/<id>/download that would write a
    'downloaded' audit record although no file left the server - false
    evidence. The API is not for HEAD; refuse it before any handler runs."""
    if request.method == "HEAD" and request.path.startswith("/api/"):  # AUTHZ-CHECK:head
        raise ApiError(405, "HEAD is not supported on the API.")


def csrf_protect():
    """before_request, after load_session.

    1. Any state-changing API request that carries an Origin header must come
       from our own origin.
    2. Authenticated state-changing requests must echo the per-session CSRF
       token in X-CSRF-Token. A cross-site form cannot set custom headers.
    3. Login must be JSON, which a cross-site HTML form cannot send without a
       CORS preflight that we never approve.
    The session cookie is also SameSite=Strict; these are layers, not
    alternatives.
    """
    if request.method in SAFE_METHODS or not request.path.startswith("/api/"):
        return
    origin = request.headers.get("Origin")
    if origin is not None and not _same_origin(origin):
        audit.append("security.bad_origin", "denied", details={"path": request.path, "origin": origin[:200]})
        raise ApiError(403, "Cross-origin request refused.")
    if request.path in ("/api/auth/login", "/api/auth/login/mfa"):
        if not request.is_json:
            raise ApiError(415, "Login must be sent as JSON.")
        return
    if g.user is None:
        return  # the route's own login check will answer 401
    if not constant_time_equal(request.headers.get("X-CSRF-Token"), g.session["csrf_token"]):
        audit.append("security.csrf_rejected", "denied", details={"path": request.path, "method": request.method})
        raise ApiError(403, "Missing or invalid CSRF token.")


# ---------------------------------------------------------------------------
# Route decorators
# ---------------------------------------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user is None:  # AUTHZ-CHECK:login
            raise ApiError(401, "Please sign in.")
        return fn(*args, **kwargs)
    # Declares the route's access rule. tests/test_route_policy.py fails the
    # build for any /api/ route that does not declare one.
    wrapper.tv_access = "signed-in"
    return wrapper


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user["role"] not in roles:  # AUTHZ-CHECK:role
                audit.append("access.denied", "denied",
                             details={"reason": "role", "required": list(roles), "path": request.path,
                                      "method": request.method})
                raise ApiError(403, "Your role does not allow this.")
            return fn(*args, **kwargs)
        wrapper.tv_access = "roles:" + ",".join(sorted(roles))
        return wrapper
    return decorator


def public(fn):
    """Marks a route as deliberately reachable without signing in."""
    fn.tv_access = "public"
    return fn


def require_recent_auth():
    """Step-up authentication ("sudo mode"). Sensitive actions need the password
    (and code, with MFA) to have been proved recently on THIS session. A stolen
    session cookie, or a laptop left unlocked, cannot share documents or use
    admin powers without the password. Answers 403 with code 'reauth_required';
    the UI asks for the password and retries."""
    ts = g.session.get("reauth_at") if g.session else None
    limit = iso(utcnow() - timedelta(minutes=cfg().REAUTH_MINUTES))
    if not ts or ts < limit:  # AUTHZ-CHECK:reauth
        record = dict(action="auth.reauth_required", outcome="denied",
                      details={"path": request.path, "method": request.method})
        if get_db().in_transaction:
            audit.defer(**record)  # survives the rollback (see authz._deny)
        else:
            audit.append(record.pop("action"), record.pop("outcome"), **record)
        raise ApiError(403, "Please confirm your password to continue.", code="reauth_required")


def recent_auth(fn):
    """Route decorator form of require_recent_auth(). Place it under the
    login/role decorator. tests/test_route_policy.py lists the routes that must
    carry it, so deleting it fails the build."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        require_recent_auth()
        return fn(*args, **kwargs)
    wrapper.tv_reauth = True
    return wrapper


# ---------------------------------------------------------------------------
# Throttling, stored in the database: shared by every worker process and it
# survives restarts. (v1 kept this in memory, per process - THREATS OP-16.)
# ---------------------------------------------------------------------------
def throttle(key: str, limit: int, window_seconds: int = 300) -> bool:
    """Record one attempt for `key`; False if `limit` attempts already happened
    inside the window."""
    db = get_db()
    now = utcnow()
    since = iso(now - timedelta(seconds=window_seconds))
    with transaction(db):
        db.execute("DELETE FROM login_attempts WHERE ts < ?", (iso(now - timedelta(days=1)),))
        n = db.execute("SELECT COUNT(*) FROM login_attempts WHERE key = ? AND ts >= ?", (key, since)).fetchone()[0]
        if n >= limit:  # AUTHZ-CHECK:throttle
            return False
        db.execute("INSERT INTO login_attempts (key, ts) VALUES (?, ?)", (key, iso(now)))
    return True
