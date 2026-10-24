"""Attack your DEPLOYED TrustVault the way a judge will, and report.
 
    python -m scripts.check_live https://trustvault-15td.onrender.com
 
Uses the seeded demo accounts. Every write it attempts is one that MUST be
refused; it changes nothing on the site (refused attempts do appear in the
audit trail and alerts, which is correct). Standard library only.
Exit code 0 = every check passed.
"""
import http.cookiejar
import ipaddress
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
 
# Variable names are roles in the story: admin, an owner (olivia), the person a
# document is shared with (vera) and a stranger to it (victor).
PW = {"admin": "Admin_123_demo", "olivia": "Owner1_123_demo", "victor": "Viewer2_123_demo",
      "vera": "Viewer1_123_demo", "ext": "Partner-Demo-2026!", "maya": "Maya-Demo-2026!"}
EMAIL = {"ext": "ext@partner.test", "admin": "jeevan@trustvault.test", "olivia": "advik@trustvault.test",
         "victor": "akhil@trustvault.test", "vera": "akhilesh@trustvault.test"}
 
 
class Session:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None
 
    def call(self, method, path, body=None, headers=None, raw=None, ctype="application/json", csrf=True):
        hdrs = dict(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
        if data is not None:
            hdrs.setdefault("Content-Type", ctype)
        if csrf and self.csrf and method not in ("GET", "HEAD"):
            hdrs.setdefault("X-CSRF-Token", self.csrf)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers
 
    def login(self, who):
        email = EMAIL.get(who, f"{who}@trustvault.test")
        s, b, h = self.call("POST", "/api/auth/login", {"email": email, "password": PW[who]})
        if s != 200:
            sys.exit(f"Could not sign in as {email} ({s}): {b[:200]!r}. Did you seed with TV_DEMO_MODE=1? "
                     "If you see 429, wait 5 minutes (sign-in rate limit).")
        d = json.loads(b)
        self.csrf = d.get("csrfToken")
        return h
 
 
def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    base = sys.argv[1].rstrip("/")
    https = base.startswith("https://")
    results = []
 
    def check(label, passed, detail=""):
        results.append(passed)
        print(("PASS  " if passed else "FAIL  ") + label + (f"  [{detail}]" if detail and not passed else ""))
 
    def section(t):
        print(f"\n--- {t}")
 
    anon = Session(base)
    s, _, h = anon.call("GET", "/healthz")
    check("site is up", s == 200, s)
 
    section("Transport and headers")
    s, _, h = anon.call("GET", "/")
    check("Content-Security-Policy is strict", "script-src 'self'" in h.get("Content-Security-Policy", ""), h.get("Content-Security-Policy"))
    check("clickjacking blocked (X-Frame-Options DENY)", h.get("X-Frame-Options") == "DENY")
    check("MIME sniffing off", h.get("X-Content-Type-Options") == "nosniff")
    check("no Referer leakage", h.get("Referrer-Policy") == "no-referrer")
    if https:
        check("HSTS enabled", "max-age" in h.get("Strict-Transport-Security", ""))
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None  # report the redirect itself instead of following it
        try:
            urllib.request.build_opener(NoRedirect).open(base.replace("https://", "http://", 1) + "/healthz", timeout=15)
            plain_ok = False
        except urllib.error.HTTPError as e:
            plain_ok = e.code in (301, 302, 307, 308)
        except Exception:
            plain_ok = True  # redirected to https and followed, or http closed
        check("plain HTTP does not serve the app (Force HTTPS on)", plain_ok)
    olivia = Session(base)
    lh = olivia.login("olivia")
    cookie = lh.get("Set-Cookie", "")
    check("session cookie is HttpOnly + SameSite=Strict", "HttpOnly" in cookie and "SameSite=Strict" in cookie, cookie[:80])
    if https:
        check("session cookie is Secure with the __Host- prefix", "Secure" in cookie and cookie.startswith("__Host-"), cookie[:80])
    else:
        print("note  not HTTPS: Secure/__Host-/HSTS checks skipped (run against your https:// URL)")
 
    victor, admin, vera = Session(base), Session(base), Session(base)
    victor.login("victor"); admin.login("admin"); vera.login("vera")
 
    mine = json.loads(olivia.call("GET", "/api/documents?scope=mine")[1])["documents"]
    secret = next((d for d in mine if d["title"] == "Salary letter - Akhilesh"), None)
    check("found Advik's private document to attack", secret is not None)
    if not secret:
        sys.exit("Seed data missing - run: python -m scripts.seed --reset")
    D = secret["id"]
    grants = json.loads(olivia.call("GET", f"/api/documents/{D}/grants")[1])["grants"]
    G = grants[0]["id"] if grants else "0" * 32
 
    section("A stranger (Akhil) on every route of a document he was not given")
    routes = [("GET", f"/api/documents/{D}", None), ("GET", f"/api/documents/{D}/download", None),
              ("GET", f"/api/documents/{D}/download?version=1", None), ("GET", f"/api/documents/{D}/activity", None),
              ("GET", f"/api/documents/{D}/grants", None), ("PATCH", f"/api/documents/{D}", {"title": "pwned"}),
              ("DELETE", f"/api/documents/{D}", None), ("POST", f"/api/documents/{D}/restore", {}),
              ("POST", f"/api/documents/{D}/grants", {"user_id": "SELF", "permission": "edit"}),
              ("PATCH", f"/api/documents/{D}/grants/{G}", {"permission": "edit"}),
              ("DELETE", f"/api/documents/{D}/grants/{G}", None), ("POST", f"/api/documents/{D}/suggestions", {})]
    me = json.loads(victor.call("GET", "/api/auth/me")[1])["user"]["id"]
    for m, p, body in routes:
        if body and body.get("user_id") == "SELF":
            body = {**body, "user_id": me}
        s, b, _ = victor.call(m, p, body)
        check(f"{m:6} {p.replace(D, '<doc>').replace(G, '<grant>'):42} -> 404", s == 404 and b"Salary" not in b, s)
    s, b, _ = victor.call("POST", "/api/review/revoke", {"grant_ids": [G]})
    check("bulk-revoke someone else's grant refused", s in (403, 404), s)
    s, b, _ = victor.call("GET", "/api/documents?q=Akhilesh")
    check("search does not reveal it", json.loads(b)["total"] == 0)
    s, b, _ = victor.call("GET", "/api/documents?tag=payroll")
    titles = [d["title"] for d in json.loads(b)["documents"]]
    check("tag filter does not reveal it", "Salary letter - Akhilesh" not in titles, titles)
    d = victor.call("GET", "/api/dashboard")[1]
    check("dashboard does not reveal it", b"Salary letter - Akhilesh" not in d)
    f = victor.call("GET", "/api/activity")[1]
    check("activity feed does not reveal it", b"Salary letter - Akhilesh" not in f)
    s, _, _ = victor.call("GET", "/api/documents/" + "0" * 32)
    s2, _, _ = victor.call("GET", f"/api/documents/{D}")
    check("'not yours' looks identical to 'does not exist'", s == s2 == 404)
    check("Advik's document is unchanged", json.loads(olivia.call("GET", f"/api/documents/{D}")[1])["document"]["title"] == "Salary letter - Akhilesh")
 
    section("Verbs, forged requests, sessions")
    s, _, _ = vera.call("HEAD", f"/api/documents/{D}/download")
    check("HEAD on a download is refused (no false audit record)", s == 405, s)
    s, _, _ = olivia.call("POST", f"/api/documents/{D}/grants", {"user_id": me, "permission": "read"}, csrf=False)
    check("state change without CSRF token refused", s == 403, s)
    s, _, _ = olivia.call("POST", f"/api/documents/{D}/grants", {"user_id": me, "permission": "read"}, headers={"Origin": "https://evil.example"})
    check("state change from a foreign Origin refused (even with token)", s == 403, s)
    s, _, _ = olivia.call("POST", f"/api/documents/{D}/grants", raw=json.dumps({"user_id": me, "permission": "read"}).encode(), ctype="text/plain", csrf=False)
    check("text/plain cross-site 'simple request' refused", s == 403, s)
    s, _, h = victor.call("GET", "/api/documents", headers={"Origin": "https://evil.example"})
    check("no CORS headers for foreign origins", "Access-Control-Allow-Origin" not in h)
    s, _, _ = anon.call("GET", f"/api/documents/{D}/download")
    check("no session -> 401", s == 401, s)
    forged = Session(base)
    forged.call("GET", "/healthz")
    s, _, _ = forged.call("GET", f"/api/documents/{D}", headers={"Cookie": "__Host-tv_session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; tv_session=AAAA"})
    check("forged session cookie -> 401", s == 401, s)
    s, _, _ = olivia.call("POST", f"/api/documents/{D}/grants", raw=b"[" * 50000 + b"]" * 50000)
    check("deeply nested JSON -> 400, not a crash", s == 400, s)
    s, _, _ = victor.call("GET", "/api/documents?page=99999999999999999999999")
    check("absurd page number -> no crash", s < 500, s)
    s, _, _ = victor.call("GET", "/api/admin/audit")
    check("viewer cannot open the audit trail", s == 403, s)
    s, _, _ = victor.call("PATCH", f"/api/admin/users/{me}", {"role": "admin"})
    check("viewer cannot make himself admin", s == 403, s)
 
    section("Administrator has no backdoor")
    # Step up first, so the refusals below come from the real controls
    # (no-backdoor, self-transfer, demo protection), not from "confirm your password".
    s, _, _ = admin.call("POST", "/api/auth/reauth", {"password": PW["admin"]})
    check("admin step-up re-authentication works", s == 200, s)
    s, b, _ = admin.call("GET", f"/api/documents/{D}/download")
    check("admin cannot download a document not shared with them", s == 404 and b"salary" not in b.lower(), s)
    s, b, _ = admin.call("POST", f"/api/admin/documents/{D}/transfer", {"new_owner_id": json.loads(admin.call("GET", "/api/auth/me")[1])["user"]["id"]})
    check("admin cannot transfer a document to themselves", s == 403, s)
    rows = json.loads(admin.call("GET", f"/api/admin/audit?document_id={D}&page_size=200")[1])["entries"]
    check("audit trail holds no raw file hashes (hash-confirmation)", not any("sha256" in (r["details"] or "") for r in rows if r["ts"] > "2026-10-22"))
 
    section("Two-step sign-in and demo safety")
    maya = Session(base)
    s, b, _ = maya.call("POST", "/api/auth/login", {"email": "maya@trustvault.test", "password": PW["maya"]})
    body = json.loads(b) if s == 200 else {}
    check("Maya's password alone gives no session", body.get("mfa_required") is True and "csrfToken" not in body)
    olivia_id = json.loads(olivia.call("GET", "/api/auth/me")[1])["user"]["id"]
    s, b, _ = admin.call("POST", f"/api/admin/users/{olivia_id}/reset-password", {"new_password": "Hijacked-Pass-1234"})
    check("demo accounts cannot be hijacked by the demo admin", s == 403 and b"reauth" not in b, s)
 
    section("Deployment sanity")
    rows = json.loads(admin.call("GET", "/api/admin/audit?action=auth.login&page_size=5")[1])["entries"]
    ip = next((r["ip"] for r in rows if r["ip"]), None)
    try:
        private = ip is None or ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback
    except ValueError:
        private = True
    if base.startswith(("http://127.", "http://localhost")):
        print(f"note  local run: audit records IP {ip}")
    else:
        check(f"audit records real client IPs (got {ip})", not private,
              "proxy setting wrong: set TV_TRUSTED_PROXIES to the number of proxies in front of the app")
    v = json.loads(admin.call("GET", "/api/admin/audit/verify")[1])
    check(f"audit chain intact ({v.get('count')} records)", v.get("valid") is True, v.get("reason"))
 
    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed." + ("" if passed == len(results) else "  FIX THE FAILURES BEFORE SUBMITTING."))
    sys.exit(0 if passed == len(results) else 1)
 
 
if __name__ == "__main__":
    main()
 
 
