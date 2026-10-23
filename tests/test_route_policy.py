"""Every API route declares who may call it, and that declaration is enforced.

Why this file exists: the mutation sweep (scripts/mutation_sweep.py) showed that
deleting @login_required from a document route left behaviour unchanged,
because authorize() also refuses anonymous callers. Defence in depth, but a
removed check that no test notices. And deleting @roles_required("admin") from
six admin routes went unnoticed because no test called them as a non-admin.

THREATS.md: AC-16 (route without an access rule), AC-17 (admin route reachable
by non-admins), AC-6 (anonymous access).
"""
import hashlib
import unittest

from tests.base import TrustVaultTestCase

PUBLIC = {"auth.login", "auth.login_mfa", "auth.public_config"}
# The exact rule each role-restricted endpoint must declare.
ROLE_RULES = {
    "documents.upload_document": "roles:owner",
    "users.directory": "roles:admin,owner",
}


def api_endpoints(app):
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api/"):
            yield rule


class EveryRouteDeclaresItsAccessRule(TrustVaultTestCase):
    def test_no_api_route_is_left_open_by_accident(self):
        missing = []
        for rule in api_endpoints(self.app):
            access = getattr(self.app.view_functions[rule.endpoint], "tv_access", None)
            if rule.endpoint in PUBLIC:
                self.assertEqual(access, "public", rule.endpoint)
            elif access is None:
                missing.append(f"{rule.rule} ({rule.endpoint})")
        self.assertEqual(missing, [], "API routes without @login_required / @roles_required / @public")

    def test_admin_and_owner_routes_declare_the_right_role(self):
        for rule in api_endpoints(self.app):
            access = getattr(self.app.view_functions[rule.endpoint], "tv_access", None)
            if rule.endpoint.startswith("admin."):
                self.assertEqual(access, "roles:admin", rule.rule)
            elif rule.endpoint in ROLE_RULES:
                self.assertEqual(access, ROLE_RULES[rule.endpoint], rule.rule)

    def test_sensitive_routes_require_a_recent_password(self):
        """AN-16: step-up re-authentication. Deleting @recent_auth from any of
        these routes fails here, even though behaviour for a fresh session is
        unchanged."""
        required = {"grants.create_grant", "grants.accept_suggestion", "documents.delete_document",
                    "documents.restore_document"}
        for rule in api_endpoints(self.app):
            if rule.endpoint.startswith("admin.") and rule.methods & {"POST", "PATCH", "DELETE"}:
                required.add(rule.endpoint)
        missing = sorted(e for e in required if not getattr(self.app.view_functions[e], "tv_reauth", False))
        self.assertEqual(missing, [])
        self.assertGreaterEqual(len(required), 15)

    def test_every_non_public_route_refuses_anonymous_callers(self):
        anon = self.app.test_client()
        for rule in api_endpoints(self.app):
            if rule.endpoint in PUBLIC:
                continue
            path = rule.rule
            for arg in rule.arguments:
                path = path.replace(f"<{arg}>", "0" * 32)
            for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
                with self.subTest(route=f"{method} {rule.rule}"):
                    r = anon.open(path, method=method, json={} if method != "GET" else None)
                    self.assertEqual(r.status_code, 401, r.get_data(as_text=True)[:200])


class AdminRoutesRefuseEveryoneElse(TrustVaultTestCase):
    """Each admin action, called by an owner and by a viewer with a body that
    WOULD succeed for an admin, must be refused and change nothing."""

    def pending_request(self):
        if not hasattr(self, "_pending"):
            r = self.admin.post(f"/api/admin/users/{self.bob.id}/reset-password", {"new_password": "Queued-Pass-4821"})
            self._pending = r.get_json()["request_id"]
        return self._pending

    def snapshot(self):
        db = self.db()
        rows = []
        for sql in ("SELECT id, email, role, is_active, password_hash, mfa_enabled, locked_until, failed_logins FROM users ORDER BY id",
                    "SELECT id, owner_id, deleted_at, purged_at, legal_hold FROM documents ORDER BY id",
                    "SELECT id, revoked_at FROM grants ORDER BY id"):
            rows += [tuple(r) for r in db.execute(sql)]
        rows += [tuple(r) for r in db.execute("SELECT id, status FROM admin_requests ORDER BY id")]
        db.close()
        return hashlib.sha256(repr(rows).encode()).hexdigest()

    def test_every_admin_endpoint(self):
        doc = self.alice.upload()
        self.alice.grant(doc, self.vera)
        self.alice.delete(f"/api/documents/{doc}")
        db = self.db()  # make unlock / reset-mfa meaningful
        db.execute("UPDATE users SET locked_until = '2999-01-01T00:00:00.000000Z', mfa_enabled = 1 WHERE id = ?", (self.vera.id,))
        db.close()
        calls = [
            ("GET", "/api/admin/users", None), ("GET", "/api/admin/documents", None), ("GET", "/api/admin/audit", None),
            ("GET", "/api/admin/audit/verify", None), ("GET", "/api/admin/audit/export", None),
            ("GET", "/api/admin/alerts", None), ("GET", "/api/admin/stats", None),
            ("POST", "/api/admin/users", {"email": "new@x.y", "name": "New", "role": "admin", "password": "Valid-Password-123"}),
            ("PATCH", f"/api/admin/users/{self.vera.id}", {"role": "admin"}),
            ("POST", f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Hijacked-Pass-123"}),
            ("POST", f"/api/admin/users/{self.vera.id}/reset-mfa", {}),
            ("POST", f"/api/admin/users/{self.vera.id}/unlock", {}),
            ("POST", f"/api/admin/users/{self.vera.id}/offboard", {}),
            ("POST", f"/api/admin/documents/{doc}/transfer", {"new_owner_id": self.bob.id}),
            ("POST", f"/api/admin/documents/{doc}/legal-hold", {"hold": True, "reason": "x"}),
            ("POST", "/api/admin/purge-expired", {}),
            ("GET", "/api/admin/requests", None),
            ("POST", f"/api/admin/requests/{self.pending_request()}/approve", {}),
            ("POST", f"/api/admin/requests/{self.pending_request()}/reject", {}),
        ]
        self.cfg.TRASH_RETENTION_DAYS = -1  # purge WOULD destroy the trashed document
        covered = {c[1].split("/api/admin/")[1].split("/")[0] for c in calls}
        self.assertTrue({"users", "documents", "audit", "alerts", "stats", "purge-expired"} <= covered)
        before = self.snapshot()
        for who in (self.bob, self.vera, self.mallory):
            for method, path, body in calls:
                with self.subTest(who=who.email, call=f"{method} {path}"):
                    r = {"GET": lambda: who.get(path), "POST": lambda: who.post(path, body),
                         "PATCH": lambda: who.patch(path, body)}[method]()
                    self.assertEqual(r.status_code, 403, r.get_data(as_text=True)[:200])
        self.assertEqual(self.snapshot(), before, "a refused admin call changed something")
        db = self.db()
        self.assertIsNone(db.execute("SELECT 1 FROM users WHERE email = 'new@x.y'").fetchone())
        db.close()

    def test_every_admin_route_is_in_the_list_above(self):
        """If someone adds an admin route, this forces them to add it to the test."""
        listed = {"admin.list_users", "admin.list_documents", "admin.audit_list", "admin.audit_verify", "admin.audit_export",
                  "admin.alerts", "admin.stats", "admin.create_user", "admin.update_user", "admin.reset_password",
                  "admin.reset_mfa", "admin.unlock_user", "admin.offboard_user", "admin.transfer_ownership",
                  "admin.legal_hold", "admin.purge_expired",
                  "admin.list_requests", "admin.approve_request", "admin.reject_request"}
        actual = {r.endpoint for r in api_endpoints(self.app) if r.endpoint.startswith("admin.")}
        self.assertEqual(actual, listed)


class StrangerNarrowingAndSuggestions(TrustVaultTestCase):
    """Routes the first walker only exercised with 'widening' bodies."""

    def test_stranger_cannot_downgrade_shorten_or_touch_suggestions(self):
        old = self.alice.upload("Old", category="Finance")
        self.alice.grant(old, self.vera)
        doc = self.alice.upload("New", category="Finance")
        gid = self.alice.grant(doc, self.bob, "edit", expires_at="2026-12-31")
        sid = self.alice.post(f"/api/documents/{doc}/suggestions").get_json()["suggestions"][0]["id"]
        for who in (self.mallory, self.vera):
            with self.subTest(who=who.email):
                self.assertEqual(who.patch(f"/api/documents/{doc}/grants/{gid}", {"permission": "read"}).status_code, 404)
                self.assertEqual(who.patch(f"/api/documents/{doc}/grants/{gid}", {"expires_at": "2026-11-30"}).status_code, 404)
                self.assertEqual(who.post(f"/api/documents/{doc}/suggestions/{sid}/dismiss").status_code, 404)
                self.assertEqual(who.post(f"/api/documents/{doc}/suggestions/{sid}/accept", {"permission": "read"}).status_code, 404)
        g = self.alice.get(f"/api/documents/{doc}/grants").get_json()["grants"][0]
        self.assertEqual((g["permission"], g["expires_at"][:10]), ("edit", "2026-12-31"))
        self.assertEqual(len(self.alice.post(f"/api/documents/{doc}/suggestions").get_json()["suggestions"]), 1)


if __name__ == "__main__":
    unittest.main()
