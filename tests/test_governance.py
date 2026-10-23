"""Governance features: widening needs the owner role, access review, offboarding,
legal hold, tags, demo protection, migrations, and the check-then-act race.

THREATS.md: AC-11 (race), AC-12 (demoted owner widens), RV-11 (reactivated leaver),
RT-1/RT-2 (legal hold), RW-1 (bulk revoke confusion), SR-6 (tag leakage), OP-10 (demo sabotage),
OP-11 (schema upgrade).
"""
import io
import os
import sqlite3
import threading
import time
import unittest

from app import create_app
from app.config import Config
from app.db import connect, init_schema, now_iso
from tests.base import PASSWORD, TrustVaultTestCase, pdf_bytes


class WideningNeedsOwnerRole(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.doc = self.alice.upload("Plan", "p.pdf", pdf_bytes("PLAN"))
        self.gid = self.alice.grant(self.doc, self.vera, "read")
        self.admin.patch(f"/api/admin/users/{self.alice.id}", {"role": "viewer"})
        self.alice.login()
        self.alice.client.get("/")  # new session after role change

    def test_demoted_owner_cannot_share_upgrade_or_restore(self):
        r = self.alice.post(f"/api/documents/{self.doc}/grants", {"user_id": self.mallory.id, "permission": "read"})
        self.assertEqual(r.status_code, 403)
        r = self.alice.patch(f"/api/documents/{self.doc}/grants/{self.gid}", {"permission": "edit"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.mallory.get(f"/api/documents/{self.doc}").status_code, 404)
        self.assertEqual(self.vera.patch(f"/api/documents/{self.doc}", {"title": "x"}).status_code, 403)
        self.assertEqual(self.alice.delete(f"/api/documents/{self.doc}").status_code, 200)
        self.assertEqual(self.alice.post(f"/api/documents/{self.doc}/restore").status_code, 403)

    def test_demoted_owner_can_still_narrow(self):
        self.assertEqual(self.alice.get(f"/api/documents/{self.doc}/grants").status_code, 200)
        self.assertEqual(self.alice.delete(f"/api/documents/{self.doc}/grants/{self.gid}").status_code, 200)
        self.assertEqual(self.vera.get(f"/api/documents/{self.doc}").status_code, 404)

    def test_alert_lists_documents_of_demoted_owners(self):
        titles = [a["title"] for a in self.admin.get("/api/admin/alerts").get_json()["alerts"]]
        self.assertIn("Documents owned by people who are no longer owners", titles)


class ExtendingIsWidening(TrustVaultTestCase):
    def test_demoted_owner_can_shorten_but_not_extend_or_remove_expiry(self):
        from datetime import timedelta
        from app.db import iso, utcnow
        doc = self.alice.upload()
        in30 = iso(utcnow() + timedelta(days=30))
        gid = self.alice.grant(doc, self.vera, "read", expires_at=in30)
        self.admin.patch(f"/api/admin/users/{self.alice.id}", {"role": "viewer"})
        self.alice.login()
        later = iso(utcnow() + timedelta(days=200))
        sooner = iso(utcnow() + timedelta(days=5))
        self.assertEqual(self.alice.patch(f"/api/documents/{doc}/grants/{gid}", {"expires_at": later}).status_code, 403)
        self.assertEqual(self.alice.patch(f"/api/documents/{doc}/grants/{gid}", {"expires_at": None}).status_code, 403)
        self.assertEqual(self.alice.patch(f"/api/documents/{doc}/grants/{gid}", {"expires_at": sooner}).status_code, 200)


class AccessReview(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.d1 = self.alice.upload("HR one", category="HR")
        self.d2 = self.alice.upload("General two", category="General")
        self.g1 = self.alice.grant(self.d1, self.vera, "edit")
        self.g2 = self.alice.grant(self.d2, self.mallory, "read")
        self.bob_doc = self.bob.upload("Bob's")
        self.bob_grant = self.bob.grant(self.bob_doc, self.vera)

    def test_review_lists_only_my_documents_with_flags(self):
        rows = self.alice.get("/api/review/grants").get_json()["grants"]
        self.assertEqual({r["grant_id"] for r in rows}, {self.g1, self.g2})
        hr = next(r for r in rows if r["grant_id"] == self.g1)
        codes = {f["code"] for f in hr["flags"]}
        self.assertIn("no_expiry", codes)
        self.assertIn("sensitive_edit", codes)

    def test_viewer_sees_nothing_in_review(self):
        self.assertEqual(self.vera.get("/api/review/grants").get_json()["grants"], [])

    def test_bulk_revoke_works(self):
        r = self.alice.post("/api/review/revoke", {"grant_ids": [self.g1, self.g2]})
        self.assertEqual(r.get_json()["revoked"], 2)
        self.assertEqual(self.vera.get(f"/api/documents/{self.d1}").status_code, 404)
        self.assertEqual(self.mallory.get(f"/api/documents/{self.d2}").status_code, 404)

    def test_bulk_revoke_refuses_someone_elses_grant_and_changes_nothing(self):
        r = self.alice.post("/api/review/revoke", {"grant_ids": [self.g1, self.bob_grant]})
        self.assertIn(r.status_code, (403, 404))
        # all-or-nothing: Alice's own grant was not revoked either
        self.assertEqual(self.vera.get(f"/api/documents/{self.d1}").status_code, 200)
        self.assertEqual(self.vera.get(f"/api/documents/{self.bob_doc}").status_code, 200)
        self.assertTrue(self.audit_rows(actor_id=self.alice.id, outcome="denied", document_id=self.bob_doc))


class Offboarding(TrustVaultTestCase):
    def test_offboard_revokes_everything_so_reactivation_restores_nothing(self):
        doc = self.alice.upload()
        self.alice.grant(doc, self.vera, "edit")
        r = self.admin.post(f"/api/admin/users/{self.vera.id}/offboard")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["grants_revoked"], 1)
        self.assertEqual(self.vera.get("/api/documents").status_code, 401)
        self.admin.patch(f"/api/admin/users/{self.vera.id}", {"active": True})
        self.vera.login()
        self.assertEqual(self.vera.get(f"/api/documents/{doc}").status_code, 404)

    def test_offboarding_an_owner_lists_documents_to_transfer(self):
        doc = self.alice.upload("Orphan")
        r = self.admin.post(f"/api/admin/users/{self.alice.id}/offboard").get_json()
        self.assertEqual([d["id"] for d in r["documents_to_transfer"]], [doc])

    def test_only_admins_can_offboard(self):
        self.assertEqual(self.alice.post(f"/api/admin/users/{self.vera.id}/offboard").status_code, 403)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)


class LegalHold(TrustVaultTestCase):
    def test_hold_blocks_deletion_by_the_owner(self):
        doc = self.alice.upload()
        self.assertEqual(self.admin.post(f"/api/admin/documents/{doc}/legal-hold",
                                         {"hold": True, "reason": "Litigation 2026-17"}).status_code, 200)
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}").status_code, 423)
        self.assertEqual(self.alice.get(f"/api/documents/{doc}").status_code, 200)
        self.assertTrue(self.audit_rows(action="document.delete", outcome="denied", document_id=doc))
        self.admin.post(f"/api/admin/documents/{doc}/legal-hold", {"hold": False})
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}").status_code, 200)

    def test_hold_stops_purge_of_a_trashed_document(self):
        from app.db import get_db
        from app.retention import purge_expired
        doc = self.alice.upload()
        self.alice.delete(f"/api/documents/{doc}")
        self.admin.post(f"/api/admin/documents/{doc}/legal-hold", {"hold": True, "reason": "Regulator request"})
        with self.app.app_context():
            self.assertEqual(purge_expired(get_db(), retention_days=-1), [])
        self.assertEqual(self.alice.post(f"/api/documents/{doc}/restore").status_code, 200)

    def test_hold_gives_admin_no_access_and_needs_reason(self):
        doc = self.alice.upload()
        self.assertEqual(self.admin.post(f"/api/admin/documents/{doc}/legal-hold", {"hold": True}).status_code, 400)
        self.admin.post(f"/api/admin/documents/{doc}/legal-hold", {"hold": True, "reason": "x"})
        self.assertEqual(self.admin.get(f"/api/documents/{doc}/download").status_code, 404)
        self.assertEqual(self.alice.post(f"/api/admin/documents/{doc}/legal-hold", {"hold": False}).status_code, 403)


class Tags(TrustVaultTestCase):
    def test_tags_organise_and_filter(self):
        r = self.alice.post("/api/documents", data={"title": "T", "category": "HR", "tags": "Payroll, 2026",
                                                    "file": (io.BytesIO(pdf_bytes()), "t.pdf")})
        doc = r.get_json()["document"]
        self.assertEqual(doc["tags"], ["2026", "payroll"])
        listing = self.alice.get("/api/documents?tag=payroll").get_json()
        self.assertEqual([d["id"] for d in listing["documents"]], [doc["id"]])
        self.assertEqual(listing["tags"], ["2026", "payroll"])

    def test_tags_never_widen_or_leak(self):
        r = self.alice.post("/api/documents", data={"title": "Secret", "category": "HR", "tags": "merger-zeta",
                                                    "file": (io.BytesIO(pdf_bytes()), "s.pdf")})
        listing = self.mallory.get("/api/documents?tag=merger-zeta").get_json()
        self.assertEqual(listing["total"], 0)
        self.assertNotIn("merger-zeta", listing["tags"])

    def test_tag_validation_and_edit_rights(self):
        doc = self.alice.upload()
        self.assertEqual(self.alice.patch(f"/api/documents/{doc}", {"tags": ["<script>"]}).status_code, 400)
        self.assertEqual(self.alice.patch(f"/api/documents/{doc}", {"tags": [str(i) for i in range(11)]}).status_code, 400)
        self.alice.grant(doc, self.vera, "read")
        self.assertEqual(self.vera.patch(f"/api/documents/{doc}", {"tags": ["mine"]}).status_code, 403)


class DemoProtection(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.cfg.DEMO_MODE = True
        db = self.db()
        db.execute("UPDATE users SET is_demo = 1 WHERE id = ?", (self.vera.id,))
        db.close()

    def test_admin_cannot_lock_others_out_of_shared_demo_accounts(self):
        for path, body in ((f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Hijack-Pass-123"}),
                           (f"/api/admin/users/{self.vera.id}/offboard", {})):
            with self.subTest(path=path):
                self.assertEqual(self.admin.post(path, body).status_code, 403)
        self.assertEqual(self.vera.login().status_code, 200)

    def test_non_demo_accounts_are_unaffected(self):
        r = self.admin_do(f"/api/admin/users/{self.mallory.id}/reset-password", {"new_password": "Fresh-Pass-1234"})
        self.assertEqual(r.status_code, 200)


class Migrations(unittest.TestCase):
    def test_a_version_1_database_upgrades_in_place(self):
        import secrets
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "old.db")
            db = connect(path)
            init_schema(db)  # exactly what an earlier deployment created
            db.execute("INSERT INTO users (id, email, name, role, password_hash, created_at, updated_at) "
                       "VALUES ('a'*1, 'old@x.y', 'Old', 'owner', 'h', ?, ?)", (now_iso(), now_iso()))
            db.close()
            create_app(Config(TESTING=True, DATABASE_PATH=path, MASTER_KEY=secrets.token_bytes(32),
                              AUDIT_KEY=secrets.token_bytes(32), SECURE_COOKIES=False))
            db = connect(path)
            from app.migrations import LATEST
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], LATEST)
            cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
            self.assertIn("mfa_enabled", cols)
            self.assertEqual(db.execute("SELECT email FROM users").fetchone()[0], "old@x.y")
            db.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class CheckThenActRace(TrustVaultTestCase):
    """AC-11: a revoke that commits while a download is waiting must win."""

    def test_download_waiting_on_a_revoke_is_refused(self):
        doc = self.alice.upload("Race", "r.pdf", pdf_bytes("RACE"))
        gid = self.alice.grant(doc, self.vera)
        holder = sqlite3.connect(self.cfg.DATABASE_PATH, isolation_level=None, timeout=15)
        holder.execute("BEGIN IMMEDIATE")  # someone is mid-way through revoking
        holder.execute("UPDATE grants SET revoked_at = ? WHERE id = ?", (now_iso(), gid))
        result = {}

        def download():
            result["r"] = self.vera.get(f"/api/documents/{doc}/download")

        t = threading.Thread(target=download)
        t.start()
        time.sleep(0.6)  # the download is now waiting for the write lock
        holder.execute("COMMIT")
        holder.close()
        t.join(20)
        self.assertEqual(result["r"].status_code, 404)
        self.assertNotIn(b"RACE", result["r"].data)


if __name__ == "__main__":
    unittest.main()
