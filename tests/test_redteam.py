"""Findings from attacking the finished system (THREATS.md section PT).

Each test reproduces the original attack and asserts it now fails.
PT-1 redaction bypass via version history, PT-2 hash-confirmation from the audit,
PT-3 HEAD writes false evidence, PT-4 trash oracle, PT-5 deep-JSON crash,
PT-6 demo MFA sabotage, PT-7 seeding public passwords into production,
and regression tests for attacks that already failed (PT-8..12).
"""
import hashlib
import io
import json
import unittest

from tests.base import PASSWORD, TrustVaultTestCase, pdf_bytes


class RedactionBypass(TrustVaultTestCase):
    """PT-1: the owner replaces an unredacted file with a redacted version."""

    def setUp(self):
        super().setUp()
        self.doc = self.alice.upload("Contract", "contract.txt", b"Salary: INR 21,00,000 (UNREDACTED)")
        self.alice.post(f"/api/documents/{self.doc}/versions",
                        data={"file": (io.BytesIO(b"Salary: [REDACTED]"), "contract-redacted.txt")})

    def test_reader_cannot_download_earlier_versions(self):
        self.alice.grant(self.doc, self.vera, "read")
        r = self.vera.get(f"/api/documents/{self.doc}/download?version=1")
        self.assertEqual(r.status_code, 403)
        self.assertNotIn(b"UNREDACTED", r.data)
        self.assertIn(b"REDACTED", self.vera.get(f"/api/documents/{self.doc}/download").data)
        self.assertTrue(self.audit_rows(action="document.download_history", outcome="denied", actor_id=self.vera.id))

    def test_reader_does_not_even_see_earlier_version_names(self):
        self.alice.grant(self.doc, self.vera, "read")
        versions = self.vera.get(f"/api/documents/{self.doc}").get_json()["document"]["versions"]
        self.assertEqual([v["filename"] for v in versions], ["contract-redacted.txt"])

    def test_editor_and_owner_keep_history(self):
        self.alice.grant(self.doc, self.vera, "edit")
        self.assertIn(b"UNREDACTED", self.vera.get(f"/api/documents/{self.doc}/download?version=1").data)
        self.assertIn(b"UNREDACTED", self.alice.get(f"/api/documents/{self.doc}/download?version=1").data)
        self.assertEqual(len(self.vera.get(f"/api/documents/{self.doc}").get_json()["document"]["versions"]), 2)


class HashConfirmation(TrustVaultTestCase):
    """PT-2: an admin brute-forces a templated document from hashes in the audit trail."""

    def test_admin_cannot_confirm_contents_from_the_audit(self):
        letter = lambda n: f"Dear Vera, your salary is INR {n},00,000.".encode()
        doc = self.alice.upload("Salary letter", "letter.txt", letter(18))
        self.alice.grant(doc, self.vera)
        self.vera.get(f"/api/documents/{doc}/download")
        audit = self.admin.get(f"/api/admin/audit?document_id={doc}").get_data(as_text=True)
        export = self.admin.get("/api/admin/audit/export").get_data(as_text=True)
        for n in range(1, 100):
            h = hashlib.sha256(letter(n)).hexdigest()
            self.assertNotIn(h, audit)
            self.assertNotIn(h, export)

    def test_the_record_still_identifies_the_exact_file_with_the_server_key(self):
        from app.security import content_fingerprint
        doc = self.alice.upload("X", "x.txt", b"exact bytes")
        row = self.audit_rows(action="document.upload", document_id=doc)[0]
        self.assertEqual(json.loads(row["details"])["content_fp"],
                         content_fingerprint(self.cfg.AUDIT_KEY, hashlib.sha256(b"exact bytes").hexdigest()))


class HeadIsNotADownload(TrustVaultTestCase):
    """PT-3: HEAD ran the download handler and logged a download that never happened."""

    def test_head_is_refused_and_writes_no_download_record(self):
        doc = self.alice.upload()
        self.alice.grant(doc, self.vera)
        r = self.vera.client.head(f"/api/documents/{doc}/download")
        self.assertEqual(r.status_code, 405)
        self.assertEqual(self.audit_rows(action="document.download", actor_id=self.vera.id), [])

    def test_head_gives_strangers_nothing_either(self):
        doc = self.alice.upload()
        r = self.mallory.client.head(f"/api/documents/{doc}")
        self.assertEqual(r.status_code, 405)


class TrashOracle(TrustVaultTestCase):
    """PT-4: a former grantee could tell 'in the trash' (403) from 'gone' (404)."""

    def test_former_grantee_gets_the_same_404_as_a_stranger(self):
        doc = self.alice.upload()
        self.alice.grant(doc, self.vera)
        self.alice.delete(f"/api/documents/{doc}")
        for path, method in ((f"/api/documents/{doc}/restore", "post"), (f"/api/documents/{doc}", "get"),
                             (f"/api/documents/{doc}/download", "get")):
            with self.subTest(path=path):
                a = getattr(self.vera, method)(path)
                b = getattr(self.mallory, method)(path)
                self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))
                self.assertEqual(a.status_code, 404)


class Robustness(TrustVaultTestCase):
    """PT-5: pathological input must be a clean 400, never a crash."""

    def test_deeply_nested_json_is_a_400(self):
        doc = self.alice.upload()
        deep = "[" * 100000 + "]" * 100000
        r = self.alice.client.post(f"/api/documents/{doc}/grants", data=deep, content_type="application/json",
                                   headers={"X-CSRF-Token": self.alice.csrf})
        self.assertEqual(r.status_code, 400)

    def test_huge_page_number_is_not_a_crash(self):
        r = self.vera.get("/api/documents?page=99999999999999999999999999")
        self.assertLess(r.status_code, 500)


class DemoSafety(TrustVaultTestCase):
    def test_demo_mfa_cannot_be_turned_off(self):
        """PT-6: Maya's key is public, so any judge could switch her MFA off for everyone."""
        self.cfg.DEMO_MODE = True
        db = self.db()
        db.execute("UPDATE users SET is_demo = 1, mfa_enabled = 1 WHERE id = ?", (self.alice.id,))
        db.close()
        r = self.alice.post("/api/auth/mfa/disable", {"current_password": PASSWORD, "code": "000000"})
        self.assertEqual(r.status_code, 403)
        db = self.db()
        self.assertEqual(db.execute("SELECT mfa_enabled FROM users WHERE id = ?", (self.alice.id,)).fetchone()[0], 1)
        db.close()

    def test_seed_refuses_production_without_demo_mode(self):
        """PT-7: public demo passwords must never land on a real deployment."""
        from scripts.seed import seed
        self.cfg.ENV, self.cfg.DEMO_MODE = "production", False
        with self.assertRaises(SystemExit):
            seed(self.app)
        db = self.db()
        self.assertIsNone(db.execute("SELECT 1 FROM users WHERE email = 'admin@trustvault.test'").fetchone())
        db.close()


class AlreadyHeld(TrustVaultTestCase):
    """Regression tests for attacks that failed on the first try (PT-8..12)."""

    def test_login_from_origin_null_is_refused(self):
        r = self.app.test_client().post("/api/auth/login", json={"email": self.vera.email, "password": PASSWORD},
                                        headers={"Origin": "null"})
        self.assertEqual(r.status_code, 403)

    def test_text_plain_simple_request_cannot_change_state(self):
        doc = self.alice.upload()
        r = self.alice.client.post(f"/api/documents/{doc}/grants", content_type="text/plain",
                                   data=json.dumps({"user_id": self.mallory.id, "permission": "read"}))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.mallory.get(f"/api/documents/{doc}").status_code, 404)

    def test_referrer_policy_hides_document_urls(self):
        self.assertEqual(self.vera.get("/api/documents").headers["Referrer-Policy"], "no-referrer")

    def test_no_cors_headers_are_ever_sent(self):
        r = self.vera.get("/api/documents", headers={"Origin": "https://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", r.headers)
        self.assertNotIn("Access-Control-Allow-Credentials", r.headers)

    def test_method_override_headers_are_ignored(self):
        doc = self.alice.upload()
        for hdr in ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"):
            self.mallory.get(f"/api/documents/{doc}", headers={hdr: "DELETE"})
        self.assertEqual(self.alice.get(f"/api/documents/{doc}").status_code, 200)

    def test_spoofed_forwarded_for_is_not_trusted_without_a_proxy(self):
        doc = self.alice.upload()
        self.mallory.get(f"/api/documents/{doc}", headers={"X-Forwarded-For": "8.8.8.8"})
        self.assertNotEqual(self.audit_rows(actor_id=self.mallory.id)[-1]["ip"], "8.8.8.8")

    def test_editor_planted_html_is_never_rendered(self):
        doc = self.alice.upload("T", "t.txt", b"plain")
        self.alice.grant(doc, self.bob, "edit")
        self.alice.grant(doc, self.vera, "read")
        self.bob.post(f"/api/documents/{doc}/versions", data={"file": (io.BytesIO(b"<html><script>alert(1)</script>"), "t.txt")})
        r = self.vera.get(f"/api/documents/{doc}/download")
        self.assertEqual(r.mimetype, "application/octet-stream")
        self.assertTrue(r.headers["Content-Disposition"].startswith("attachment"))


if __name__ == "__main__":
    unittest.main()
