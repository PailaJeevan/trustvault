"""In-app viewer and 'your access ends' (THREATS.md VW-1..3)."""
import json
import unittest

from tests.base import TrustVaultTestCase, pdf_bytes


class Viewer(TrustVaultTestCase):
    def test_view_is_authorised_and_recorded_as_a_view(self):
        doc = self.alice.upload("Notes", "n.txt", b"hello")
        self.alice.grant(doc, self.vera)
        r = self.vera.get(f"/api/documents/{doc}/download?purpose=view")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "application/octet-stream")  # still never rendered by the browser itself
        row = self.audit_rows(action="document.download", actor_id=self.vera.id)[-1]
        self.assertEqual(json.loads(row["details"])["purpose"], "view")

    def test_view_is_refused_exactly_like_download_for_strangers(self):
        doc = self.alice.upload("Notes", "n.txt", b"hello")
        r = self.mallory.get(f"/api/documents/{doc}/download?purpose=view")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"hello", r.data)

    def test_unknown_purpose_is_rejected(self):
        doc = self.alice.upload()
        self.assertEqual(self.alice.get(f"/api/documents/{doc}/download?purpose=exfiltrate").status_code, 400)

    def test_csp_allows_blob_images_only(self):
        csp = self.vera.get("/").headers["Content-Security-Policy"]
        self.assertIn("img-src 'self' data: blob:", csp)
        self.assertIn("script-src 'self';", csp)
        self.assertNotIn("blob:", csp.split("img-src")[0])


class MyExpiry(TrustVaultTestCase):
    def test_grantee_sees_when_their_access_ends(self):
        doc = self.alice.upload()
        self.alice.grant(doc, self.vera, expires_at="2026-12-31")
        listed = self.vera.get("/api/documents").get_json()["documents"][0]
        self.assertTrue(listed["my_expires_at"].startswith("2026-12-31"))
        single = self.vera.get(f"/api/documents/{doc}").get_json()["document"]
        self.assertTrue(single["my_expires_at"].startswith("2026-12-31"))
        self.assertIsNone(self.alice.get(f"/api/documents/{doc}").get_json()["document"]["my_expires_at"])

    def test_no_expiry_shows_as_none(self):
        doc = self.alice.upload()
        self.alice.grant(doc, self.vera)
        self.assertIsNone(self.vera.get(f"/api/documents/{doc}").get_json()["document"]["my_expires_at"])


if __name__ == "__main__":
    unittest.main()
