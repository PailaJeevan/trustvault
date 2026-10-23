"""Dashboard, activity feed, admin analytics and download receipts.

THREATS.md: IN-1 (dashboard counts leak), IN-2 (feed shows other people's documents),
IN-3 (analytics for non-admins), AU-9 (download receipt).
"""
import json
import unittest

from tests.base import TrustVaultTestCase, pdf_bytes


class Dashboard(TrustVaultTestCase):
    def test_counts_and_recent_only_include_what_you_can_open(self):
        mine = self.alice.upload("Alice's own")
        self.bob.upload("Bob secret")
        shared = self.bob.upload("Bob shared")
        self.bob.grant(shared, self.alice)
        r = self.alice.get("/api/dashboard").get_json()
        self.assertEqual(r["counts"], {"owned": 1, "shared_with_me": 1})
        self.assertEqual({d["id"] for d in r["recent"]}, {mine, shared})
        self.assertNotIn("Bob secret", json.dumps(r))

    def test_viewer_with_nothing_sees_nothing(self):
        self.alice.upload("Hidden")
        r = self.mallory.get("/api/dashboard").get_json()
        self.assertEqual(r["counts"], {"owned": 0, "shared_with_me": 0})
        self.assertEqual(r["recent"], [])
        self.assertNotIn("owner", r)


class ActivityFeed(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.doc = self.alice.upload("Plan", "p.pdf", pdf_bytes())
        self.alice.grant(self.doc, self.vera)
        self.vera.get(f"/api/documents/{self.doc}/download")
        self.mallory.get(f"/api/documents/{self.doc}/download")  # refused

    def test_owner_sees_downloads_and_refusals_by_others(self):
        r = self.alice.get("/api/activity").get_json()
        pairs = {(e["actor_email"], e["action"], e["outcome"]) for e in r["events"]}
        self.assertIn((self.vera.email, "document.download", "success"), pairs)
        self.assertIn((self.mallory.email, "document.download", "denied"), pairs)
        self.assertFalse(any(e["actor_email"] == self.alice.email for e in r["events"]))
        self.assertGreaterEqual(r["unread"], 2)

    def test_grantee_does_not_see_activity_on_documents_shared_with_them(self):
        r = self.vera.get("/api/activity").get_json()
        self.assertEqual(r["events"], [])
        self.assertNotIn(self.mallory.email, json.dumps(r))

    def test_marking_seen_resets_unread(self):
        self.assertEqual(self.alice.post("/api/activity/seen").get_json()["unread"], 0)
        self.assertEqual(self.alice.get("/api/activity").get_json()["unread"], 0)
        self.vera.get(f"/api/documents/{self.doc}/download")
        self.assertEqual(self.alice.get("/api/activity").get_json()["unread"], 1)

    def test_dashboard_reports_refusals_on_my_documents(self):
        r = self.alice.get("/api/dashboard").get_json()
        self.assertEqual(r["owner"]["refused_on_mine_7d"], 1)
        self.assertEqual(r["owner"]["downloads_by_others_7d"], 1)


class AdminStats(TrustVaultTestCase):
    def test_admin_only(self):
        for p in (self.alice, self.vera):
            self.assertEqual(p.get("/api/admin/stats").status_code, 403)

    def test_series_and_totals(self):
        doc = self.alice.upload()
        self.mallory.get(f"/api/documents/{doc}")
        r = self.admin.get("/api/admin/stats").get_json()
        self.assertEqual(len(r["series"]), 14)
        self.assertGreaterEqual(r["series"][-1]["refused"], 1)
        self.assertEqual(r["totals"]["documents"], 1)
        self.assertEqual(r["top_refused"][0]["who"], self.mallory.email)
        self.assertNotIn(b"%PDF", self.admin.get("/api/admin/stats").data)


class DownloadReceipt(TrustVaultTestCase):
    def test_receipt_header_is_the_audit_record_of_this_download(self):
        doc = self.alice.upload("R", "r.pdf", pdf_bytes("R"))
        self.alice.grant(doc, self.vera)
        r = self.vera.get(f"/api/documents/{doc}/download")
        seq = int(r.headers["X-TrustVault-Receipt"])
        row = self.audit_rows(seq=seq)[0]
        self.assertEqual((row["action"], row["actor_id"], row["document_id"]),
                         ("document.download", self.vera.id, doc))


if __name__ == "__main__":
    unittest.main()
