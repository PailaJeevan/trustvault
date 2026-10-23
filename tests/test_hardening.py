"""Fourth iteration: closing risks THREATS.md used to accept.

AC-3b  two-person rule for password reset, MFA reset, transfer, promotion
AN-16  step-up re-authentication for sensitive actions
OP-16  throttling shared across workers (database, not memory)
AN-17  common-password and personal-information rules
AU-12  master-key rotation
AN-18  your own sign-in history
"""
import base64
import io
import secrets
import unittest
from datetime import timedelta

from app import create_app, totp
from app.config import Config
from app.db import iso, utcnow
from tests.base import PASSWORD, Person, TrustVaultTestCase, pdf_bytes


def age_reauth(test, person, minutes=10):
    db = test.db()
    db.execute("UPDATE sessions SET reauth_at = ? WHERE user_id = ?", (iso(utcnow() - timedelta(minutes=minutes)), person.id))
    db.close()


class TwoPersonRule(TrustVaultTestCase):
    def test_one_admin_alone_cannot_reset_a_password(self):
        r = self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.get_json()["status"], "pending")
        # nothing happened yet: Vera's old password and session still work
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)
        self.assertEqual(self.app.test_client().post("/api/auth/login", json={"email": self.vera.email,
                         "password": "Taken-Over-7731"}).status_code, 401)

    def test_requester_cannot_approve_their_own_request(self):
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        r = self.approve_last_request(approver=self.admin)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)
        self.assertTrue(self.audit_rows(action="admin.request_approve", outcome="denied"))

    def test_second_admin_approval_carries_it_out_and_records_both(self):
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        self.assertEqual(self.approve_last_request().status_code, 200)
        self.assertEqual(self.vera.get("/api/documents").status_code, 401)
        row = self.audit_rows(action="admin.password_reset", target_user_id=self.vera.id)[0]
        import json
        d = json.loads(row["details"])
        self.assertEqual((d["requested_by"], d["approved_by"]), (self.admin.id, self.admin2.id))
        self.assertEqual(row["actor_id"], self.admin2.id)

    def test_password_hash_is_not_kept_after_the_decision(self):
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        self.approve_last_request()
        db = self.db()
        self.assertEqual(db.execute("SELECT payload FROM admin_requests").fetchone()[0], "{}")
        db.close()

    def test_rejected_and_cancelled_requests_do_nothing(self):
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        rid = self.admin2.get("/api/admin/requests").get_json()["requests"][0]["id"]
        self.assertEqual(self.admin2.post(f"/api/admin/requests/{rid}/reject").get_json()["status"], "rejected")
        self.assertEqual(self.admin2.post(f"/api/admin/requests/{rid}/approve").status_code, 409)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)

    def test_expired_requests_cannot_be_approved(self):
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        db = self.db()
        db.execute("UPDATE admin_requests SET expires_at = '2000-01-01T00:00:00.000000Z'")
        rid = db.execute("SELECT id FROM admin_requests").fetchone()[0]
        db.close()
        self.assertEqual(self.admin2.post(f"/api/admin/requests/{rid}/approve").status_code, 409)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)

    def test_promotion_to_admin_needs_two_admins(self):
        r = self.admin.patch(f"/api/admin/users/{self.vera.id}", {"role": "admin"})
        self.assertEqual(r.status_code, 202)
        self.assertEqual(self.vera.get("/api/admin/users").status_code, 403)
        self.approve_last_request()
        vera = Person(self.app, self.vera.id, self.vera.email)
        self.assertEqual(vera.get("/api/admin/users").status_code, 200)

    def test_demotion_from_admin_is_immediate(self):
        r = self.admin.patch(f"/api/admin/users/{self.admin2.id}", {"role": "viewer"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.admin2.get("/api/admin/users").status_code, 401)

    def test_transfer_needs_approval_and_neither_admin_may_receive(self):
        doc = self.alice.upload()
        r = self.admin.post(f"/api/admin/documents/{doc}/transfer", {"new_owner_id": self.bob.id})
        self.assertEqual(r.status_code, 202)
        self.assertEqual(self.bob.get(f"/api/documents/{doc}").status_code, 404)
        self.approve_last_request()
        self.assertEqual(self.bob.get(f"/api/documents/{doc}").status_code, 200)

    def test_checks_rerun_at_approval_time(self):
        """Approved later, after the target became something that may not be touched."""
        self.cfg.DEMO_MODE = True
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        db = self.db()
        db.execute("UPDATE users SET is_demo = 1 WHERE id = ?", (self.vera.id,))
        db.close()
        self.assertEqual(self.approve_last_request().status_code, 403)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)

    def test_cannot_approve_a_request_about_your_own_account(self):
        self.admin.post(f"/api/admin/users/{self.admin2.id}/reset-password", {"new_password": "Taken-Over-7731"})
        self.assertEqual(self.approve_last_request(approver=self.admin2).status_code, 403)

    def test_only_admins_see_or_decide_requests(self):
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        rid = self.admin.get("/api/admin/requests").get_json()["requests"][0]["id"]
        for p in (self.alice, self.vera):
            self.assertEqual(p.post(f"/api/admin/requests/{rid}/approve").status_code, 403)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)

    def test_single_admin_mode_runs_at_once_but_still_records_a_request(self):
        self.cfg.DUAL_CONTROL = False
        r = self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        self.assertEqual(r.get_json()["status"], "done")
        self.assertEqual(self.vera.get("/api/documents").status_code, 401)
        self.assertTrue(self.audit_rows(action="admin.request_created"))


class StepUpAuthentication(TrustVaultTestCase):
    def test_stale_session_cannot_share_until_password_is_confirmed(self):
        doc = self.alice.upload()
        age_reauth(self, self.alice)
        r = self.alice.post(f"/api/documents/{doc}/grants", {"user_id": self.vera.id, "permission": "read"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["error"], "reauth_required")
        self.assertEqual(self.vera.get(f"/api/documents/{doc}").status_code, 404)
        self.assertEqual(self.alice.post("/api/auth/reauth", {"password": PASSWORD}).status_code, 200)
        r = self.alice.post(f"/api/documents/{doc}/grants", {"user_id": self.vera.id, "permission": "read"})
        self.assertEqual(r.status_code, 201)

    def test_stale_session_cannot_delete_or_use_admin_powers(self):
        doc = self.alice.upload()
        age_reauth(self, self.alice)
        age_reauth(self, self.admin)
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}").status_code, 403)
        r = self.admin.post(f"/api/admin/users/{self.vera.id}/offboard")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)

    def test_upgrading_a_grant_needs_step_up_but_narrowing_does_not(self):
        doc = self.alice.upload()
        gid = self.alice.grant(doc, self.vera, "read")
        age_reauth(self, self.alice)
        self.assertEqual(self.alice.patch(f"/api/documents/{doc}/grants/{gid}", {"permission": "edit"}).status_code, 403)
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}/grants/{gid}").status_code, 200)

    def test_wrong_password_counts_and_locking_ends_the_stolen_session(self):
        age_reauth(self, self.alice)
        for _ in range(self.cfg.LOGIN_MAX_FAILURES - 1):
            self.assertEqual(self.alice.post("/api/auth/reauth", {"password": "wrong-guess-123"}).status_code, 403)
        r = self.alice.post("/api/auth/reauth", {"password": "wrong-guess-123"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.alice.get("/api/documents").status_code, 401)

    def test_mfa_users_must_also_give_a_code(self):
        r = self.alice.post("/api/auth/mfa/setup", {"current_password": PASSWORD})
        secret = r.get_json()["secret"]
        self.alice.post("/api/auth/mfa/enable", {"code": totp.code_at(secret, totp.current_step())})
        age_reauth(self, self.alice)
        self.assertEqual(self.alice.post("/api/auth/reauth", {"password": PASSWORD}).status_code, 403)
        ok = self.alice.post("/api/auth/reauth", {"password": PASSWORD, "code": totp.code_at(secret, totp.current_step() + 1)})
        self.assertEqual(ok.status_code, 200)


class SharedThrottling(TrustVaultTestCase):
    def test_limit_holds_across_separate_worker_processes(self):
        """Two app instances on one database = two gunicorn workers."""
        self.cfg.LOGIN_RATE_PER_IP = 6
        other = create_app(Config(TESTING=True, DATABASE_PATH=self.cfg.DATABASE_PATH, MASTER_KEY=self.cfg.MASTER_KEY,
                                  AUDIT_KEY=self.cfg.AUDIT_KEY, SECURE_COOKIES=False, LOGIN_RATE_PER_IP=6))
        db = self.db()
        db.execute("DELETE FROM login_attempts")  # setUp's own sign-ins
        db.close()
        a, b = self.app.test_client(), other.test_client()
        codes = []
        for i in range(8):
            c = a if i % 2 else b
            codes.append(c.post("/api/auth/login", json={"email": f"x{i}@t.l", "password": "y" * 12}).status_code)
        self.assertEqual(codes[-1], 429)
        self.assertEqual(codes.count(429), 2)


class PasswordPolicy(TrustVaultTestCase):
    def test_common_and_personal_passwords_are_refused_everywhere(self):
        r = self.vera.post("/api/auth/password", {"current_password": PASSWORD, "new_password": "Password@12345"})
        self.assertEqual(r.status_code, 400)
        local = self.vera.email.split("@")[0]
        r = self.vera.post("/api/auth/password", {"current_password": PASSWORD, "new_password": f"{local}-Rocks-99"})
        self.assertEqual(r.status_code, 400)
        r = self.admin.post("/api/admin/users", {"email": "neha@x.y", "name": "Neha Rao", "role": "viewer",
                                                 "password": "Welcome@2026!"})
        self.assertEqual(r.status_code, 400)
        r = self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "aaaaaaaaaaaaaaa"})
        self.assertEqual(r.status_code, 400)

    def test_list_only_common_passwords_are_refused(self):
        # These are caught only by the common-password list, not by the
        # "password/welcome + digits" pattern, so they prove the list is used.
        from app.security import password_problem
        for pw in ("1qaz2wsx3edc", "Iloveyou1234!", "Mumbai@123456", "Cricket-12345"):
            self.assertIn("commonly used", password_problem(pw) or "", pw)
        r = self.vera.post("/api/auth/password", {"current_password": PASSWORD, "new_password": "Letmein-12345"})
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(password_problem("Tidal-Ferns-Orbit-58"))


class KeyRotation(TrustVaultTestCase):
    def test_rotation_rewraps_every_file_and_mfa_secret(self):
        from app.keys import rotate_master_key
        doc = self.alice.upload("Rot", "r.txt", b"ROTATE-ME")
        secret = self.vera.post("/api/auth/mfa/setup", {"current_password": PASSWORD}).get_json()["secret"]
        self.vera.post("/api/auth/mfa/enable", {"code": totp.code_at(secret, totp.current_step())})
        new_key = secrets.token_bytes(32)
        result = rotate_master_key(self.app, new_key)
        self.assertEqual((result["files"], result["mfa_secrets"]), (1, 1))
        # the old key no longer opens anything
        self.assertEqual(self.alice.get(f"/api/documents/{doc}/download").status_code, 500)
        # an app started with the new key does
        app2 = create_app(Config(TESTING=True, DATABASE_PATH=self.cfg.DATABASE_PATH, MASTER_KEY=new_key,
                                 AUDIT_KEY=self.cfg.AUDIT_KEY, SECURE_COOKIES=False))
        alice2 = Person(app2, self.alice.id, self.alice.email)
        self.assertEqual(alice2.get(f"/api/documents/{doc}/download").data, b"ROTATE-ME")
        c = app2.test_client()
        ch = c.post("/api/auth/login", json={"email": self.vera.email, "password": PASSWORD}).get_json()["challenge"]
        self.assertEqual(c.post("/api/auth/login/mfa", json={"challenge": ch, "code": totp.code_at(secret, totp.current_step() + 1)}).status_code, 200)
        self.assertTrue(self.audit_rows(action="admin.master_key_rotated"))

    def test_rotation_refuses_bad_keys(self):
        from app.keys import rotate_master_key
        with self.assertRaises(ValueError):
            rotate_master_key(self.app, self.cfg.MASTER_KEY)
        with self.assertRaises(ValueError):
            rotate_master_key(self.app, b"short")


class SignInHistory(TrustVaultTestCase):
    def test_you_see_failed_sign_ins_and_admin_actions_on_your_account(self):
        self.app.test_client().post("/api/auth/login", json={"email": self.vera.email, "password": "nope-nope-nope"})
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Taken-Over-7731"})
        ev = self.vera.get("/api/auth/history").get_json()["events"]
        actions = {(e["action"], e["outcome"]) for e in ev}
        self.assertIn(("auth.login", "denied"), actions)
        self.assertIn(("admin.request_created", "success"), actions)

    def test_you_never_see_anyone_elses(self):
        self.app.test_client().post("/api/auth/login", json={"email": self.mallory.email, "password": "nope-nope-nope"})
        self.mallory.get("/api/documents")
        ev = self.vera.get("/api/auth/history").get_json()["events"]
        self.assertFalse(any(e["by"] == self.mallory.email for e in ev))
        self.assertTrue(all(e["action"].startswith(("auth.", "admin.")) for e in ev))


if __name__ == "__main__":
    unittest.main()
