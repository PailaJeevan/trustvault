"""Two-step sign-in and managing your own sessions.

THREATS.md: AN-7 (no second factor), AN-8 (MFA bypass), AN-9 (code replay),
AN-10 (MFA brute force), AN-11 (stolen session removes MFA), SS-1 (ending someone else's session).
"""
import time
import unittest

from app import totp
from tests.base import PASSWORD, Person, TrustVaultTestCase


class Totp(unittest.TestCase):
    def test_rfc6238_reference_vector(self):
        # RFC 6238 appendix B, SHA-1, T = 59s -> 94287082 (8 digits); last 6 = 287082
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of "12345678901234567890"
        self.assertEqual(totp.code_at(secret, 59 // 30), "287082")

    def test_drift_and_replay(self):
        s = totp.new_secret()
        now = 1_800_000_000
        step = totp.current_step(now)
        self.assertEqual(totp.verify(s, totp.code_at(s, step - 1), 0, now), step - 1)
        self.assertIsNone(totp.verify(s, totp.code_at(s, step - 2), 0, now))
        self.assertIsNone(totp.verify(s, totp.code_at(s, step), step, now))  # already used
        self.assertIsNone(totp.verify(s, "12345", 0, now))
        self.assertIsNone(totp.verify(s, "abcdef", 0, now))


class MfaFlow(TrustVaultTestCase):
    def enrol(self, person):
        r = person.post("/api/auth/mfa/setup", {"current_password": PASSWORD})
        self.assertEqual(r.status_code, 200, r.get_json())
        secret = r.get_json()["secret"]
        r = person.post("/api/auth/mfa/enable", {"code": totp.code_at(secret, totp.current_step())})
        self.assertEqual(r.status_code, 200, r.get_json())
        return secret

    def password_step(self, person):
        c = self.app.test_client()
        r = c.post("/api/auth/login", json={"email": person.email, "password": PASSWORD})
        return c, r

    def test_password_alone_gives_no_session_once_mfa_is_on(self):
        doc = self.alice.upload()
        self.enrol(self.alice)
        c, r = self.password_step(self.alice)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["mfa_required"])
        self.assertNotIn("csrfToken", r.get_json())
        self.assertIsNone(c.get_cookie("tv_session"))
        self.assertEqual(c.get(f"/api/documents/{doc}/download").status_code, 401)

    def test_correct_code_completes_sign_in(self):
        secret = self.enrol(self.alice)
        c, r = self.password_step(self.alice)
        # the code used at enrolment is spent; use the next step
        code = totp.code_at(secret, totp.current_step() + 1)
        r = c.post("/api/auth/login/mfa", json={"challenge": r.get_json()["challenge"], "code": code})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(c.get("/api/documents").status_code, 200)
        self.assertTrue(self.audit_rows(action="auth.login", outcome="success", actor_id=self.alice.id))

    def test_wrong_code_is_refused_and_counts_towards_lockout(self):
        self.enrol(self.alice)
        for _ in range(self.cfg.LOGIN_MAX_FAILURES):
            c, r = self.password_step(self.alice)
            ch = r.get_json().get("challenge")
            if ch is None:
                break
            self.assertEqual(c.post("/api/auth/login/mfa", json={"challenge": ch, "code": "000000"}).status_code, 401)
        c, r = self.password_step(self.alice)
        self.assertEqual(r.status_code, 401)  # locked now, even with the right password

    def test_challenge_cannot_be_brute_forced(self):
        secret = self.enrol(self.alice)
        c, r = self.password_step(self.alice)
        ch = r.get_json()["challenge"]
        db = self.db()
        db.execute("UPDATE mfa_challenges SET attempts = 5")
        db.close()
        good = totp.code_at(secret, totp.current_step() + 1)
        self.assertEqual(c.post("/api/auth/login/mfa", json={"challenge": ch, "code": good}).status_code, 401)

    def test_code_cannot_be_replayed(self):
        secret = self.enrol(self.alice)
        code = totp.code_at(secret, totp.current_step() + 1)
        c1, r1 = self.password_step(self.alice)
        self.assertEqual(c1.post("/api/auth/login/mfa", json={"challenge": r1.get_json()["challenge"],
                                                              "code": code}).status_code, 200)
        c2, r2 = self.password_step(self.alice)
        self.assertEqual(c2.post("/api/auth/login/mfa", json={"challenge": r2.get_json()["challenge"],
                                                              "code": code}).status_code, 401)

    def test_challenge_expires(self):
        secret = self.enrol(self.alice)
        c, r = self.password_step(self.alice)
        db = self.db()
        db.execute("UPDATE mfa_challenges SET expires_at = '2000-01-01T00:00:00.000000Z'")
        db.close()
        code = totp.code_at(secret, totp.current_step() + 1)
        self.assertEqual(c.post("/api/auth/login/mfa", json={"challenge": r.get_json()["challenge"],
                                                             "code": code}).status_code, 401)

    def test_disabling_needs_password_and_code(self):
        secret = self.enrol(self.alice)
        r = self.alice.post("/api/auth/mfa/disable", {"current_password": PASSWORD, "code": "000000"})
        self.assertEqual(r.status_code, 403)
        r = self.alice.post("/api/auth/mfa/disable", {"current_password": "wrong-password-1", "code":
                                                      totp.code_at(secret, totp.current_step() + 1)})
        self.assertEqual(r.status_code, 403)
        db = self.db()
        self.assertEqual(db.execute("SELECT mfa_enabled FROM users WHERE id = ?", (self.alice.id,)).fetchone()[0], 1)
        db.close()

    def test_secret_is_encrypted_at_rest(self):
        secret = self.enrol(self.alice)
        db = self.db()
        stored = db.execute("SELECT mfa_secret_enc FROM users WHERE id = ?", (self.alice.id,)).fetchone()[0]
        db.close()
        self.assertNotIn(secret.encode(), stored)

    def test_enabling_mfa_ends_other_sessions(self):
        other = Person(self.app, self.alice.id, self.alice.email)
        self.enrol(self.alice)
        self.assertEqual(other.get("/api/documents").status_code, 401)
        self.assertEqual(self.alice.get("/api/documents").status_code, 200)

    def test_admin_mfa_reset_ends_sessions_and_is_flagged(self):
        self.enrol(self.alice)
        r = self.admin.post(f"/api/admin/users/{self.alice.id}/reset-mfa")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.alice.get("/api/documents").status_code, 401)
        titles = [a["title"] for a in self.admin.get("/api/admin/alerts").get_json()["alerts"]]
        self.assertIn("Privileged administrator action", titles)


class OwnSessions(TrustVaultTestCase):
    def test_list_and_end_own_sessions(self):
        phone = Person(self.app, self.vera.id, self.vera.email)
        sessions = self.vera.get("/api/auth/sessions").get_json()["sessions"]
        self.assertEqual(len(sessions), 2)
        self.assertNotIn("token_hash", sessions[0])
        other = next(s for s in sessions if not s["current"])
        self.assertEqual(self.vera.delete(f"/api/auth/sessions/{other['public_id']}").status_code, 200)
        self.assertEqual(phone.get("/api/documents").status_code, 401)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)

    def test_cannot_end_someone_elses_session(self):
        target = self.vera.get("/api/auth/sessions").get_json()["sessions"][0]["public_id"]
        self.assertEqual(self.mallory.delete(f"/api/auth/sessions/{target}").status_code, 404)
        self.assertEqual(self.vera.get("/api/documents").status_code, 200)
        self.assertNotIn(target, str(self.mallory.get("/api/auth/sessions").get_json()))

    def test_end_all_other_sessions(self):
        phone = Person(self.app, self.vera.id, self.vera.email)
        r = self.vera.post("/api/auth/sessions/end-others")
        self.assertEqual(r.get_json()["ended"], 1)
        self.assertEqual(phone.get("/api/documents").status_code, 401)


if __name__ == "__main__":
    unittest.main()
