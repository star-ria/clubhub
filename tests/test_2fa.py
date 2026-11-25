import os, sys, tempfile, time, unittest
from datetime import datetime, timedelta
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db, security, services  # noqa: E402
from app import app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # ASCII "12345678901234567890" in base32


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def user_row(email):
    conn = db.get_conn(); r = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone(); conn.close(); return r


def sql(q, *p):
    conn = db.get_conn(); conn.execute(q, p); conn.commit(); conn.close()


def code(secret, offset=0):
    return security.totp(secret, at=time.time() + 30 * offset)


class TotpMathTests(unittest.TestCase):
    def test_rfc6238_sha1_test_vectors(self):  # RFC 6238 Appendix B (8-digit codes)
        for t, expected in [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924")]:
            self.assertEqual(security.totp(RFC_SECRET, at=t, digits=8), expected)

    def test_window_and_replay_rules(self):
        t = 1_000_000 * 30 + 5; step = t // 30
        good = security.totp(RFC_SECRET, at=t)
        self.assertEqual(security.verify_totp(RFC_SECRET, good, 0, at=t), step)
        self.assertEqual(security.verify_totp(RFC_SECRET, security.totp(RFC_SECRET, at=t - 30), 0, at=t), step - 1)  # 1 step of drift
        self.assertIsNone(security.verify_totp(RFC_SECRET, security.totp(RFC_SECRET, at=t - 90), 0, at=t))            # too old
        self.assertIsNone(security.verify_totp(RFC_SECRET, good, step, at=t))                                          # replay

    def test_bad_input_rejected(self):
        for bad in ("", "12345", "1234567", "abcdef", None, "12 456"):
            self.assertIsNone(security.verify_totp(RFC_SECRET, bad, 0))

    def test_encryption_roundtrip_and_backup_code_hashing(self):
        s = security.generate_secret()
        enc = security.encrypt(s); self.assertNotIn(s, enc); self.assertEqual(security.decrypt(enc), s)
        self.assertEqual(security.hash_backup_code("ABCDE-fghij"), security.hash_backup_code(" abcde fghij "))


class TwoFactorFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        sql("DELETE FROM backup_codes")
        sql("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=0, totp_failures=0, totp_locked_until=NULL")
        self.leader_id = user_row("l@t")["id"]
        self.c = app.test_client()

    def tearDown(self):  # other test modules share this database and log in as the same users
        sql("DELETE FROM backup_codes")
        sql("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=0, totp_failures=0, totp_locked_until=NULL")

    def enable(self):
        """Turn 2FA on for the leader through the real service functions; returns (secret, backup_codes)."""
        services.start_2fa_setup(self.leader_id)
        secret = services.pending_2fa_setup(self.leader_id)[0]
        ok, codes = services.confirm_2fa_setup(self.leader_id, code(secret))
        self.assertTrue(ok)
        sql("UPDATE users SET totp_last_step = 0 WHERE id = ?", self.leader_id)  # so tests can log in repeatedly
        return secret, codes

    def password_login(self, c=None, email="l@t"):
        c = c or self.c
        return c.post("/login", data={"email": email, "password": "pw", "csrf_token": token(c)})

    def second_factor(self, value, c=None):
        c = c or self.c
        return c.post("/login/2fa", data={"code": value, "csrf_token": token(c)}, follow_redirects=False)

    def logged_in(self, c=None):
        return (c or self.c).get("/my-clubs").status_code == 200

    # ---------- setup ----------
    def test_setup_flow_stores_encrypted_secret_and_shows_backup_codes_once(self):
        c = app.test_client(); self.password_login(c)
        self.assertIn(b"Set up 2FA", c.get("/security").data)
        c.post("/security/2fa/start", data={"csrf_token": token(c)})
        page = c.get("/security").data.decode(); self.assertIn("Turn on 2FA", page)
        secret = services.pending_2fa_setup(self.leader_id)[0]
        self.assertIn(secret[:4], page)
        stored = user_row("l@t")["totp_secret"]; self.assertNotIn(secret, stored)  # encrypted at rest
        r = c.post("/security/2fa/confirm", data={"code": "000000", "csrf_token": token(c)}, follow_redirects=True)
        self.assertIn(b"isn&#39;t right", r.data); self.assertEqual(user_row("l@t")["totp_enabled"], 0)
        r = c.post("/security/2fa/confirm", data={"code": code(secret), "csrf_token": token(c)})
        self.assertIn(b"Save these backup codes", r.data); self.assertEqual(user_row("l@t")["totp_enabled"], 1)
        conn = db.get_conn(); self.assertEqual(conn.execute("SELECT COUNT(*) n FROM backup_codes").fetchone()["n"], 8); conn.close()
        self.assertNotIn(b"Save these backup codes", c.get("/security").data)

    def test_only_leaders_and_admins_have_security_page(self):
        s = app.test_client(); self.password_login(s, "s@t")
        self.assertEqual(s.get("/security").status_code, 403)
        self.assertEqual(app.test_client().get("/security").status_code, 302)

    def test_csrf_required_on_2fa_endpoints(self):
        c = app.test_client(); self.password_login(c)
        for path in ("/security/2fa/start", "/security/2fa/confirm", "/security/2fa/disable", "/login/2fa"):
            self.assertEqual(c.post(path, data={"code": "123456"}).status_code, 400, path)

    # ---------- sign-in ----------
    def test_login_without_2fa_is_unchanged(self):
        self.assertEqual(self.password_login().headers["Location"], "/"); self.assertTrue(self.logged_in())

    def test_password_alone_is_not_enough_when_2fa_on(self):
        secret, _ = self.enable()
        r = self.password_login(); self.assertIn("/login/2fa", r.headers["Location"])
        self.assertFalse(self.logged_in())

    def test_correct_code_signs_in_and_wrong_code_does_not(self):
        secret, _ = self.enable(); self.password_login()
        r = self.second_factor("000000"); self.assertEqual(r.status_code, 200); self.assertFalse(self.logged_in())
        self.second_factor(code(secret)); self.assertTrue(self.logged_in())

    def test_code_cannot_be_replayed(self):
        secret, _ = self.enable(); good = code(secret)
        self.password_login(); self.second_factor(good); self.assertTrue(self.logged_in())
        other = app.test_client(); self.password_login(other)
        self.second_factor(good, other); self.assertFalse(self.logged_in(other))

    def test_backup_code_works_once_only(self):
        _, codes = self.enable()
        self.password_login(); self.second_factor(codes[0]); self.assertTrue(self.logged_in())
        other = app.test_client(); self.password_login(other); self.second_factor(codes[0], other); self.assertFalse(self.logged_in(other))
        third = app.test_client(); self.password_login(third); self.second_factor(codes[1].upper(), third); self.assertTrue(self.logged_in(third))

    def test_lockout_after_five_failures_then_expires(self):
        secret, _ = self.enable()
        t0 = datetime(2026, 11, 24, 10, 0)
        with patch("services.now", return_value=t0):
            self.password_login()
            for _ in range(5):
                self.second_factor("000000")
            self.assertIn(b"Too many incorrect codes", self.second_factor(code(secret)).data)  # even the right code is refused while locked
            self.assertFalse(self.logged_in())
        with patch("services.now", return_value=t0 + timedelta(minutes=6)):
            self.second_factor(code(secret)); self.assertTrue(self.logged_in())

    def test_2fa_step_requires_the_password_step_and_expires(self):
        self.enable()
        self.assertEqual(self.c.get("/login/2fa").status_code, 302)          # no pending login
        self.password_login()
        with self.c.session_transaction() as s:
            s["pending_at"] = time.time() - 3600
        self.assertEqual(self.c.get("/login/2fa").status_code, 302)          # expired
        self.assertFalse(self.logged_in())

    def test_wrong_password_never_reaches_2fa_step(self):
        self.enable()
        r = self.c.post("/login", data={"email": "l@t", "password": "bad", "csrf_token": token(self.c)})
        self.assertEqual(r.status_code, 200); self.assertEqual(self.c.get("/login/2fa").status_code, 302)

    # ---------- turning it off ----------
    def test_disable_needs_password_and_code(self):
        secret, _ = self.enable(); self.password_login(); self.second_factor(code(secret))
        post = lambda pw, cd: self.c.post("/security/2fa/disable", data={"password": pw, "code": cd, "csrf_token": token(self.c)}, follow_redirects=True)
        self.assertIn(b"Incorrect password", post("bad", code(secret, 1)).data); self.assertEqual(user_row("l@t")["totp_enabled"], 1)
        self.assertIn(b"isn&#39;t right", post("pw", "000000").data); self.assertEqual(user_row("l@t")["totp_enabled"], 1)
        self.assertIn(b"turned off", post("pw", code(secret, 1)).data)
        r = user_row("l@t"); self.assertEqual((r["totp_enabled"], r["totp_secret"]), (0, None))
        other = app.test_client(); self.assertEqual(self.password_login(other).headers["Location"], "/")

    def test_my_clubs_banner_hides_once_enabled(self):
        self.password_login(); self.assertIn(b"Set it up", self.c.get("/my-clubs").data)
        sql("UPDATE users SET totp_enabled=1 WHERE id=?", self.leader_id)
        self.assertNotIn(b"Set it up", self.c.get("/my-clubs").data)


if __name__ == "__main__":
    unittest.main()
