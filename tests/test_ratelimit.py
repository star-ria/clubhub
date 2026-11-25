import os, sys, tempfile, time, unittest
from datetime import datetime, timedelta
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import app as app_module  # noqa: E402
import db, security, services  # noqa: E402
from flask import Flask, request  # noqa: E402
from werkzeug.security import check_password_hash, generate_password_hash  # noqa: E402

app = app_module.app
T0 = datetime(2026, 11, 24, 10, 0, 0)
at = lambda **kw: patch("services.now", return_value=T0 + timedelta(**kw))


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def attempt(c, email, pw, ip="10.0.0.1", headers=None):
    return c.post("/login", data={"email": email, "password": pw, "csrf_token": token(c)}, environ_overrides={"REMOTE_ADDR": ip}, headers=headers or {})


def failures():
    conn = db.get_conn(); n = conn.execute("SELECT COUNT(*) n FROM login_failures").fetchone()["n"]; conn.close(); return n


class LoginThrottleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db(); conn = db.get_conn()
        for n, e, r in [("Le", "l@t", "leader"), ("St", "s@t", "student")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        self.c = app.test_client(); self._wipe()

    def tearDown(self):
        self._wipe()
        conn = db.get_conn(); conn.execute("DELETE FROM backup_codes")
        conn.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=0, totp_failures=0, totp_locked_until=NULL"); conn.commit(); conn.close()

    def _wipe(self):
        conn = db.get_conn(); conn.execute("DELETE FROM login_failures"); conn.commit(); conn.close()

    def fail(self, n, email="l@t", ip="10.0.0.1"):
        for _ in range(n):
            self.assertEqual(attempt(self.c, email, "wrong", ip).status_code, 200)

    # ---------- the main rule ----------
    def test_five_wrong_passwords_then_locked_even_for_the_right_password(self):
        with at():
            self.fail(5)
            r = attempt(self.c, "l@t", "pw")
            self.assertEqual(r.status_code, 429); self.assertIn(b"Too many attempts", r.data); self.assertIn(b"15 minutes", r.data)
            self.assertEqual(int(r.headers["Retry-After"]), 900)
            self.assertEqual(self.c.get("/my-clubs").status_code, 302)  # not signed in

    def test_lock_is_a_sliding_window_and_refused_attempts_do_not_extend_it(self):
        with at(): self.fail(5)
        with at(minutes=10):
            r = attempt(self.c, "l@t", "pw"); self.assertEqual(r.status_code, 429); self.assertIn(b"5 minutes", r.data)
            self.assertEqual(failures(), 5)  # the refused attempt was not recorded
        with at(minutes=14, seconds=59): self.assertEqual(attempt(self.c, "l@t", "pw").status_code, 429)
        with at(minutes=15, seconds=1): self.assertEqual(attempt(self.c, "l@t", "pw").status_code, 302)

    def test_failures_below_the_limit_never_lock(self):
        with at():
            self.fail(4); self.assertEqual(attempt(self.c, "l@t", "pw").status_code, 302)

    def test_success_forgets_earlier_mistakes(self):
        with at():
            self.fail(4); attempt(self.c, "l@t", "pw"); self.fail(4)
            self.assertEqual(attempt(self.c, "l@t", "pw").status_code, 302)

    # ---------- scope of the three limits ----------
    def test_pair_lock_does_not_block_other_accounts_or_other_ips(self):
        with at():
            self.fail(5)
            self.assertEqual(attempt(self.c, "s@t", "pw", ip="10.0.0.1").status_code, 302)  # other account, same IP
            self.assertEqual(attempt(self.c, "l@t", "pw", ip="10.0.0.2").status_code, 302)  # same account, other IP

    def test_one_ip_trying_many_accounts_is_stopped(self):
        with at():
            for i in range(20):
                attempt(self.c, f"nobody{i}@t", "wrong", ip="10.9.9.9")
            self.assertEqual(attempt(self.c, "l@t", "pw", ip="10.9.9.9").status_code, 429)
            self.assertEqual(attempt(self.c, "l@t", "pw", ip="10.9.9.8").status_code, 302)

    def test_many_ips_attacking_one_account_is_stopped(self):
        with at():
            for i in range(15):
                attempt(self.c, "l@t", "wrong", ip=f"10.1.0.{i}")
            self.assertEqual(attempt(self.c, "l@t", "pw", ip="10.1.0.99").status_code, 429)

    def test_unknown_emails_are_throttled_the_same_way(self):
        with at():
            self.fail(5, email="ghost@t")
            r = attempt(self.c, "ghost@t", "wrong"); self.assertEqual(r.status_code, 429); self.assertIn(b"Too many attempts", r.data)
            self.assertEqual(attempt(self.c, "GHOST@t ", "wrong").status_code, 429)  # case / spaces don't dodge the lock

    def test_spoofed_forwarded_header_is_ignored_by_default(self):
        with at():
            for i in range(5):
                attempt(self.c, "l@t", "wrong", headers={"X-Forwarded-For": f"1.2.3.{i}"})
            self.assertEqual(attempt(self.c, "l@t", "pw", headers={"X-Forwarded-For": "5.6.7.8"}).status_code, 429)

    def test_proxy_headers_trusted_only_when_configured(self):
        def client(hops):
            t = Flask("probe"); t.add_url_rule("/", "ip", lambda: request.remote_addr)
            return app_module.apply_proxy_fix(t, hops).test_client()
        hdr = {"X-Forwarded-For": "9.9.9.9"}
        self.assertEqual(client(0).get("/", headers=hdr, environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).get_data(as_text=True), "10.0.0.1")
        self.assertEqual(client(1).get("/", headers=hdr, environ_overrides={"REMOTE_ADDR": "10.0.0.1"}).get_data(as_text=True), "9.9.9.9")

    def test_unknown_email_still_costs_a_password_hash_check(self):
        with patch("app.check_password_hash", wraps=check_password_hash) as m:
            attempt(self.c, "nobody@t", "x")
        self.assertEqual(m.call_count, 1); self.assertEqual(m.call_args[0][0], app_module.DUMMY_HASH)

    def test_old_failure_rows_are_purged(self):
        with at(): services.record_failure("login", "a@t", "1.1.1.1")
        with at(days=2): services.record_failure("login", "b@t", "1.1.1.1")
        self.assertEqual(failures(), 1)

    def test_normal_use_and_get_requests_are_unaffected(self):
        with at():
            self.fail(5)
            self.assertEqual(self.c.get("/login").status_code, 200)
            self.assertEqual(self.c.get("/signup").status_code, 200)

    # ---------- re-entering the current password ----------
    def test_change_password_current_password_guessing_is_limited(self):
        ok, uid = services.create_user({"name": "Rate Tester", "email": "su_rate@uwi.edu", "role": "student", "password": "Old-passphrase-55", "confirm": "Old-passphrase-55"})
        self.assertTrue(ok)
        try:
            c = app.test_client(); self.assertEqual(attempt(c, "su_rate@uwi.edu", "Old-passphrase-55").status_code, 302)
            change = lambda cur: c.post("/account/password", data={"current": cur, "new": "Brand-new-phrase-66", "confirm": "Brand-new-phrase-66", "csrf_token": token(c)})
            with at():
                for _ in range(5): self.assertIn(b"incorrect", change("nope").data)
                r = change("Old-passphrase-55"); self.assertIn(b"Too many attempts", r.data)
                self.assertTrue(check_password_hash(services.get_user(uid)["password_hash"], "Old-passphrase-55"))
            with at(minutes=16):
                r = c.post("/account/password", data={"current": "Old-passphrase-55", "new": "Brand-new-phrase-66", "confirm": "Brand-new-phrase-66", "csrf_token": token(c)}, follow_redirects=True)
                self.assertIn(b"Password changed", r.data)
        finally:
            conn = db.get_conn(); conn.execute("DELETE FROM notifications WHERE user_id = ?", (uid,)); conn.execute("DELETE FROM users WHERE id = ?", (uid,)); conn.commit(); conn.close()

    def test_turning_off_2fa_password_guessing_is_limited(self):
        uid = services.get_user_by_email("l@t")["id"]
        services.start_2fa_setup(uid); secret = services.pending_2fa_setup(uid)[0]
        self.assertTrue(services.confirm_2fa_setup(uid, security.totp(secret))[0])
        conn = db.get_conn(); conn.execute("UPDATE users SET totp_last_step = 0 WHERE id = ?", (uid,)); conn.commit(); conn.close()
        with at():
            for _ in range(5): self.assertEqual(services.disable_2fa(uid, "bad", "000000", ip="1.1.1.1"), (False, "Incorrect password."))
            ok, msg = services.disable_2fa(uid, "pw", security.totp(secret, at=time.time() + 30), ip="1.1.1.1")
            self.assertFalse(ok); self.assertIn("Too many attempts", msg)


if __name__ == "__main__":
    unittest.main()
