import os, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db, passwords, services  # noqa: E402
from app import app  # noqa: E402

STRONG = "correct-horse-battery-9"


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def rows(q, *p):
    conn = db.get_conn(); r = conn.execute(q, p).fetchall(); conn.close(); return r


class PasswordRuleTests(unittest.TestCase):
    def test_blocking_rules(self):
        c = passwords.check_password
        self.assertFalse(c("short1A")["ok"])
        self.assertIn("at least 8", c("short1A")["errors"][0])
        self.assertFalse(c("password")["ok"]); self.assertFalse(c("Password123")["ok"]);
        self.assertFalse(c("aaaaaaaaaa")["ok"])
        self.assertFalse(c("x" * 129)["ok"])
        self.assertIn("name or email", " ".join(c("raya-secret-77", email="raya@uwi.edu", name="Raya Smith")["errors"]))
        self.assertIn("name or email", " ".join(c("my-smith-2026!", name="Raya Smith")["errors"]))

    def test_strength_scores_and_suggestions(self):
        c = passwords.check_password
        self.assertEqual(c("correct horse battery staple")["label"], "Strong")
        self.assertLess(c("Abcdefg1")["score"], c("Tr0ub4dor&3-xyz")["score"])
        weak = c("hunter22")
        self.assertTrue(weak["ok"] and weak["suggestions"] and weak["score"] <= 2)
        self.assertEqual(c("")["score"], 0)

    def test_sequences_flagged_and_lower_score(self):
        r = passwords.check_password("Abc12345xyz!")
        self.assertTrue(any("sequences" in t for t in r["suggestions"]))


class AccountFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()

    def tearDown(self):
        conn = db.get_conn()
        ids = [r["id"] for r in conn.execute("SELECT id FROM users WHERE email LIKE 'su\\_%' ESCAPE '\\'")]
        for i in ids:
            conn.execute("DELETE FROM notifications WHERE user_id = ?", (i,)); conn.execute("DELETE FROM users WHERE id = ?", (i,))
        conn.commit(); conn.close()

    def form(self, **over):
        return {"name": "Sam Test", "email": "su_sam@uwi.edu", "role": "student", "password": STRONG, "confirm": STRONG, **over}

    def signup(self, c=None, **over):
        c = c or app.test_client()
        return c, c.post("/signup", data={**self.form(**over), "csrf_token": token(c)}, follow_redirects=True)

    # ---------- sign up ----------
    def test_student_signup_creates_account_and_logs_in(self):
        c, r = self.signup()
        self.assertIn(b"Welcome to FST Club Hub", r.data)
        u = rows("SELECT * FROM users WHERE email = 'su_sam@uwi.edu'")[0]
        self.assertEqual(u["role"], "student"); self.assertEqual(c.get("/clubs").status_code, 200)

    def test_leader_signup_and_password_is_hashed(self):
        c, _ = self.signup(email="su_lead@uwi.edu", role="leader")
        u = rows("SELECT * FROM users WHERE email = 'su_lead@uwi.edu'")[0]
        self.assertEqual(u["role"], "leader"); self.assertNotIn(STRONG, u["password_hash"]); self.assertEqual(c.get("/my-clubs").status_code, 200)

    def test_cannot_self_register_as_admin(self):
        _, r = self.signup(email="su_admin@uwi.edu", role="admin")
        self.assertIn(b"student or a club representative", r.data); self.assertEqual(rows("SELECT * FROM users WHERE email='su_admin@uwi.edu'"), [])

    def test_duplicate_email_case_insensitive(self):
        self.signup(); _, r = self.signup(email="SU_Sam@UWI.edu")
        self.assertIn(b"already exists", r.data); self.assertEqual(len(rows("SELECT * FROM users WHERE email LIKE 'su\\_sam%' ESCAPE '\\'")), 1)

    def test_validation_errors_create_nothing(self):
        for over, msg in [({"email": "nope"}, b"valid email"), ({"name": "S"}, b"Enter your name"), ({"role": ""}, b"student or a club"),
                          ({"password": "password1", "confirm": "password1"}, b"too common"), ({"confirm": "different-one-1"}, b"don&#39;t match"),
                          ({"password": "short", "confirm": "short"}, b"at least 8")]:
            _, r = self.signup(**over); self.assertIn(msg, r.data, over)
        self.assertEqual(rows("SELECT * FROM users WHERE email = 'su_sam@uwi.edu'"), [])

    def test_form_keeps_typed_values_but_never_the_password(self):
        _, r = self.signup(name="Keep Me", password="x", confirm="x")
        self.assertIn(b"Keep Me", r.data); self.assertNotIn(b'value="x"', r.data)

    def test_domain_restriction_when_configured(self):
        with patch.dict(os.environ, {"ALLOWED_EMAIL_DOMAINS": "mymona.uwi.edu"}):
            _, r = self.signup(email="su_out@gmail.com"); self.assertIn(b"@mymona.uwi.edu", r.data)
            self.signup(email="su_in@mymona.uwi.edu"); self.assertEqual(len(rows("SELECT * FROM users WHERE email='su_in@mymona.uwi.edu'")), 1)

    def test_csrf_and_logged_in_redirect(self):
        self.assertEqual(app.test_client().post("/signup", data=self.form()).status_code, 400)
        c, _ = self.signup(); self.assertEqual(c.get("/signup").status_code, 302)

    def test_password_check_endpoint(self):
        c = app.test_client(); t = token(c)
        r = c.post("/password-check", data={"password": "password1", "csrf_token": t}).get_json()
        self.assertFalse(r["ok"]); self.assertEqual(r["label"], "Too weak")
        r = c.post("/password-check", data={"password": STRONG, "csrf_token": t}).get_json()
        self.assertTrue(r["ok"]); self.assertGreaterEqual(r["score"], 3)
        self.assertEqual(c.post("/password-check", data={"password": "x"}).status_code, 400)

    # ---------- change password ----------
    def change(self, c, current=STRONG, new="N3w-passphrase-77", confirm=None):
        return c.post("/account/password", data={"current": current, "new": new, "confirm": new if confirm is None else confirm,
                                                 "csrf_token": token(c)}, follow_redirects=True)

    def test_change_password_success(self):
        c, _ = self.signup()
        self.assertIn(b"Password changed", self.change(c).data)
        fresh = app.test_client()
        bad = fresh.post("/login", data={"email": "su_sam@uwi.edu", "password": STRONG, "csrf_token": token(fresh)}); self.assertEqual(bad.status_code, 200)
        good = fresh.post("/login", data={"email": "su_sam@uwi.edu", "password": "N3w-passphrase-77", "csrf_token": token(fresh)}); self.assertEqual(good.status_code, 302)
        uid = rows("SELECT id FROM users WHERE email='su_sam@uwi.edu'")[0]["id"]
        self.assertTrue(any("password was changed" in n["message"] for n in services.list_notifications(uid)))

    def test_change_password_rejections_leave_password_unchanged(self):
        c, _ = self.signup(); before = rows("SELECT password_hash h FROM users WHERE email='su_sam@uwi.edu'")[0]["h"]
        for kwargs, msg in [({"current": "wrong-one-1"}, b"current password is incorrect"), ({"new": "password1"}, b"too common"),
                            ({"new": STRONG}, b"different from your current"), ({"confirm": "nope"}, b"don&#39;t match"), ({"new": "short"}, b"at least 8")]:
            self.assertIn(msg, self.change(c, **kwargs).data, kwargs)
        self.assertEqual(rows("SELECT password_hash h FROM users WHERE email='su_sam@uwi.edu'")[0]["h"], before)

    def test_change_password_requires_login_and_csrf(self):
        self.assertEqual(app.test_client().get("/account/password").status_code, 302)
        c, _ = self.signup(); self.assertEqual(c.post("/account/password", data={"current": STRONG, "new": "N3w-passphrase-77", "confirm": "N3w-passphrase-77"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
