import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db, services  # noqa: E402
from app import app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

GOOD = {"name": "Chess Club", "category": "Academic", "description": "We play chess.", "contact_email": "chess@uwi.edu"}


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def login(c, email):
    r = c.post("/login", data={"email": email, "password": "pw", "csrf_token": token(c)})
    assert r.status_code == 302


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        conn = db.get_conn(); conn.execute("DELETE FROM announcements"); conn.execute("DELETE FROM memberships"); conn.execute("DELETE FROM events"); conn.execute("DELETE FROM clubs"); conn.execute("DELETE FROM notifications"); conn.commit(); conn.close()
        self.leader, self.admin, self.student = (app.test_client() for _ in range(3))
        login(self.leader, "l@t"); login(self.admin, "a@t"); login(self.student, "s@t")

    def post_club(self, **over):
        data = {**GOOD, **over, "csrf_token": token(self.leader)}
        return self.leader.post("/clubs/register", data=data, follow_redirects=True)

    def club_id(self):
        return services.list_clubs()[0]["id"]

    def act(self, action, expected, reason=""):
        return self.admin.post(f"/admin/clubs/{self.club_id()}/{action}", follow_redirects=True,
                               data={"expected_status": expected, "reason": reason, "csrf_token": token(self.admin)})

    # ---- US-01 ----
    def test_valid_registration_is_pending_and_admin_notified(self):
        r = self.post_club()
        self.assertIn(b"Pending", r.data)
        self.assertEqual(services.list_clubs()[0]["status"], "Pending")
        self.assertEqual(len(services.list_notifications(1)), 1)

    def test_duplicate_name_case_insensitive(self):
        self.post_club(); r = self.post_club(name="chess club")
        self.assertIn(b"already exists", r.data); self.assertEqual(len(services.list_clubs()), 1)

    def test_missing_field_and_bad_email_rejected(self):
        self.assertIn(b"Description is required", self.post_club(description="").data)
        self.assertIn(b"valid email", self.post_club(contact_email="nope").data)
        self.assertEqual(len(services.list_clubs()), 0)

    def test_name_length_and_description_length(self):
        self.assertIn(b"3 to 60", self.post_club(name="ab").data)
        self.assertIn(b"500 characters", self.post_club(description="x" * 501).data)

    def test_student_cannot_register(self):
        r = self.student.post("/clubs/register", data={**GOOD, "csrf_token": token(self.student)})
        self.assertEqual(r.status_code, 403)

    def test_csrf_required(self):
        self.assertEqual(self.leader.post("/clubs/register", data=GOOD).status_code, 400)

    # ---- US-08 ----
    def test_approve_notifies_rep(self):
        self.post_club(); self.act("approve", "Pending")
        self.assertEqual(services.list_clubs()[0]["status"], "Approved")
        self.assertTrue(any("approved" in n["message"] for n in services.list_notifications(2)))

    def test_reject_requires_reason_and_sends_it(self):
        self.post_club()
        self.assertIn(b"reason is required", self.act("reject", "Pending").data)
        self.assertEqual(services.list_clubs()[0]["status"], "Pending")
        self.act("reject", "Pending", "Incomplete details")
        self.assertEqual(services.list_clubs()[0]["status"], "Rejected")
        self.assertTrue(any("Incomplete details" in n["message"] for n in services.list_notifications(2)))

    def test_stale_action_blocked(self):
        self.post_club(); self.act("approve", "Pending")
        self.assertIn(b"Blocked", self.act("reject", "Pending", "late").data)
        self.assertEqual(services.list_clubs()[0]["status"], "Approved")

    def test_deactivate_keeps_record_and_filter_empty_state(self):
        self.post_club(); self.act("approve", "Pending"); self.act("deactivate", "Approved")
        self.assertEqual(services.list_clubs()[0]["status"], "Inactive")
        self.assertIn(b"No clubs found", self.admin.get("/admin/clubs?status=Pending").data)

    def test_non_admin_cannot_act(self):
        self.post_club()
        r = self.leader.post(f"/admin/clubs/{self.club_id()}/approve", data={"expected_status": "Pending", "csrf_token": token(self.leader)})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
