import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db, services  # noqa: E402
from app import app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def login(c, email):
    assert c.post("/login", data={"email": email, "password": "pw", "csrf_token": token(c)}).status_code == 302


class SearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        conn = db.get_conn(); conn.execute("DELETE FROM announcements"); conn.execute("DELETE FROM memberships"); conn.execute("DELETE FROM events"); conn.execute("DELETE FROM clubs")
        leader = conn.execute("SELECT id FROM users WHERE email='l@t'").fetchone()["id"]
        for name, cat, desc, status in [
            ("Chess Club", "Academic", "Play chess every week.", "Approved"),
            ("Coding Circle", "Technology", "We love CHESS engines and algorithms.", "Approved"),
            ("Astronomy Club", "Science", "Stargazing 100% of the time_", "Approved"),
            ("Chess Pending", "Academic", "pending chess", "Pending"),
            ("Chess Rejected", "Academic", "rejected chess", "Rejected"),
            ("Chess Inactive", "Academic", "inactive chess", "Inactive")]:
            conn.execute("INSERT INTO clubs (name,category,description,contact_email,status,leader_id) VALUES (?,?,?,?,?,?)",
                         (name, cat, desc, "c@uwi.edu", status, leader))
        conn.commit(); conn.close()
        self.student, self.leader = app.test_client(), app.test_client()
        login(self.student, "s@t"); login(self.leader, "l@t")

    def names(self, **q):
        return [r["name"] for r in services.search_clubs(**q)]

    def test_keyword_matches_name_or_description_case_insensitive(self):
        self.assertEqual(self.names(keyword="CHESS"), ["Chess Club", "Coding Circle"])

    def test_only_approved_clubs_ever_appear(self):
        for n in self.names(keyword="chess"):
            self.assertNotIn(n, ["Chess Pending", "Chess Rejected", "Chess Inactive"])
        self.assertEqual(len(self.names()), 3)

    def test_empty_search_lists_all_approved(self):
        self.assertEqual(self.names(), ["Astronomy Club", "Chess Club", "Coding Circle"])

    def test_category_filter_and_combined(self):
        self.assertEqual(self.names(category="Technology"), ["Coding Circle"])
        self.assertEqual(self.names(keyword="chess", category="Academic"), ["Chess Club"])

    def test_wildcards_are_literal(self):
        self.assertEqual(self.names(keyword="%"), ["Astronomy Club"])
        self.assertEqual(self.names(keyword="_"), ["Astronomy Club"])

    def test_page_shows_name_category_description_and_count(self):
        r = self.student.get("/clubs?q=chess")
        for text in (b"Chess Club", b"Academic", b"Play chess every week", b"2 clubs found"):
            self.assertIn(text, r.data)
        self.assertNotIn(b"Chess Pending", r.data)

    def test_no_match_message(self):
        self.assertIn(b"No clubs found", self.student.get("/clubs?q=zzzz").data)

    def test_only_students_can_browse_and_login_required(self):
        self.assertEqual(self.leader.get("/clubs").status_code, 403)
        self.assertEqual(app.test_client().get("/clubs").status_code, 302)

    def test_detail_page_only_for_approved_clubs(self):
        conn = db.get_conn()
        ok = conn.execute("SELECT id FROM clubs WHERE name='Chess Club'").fetchone()["id"]
        bad = conn.execute("SELECT id FROM clubs WHERE name='Chess Pending'").fetchone()["id"]
        conn.close()
        self.assertEqual(self.student.get(f"/clubs/{ok}").status_code, 200)
        self.assertEqual(self.student.get(f"/clubs/{bad}").status_code, 404)

    def test_search_is_fast(self):
        import time
        t = time.time(); self.student.get("/clubs?q=chess"); self.assertLess(time.time() - t, 3)


if __name__ == "__main__":
    unittest.main()
