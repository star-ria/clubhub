import os, sys, tempfile, unittest
from datetime import datetime
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db, services  # noqa: E402
from app import app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

T1, T2 = datetime(2026, 11, 24, 9, 5, 0), datetime(2026, 11, 24, 15, 30, 0)


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def login(c, email):
    assert c.post("/login", data={"email": email, "password": "pw", "csrf_token": token(c)}).status_code == 302


def rows(sql, *p):
    conn = db.get_conn(); r = conn.execute(sql, p).fetchall(); conn.close(); return r


def uid(email):
    return rows("SELECT id FROM users WHERE email = ?", email)[0]["id"]


class AnnouncementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student"), ("Le2", "l2@t", "leader"),
                        ("St2", "s2@t", "student"), ("St3", "s3@t", "student")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        conn = db.get_conn()
        for t in ("announcements", "memberships", "events", "clubs"):
            conn.execute(f"DELETE FROM {t}")
        conn.execute("DELETE FROM notifications")
        ids = {}
        for key, name, leader, status in [("club", "Chess Club", "l@t", "Approved"), ("other", "Art Club", "l2@t", "Approved"),
                                          ("pending", "New Club", "l@t", "Pending"), ("inactive", "Old Club", "l@t", "Inactive")]:
            ids[key] = conn.execute("INSERT INTO clubs (name,category,description,contact_email,status,leader_id) VALUES (?,?,?,?,?,?)",
                                    (name, "Academic", "d", "c@uwi.edu", status, uid(leader))).lastrowid
        # s@t = accepted member, s2@t = pending request, s3@t = declined
        for email, st in [("s@t", "Accepted"), ("s2@t", "Pending"), ("s3@t", "Declined")]:
            conn.execute("INSERT INTO memberships (club_id, student_id, status) VALUES (?,?,?)", (ids["club"], uid(email), st))
        conn.commit(); conn.close()
        self.__dict__.update({f"{k}_id": v for k, v in ids.items()})
        self.clock = patch("services.now", return_value=T1); self.clock.start(); self.addCleanup(self.clock.stop)
        self.leader, self.leader2, self.member, self.pending, self.declined = (app.test_client() for _ in range(5))
        for c, e in [(self.leader, "l@t"), (self.leader2, "l2@t"), (self.member, "s@t"), (self.pending, "s2@t"), (self.declined, "s3@t")]:
            login(c, e)

    def post(self, club_id=None, client=None, **over):
        c = client or self.leader
        return c.post(f"/clubs/{club_id or self.club_id}/announcements/new", follow_redirects=True,
                      data={"title": "Meeting moved", "message": "We now meet on Friday.", **over, "csrf_token": token(c)})

    def n(self):
        return rows("SELECT COUNT(*) n FROM announcements")[0]["n"]

    # ---------- posting ----------
    def test_valid_post_appears_with_timestamp_and_is_visible_to_members(self):
        self.assertIn(b"Announcement posted", self.post().data)
        html = self.member.get(f"/clubs/{self.club_id}/announcements").data.decode()
        self.assertIn("Meeting moved", html); self.assertIn("We now meet on Friday.", html); self.assertIn("24 Nov 2026, 09:05 AM", html)

    def test_newest_first(self):
        self.post(title="First")
        with patch("services.now", return_value=T2):
            self.post(title="Second")
        html = self.member.get(f"/clubs/{self.club_id}/announcements").data.decode()
        self.assertLess(html.index("Second"), html.index("First"))

    def test_only_accepted_members_are_notified(self):
        self.post()
        self.assertTrue(any("Meeting moved" in n["message"] for n in services.list_notifications(uid("s@t"))))
        for email in ("s2@t", "s3@t", "l@t"):
            self.assertEqual(services.list_notifications(uid(email)), [])

    def test_empty_title_or_message_rejected(self):
        self.assertIn(b"Title is required", self.post(title="").data)
        self.assertIn(b"Message is required", self.post(message="   ").data)
        self.assertEqual(self.n(), 0)

    def test_length_limits_with_character_count(self):
        self.assertIn(b"1,000 characters or fewer (currently 1001)", self.post(message="x" * 1001).data)
        self.assertIn(b"80 characters or fewer (currently 81)", self.post(title="t" * 81).data)
        self.assertEqual(self.n(), 0)
        self.post(title="t" * 80, message="m" * 1000); self.assertEqual(self.n(), 1)

    def test_form_keeps_text_after_error(self):
        self.assertIn(b"Keep this text", self.post(title="", message="Keep this text").data)

    def test_notifications_not_sent_when_post_fails(self):
        self.post(title=""); self.assertEqual(services.list_notifications(uid("s@t")), [])

    # ---------- who may post ----------
    def test_only_the_clubs_leader_can_post(self):
        self.assertEqual(self.post(client=self.leader2).status_code, 403)
        self.assertEqual(self.post(client=self.member).status_code, 403)
        self.assertEqual(self.n(), 0)
        self.assertFalse(services.post_announcement(uid("l2@t"), self.club_id, {"title": "x", "message": "y"})[0])

    def test_unapproved_club_cannot_post(self):
        self.assertIn(b"must be approved", self.post(club_id=self.pending_id).data)
        self.assertEqual(self.n(), 0)
        self.assertFalse(services.post_announcement(uid("l@t"), self.pending_id, {"title": "x", "message": "y"})[0])

    def test_csrf_enforced(self):
        self.assertEqual(self.leader.post(f"/clubs/{self.club_id}/announcements/new", data={"title": "a", "message": "b"}).status_code, 400)

    # ---------- who may read ----------
    def test_only_active_members_can_read(self):
        self.post()
        self.assertEqual(self.member.get(f"/clubs/{self.club_id}/announcements").status_code, 200)
        for c in (self.pending, self.declined):
            self.assertEqual(c.get(f"/clubs/{self.club_id}/announcements").status_code, 403)
        self.assertEqual(app.test_client().get(f"/clubs/{self.club_id}/announcements").status_code, 302)
        self.assertEqual(self.leader.get(f"/clubs/{self.club_id}/announcements").status_code, 403)  # leaders use the manage page

    def test_member_of_one_club_cannot_read_another(self):
        self.assertEqual(self.member.get(f"/clubs/{self.other_id}/announcements").status_code, 403)

    def test_inactive_or_unapproved_club_feed_is_404(self):
        for cid in (self.inactive_id, self.pending_id):
            self.assertEqual(self.member.get(f"/clubs/{cid}/announcements").status_code, 404)

    def test_leader_sees_feed_on_manage_page_but_other_leader_cannot(self):
        self.post(); self.assertIn(b"Meeting moved", self.leader.get(f"/clubs/{self.club_id}/announcements/new").data)
        self.assertEqual(self.leader2.get(f"/clubs/{self.club_id}/announcements/new").status_code, 403)

    def test_html_in_announcement_is_escaped(self):
        self.post(title="<script>alert(1)</script>", message="<b>hi</b>")
        html = self.member.get(f"/clubs/{self.club_id}/announcements").data.decode()
        self.assertNotIn("<script>alert(1)</script>", html); self.assertIn("&lt;script&gt;", html)

    def test_links_shown_only_where_allowed(self):
        self.assertIn(f"/clubs/{self.club_id}/announcements", self.member.get(f"/clubs/{self.club_id}").data.decode())
        self.assertNotIn("View announcements", self.pending.get(f"/clubs/{self.club_id}").data.decode())
        self.assertIn(f"/clubs/{self.club_id}/announcements/new", self.leader.get("/my-clubs").data.decode())
        self.assertIn("View announcements", self.member.get("/my-memberships").data.decode())


if __name__ == "__main__":
    unittest.main()
