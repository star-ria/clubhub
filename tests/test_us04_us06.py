import os, sys, tempfile, unittest
from datetime import datetime
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db, services  # noqa: E402
from app import app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

NOW = datetime(2026, 11, 24, 12, 0)
GOOD = {"title": "Chess Night", "description": "Come and play.", "event_date": "2026-12-01",
        "start_time": "18:00", "end_time": "20:00", "venue": "FST Library"}


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def login(c, email):
    assert c.post("/login", data={"email": email, "password": "pw", "csrf_token": token(c)}).status_code == 302


def rows(sql, *p):
    conn = db.get_conn(); r = conn.execute(sql, p).fetchall(); conn.close(); return r


class EventTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student"), ("Le2", "l2@t", "leader")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        p = patch("services.now", return_value=NOW); p.start(); self.addCleanup(p.stop)
        conn = db.get_conn(); conn.execute("DELETE FROM announcements"); conn.execute("DELETE FROM memberships"); conn.execute("DELETE FROM events"); conn.execute("DELETE FROM clubs")
        uid = lambda e: conn.execute("SELECT id FROM users WHERE email=?", (e,)).fetchone()["id"]
        ids = {}
        for key, name, leader, status in [("club", "Chess Club", "l@t", "Approved"), ("other", "Art Club", "l2@t", "Approved"),
                                          ("pending", "New Club", "l@t", "Pending"), ("inactive", "Old Club", "l2@t", "Inactive")]:
            ids[key] = conn.execute("INSERT INTO clubs (name,category,description,contact_email,status,leader_id) VALUES (?,?,?,?,?,?)",
                                    (name, "Academic", "d", "c@uwi.edu", status, uid(leader))).lastrowid
        conn.commit(); conn.close()
        self.__dict__.update({f"{k}_id": v for k, v in ids.items()})
        self.leader, self.student = app.test_client(), app.test_client()
        login(self.leader, "l@t"); login(self.student, "s@t")

    def add_event(self, club_id=None, title="E", date="2026-12-01", start="18:00", status="Published"):
        conn = db.get_conn()
        conn.execute("INSERT INTO events (club_id,title,description,event_date,start_time,venue,status) VALUES (?,?,?,?,?,?,?)",
                     (club_id or self.club_id, title, "d", date, start, "Hall", status))
        conn.commit(); conn.close()

    def post_event(self, action="publish", club_id=None, **over):
        data = {**GOOD, **over, "action": action, "csrf_token": token(self.leader)}
        return self.leader.post(f"/clubs/{club_id or self.club_id}/events/new", data=data, follow_redirects=True)

    def count(self):
        return rows("SELECT COUNT(*) n FROM events")[0]["n"]

    # ---------- US-04 ----------
    def test_publish_valid_event_appears_in_student_list(self):
        self.assertIn(b"Event published", self.post_event().data)
        self.assertEqual(rows("SELECT status FROM events")[0]["status"], "Published")
        self.assertIn(b"Chess Night", self.student.get("/events").data)

    def test_draft_saved_but_never_visible_to_students(self):
        self.assertIn(b"saved as a draft", self.post_event("save_draft").data)
        self.assertEqual(rows("SELECT status FROM events")[0]["status"], "Draft")
        self.assertNotIn(b"Chess Night", self.student.get("/events").data)

    def test_past_date_rejected_nothing_saved(self):
        self.assertIn(b"can&#39;t be in the past", self.post_event(event_date="2026-11-23").data)
        self.assertEqual(self.count(), 0)

    def test_today_but_earlier_time_rejected(self):
        self.assertIn(b"already passed", self.post_event(event_date="2026-11-24", start_time="09:00").data)
        self.assertEqual(self.count(), 0)

    def test_blank_mandatory_fields_rejected(self):
        for field in ("title", "description", "event_date", "start_time", "venue"):
            self.assertIn(b"required", self.post_event(**{field: ""}).data, field)
        self.assertEqual(self.count(), 0)

    def test_end_before_start_rejected(self):
        self.assertIn(b"End time must be after", self.post_event(start_time="18:00", end_time="17:00").data)
        self.assertEqual(self.count(), 0)

    def test_title_length_limits(self):
        self.assertIn(b"3 to 100", self.post_event(title="ab").data)
        self.assertIn(b"3 to 100", self.post_event(title="x" * 101).data)

    def test_end_time_optional(self):
        self.post_event(end_time=""); self.assertEqual(self.count(), 1)

    def test_cannot_create_for_someone_elses_club(self):
        data = {**GOOD, "action": "publish", "csrf_token": token(self.leader)}
        self.assertEqual(self.leader.post(f"/clubs/{self.other_id}/events/new", data=data).status_code, 403)
        self.assertEqual(self.count(), 0)

    def test_cannot_create_for_unapproved_club(self):
        r = self.leader.post(f"/clubs/{self.pending_id}/events/new", data={**GOOD, "action": "publish", "csrf_token": token(self.leader)}, follow_redirects=True)
        self.assertIn(b"must be approved", r.data); self.assertEqual(self.count(), 0)
        self.assertEqual(services.create_event(rows("SELECT id FROM users WHERE email='l@t'")[0]["id"], self.pending_id, GOOD, True)[0], False)

    def test_student_cannot_use_leader_pages_and_csrf_enforced(self):
        self.assertEqual(self.student.get(f"/clubs/{self.club_id}/events/new").status_code, 403)
        self.assertEqual(self.leader.post(f"/clubs/{self.club_id}/events/new", data={**GOOD, "action": "publish"}).status_code, 400)

    def test_publish_a_draft_later_and_blocked_when_stale(self):
        self.post_event("save_draft"); eid = rows("SELECT id FROM events")[0]["id"]
        url = f"/clubs/{self.club_id}/events/{eid}/publish"
        self.assertIn(b"Event published", self.leader.post(url, data={"csrf_token": token(self.leader)}, follow_redirects=True).data)
        self.assertIn(b"already published", self.leader.post(url, data={"csrf_token": token(self.leader)}, follow_redirects=True).data)

    def test_draft_whose_time_has_passed_cannot_be_published(self):
        self.add_event(title="Old draft", date="2026-11-20", status="Draft"); eid = rows("SELECT id FROM events")[0]["id"]
        r = self.leader.post(f"/clubs/{self.club_id}/events/{eid}/publish", data={"csrf_token": token(self.leader)}, follow_redirects=True)
        self.assertIn(b"has passed", r.data); self.assertEqual(rows("SELECT status FROM events")[0]["status"], "Draft")

    # ---------- US-06 ----------
    def test_list_soonest_first_with_details(self):
        self.add_event(title="Later", date="2026-12-20"); self.add_event(title="Sooner", date="2026-11-25", start="09:30")
        html = self.student.get("/events").data.decode()
        self.assertLess(html.index("Sooner"), html.index("Later"))
        for text in ("Chess Club", "Wed 25 Nov 2026", "9:30 AM", "Hall"):
            self.assertIn(text, html)

    def test_drafts_past_events_and_inactive_clubs_never_shown(self):
        self.add_event(title="DraftEv", status="Draft"); self.add_event(title="PastEv", date="2026-11-20")
        self.add_event(title="EarlierToday", date="2026-11-24", start="08:00"); self.add_event(self.inactive_id, "InactiveClubEv")
        html = self.student.get("/events").data.decode()
        for t in ("DraftEv", "PastEv", "EarlierToday", "InactiveClubEv"):
            self.assertNotIn(t, html)
        self.assertIn("No upcoming events", html)

    def test_club_and_date_filters(self):
        self.add_event(title="ChessEv", date="2026-12-01"); self.add_event(self.other_id, "ArtEv", date="2026-12-15")
        h = self.student.get(f"/events?club={self.other_id}").data.decode(); self.assertIn("ArtEv", h); self.assertNotIn("ChessEv", h)
        h = self.student.get("/events?from=2026-12-10&to=2026-12-31").data.decode(); self.assertIn("ArtEv", h); self.assertNotIn("ChessEv", h)

    def test_no_events_match_filters_vs_no_upcoming(self):
        self.assertIn(b"No upcoming events", self.student.get("/events?from=2026-12-01").data)
        self.add_event()
        self.assertIn(b"No events match your filters", self.student.get("/events?from=2027-06-01").data)

    def test_bad_filter_input_handled(self):
        self.add_event()
        r = self.student.get("/events?from=garbage&to=2026-01-01&club=abc")
        self.assertEqual(r.status_code, 200); self.assertIn(b"valid dates", r.data)
        r = self.student.get("/events?from=2026-12-31&to=2026-12-01")
        self.assertIn(b"on or after", r.data);

    def test_detail_page_only_for_published(self):
        self.add_event(title="Pub"); self.add_event(title="Dr", status="Draft")
        pub, dr = [r["id"] for r in rows("SELECT id FROM events ORDER BY id")]
        self.assertEqual(self.student.get(f"/events/{pub}").status_code, 200)
        self.assertEqual(self.student.get(f"/events/{dr}").status_code, 404)

    def test_events_page_requires_student_login(self):
        self.assertEqual(app.test_client().get("/events").status_code, 302)
        self.assertEqual(self.leader.get("/events").status_code, 403)


if __name__ == "__main__":
    unittest.main()
