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


def rows(sql, *p):
    conn = db.get_conn(); r = conn.execute(sql, p).fetchall(); conn.close(); return r


def uid(email):
    return rows("SELECT id FROM users WHERE email = ?", email)[0]["id"]


class MembershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student"), ("Le2", "l2@t", "leader"), ("St2", "s2@t", "student")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        conn = db.get_conn()
        for t in ("announcements", "memberships", "events", "clubs"):
            conn.execute(f"DELETE FROM {t}")
        ids = {}
        for key, name, leader, status, accepting in [("club", "Chess Club", "l@t", "Approved", 1), ("other", "Art Club", "l2@t", "Approved", 1),
                                                      ("pending", "New Club", "l@t", "Pending", 1), ("closed", "Closed Club", "l@t", "Approved", 0),
                                                      ("inactive", "Old Club", "l@t", "Inactive", 1)]:
            ids[key] = conn.execute("INSERT INTO clubs (name,category,description,contact_email,status,accepting_members,leader_id) VALUES (?,?,?,?,?,?,?)",
                                    (name, "Academic", "d", "c@uwi.edu", status, accepting, uid(leader))).lastrowid
        conn.execute("DELETE FROM notifications"); conn.commit(); conn.close()
        self.__dict__.update({f"{k}_id": v for k, v in ids.items()})
        self.student, self.student2, self.leader, self.leader2 = (app.test_client() for _ in range(4))
        for c, e in [(self.student, "s@t"), (self.student2, "s2@t"), (self.leader, "l@t"), (self.leader2, "l2@t")]:
            login(c, e)

    def join(self, club_id=None, client=None):
        c = client or self.student
        return c.post(f"/clubs/{club_id or self.club_id}/join", data={"csrf_token": token(c)}, follow_redirects=True)

    def decide(self, mid, decision, expected="Pending", client=None, club_id=None):
        c = client or self.leader
        return c.post(f"/clubs/{club_id or self.club_id}/requests/{mid}/{decision}", follow_redirects=True,
                      data={"expected_status": expected, "csrf_token": token(c)})

    def req_id(self):
        return rows("SELECT id FROM memberships ORDER BY id DESC")[0]["id"]

    def n_requests(self):
        return rows("SELECT COUNT(*) n FROM memberships")[0]["n"]

    # ---------- US-03 ----------
    def test_valid_join_creates_pending_and_notifies_leader(self):
        self.assertIn(b"Request sent", self.join().data)
        self.assertEqual(rows("SELECT status FROM memberships")[0]["status"], "Pending")
        self.assertTrue(any("St requested to join" in n["message"] for n in services.list_notifications(uid("l@t"))))

    def test_join_button_disabled_and_status_shown_when_pending(self):
        self.join()
        html = self.student.get(f"/clubs/{self.club_id}").data.decode()
        self.assertIn("Request pending", html); self.assertNotIn("Join this club", html)

    def test_only_one_open_request_per_club(self):
        self.join()
        self.assertIn(b"already have a pending request", self.join().data)
        self.assertEqual(self.n_requests(), 1)

    def test_unique_index_blocks_duplicates_even_if_service_check_is_bypassed(self):
        self.join(); conn = db.get_conn()
        with self.assertRaises(Exception):
            conn.execute("INSERT INTO memberships (club_id, student_id) VALUES (?, ?)", (self.club_id, uid("s@t")))
        conn.close()

    def test_unapproved_or_inactive_clubs_cannot_be_joined(self):
        for cid in (self.pending_id, self.inactive_id):
            self.assertIn(b"isn&#39;t available", self.join(cid).data)
        self.assertEqual(self.n_requests(), 0)

    def test_closed_club_shows_message_and_creates_no_request(self):
        self.assertIn(b"not accepting new members", self.student.get(f"/clubs/{self.closed_id}").data)
        self.assertIn(b"not accepting new members", self.join(self.closed_id).data)
        self.assertEqual(self.n_requests(), 0)

    def test_only_students_can_join_and_csrf_enforced(self):
        self.assertEqual(self.leader.post(f"/clubs/{self.club_id}/join", data={"csrf_token": token(self.leader)}).status_code, 403)
        self.assertEqual(self.student.post(f"/clubs/{self.club_id}/join").status_code, 400)

    def test_my_memberships_lists_statuses(self):
        self.join(); html = self.student.get("/my-memberships").data.decode()
        self.assertIn("Chess Club", html); self.assertIn("Pending", html)

    # ---------- UC-05: accept / decline ----------
    def test_accept_makes_student_a_member_and_notifies_them(self):
        self.join(); self.assertIn(b"now a member", self.decide(self.req_id(), "accept").data)
        self.assertTrue(services.is_active_member(uid("s@t"), self.club_id))
        self.assertIn(b"Member", self.student.get(f"/clubs/{self.club_id}").data)
        self.assertIn(b"already a member", self.join().data)
        self.assertTrue(any("accepted" in n["message"] for n in services.list_notifications(uid("s@t"))))

    def test_decline_then_student_may_request_again(self):
        self.join(); self.decide(self.req_id(), "decline")
        self.assertFalse(services.is_active_member(uid("s@t"), self.club_id))
        self.assertIn(b"previous request was declined", self.student.get(f"/clubs/{self.club_id}").data)
        self.join(); self.assertEqual(self.n_requests(), 2)

    def test_stale_decision_blocked(self):
        self.join(); mid = self.req_id(); self.decide(mid, "accept")
        self.assertIn(b"Blocked", self.decide(mid, "decline").data)
        self.assertEqual(rows("SELECT status FROM memberships")[0]["status"], "Accepted")

    def test_requests_page_lists_only_pending(self):
        self.join(); self.join(client=self.student2); self.decide(rows("SELECT id FROM memberships ORDER BY id")[0]["id"], "accept")
        html = self.leader.get(f"/clubs/{self.club_id}/requests").data.decode()
        self.assertIn("St2", html); self.assertNotIn(">St<", html)

    def test_leader_of_another_club_cannot_view_or_decide(self):
        self.join(); mid = self.req_id()
        self.assertEqual(self.leader2.get(f"/clubs/{self.club_id}/requests").status_code, 403)
        self.assertEqual(self.decide(mid, "accept", client=self.leader2).status_code, 403)
        self.assertEqual(rows("SELECT status FROM memberships")[0]["status"], "Pending")

    def test_request_from_another_club_cannot_be_decided_through_my_club(self):
        self.join(self.other_id); mid = self.req_id()
        self.assertIn(b"Request not found", self.decide(mid, "accept", club_id=self.club_id).data)
        self.assertEqual(rows("SELECT status FROM memberships")[0]["status"], "Pending")

    def test_student_cannot_open_leader_pages(self):
        self.assertEqual(self.student.get(f"/clubs/{self.club_id}/requests").status_code, 403)

    # ---------- open / close to new members ----------
    def test_leader_can_close_and_reopen_club(self):
        r = self.leader.post(f"/clubs/{self.club_id}/accepting", data={"accepting": "0", "csrf_token": token(self.leader)}, follow_redirects=True)
        self.assertIn(b"closed to new members", r.data); self.assertIn(b"not accepting", self.join().data)
        self.leader.post(f"/clubs/{self.club_id}/accepting", data={"accepting": "1", "csrf_token": token(self.leader)})
        self.assertIn(b"Request sent", self.join().data)

    def test_only_owner_can_toggle(self):
        r = self.leader2.post(f"/clubs/{self.club_id}/accepting", data={"accepting": "0", "csrf_token": token(self.leader2)})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(rows("SELECT accepting_members a FROM clubs WHERE id = ?", self.club_id)[0]["a"], 1)

    def test_my_clubs_shows_pending_count(self):
        self.join(); self.assertIn(b"Membership requests (1)", self.leader.get("/my-clubs").data)


if __name__ == "__main__":
    unittest.main()
