import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db, services  # noqa: E402
from app import app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

NEW = {"description": "Fresh description about robots", "contact_email": "new@uwi.edu",
       "contact_phone": "876-555-0199", "meeting_info": "Fridays 3pm, Room 5"}


def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]


def login(c, email):
    assert c.post("/login", data={"email": email, "password": "pw", "csrf_token": token(c)}).status_code == 302


def club_row(cid):
    conn = db.get_conn(); r = dict(conn.execute("SELECT * FROM clubs WHERE id = ?", (cid,)).fetchone()); conn.close(); return r


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()
        conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student"), ("Le2", "l2@t", "leader")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        conn.commit(); conn.close()

    def setUp(self):
        conn = db.get_conn()
        for t in ("announcements", "memberships", "events", "clubs"):
            conn.execute(f"DELETE FROM {t}")
        uid = lambda e: conn.execute("SELECT id FROM users WHERE email=?", (e,)).fetchone()["id"]
        ids = {}
        for key, name, leader, status in [("club", "Chess Club", "l@t", "Approved"), ("other", "Art Club", "l2@t", "Approved"), ("pending", "New Club", "l@t", "Pending")]:
            ids[key] = conn.execute("INSERT INTO clubs (name,category,description,contact_email,contact_phone,meeting_info,status,leader_id) VALUES (?,?,?,?,?,?,?,?)",
                                    (name, "Academic", "Old description", "old@uwi.edu", "876-555-0100", "Mondays 5pm", status, uid(leader))).lastrowid
        conn.commit(); conn.close()
        self.__dict__.update({f"{k}_id": v for k, v in ids.items()})
        self.leader, self.leader2, self.student = (app.test_client() for _ in range(3))
        login(self.leader, "l@t"); login(self.leader2, "l2@t"); login(self.student, "s@t")

    def save(self, club_id=None, client=None, **over):
        c = client or self.leader
        return c.post(f"/clubs/{club_id or self.club_id}/edit", data={**NEW, **over, "csrf_token": token(c)}, follow_redirects=True)

    def assert_unchanged(self):
        r = club_row(self.club_id)
        self.assertEqual((r["description"], r["contact_email"], r["contact_phone"], r["meeting_info"]),
                         ("Old description", "old@uwi.edu", "876-555-0100", "Mondays 5pm"))

    def test_form_is_prefilled_with_current_values(self):
        html = self.leader.get(f"/clubs/{self.club_id}/edit").data.decode()
        for v in ("Old description", "old@uwi.edu", "876-555-0100", "Mondays 5pm"):
            self.assertIn(v, html)

    def test_valid_update_saved_confirmed_and_shown_on_public_page(self):
        self.assertIn(b"Club profile updated", self.save().data)
        page = self.student.get(f"/clubs/{self.club_id}").data.decode()
        for v in ("Fresh description about robots", "new@uwi.edu", "876-555-0199", "Fridays 3pm, Room 5"):
            self.assertIn(v, page)

    def test_updated_description_is_searchable(self):
        self.save(); self.assertIn(b"Chess Club", self.student.get("/clubs?q=robots").data)
        self.assertNotIn(b"Chess Club", self.student.get("/clubs?q=Old+description").data)

    def test_name_and_category_cannot_be_changed(self):
        self.save(name="Hacked Name", category="Sports & Wellness")
        r = club_row(self.club_id); self.assertEqual((r["name"], r["category"]), ("Chess Club", "Academic"))
        self.assertNotIn('name="name"', self.leader.get(f"/clubs/{self.club_id}/edit").data.decode())

    def test_invalid_phone_rejected_and_old_value_kept(self):
        r = self.save(contact_phone="abc")
        self.assertIn(b"valid phone number", r.data); self.assert_unchanged()

    def test_invalid_email_rejected(self):
        self.assertIn(b"valid email", self.save(contact_email="nope").data); self.assert_unchanged()

    def test_description_over_500_rejected_with_count(self):
        r = self.save(description="x" * 501)
        self.assertIn(b"500 characters or fewer (currently 501)", r.data); self.assert_unchanged()
        self.save(description="x" * 500); self.assertEqual(len(club_row(self.club_id)["description"]), 500)

    def test_required_fields(self):
        self.assertIn(b"Description is required", self.save(description="").data)
        self.assertIn(b"Contact email is required", self.save(contact_email="").data); self.assert_unchanged()

    def test_all_or_nothing_when_one_field_invalid(self):
        self.save(contact_phone="abc")  # meeting_info etc. are valid but must NOT be saved
        self.assert_unchanged()

    def test_optional_fields_can_be_cleared(self):
        self.save(contact_phone="", meeting_info="")
        r = club_row(self.club_id); self.assertIsNone(r["contact_phone"]); self.assertIsNone(r["meeting_info"])

    def test_error_page_keeps_what_the_leader_typed(self):
        self.assertIn(b"Fresh description about robots", self.save(contact_phone="abc").data)

    def test_cancel_does_not_change_anything(self):
        r = self.leader.get(f"/clubs/{self.club_id}/edit")
        self.assertIn(b"Cancel", r.data); self.assertIn(f'href="/my-clubs"'.encode(), r.data); self.assert_unchanged()

    def test_only_the_registered_leader_can_edit(self):
        self.assertEqual(self.leader2.get(f"/clubs/{self.club_id}/edit").status_code, 403)
        self.assertEqual(self.save(client=self.leader2).status_code, 403); self.assert_unchanged()
        self.assertEqual(self.student.get(f"/clubs/{self.club_id}/edit").status_code, 403)
        self.assertEqual(app.test_client().get(f"/clubs/{self.club_id}/edit").status_code, 302)
        ok, errs = services.update_club_profile(services.get_user_by_email("l2@t")["id"], self.club_id, NEW)
        self.assertFalse(ok); self.assert_unchanged()

    def test_unapproved_club_cannot_be_edited(self):
        self.assertIn(b"must be approved", self.leader.get(f"/clubs/{self.pending_id}/edit", follow_redirects=True).data)
        self.assertFalse(services.update_club_profile(services.get_user_by_email("l@t")["id"], self.pending_id, NEW)[0])

    def test_csrf_enforced_and_unknown_club_404(self):
        self.assertEqual(self.leader.post(f"/clubs/{self.club_id}/edit", data=NEW).status_code, 400)
        self.assertEqual(self.leader.get("/clubs/99999/edit").status_code, 404)

    def test_my_clubs_links_to_edit_for_approved_only(self):
        html = self.leader.get("/my-clubs").data.decode()
        self.assertIn(f"/clubs/{self.club_id}/edit", html); self.assertNotIn(f"/clubs/{self.pending_id}/edit", html)


if __name__ == "__main__":
    unittest.main()
