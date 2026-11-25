"""Automated UI checks: every key page, for every role, must meet basic structure + accessibility rules."""
import os, sys, tempfile, unittest
from html.parser import HTMLParser
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("CLUBHUB_DB", os.path.join(tempfile.mkdtemp(), "test.db"))
import db  # noqa: E402
from app import app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402


class Scan(HTMLParser):
    def __init__(self):
        super().__init__(); self.lang = None; self.h1 = 0; self.title = ""; self._in_title = False; self.ids = []; self.label_for = set()
        self.controls = []; self.viewport = False; self.main_id = False; self.skip = False; self.imgs_no_alt = 0; self.post_forms = []; self._form = None

    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "html": self.lang = a.get("lang")
        if tag == "h1": self.h1 += 1
        if tag == "title": self._in_title = True
        if a.get("id"): self.ids.append(a["id"])
        if tag == "label" and a.get("for"): self.label_for.add(a["for"])
        if tag == "meta" and a.get("name") == "viewport": self.viewport = True
        if tag == "main" and a.get("id") == "main": self.main_id = True
        if tag == "a" and a.get("href") == "#main": self.skip = True
        if tag == "img" and "alt" not in a: self.imgs_no_alt += 1
        if tag in ("input", "select", "textarea") and a.get("type") not in ("hidden", "submit", "button"):
            self.controls.append((tag, a.get("id"), a.get("aria-label")))
        if tag == "form":
            self._form = {"post": (a.get("method") or "get").lower() == "post", "csrf": False}; self.post_forms.append(self._form)
        if tag == "input" and a.get("name") == "csrf_token" and self._form is not None: self._form["csrf"] = True

    def handle_endtag(self, tag):
        if tag == "title": self._in_title = False
        if tag == "form": self._form = None

    def handle_data(self, d):
        if self._in_title: self.title += d


def rows(q, *p):
    conn = db.get_conn(); r = conn.execute(q, p).fetchall(); conn.close(); return r


def login(c, email):
    c.get("/login")
    with c.session_transaction() as s:
        t = s["csrf"]
    assert c.post("/login", data={"email": email, "password": "pw", "csrf_token": t}).status_code == 302


class UiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db(); conn = db.get_conn()
        for n, e, r in [("Ad", "a@t", "admin"), ("Le", "l@t", "leader"), ("St", "s@t", "student")]:
            conn.execute("INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)", (n, e, generate_password_hash("pw"), r))
        for t in ("announcements", "memberships", "events", "clubs"):
            conn.execute(f"DELETE FROM {t}")
        lid = conn.execute("SELECT id FROM users WHERE email='l@t'").fetchone()["id"]; sid = conn.execute("SELECT id FROM users WHERE email='s@t'").fetchone()["id"]
        cid = conn.execute("INSERT INTO clubs (name,category,description,contact_email,status,leader_id) VALUES ('UI Club','Academic','d','c@uwi.edu','Approved',?)", (lid,)).lastrowid
        conn.execute("INSERT INTO clubs (name,category,description,contact_email,status,leader_id) VALUES ('Waiting Club','Academic','d','c@uwi.edu','Pending',?)", (lid,))
        conn.execute("INSERT INTO events (club_id,title,description,event_date,start_time,venue,status) VALUES (?,?,?,?,?,?,?)", (cid, "Future Ev", "d", "2099-01-01", "10:00", "Hall", "Published"))
        conn.execute("INSERT INTO events (club_id,title,description,event_date,start_time,venue,status) VALUES (?,?,?,?,?,?,?)", (cid, "Draft Ev", "d", "2099-01-02", "10:00", "Hall", "Draft"))
        conn.execute("INSERT INTO memberships (club_id, student_id, status) VALUES (?,?, 'Accepted')", (cid, sid))
        conn.execute("INSERT INTO announcements (club_id, author_id, title, message, posted_at) VALUES (?,?,?,?,?)", (cid, lid, "Hi", "msg", "2026-11-24 10:00:00"))
        conn.commit(); conn.close(); cls.cid = cid
        cls.pages = {
            None: ["/login", "/signup"],
            "s@t": ["/clubs", f"/clubs/{cid}", "/clubs?q=zzzz", "/events", "/events?from=2098-01-01", "/my-memberships", "/notifications", "/account/password", f"/clubs/{cid}/announcements"],
            "l@t": ["/my-clubs", "/clubs/register", f"/clubs/{cid}/events", f"/clubs/{cid}/events/new", f"/clubs/{cid}/requests", f"/clubs/{cid}/announcements/new", f"/clubs/{cid}/edit", "/security", "/notifications"],
            "a@t": ["/admin/clubs", "/admin/clubs?status=Rejected", "/security", "/account/password"]}

    def scan(self, client, url):
        r = client.get(url); self.assertEqual(r.status_code, 200, url)
        s = Scan(); s.feed(r.data.decode()); return s

    def test_every_page_meets_basic_structure_and_accessibility_rules(self):
        for who, urls in self.pages.items():
            c = app.test_client()
            if who: login(c, who)
            for url in urls:
                s = self.scan(c, url); tag = f"{who} {url}"
                self.assertEqual(s.lang, "en", tag); self.assertTrue(s.title.strip(), tag)
                self.assertEqual(s.h1, 1, f"{tag}: expected exactly one h1")
                self.assertTrue(s.viewport and s.main_id and s.skip, f"{tag}: viewport / main#main / skip link")
                self.assertEqual(len(s.ids), len(set(s.ids)), f"{tag}: duplicate ids")
                for tagname, cid_, aria in s.controls:
                    self.assertTrue(aria or (cid_ and cid_ in s.label_for), f"{tag}: unlabeled <{tagname} id={cid_}>")
                self.assertEqual(s.imgs_no_alt, 0, tag)
                for f in s.post_forms:
                    if f["post"]: self.assertTrue(f["csrf"], f"{tag}: POST form without csrf token")

    def test_current_page_is_marked_in_navigation(self):
        c = app.test_client(); login(c, "s@t")
        self.assertIn('href="/clubs" aria-current="page"', c.get("/clubs").data.decode())
        self.assertNotIn('href="/events" aria-current="page"', c.get("/clubs").data.decode())

    def test_error_pages_are_friendly_and_keep_status_codes(self):
        c = app.test_client(); login(c, "s@t")
        for url, code, text in [("/clubs/99999", 404, "Page not found"), ("/my-clubs", 403, "don&#39;t have access")]:
            r = c.get(url); self.assertEqual(r.status_code, code); self.assertIn(text, r.data.decode())
        r = c.post("/account/password", data={"current": "x"}); self.assertEqual(r.status_code, 400); self.assertIn("session may have expired", r.data.decode())

    def test_tables_have_labels_for_phone_layout(self):
        c = app.test_client(); login(c, "a@t"); html = c.get("/admin/clubs").data.decode()
        self.assertIn('class="stack"', html); self.assertIn('data-label="Actions"', html)

    def test_dark_mode_and_focus_styles_present(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "style.css")) as fh:
            css = fh.read()
        for needle in ("prefers-color-scheme:dark", ":focus-visible", "prefers-reduced-motion", "max-width:640px"):
            self.assertIn(needle, css)


if __name__ == "__main__":
    unittest.main()
