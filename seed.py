"""Creates demo accounts (development only)."""
import db
from werkzeug.security import generate_password_hash

db.init_db()
conn = db.get_conn()
for name, email, role in [("Admin User", "admin@uwi.test", "admin"),
                          ("Club Leader", "leader@uwi.test", "leader"),
                          ("Student User", "student@uwi.test", "student")]:
    conn.execute("INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?,?,?,?)",
                 (name, email, generate_password_hash("password123"), role))
conn.commit()
conn.close()
print("Seeded. Log in with admin@/leader@/student@uwi.test, password: password123")

# demo clubs (3 approved + 1 pending) so search has something to find
conn = db.get_conn()
leader = conn.execute("SELECT id FROM users WHERE email = 'leader@uwi.test'").fetchone()["id"]
for name, cat, desc, status in [
    ("Chess Club", "Academic", "Weekly casual and competitive chess for all skill levels.", "Approved"),
    ("Computing Society", "Technology", "Workshops, hackathons and career talks for computing students.", "Approved"),
    ("Astronomy Club", "Science", "Stargazing nights and talks about space science.", "Approved"),
    ("Debate Society", "Academic", "Public speaking and debating practice.", "Pending")]:
    conn.execute("INSERT OR IGNORE INTO clubs (name, category, description, contact_email, status, leader_id) VALUES (?,?,?,?,?,?)",
                 (name, cat, desc, "club@uwi.test", status, leader))
conn.commit()
conn.close()

# demo events (relative to today) for the approved Chess Club
from datetime import date, timedelta
conn = db.get_conn()
chess = conn.execute("SELECT id FROM clubs WHERE name = 'Chess Club'").fetchone()["id"]
if not conn.execute("SELECT 1 FROM events").fetchone():
    for title, days, status in [("Beginner chess night", 3, "Published"), ("Club tournament", 10, "Published"), ("Planning meeting", 5, "Draft")]:
        conn.execute("INSERT INTO events (club_id, title, description, event_date, start_time, end_time, venue, status) VALUES (?,?,?,?,?,?,?,?)",
                     (chess, title, "Everyone is welcome.", (date.today() + timedelta(days=days)).isoformat(), "17:00", "19:00", "FST Library", status))
conn.commit()
conn.close()

# demo membership request: a second student asks to join Chess Club
conn = db.get_conn()
conn.execute("INSERT OR IGNORE INTO users (name, email, password_hash, role) VALUES (?,?,?,?)",
             ("Second Student", "student2@uwi.test", generate_password_hash("password123"), "student"))
s2 = conn.execute("SELECT id FROM users WHERE email = 'student2@uwi.test'").fetchone()["id"]
chess = conn.execute("SELECT id FROM clubs WHERE name = 'Chess Club'").fetchone()["id"]
if not conn.execute("SELECT 1 FROM memberships WHERE student_id = ?", (s2,)).fetchone():
    conn.execute("INSERT INTO memberships (club_id, student_id) VALUES (?, ?)", (chess, s2))
conn.commit()
conn.close()
