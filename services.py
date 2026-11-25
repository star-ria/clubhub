"""Application Layer: business rules for US-01 (ClubFunc) and US-08 (SystemFunc).
Every rule is enforced here, so the UI can never bypass it."""
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import closing

import math
import os

from werkzeug.security import check_password_hash, generate_password_hash

import passwords
import security
from db import get_conn

CATEGORIES = ["Academic", "Technology", "Science", "Arts & Culture", "Sports & Wellness", "Community Service", "Other"]
STATUSES = ["Pending", "Approved", "Rejected", "Inactive"]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[0-9+()\-\s]{7,20}$")

# action -> (status the club must be in, status it moves to)
RULES = {"approve": ("Pending", "Approved"), "reject": ("Pending", "Rejected"), "deactivate": ("Approved", "Inactive")}


def get_user(user_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_email(email):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", ((email or "").strip().lower(),)).fetchone()


def notify(conn, user_id, message):
    conn.execute("INSERT INTO notifications (user_id, message) VALUES (?, ?)", (user_id, message))


def list_notifications(user_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()


# ---------------- US-01: Register a new club ----------------
def validate_club_form(form):
    """Return {field: message}. Mandatory: name, category, description, contact email."""
    errors = {}
    name = (form.get("name") or "").strip()
    if not name:
        errors["name"] = "Club name is required."
    elif not 3 <= len(name) <= 60:
        errors["name"] = "Club name must be 3 to 60 characters."

    if (form.get("category") or "") not in CATEGORIES:
        errors["category"] = "Please choose a category."

    description = (form.get("description") or "").strip()
    if not description:
        errors["description"] = "Description is required."
    elif len(description) > 500:
        errors["description"] = f"Description must be 500 characters or fewer (currently {len(description)})."

    email = (form.get("contact_email") or "").strip()
    if not email:
        errors["contact_email"] = "Contact email is required."
    elif not EMAIL_RE.match(email):
        errors["contact_email"] = "Enter a valid email address."

    phone = (form.get("contact_phone") or "").strip()
    if phone and not PHONE_RE.match(phone):
        errors["contact_phone"] = "Enter a valid phone number."

    if len((form.get("meeting_info") or "").strip()) > 200:
        errors["meeting_info"] = "Meeting information must be 200 characters or fewer."
    return errors


def register_club(leader_id, form):
    """Returns (True, club_id) or (False, errors). Saved as 'Pending'; admins are notified."""
    errors = validate_club_form(form)
    if errors:
        return False, errors
    name = form["name"].strip()
    try:
        with closing(get_conn()) as conn, conn:  # one transaction: club + notifications
            user = conn.execute("SELECT role FROM users WHERE id = ?", (leader_id,)).fetchone()
            if not user or user["role"] != "leader":
                return False, {"_form": "Only club representatives can register a club."}
            cur = conn.execute(
                "INSERT INTO clubs (name, category, description, contact_email, contact_phone, meeting_info, leader_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, form["category"], form["description"].strip(), form["contact_email"].strip(),
                 (form.get("contact_phone") or "").strip() or None,
                 (form.get("meeting_info") or "").strip() or None, leader_id))
            for admin in conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchall():
                notify(conn, admin["id"], f'New club registration awaiting review: "{name}".')
            return True, cur.lastrowid
    except sqlite3.IntegrityError:  # UNIQUE (case-insensitive) name
        return False, {"name": "A club with this name already exists."}


def clubs_for_leader(leader_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT clubs.*, (SELECT COUNT(*) FROM memberships m WHERE m.club_id = clubs.id AND m.status = 'Pending') AS pending_requests"
                            " FROM clubs WHERE leader_id = ? ORDER BY created_at DESC, id DESC", (leader_id,)).fetchall()


# ---------------- US-08: Review and manage registered clubs ----------------
def list_clubs(status=None):
    sql = ("SELECT c.*, u.name AS leader_name FROM clubs c JOIN users u ON u.id = c.leader_id")
    params = ()
    if status in STATUSES:
        sql += " WHERE c.status = ?"
        params = (status,)
    sql += " ORDER BY c.created_at DESC, c.id DESC"
    with closing(get_conn()) as conn:
        return conn.execute(sql, params).fetchall()


def change_club_status(club_id, action, expected_status, reason=""):
    """Approve / reject / deactivate. Returns (ok, message). Blocks stale actions."""
    if action not in RULES:
        return False, "Unknown action."
    required, new_status = RULES[action]
    reason = (reason or "").strip()
    if action == "reject":
        if not reason:
            return False, "A reason is required to reject a club."
        if len(reason) > 500:
            return False, "Rejection reason must be 500 characters or fewer."
    with closing(get_conn()) as conn, conn:
        club = conn.execute("SELECT * FROM clubs WHERE id = ?", (club_id,)).fetchone()
        if not club:
            return False, "Club not found."
        if club["status"] != required or club["status"] != expected_status:
            return False, f'Blocked: "{club["name"]}" is now {club["status"]}, so this action no longer applies. Refresh the list.'
        cur = conn.execute("UPDATE clubs SET status = ?, rejection_reason = ? WHERE id = ? AND status = ?",
                           (new_status, reason if action == "reject" else None, club_id, required))
        if cur.rowcount != 1:  # someone else changed it between read and write
            return False, "Blocked: this club was just updated by someone else. Refresh the list."
        messages = {
            "approve": f'Your club "{club["name"]}" was approved and is now visible to students.',
            "reject": f'Your club "{club["name"]}" was rejected. Reason: {reason}',
            "deactivate": f'Your club "{club["name"]}" was deactivated and is hidden from students.',
        }
        notify(conn, club["leader_id"], messages[action])
        return True, {"approve": "Club approved.", "reject": "Club rejected and the reason was sent to the representative.",
                      "deactivate": "Club deactivated (record kept)."}[action]


# ---------------- US-02: Search and discover clubs ----------------
def search_clubs(keyword="", category=""):
    """Approved clubs only. Keyword matches name or description (not case-sensitive);
    category is an optional filter. Empty search lists every approved club."""
    keyword = (keyword or "").strip()[:100]
    sql = "SELECT id, name, category, description FROM clubs WHERE status = 'Approved'"
    params = []
    if keyword:
        escaped = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")  # treat %/_ literally
        sql += " AND (name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')"
        params += [f"%{escaped}%", f"%{escaped}%"]
    if category in CATEGORIES:
        sql += " AND category = ?"
        params.append(category)
    sql += " ORDER BY name COLLATE NOCASE"
    with closing(get_conn()) as conn:
        return conn.execute(sql, params).fetchall()


def get_approved_club(club_id):
    """A club's public page exists only while the club is Approved."""
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM clubs WHERE id = ? AND status = 'Approved'", (club_id,)).fetchone()


# ---------------- US-04 / US-06: Events ----------------
try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("America/Jamaica")
except Exception:  # tzdata missing: Jamaica is UTC-5 all year
    TZ = timezone(timedelta(hours=-5))


def now():
    """Current local (Jamaica) time, naive. Tests patch this."""
    return datetime.now(TZ).replace(tzinfo=None)


def _parse(value, fmt):
    try:
        return datetime.strptime((value or "").strip(), fmt)
    except ValueError:
        return None


def get_club(club_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM clubs WHERE id = ?", (club_id,)).fetchone()


def validate_event_form(form):
    """Returns (errors, clean). Same rules for drafts and published events."""
    errors = {}
    title = (form.get("title") or "").strip()
    if not title:
        errors["title"] = "Title is required."
    elif not 3 <= len(title) <= 100:
        errors["title"] = "Title must be 3 to 100 characters."
    description = (form.get("description") or "").strip()
    if not description:
        errors["description"] = "Description is required."
    elif len(description) > 1000:
        errors["description"] = f"Description must be 1,000 characters or fewer (currently {len(description)})."
    venue = (form.get("venue") or "").strip()
    if not venue:
        errors["venue"] = "Venue is required."
    elif len(venue) > 100:
        errors["venue"] = "Venue must be 100 characters or fewer."

    date_raw, start_raw, end_raw = ((form.get(k) or "").strip() for k in ("event_date", "start_time", "end_time"))
    d, t, e = _parse(date_raw, "%Y-%m-%d"), _parse(start_raw, "%H:%M"), _parse(end_raw, "%H:%M")
    if not date_raw:
        errors["event_date"] = "Event date is required."
    elif d is None:
        errors["event_date"] = "Enter a valid date."
    if not start_raw:
        errors["start_time"] = "Start time is required."
    elif t is None:
        errors["start_time"] = "Enter a valid start time."
    if d and t:
        if d.date() < now().date():
            errors["event_date"] = "The event date can't be in the past."
        elif datetime.combine(d.date(), t.time()) <= now():
            errors["start_time"] = "That start time has already passed today."
    if end_raw:
        if e is None:
            errors["end_time"] = "Enter a valid end time."
        elif t and e.time() <= t.time():
            errors["end_time"] = "End time must be after the start time."
    clean = {"title": title, "description": description, "venue": venue,
             "event_date": d.strftime("%Y-%m-%d") if d else None,
             "start_time": t.strftime("%H:%M") if t else None,
             "end_time": e.strftime("%H:%M") if e else None}
    return errors, clean


def create_event(leader_id, club_id, form, publish):
    """Returns (True, event_id) or (False, errors). Leaders can only add events to their own approved club."""
    errors, clean = validate_event_form(form)
    with closing(get_conn()) as conn, conn:
        club = conn.execute("SELECT * FROM clubs WHERE id = ?", (club_id,)).fetchone()
        if not club or club["leader_id"] != leader_id:
            return False, {"_form": "You can only create events for your own club."}
        if club["status"] != "Approved":
            return False, {"_form": "Your club must be approved before you can create events."}
        if errors:
            return False, errors
        cur = conn.execute(
            "INSERT INTO events (club_id, title, description, event_date, start_time, end_time, venue, status)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (club_id, clean["title"], clean["description"], clean["event_date"], clean["start_time"],
             clean["end_time"], clean["venue"], "Published" if publish else "Draft"))
        return True, cur.lastrowid


def publish_draft(leader_id, club_id, event_id):
    """Publish an existing draft (start time must still be in the future). Returns (ok, message)."""
    with closing(get_conn()) as conn, conn:
        row = conn.execute("SELECT e.*, c.leader_id, c.status AS club_status FROM events e JOIN clubs c ON c.id = e.club_id"
                           " WHERE e.id = ? AND e.club_id = ?", (event_id, club_id)).fetchone()
        if not row or row["leader_id"] != leader_id:
            return False, "Event not found."
        if row["club_status"] != "Approved":
            return False, "Your club must be approved before you can publish events."
        if row["status"] == "Published":
            return False, "This event is already published."
        if datetime.strptime(f'{row["event_date"]} {row["start_time"]}', "%Y-%m-%d %H:%M") <= now():
            return False, "This event's start time has passed, so it can't be published. Create a new event instead."
        conn.execute("UPDATE events SET status = 'Published' WHERE id = ? AND status = 'Draft'", (event_id,))
        return True, "Event published."


def list_club_events(club_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM events WHERE club_id = ? ORDER BY event_date, start_time", (club_id,)).fetchall()


def upcoming_events(club_id=None, date_from=None, date_to=None):
    """Published, future, approved-club events only; soonest first."""
    sql = ("SELECT e.*, c.name AS club_name FROM events e JOIN clubs c ON c.id = e.club_id"
           " WHERE e.status = 'Published' AND c.status = 'Approved' AND (e.event_date || ' ' || e.start_time) > ?")
    params = [now().strftime("%Y-%m-%d %H:%M")]
    if club_id:
        sql += " AND e.club_id = ?"; params.append(club_id)
    if date_from:
        sql += " AND e.event_date >= ?"; params.append(date_from)
    if date_to:
        sql += " AND e.event_date <= ?"; params.append(date_to)
    sql += " ORDER BY e.event_date, e.start_time"
    with closing(get_conn()) as conn:
        return conn.execute(sql, params).fetchall()


def approved_clubs():
    with closing(get_conn()) as conn:
        return conn.execute("SELECT id, name FROM clubs WHERE status = 'Approved' ORDER BY name COLLATE NOCASE").fetchall()


def get_published_event(event_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT e.*, c.name AS club_name FROM events e JOIN clubs c ON c.id = e.club_id"
                            " WHERE e.id = ? AND e.status = 'Published' AND c.status = 'Approved'", (event_id,)).fetchone()


# ---------------- US-03 (+ UC-05): Join a club ----------------
def membership_state(student_id, club_id):
    """The student's latest request status for a club: Pending / Accepted / Declined / None."""
    with closing(get_conn()) as conn:
        row = conn.execute("SELECT status FROM memberships WHERE student_id = ? AND club_id = ? ORDER BY id DESC LIMIT 1",
                           (student_id, club_id)).fetchone()
        return row["status"] if row else None


def is_active_member(student_id, club_id):
    """Used by US-05: only accepted members may see a club's announcements."""
    return membership_state(student_id, club_id) == "Accepted"


def request_to_join(student_id, club_id):
    """Returns (ok, message). One open request per club; approved + open clubs only."""
    with closing(get_conn()) as conn, conn:
        student = conn.execute("SELECT name, role FROM users WHERE id = ?", (student_id,)).fetchone()
        if not student or student["role"] != "student":
            return False, "Only students can request to join a club."
        club = conn.execute("SELECT * FROM clubs WHERE id = ? AND status = 'Approved'", (club_id,)).fetchone()
        if not club:
            return False, "This club isn't available."
        if not club["accepting_members"]:
            return False, "This club is not accepting new members right now."
        open_req = conn.execute("SELECT status FROM memberships WHERE club_id = ? AND student_id = ? AND status IN ('Pending','Accepted')",
                                (club_id, student_id)).fetchone()
        if open_req:
            return False, ("You are already a member of this club." if open_req["status"] == "Accepted"
                           else "You already have a pending request for this club.")
        try:
            conn.execute("INSERT INTO memberships (club_id, student_id) VALUES (?, ?)", (club_id, student_id))
        except sqlite3.IntegrityError:  # two clicks at once: the unique index wins
            return False, "You already have a pending request for this club."
        notify(conn, club["leader_id"], f'{student["name"]} requested to join "{club["name"]}".')
        return True, f'Request sent to {club["name"]}. The club leader will review it.'


def list_requests(club_id, status="Pending"):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT m.*, u.name AS student_name, u.email AS student_email FROM memberships m"
                            " JOIN users u ON u.id = m.student_id WHERE m.club_id = ? AND m.status = ? ORDER BY m.id",
                            (club_id, status)).fetchall()


def decide_request(leader_id, club_id, membership_id, decision, expected_status):
    """Leader accepts or declines a pending request. Returns (ok, message). Blocks stale decisions."""
    if decision not in ("accept", "decline"):
        return False, "Unknown action."
    new_status = "Accepted" if decision == "accept" else "Declined"
    with closing(get_conn()) as conn, conn:
        club = conn.execute("SELECT * FROM clubs WHERE id = ?", (club_id,)).fetchone()
        if not club or club["leader_id"] != leader_id:
            return False, "You can only manage requests for your own club."
        if club["status"] != "Approved":
            return False, "Your club must be approved to manage membership requests."
        req = conn.execute("SELECT * FROM memberships WHERE id = ? AND club_id = ?", (membership_id, club_id)).fetchone()
        if not req:
            return False, "Request not found."
        if req["status"] != "Pending" or expected_status != "Pending":
            return False, f"Blocked: this request is already {req['status']}. Refresh the list."
        cur = conn.execute("UPDATE memberships SET status = ?, decided_at = datetime('now') WHERE id = ? AND status = 'Pending'",
                           (new_status, membership_id))
        if cur.rowcount != 1:
            return False, "Blocked: this request was just updated. Refresh the list."
        notify(conn, req["student_id"], f'Your request to join "{club["name"]}" was {new_status.lower()}.')
        return True, "Request accepted. The student is now a member." if decision == "accept" else "Request declined."


def set_accepting_members(leader_id, club_id, accepting):
    with closing(get_conn()) as conn, conn:
        club = conn.execute("SELECT leader_id FROM clubs WHERE id = ?", (club_id,)).fetchone()
        if not club or club["leader_id"] != leader_id:
            return False
        conn.execute("UPDATE clubs SET accepting_members = ? WHERE id = ?", (1 if accepting else 0, club_id))
        return True


def student_memberships(student_id):
    with closing(get_conn()) as conn:
        return conn.execute("SELECT m.*, c.name AS club_name, c.category, c.status AS club_status FROM memberships m"
                            " JOIN clubs c ON c.id = m.club_id WHERE m.student_id = ? ORDER BY m.id DESC", (student_id,)).fetchall()


# ---------------- US-07: Update club profile and contact details ----------------
PROFILE_FIELDS = ("description", "contact_email", "contact_phone", "meeting_info")


def update_club_profile(leader_id, club_id, form):
    """Leader edits description, contact email/phone and meeting info of their own APPROVED club.
    The name (and category) can't change here. All-or-nothing: on any error the saved values stay as they were.
    Returns (True, None) or (False, errors)."""
    with closing(get_conn()) as conn, conn:
        club = conn.execute("SELECT * FROM clubs WHERE id = ?", (club_id,)).fetchone()
        if not club or club["leader_id"] != leader_id:
            return False, {"_form": "Only the registered leader of this club can edit its profile."}
        if club["status"] != "Approved":
            return False, {"_form": "Your club must be approved before you can edit its profile."}
        # reuse the registration rules, pinning the fields that are not editable
        errors = validate_club_form({**form, "name": club["name"], "category": club["category"]})
        errors = {f: m for f, m in errors.items() if f in PROFILE_FIELDS}
        if errors:
            return False, errors
        conn.execute("UPDATE clubs SET description = ?, contact_email = ?, contact_phone = ?, meeting_info = ? WHERE id = ?",
                     (form["description"].strip(), form["contact_email"].strip(),
                      (form.get("contact_phone") or "").strip() or None,
                      (form.get("meeting_info") or "").strip() or None, club_id))
        return True, None


# ---------------- US-05: Post club announcements ----------------
def validate_announcement_form(form):
    errors = {}
    title = (form.get("title") or "").strip()
    message = (form.get("message") or "").strip()
    if not title:
        errors["title"] = "Title is required."
    elif len(title) > 80:
        errors["title"] = f"Title must be 80 characters or fewer (currently {len(title)})."
    if not message:
        errors["message"] = "Message is required."
    elif len(message) > 1000:
        errors["message"] = f"Message must be 1,000 characters or fewer (currently {len(message)})."
    return errors, title, message


def post_announcement(leader_id, club_id, form):
    """Only the leader of an APPROVED club may post. Members (accepted requests) are notified.
    Returns (True, announcement_id) or (False, errors)."""
    errors, title, message = validate_announcement_form(form)
    with closing(get_conn()) as conn, conn:
        club = conn.execute("SELECT * FROM clubs WHERE id = ?", (club_id,)).fetchone()
        if not club or club["leader_id"] != leader_id:
            return False, {"_form": "Only the leader of this club can post announcements."}
        if club["status"] != "Approved":
            return False, {"_form": "Your club must be approved before you can post announcements."}
        if errors:
            return False, errors
        cur = conn.execute("INSERT INTO announcements (club_id, author_id, title, message, posted_at) VALUES (?, ?, ?, ?, ?)",
                           (club_id, leader_id, title, message, now().strftime("%Y-%m-%d %H:%M:%S")))
        for m in conn.execute("SELECT student_id FROM memberships WHERE club_id = ? AND status = 'Accepted'", (club_id,)).fetchall():
            notify(conn, m["student_id"], f'New announcement from "{club["name"]}": {title}')
        return True, cur.lastrowid


def list_announcements(club_id):
    """Newest first."""
    with closing(get_conn()) as conn:
        return conn.execute("SELECT * FROM announcements WHERE club_id = ? ORDER BY posted_at DESC, id DESC", (club_id,)).fetchall()


# ---------------- Two-factor authentication (TOTP) ----------------
MAX_2FA_FAILURES, LOCK_MINUTES = 5, 5


def start_2fa_setup(user_id):
    """Creates a fresh secret (stored encrypted, not yet active). Returns (ok, message)."""
    with closing(get_conn()) as conn, conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return False, "User not found."
        if user["totp_enabled"]:
            return False, "Two-factor authentication is already on."
        conn.execute("UPDATE users SET totp_secret = ?, totp_last_step = 0 WHERE id = ?", (security.encrypt(security.generate_secret()), user_id))
        return True, "Scan or enter the key in your authenticator app, then confirm with a code."


def pending_2fa_setup(user_id):
    """(secret, otpauth_uri) while setup is in progress, else None."""
    user = get_user(user_id)
    if not user or user["totp_enabled"] or not user["totp_secret"]:
        return None
    secret = security.decrypt(user["totp_secret"])
    return secret, security.provisioning_uri(secret, user["email"])


def confirm_2fa_setup(user_id, code):
    """Turns 2FA on once the user proves their app works. Returns (True, backup_codes) or (False, message)."""
    code = (code or "").strip().replace(" ", "")
    with closing(get_conn()) as conn, conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["totp_enabled"] or not user["totp_secret"]:
            return False, "Start the setup first."
        step = security.verify_totp(security.decrypt(user["totp_secret"]), code, user["totp_last_step"])
        if step is None:
            return False, "That code isn't right. Check the time on your phone and try again."
        codes = security.generate_backup_codes()
        conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
        conn.executemany("INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)", [(user_id, security.hash_backup_code(c)) for c in codes])
        conn.execute("UPDATE users SET totp_enabled = 1, totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL WHERE id = ?", (step, user_id))
        return True, codes


def verify_second_factor(user_id, code):
    """Checks an authenticator code or a single-use backup code. 5 wrong tries lock the account for 5 minutes.
    Returns (ok, message)."""
    code = (code or "").strip().replace(" ", "")
    stamp = now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_conn()) as conn, conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or not user["totp_enabled"]:
            return False, "Two-factor authentication is not turned on for this account."
        if user["totp_locked_until"] and user["totp_locked_until"] > stamp:
            return False, "Too many incorrect codes. Please wait a few minutes and try again."
        step = security.verify_totp(security.decrypt(user["totp_secret"]), code, user["totp_last_step"])
        if step is not None:
            conn.execute("UPDATE users SET totp_last_step = ?, totp_failures = 0, totp_locked_until = NULL WHERE id = ?", (step, user_id))
            return True, "ok"
        backup = conn.execute("SELECT id FROM backup_codes WHERE user_id = ? AND code_hash = ? AND used = 0",
                              (user_id, security.hash_backup_code(code))).fetchone() if code else None
        if backup:
            conn.execute("UPDATE backup_codes SET used = 1 WHERE id = ?", (backup["id"],))
            conn.execute("UPDATE users SET totp_failures = 0, totp_locked_until = NULL WHERE id = ?", (user_id,))
            return True, "ok"
        failures = user["totp_failures"] + 1
        if failures >= MAX_2FA_FAILURES:
            until = (now() + timedelta(minutes=LOCK_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute("UPDATE users SET totp_failures = 0, totp_locked_until = ? WHERE id = ?", (until, user_id))
            return False, f"Too many incorrect codes. Sign-in is locked for {LOCK_MINUTES} minutes."
        conn.execute("UPDATE users SET totp_failures = ? WHERE id = ?", (failures, user_id))
        return False, "That code isn't right."


def disable_2fa(user_id, password, code, ip=""):
    """Needs BOTH the password and a valid code. Returns (ok, message)."""
    user = get_user(user_id)
    if not user or not user["totp_enabled"]:
        return False, "Two-factor authentication is not on."
    wait = throttle_wait("reauth", user["email"], ip)
    if wait:
        return False, throttle_message(wait)
    if not check_password_hash(user["password_hash"], password or ""):
        record_failure("reauth", user["email"], ip)
        return False, "Incorrect password."
    clear_failures("reauth", user["email"], ip)
    ok, msg = verify_second_factor(user_id, code)
    if not ok:
        return False, msg
    with closing(get_conn()) as conn, conn:
        conn.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = 0, totp_failures = 0, totp_locked_until = NULL WHERE id = ?", (user_id,))
        conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    return True, "Two-factor authentication turned off."


# ---------------- Accounts: sign up + change password ----------------
SELF_SERVICE_ROLES = ("student", "leader")  # administrator accounts are never self-registered


def allowed_email_domains():
    """Optional: set ALLOWED_EMAIL_DOMAINS="mymona.uwi.edu,uwimona.edu.jm" to restrict sign-up to university addresses."""
    return [d.strip().lower() for d in os.environ.get("ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()]


def create_user(form):
    """Returns (True, user_id) or (False, {field: message})."""
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip().lower()
    role, password, confirm = form.get("role"), form.get("password") or "", form.get("confirm") or ""
    errors = {}
    if not 2 <= len(name) <= 60:
        errors["name"] = "Enter your name (2 to 60 characters)."
    if not email:
        errors["email"] = "Email is required."
    elif not EMAIL_RE.match(email) or len(email) > 120:
        errors["email"] = "Enter a valid email address."
    elif allowed_email_domains() and email.rsplit("@", 1)[1] not in allowed_email_domains():
        errors["email"] = "Please use your university email (" + ", ".join("@" + d for d in allowed_email_domains()) + ")."
    if role not in SELF_SERVICE_ROLES:
        errors["role"] = "Choose whether you are a student or a club representative."
    result = passwords.check_password(password, email, name)
    if not result["ok"]:
        errors["password"] = " ".join(result["errors"])
    if password != confirm:
        errors["confirm"] = "The passwords don't match."
    if errors:
        return False, errors
    try:
        with closing(get_conn()) as conn, conn:
            cur = conn.execute("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
                               (name, email, generate_password_hash(password), role))
            return True, cur.lastrowid
    except sqlite3.IntegrityError:
        return False, {"email": "An account with this email already exists."}


def change_password(user_id, current, new, confirm, ip=""):
    """Returns (True, None) or (False, {field: message}). Requires the current password."""
    user = get_user(user_id)
    if not user:
        return False, {"_form": "User not found."}
    wait = throttle_wait("reauth", user["email"], ip)
    if wait:
        return False, {"current": throttle_message(wait)}
    errors = {}
    if not check_password_hash(user["password_hash"], current or ""):
        record_failure("reauth", user["email"], ip)
        errors["current"] = "Your current password is incorrect."
    else:
        clear_failures("reauth", user["email"], ip)
    result = passwords.check_password(new, user["email"], user["name"])
    if not result["ok"]:
        errors["new"] = " ".join(result["errors"])
    elif new == current:
        errors["new"] = "Choose a password that is different from your current one."
    if new != confirm:
        errors["confirm"] = "The passwords don't match."
    if errors:
        return False, errors
    with closing(get_conn()) as conn, conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), user_id))
        notify(conn, user_id, "Your password was changed. If this wasn't you, contact an administrator right away.")
    return True, None


# ---------------- Rate limiting (brute-force protection) ----------------
THROTTLE_WINDOW_MIN = 15
# (SQL filter, max failures in the window): same email from the same IP / everything from one IP / everything against one account
THROTTLE_LIMITS = (("email = ? AND ip = ?", 5), ("ip = ?", 20), ("email = ?", 15))
_TS = "%Y-%m-%d %H:%M:%S"


def _norm_email(email):
    return (email or "").strip().lower()[:120]


def _norm_ip(ip):
    return (ip or "unknown")[:64]


def throttle_wait(kind, email, ip):
    """Seconds the caller must wait before another attempt (0 = allowed). Sliding 15-minute window.
    Unknown emails are counted exactly like real ones, so this never reveals which accounts exist."""
    email, ip = _norm_email(email), _norm_ip(ip)
    window, current = timedelta(minutes=THROTTLE_WINDOW_MIN), now()
    since, wait = (current - window).strftime(_TS), 0
    with closing(get_conn()) as conn:
        for (where, limit), params in zip(THROTTLE_LIMITS, ((email, ip), (ip,), (email,))):
            rows = conn.execute(f"SELECT attempted_at FROM login_failures WHERE kind = ? AND {where} AND attempted_at > ?"
                                " ORDER BY attempted_at DESC, id DESC LIMIT ?", (kind, *params, since, limit)).fetchall()
            if len(rows) >= limit:  # locked until the limit-th most recent failure leaves the window
                unlock = datetime.strptime(rows[-1]["attempted_at"], _TS) + window
                wait = max(wait, math.ceil((unlock - current).total_seconds()), 1)
    return wait


def throttle_message(wait):
    minutes = max(1, math.ceil(wait / 60))
    return f"Too many attempts. Please wait {minutes} minute{'s' if minutes != 1 else ''} and try again."


def record_failure(kind, email, ip):
    current = now()
    with closing(get_conn()) as conn, conn:
        conn.execute("INSERT INTO login_failures (kind, email, ip, attempted_at) VALUES (?, ?, ?, ?)",
                     (kind, _norm_email(email), _norm_ip(ip), current.strftime(_TS)))
        conn.execute("DELETE FROM login_failures WHERE attempted_at < ?", ((current - timedelta(days=1)).strftime(_TS),))


def clear_failures(kind, email, ip):
    """After a correct password: forget this email+IP's earlier mistakes."""
    with closing(get_conn()) as conn, conn:
        conn.execute("DELETE FROM login_failures WHERE kind = ? AND email = ? AND ip = ?", (kind, _norm_email(email), _norm_ip(ip)))
