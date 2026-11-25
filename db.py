"""Data Layer: connection + schema (users, clubs, notifications)."""
import os
import sqlite3

DB_PATH = os.environ.get("CLUBHUB_DB", os.path.join(os.path.dirname(__file__), "clubhub.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student','leader','admin')),
    totp_secret TEXT,                                  -- encrypted (Fernet); set during 2FA setup
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,         -- last accepted time step (replay protection)
    totp_failures INTEGER NOT NULL DEFAULT 0,
    totp_locked_until TEXT
);
CREATE TABLE IF NOT EXISTS backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    code_hash TEXT NOT NULL,                           -- SHA-256 of a high-entropy code; never stored in clear
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clubs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,          -- duplicate names rejected, not case-sensitive
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    contact_phone TEXT,
    meeting_info TEXT,
    status TEXT NOT NULL DEFAULT 'Pending'
        CHECK (status IN ('Pending','Approved','Rejected','Inactive')),
    rejection_reason TEXT,
    accepting_members INTEGER NOT NULL DEFAULT 1,       -- 0 = closed to new members
    leader_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    club_id INTEGER NOT NULL REFERENCES clubs(id),
    student_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending','Accepted','Declined')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    decided_at TEXT
);
-- a student may have only ONE open (Pending or Accepted) request per club; declined ones don't block a new request
CREATE UNIQUE INDEX IF NOT EXISTS uniq_open_membership ON memberships(club_id, student_id) WHERE status IN ('Pending','Accepted');
CREATE TABLE IF NOT EXISTS login_failures (          -- brute-force protection; rows older than 1 day are purged
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                                -- 'login' or 'reauth' (re-entering the current password)
    email TEXT NOT NULL,
    ip TEXT NOT NULL,
    attempted_at TEXT NOT NULL                         -- YYYY-MM-DD HH:MM:SS, Jamaica time
);
CREATE INDEX IF NOT EXISTS idx_login_failures_email ON login_failures(kind, email, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_failures_ip ON login_failures(kind, ip, attempted_at);
CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    club_id INTEGER NOT NULL REFERENCES clubs(id),
    author_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    posted_at TEXT NOT NULL              -- YYYY-MM-DD HH:MM:SS, Jamaica time
);
CREATE INDEX IF NOT EXISTS idx_announcements_club ON announcements(club_id, posted_at);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    club_id INTEGER NOT NULL REFERENCES clubs(id),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    event_date TEXT NOT NULL,            -- YYYY-MM-DD
    start_time TEXT NOT NULL,            -- HH:MM (24h)
    end_time TEXT,
    venue TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Draft' CHECK (status IN ('Draft','Published')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_status_date ON events(status, event_date);
CREATE INDEX IF NOT EXISTS idx_clubs_status ON clubs(status);
"""


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_conn()
    try:
        conn.executescript(SCHEMA)
        # small migrations for databases created before US-03 / 2FA
        user_cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)")]
        for col, ddl in [("totp_secret", "TEXT"), ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"), ("totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
                         ("totp_failures", "INTEGER NOT NULL DEFAULT 0"), ("totp_locked_until", "TEXT")]:
            if col not in user_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
        if "accepting_members" not in [r["name"] for r in conn.execute("PRAGMA table_info(clubs)")]:
            conn.execute("ALTER TABLE clubs ADD COLUMN accepting_members INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    finally:
        conn.close()
