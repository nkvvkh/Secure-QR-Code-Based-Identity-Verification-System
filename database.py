"""
database.py - SQLite storage. Every query is parameterized (uses ? placeholders),
so user input is never pasted into SQL text (prevents SQL injection).

Run `python database.py` to create the tables and the demo admin account.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timezone

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    department  TEXT NOT NULL,
    expiry_date TEXT NOT NULL,                 -- YYYY-MM-DD
    token_hash  TEXT NOT NULL UNIQUE,          -- SHA-256 of the QR token
    status      TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE TABLE IF NOT EXISTS verification_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_pk    INTEGER REFERENCES users(id),   -- NULL when the QR matched nobody
    result     TEXT NOT NULL,                  -- VALID / INVALID / EXPIRED / REVOKED
    reason     TEXT NOT NULL,
    ip_address TEXT,
    created_at TEXT NOT NULL
);
"""


def get_db_path():
    return os.environ.get("DATABASE_PATH") or os.path.join(BASE_DIR, "identity.db")


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def connect():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def effective_status(user):
    """ACTIVE, EXPIRED or REVOKED. Revoked always wins over expired."""
    if user["status"] == "REVOKED":
        return "REVOKED"
    if user["expiry_date"] < date.today().isoformat():
        return "EXPIRED"
    return "ACTIVE"


def _with_status(row):
    if row is None:
        return None
    data = dict(row)
    data["effective_status"] = effective_status(data)
    return data


# ------------------------------------------------------------------- setup
def init_db():
    """Create tables (safe to run many times) and the demo admin if configured."""
    with connect() as conn:
        conn.executescript(SCHEMA)
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")
    if username and password:
        create_admin_if_missing(username, password)


def create_admin_if_missing(username, password):
    with connect() as conn:
        exists = conn.execute("SELECT 1 FROM admins WHERE username = ?", (username,)).fetchone()
        if exists:
            return False
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), now_utc()),
        )
        return True


def get_admin_by_username(username):
    with connect() as conn:
        row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


# ------------------------------------------------------------------- users
def create_user(user_id, name, department, expiry_date, token_hash):
    """Insert a user. Raises sqlite3.IntegrityError if the user ID already exists."""
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (user_id, name, department, expiry_date, token_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, name, department, expiry_date, token_hash, now_utc()),
        )
        return cur.lastrowid


def get_user(pk):
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (pk,)).fetchone()
    return _with_status(row)


def get_user_by_token_hash(token_hash):
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE token_hash = ?", (token_hash,)).fetchone()
    return _with_status(row)


def list_users():
    with connect() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return [_with_status(r) for r in rows]


def update_token_hash(pk, token_hash):
    """Replace the QR token of a user (the old QR code stops working)."""
    with connect() as conn:
        conn.execute("UPDATE users SET token_hash = ? WHERE id = ?", (token_hash, pk))


def revoke_user(pk):
    with connect() as conn:
        cur = conn.execute(
            "UPDATE users SET status = 'REVOKED', revoked_at = ? WHERE id = ? AND status = 'ACTIVE'",
            (now_utc(), pk),
        )
        return cur.rowcount == 1


# -------------------------------------------------------------------- logs
def log_verification(user_pk, result, reason, ip_address):
    with connect() as conn:
        conn.execute(
            "INSERT INTO verification_logs (user_pk, result, reason, ip_address, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_pk, result, reason, ip_address, now_utc()),
        )


def list_logs(result_filter=None, limit=200):
    sql = (
        "SELECT l.*, u.name AS user_name, u.user_id AS user_code "
        "FROM verification_logs l LEFT JOIN users u ON u.id = l.user_pk "
    )
    params = []
    if result_filter:
        sql += "WHERE l.result = ? "
        params.append(result_filter)
    sql += "ORDER BY l.id DESC LIMIT ?"
    params.append(limit)
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def count_logs():
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM verification_logs").fetchone()[0]


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()
    init_db()
    print(f"Database ready at: {get_db_path()}")
    if os.environ.get("ADMIN_USERNAME"):
        print(f"Admin account '{os.environ['ADMIN_USERNAME']}' exists (created if it was missing).")
