import hashlib
import hmac
import re
import sqlite3
import json
import os
from datetime import datetime, timezone

DATABASE_NAME = os.environ.get("GRIZZONE_DB_PATH", "grizzone.db")

def _connect():
    connection = sqlite3.connect(DATABASE_NAME, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection

def _hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return salt.hex() + "$" + digest.hex()

def _verify_password(password, stored):
    try:
        salt_hex, expected = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 310000).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def create_database():
    with _connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            report_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        # Migrate legacy scan table safely, preserving old scans without assigning them to a user.
        columns = [row["name"] for row in con.execute("PRAGMA table_info(scans)").fetchall()]
        if "user_id" not in columns:
            con.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
        if "report_json" not in columns:
            con.execute("ALTER TABLE scans ADD COLUMN report_json TEXT NOT NULL DEFAULT '{}'")

def register_user(email, password):
    email = (email or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return False, "Enter a valid email address."
    if len(password or "") < 10:
        return False, "Password must be at least 10 characters."
    try:
        with _connect() as con:
            con.execute("INSERT INTO users(email,password_hash,created_at) VALUES(?,?,?)",
                        (email, _hash_password(password), datetime.now(timezone.utc).isoformat()))
        return True, "Account created."
    except sqlite3.IntegrityError:
        return False, "An account with that email already exists."

def authenticate_user(email, password):
    email = (email or "").strip().lower()
    with _connect() as con:
        row = con.execute("SELECT id,email,password_hash FROM users WHERE email=?", (email,)).fetchone()
    if not row or not _verify_password(password or "", row["password_hash"]):
        return None
    return {"id": row["id"], "email": row["email"]}

def save_scan(user_id, scan):
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect() as con:
        con.execute("""INSERT INTO scans(user_id,url,score,risk,scanned_at,report_json)
            VALUES(?,?,?,?,?,?)""",
            (user_id, scan["url"], int(scan["score"]), scan["risk"], scanned_at,
             json.dumps(scan, ensure_ascii=False, default=str)))

def get_scans(user_id):
    with _connect() as con:
        rows = con.execute("""SELECT scanned_at,url,score,risk FROM scans
            WHERE user_id=? ORDER BY id DESC LIMIT 200""", (user_id,)).fetchall()
    return [(r["scanned_at"], r["url"], r["score"], r["risk"]) for r in rows]
