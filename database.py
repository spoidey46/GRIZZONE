import sqlite3
from datetime import datetime


DATABASE_NAME = "grizzone.db"


def create_database():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            risk TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(url, score, risk):
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO scans (url, score, risk, scanned_at)
        VALUES (?, ?, ?, ?)
    """, (url, score, risk, scanned_at))

    connection.commit()
    connection.close()


def get_scans():
    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, url, score, risk, scanned_at
        FROM scans
        ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    connection.close()

    return scans