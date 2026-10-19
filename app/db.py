"""SQLite access layer.

All statements use ``?`` placeholders (prepared statements).  No SQL query in
this project is assembled with string concatenation or f-strings; user input
always travels as a bound parameter.
"""

import sqlite3

from flask import current_app, g

from .security import hash_password

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    bio           TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    content    TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes (user_id);
"""

SEED_USERS = (
    {"username": "alice", "bio": "Backend developer. Loves secure APIs."},
    {"username": "bob", "bio": "QA engineer. Tests everything twice."},
)


def get_db() -> sqlite3.Connection:
    """Return the request-scoped database connection."""
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_exception=None) -> None:
    """Close the request-scoped connection at teardown."""
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    """Create the schema and seed demonstration users when the table is empty."""
    db = get_db()
    db.executescript(SCHEMA)

    count = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if count:
        return

    seed_password = current_app.config["SEED_PASSWORD"]
    rounds = current_app.config["BCRYPT_ROUNDS"]
    for user in SEED_USERS:
        db.execute(
            "INSERT INTO users (username, password_hash, role, bio) VALUES (?, ?, ?, ?)",
            (user["username"], hash_password(seed_password, rounds=rounds), "user", user["bio"]),
        )
    db.commit()
