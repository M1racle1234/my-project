"""Output encoding helpers.

The API speaks JSON, so a browser will not execute response bodies as HTML by
itself.  The assignment nevertheless requires every user-controlled value to be
sanitized before it leaves the service, so all user-supplied text is passed
through :func:`html.escape` on serialization.  This is output encoding, not
input mutation: the database keeps the original text and a non-HTML client can
still recover the intended value after unescaping.
"""

import html


def escape_text(value: object) -> str:
    """HTML-escape a value for safe embedding, returning ``""`` for non-strings."""
    if not isinstance(value, str):
        return ""
    return html.escape(value, quote=True)


def serialize_user(row) -> dict:
    """Public representation of a user (no password hash, no internal fields)."""
    return {
        "id": row["id"],
        "username": escape_text(row["username"]),
        "bio": escape_text(row["bio"]),
    }


def serialize_note(row) -> dict:
    """Public representation of a note with escaped title and body."""
    return {
        "id": row["id"],
        "title": escape_text(row["title"]),
        "content": escape_text(row["content"]),
        "created_at": row["created_at"],
    }
