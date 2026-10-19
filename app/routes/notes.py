"""Note endpoints (the self-designed third method plus a companion listing)."""

from flask import Blueprint, g, jsonify, request

from ..db import get_db
from ..security import api_error, auth_required
from ..serializers import serialize_note

bp = Blueprint("notes", __name__, url_prefix="/api")

MAX_TITLE_LENGTH = 120
MAX_CONTENT_LENGTH = 5000
MAX_NOTES = 100


@bp.post("/notes")
@auth_required
def create_note():
    """Create a note owned by the authenticated user."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("Request body must be a JSON object", 400)

    title = data.get("title")
    content = data.get("content")
    if not isinstance(title, str) or not isinstance(content, str):
        return api_error("title and content are required strings", 400)

    title = title.strip()
    content = content.strip()
    if not 1 <= len(title) <= MAX_TITLE_LENGTH:
        return api_error(f"title must be 1-{MAX_TITLE_LENGTH} characters", 400)
    if not 1 <= len(content) <= MAX_CONTENT_LENGTH:
        return api_error(f"content must be 1-{MAX_CONTENT_LENGTH} characters", 400)

    db = get_db()
    cursor = db.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (g.current_user["id"], title, content),
    )
    db.commit()
    row = db.execute(
        "SELECT id, title, content, created_at FROM notes WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return jsonify({"note": serialize_note(row)}), 201


@bp.get("/notes")
@auth_required
def list_notes():
    """List only the current user's notes, newest first."""
    rows = get_db().execute(
        "SELECT id, title, content, created_at FROM notes "
        "WHERE user_id = ? ORDER BY id DESC LIMIT ?",
        (g.current_user["id"], MAX_NOTES),
    ).fetchall()
    return jsonify({"count": len(rows), "items": [serialize_note(row) for row in rows]})
