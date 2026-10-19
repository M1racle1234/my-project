"""Protected data endpoint (the second required method)."""

from flask import Blueprint, jsonify, request

from ..db import get_db
from ..security import api_error, auth_required
from ..serializers import serialize_user

bp = Blueprint("data", __name__, url_prefix="/api")

MAX_QUERY_LENGTH = 64
MAX_RESULTS = 100


@bp.get("/data")
@auth_required
def get_data():
    """Return the user directory; only reachable with a valid access token.

    An optional ``q`` parameter performs a substring match on the username.  It
    is bound as a query parameter, never concatenated into the SQL text, which
    is what makes the endpoint immune to SQL injection even though it accepts
    free-form input.
    """
    search = request.args.get("q", "", type=str).strip()
    if len(search) > MAX_QUERY_LENGTH:
        return api_error("Search term is too long", 400)

    db = get_db()
    if search:
        rows = db.execute(
            "SELECT id, username, bio FROM users "
            "WHERE username LIKE ? ORDER BY id LIMIT ?",
            (f"%{search}%", MAX_RESULTS),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id, username, bio FROM users ORDER BY id LIMIT ?",
            (MAX_RESULTS,),
        ).fetchall()

    return jsonify({"count": len(rows), "items": [serialize_user(row) for row in rows]})
