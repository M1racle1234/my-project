"""Authentication endpoint."""

from flask import Blueprint, current_app, jsonify, request

from ..security import api_error, authenticate, create_access_token

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.post("/login")
def login():
    """Exchange a username and password for a short-lived JWT access token."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("Request body must be a JSON object", 400)

    username = data.get("username")
    password = data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return api_error("username and password are required", 400)

    username = username.strip()
    if not 1 <= len(username) <= 64 or not 1 <= len(password) <= 128:
        return api_error("Invalid username or password format", 400)

    user = authenticate(username, password)
    if user is None:
        # Deliberately identical for unknown user and wrong password.
        return api_error("Invalid username or password", 401)

    token = create_access_token(user)
    # The value below is the RFC 6750 authentication scheme, not a credential.
    return (
        jsonify(
            {
                "access_token": token,
                "token_type": "Bearer",  # nosec B105
                "expires_in": int(current_app.config["JWT_TTL_SECONDS"]),
            }
        ),
        200,
    )
