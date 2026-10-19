"""Password hashing, JWT issuing/verification and the authentication decorator."""

import time
import uuid
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request

# A fixed hash used to spend roughly the same CPU time when a username does not
# exist, so that response timing cannot be used to enumerate accounts.
_DUMMY_HASH = bcrypt.hashpw(b"timing-equalizer", bcrypt.gensalt(rounds=12))

MAX_PASSWORD_BYTES = 72  # bcrypt only considers the first 72 bytes


def hash_password(password: str, rounds: int | None = None) -> str:
    """Hash a password with bcrypt and a per-password random salt."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    raw = password.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError("password must not exceed 72 bytes")
    cost = rounds if rounds is not None else current_app.config["BCRYPT_ROUNDS"]
    return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=cost)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish bcrypt verification that never raises on bad input."""
    if not isinstance(password, str) or not isinstance(password_hash, str):
        return False
    try:
        return bcrypt.checkpw(
            password.encode("utf-8")[:MAX_PASSWORD_BYTES], password_hash.encode("ascii")
        )
    except (ValueError, TypeError):
        return False


def find_user_by_username(username: str):
    """Look a user up with a parameterized query (SQL injection safe)."""
    from .db import get_db

    return get_db().execute(
        "SELECT id, username, password_hash, role, bio FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def authenticate(username: str, password: str):
    """Return the user row for valid credentials, otherwise ``None``."""
    user = find_user_by_username(username)
    if user is None:
        bcrypt.checkpw(password.encode("utf-8")[:MAX_PASSWORD_BYTES], _DUMMY_HASH)
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def create_access_token(user) -> str:
    """Issue a short-lived HS256 access token for a user row."""
    issued_at = int(time.time())
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iat": issued_at,
        "exp": issued_at + int(current_app.config["JWT_TTL_SECONDS"]),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def decode_access_token(token: str) -> dict:
    """Verify signature, algorithm and the required claims of a token."""
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
        options={"require": ["exp", "iat", "sub"]},
    )


def api_error(message: str, status: int):
    """Uniform JSON error response."""
    return jsonify({"error": message}), status


def auth_required(view):
    """Reject requests without a valid ``Authorization: Bearer <JWT>`` header."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return api_error("Authentication required", 401)

        try:
            payload = decode_access_token(parts[1])
        except jwt.ExpiredSignatureError:
            return api_error("Token has expired", 401)
        except jwt.InvalidTokenError:
            return api_error("Invalid token", 401)

        try:
            user_id = int(payload["sub"])
        except (KeyError, TypeError, ValueError):
            return api_error("Invalid token", 401)

        from .db import get_db

        user = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            # The token is signed but the account no longer exists.
            return api_error("Invalid token", 401)

        g.current_user = {"id": user["id"], "username": user["username"], "role": user["role"]}
        return view(*args, **kwargs)

    return wrapped
