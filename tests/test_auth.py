"""Authentication behaviour and JWT hardening tests."""

import base64
import json
import time

import jwt
import pytest

from tests.conftest import SEED_PASSWORD


def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_login_returns_token_without_secrets(client):
    response = client.post(
        "/auth/login", json={"username": "alice", "password": SEED_PASSWORD}
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["access_token"].count(".") == 2
    assert "password" not in body
    assert "password_hash" not in response.get_data(as_text=True)


def test_login_rejects_wrong_password(client):
    response = client.post(
        "/auth/login", json={"username": "alice", "password": "definitely-wrong"}
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid username or password"


def test_login_does_not_reveal_whether_user_exists(client):
    unknown = client.post(
        "/auth/login", json={"username": "nobody", "password": "definitely-wrong"}
    )
    wrong = client.post(
        "/auth/login", json={"username": "alice", "password": "definitely-wrong"}
    )

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json() == wrong.get_json()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"username": "alice"},
        {"password": SEED_PASSWORD},
        {"username": 1, "password": SEED_PASSWORD},
        {"username": "alice", "password": ["x"]},
        {"username": "", "password": SEED_PASSWORD},
        {"username": "alice", "password": ""},
    ],
)
def test_login_validates_input(client, payload):
    assert client.post("/auth/login", json=payload).status_code == 400


@pytest.mark.parametrize(
    "username",
    [
        "alice' OR '1'='1",
        "alice'--",
        "' OR 1=1 --",
        "admin'/*",
        "alice'; DROP TABLE users; --",
    ],
)
def test_login_sql_injection_attempts_fail(client, username):
    response = client.post(
        "/auth/login", json={"username": username, "password": SEED_PASSWORD}
    )

    assert response.status_code == 401
    # The table must still exist after the injection attempt.
    assert client.post(
        "/auth/login", json={"username": "alice", "password": SEED_PASSWORD}
    ).status_code == 200


def test_login_with_password_longer_than_bcrypt_limit(client):
    response = client.post(
        "/auth/login", json={"username": "alice", "password": "A" * 100}
    )

    assert response.status_code == 401


def test_expired_token_is_rejected(client, app):
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "1",
            "username": "alice",
            "role": "user",
            "iat": now - 7200,
            "exp": now - 3600,
        },
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )

    response = client.get("/api/data", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.get_json()["error"] == "Token has expired"


def test_token_signed_with_foreign_key_is_rejected(client):
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "1",
            "username": "alice",
            "role": "user",
            "iat": now,
            "exp": now + 3600,
        },
        "attacker-controlled-secret-0123456789abcdef",
        algorithm="HS256",
    )

    assert client.get(
        "/api/data", headers={"Authorization": f"Bearer {token}"}
    ).status_code == 401


def test_unsigned_alg_none_token_is_rejected(client):
    now = int(time.time())
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url(
        {
            "sub": "1",
            "username": "alice",
            "role": "admin",
            "iat": now,
            "exp": now + 3600,
        }
    )

    response = client.get(
        "/api/data", headers={"Authorization": f"Bearer {header}.{payload}."}
    )

    assert response.status_code == 401


def test_tampered_token_is_rejected(client, alice_token):
    tampered = alice_token[:-4] + ("aaaa" if alice_token[-4:] != "aaaa" else "bbbb")

    assert client.get(
        "/api/data", headers={"Authorization": f"Bearer {tampered}"}
    ).status_code == 401


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Basic dXNlcjpwYXNz", "Token abc.def.ghi", "Bearer a b"],
)
def test_malformed_authorization_header_is_rejected(client, header):
    assert client.get("/api/data", headers={"Authorization": header}).status_code == 401


def test_token_for_deleted_user_is_rejected(client, app, alice_headers):
    import sqlite3

    connection = sqlite3.connect(app.config["DATABASE"])
    connection.execute("DELETE FROM users WHERE username = 'alice'")
    connection.commit()
    connection.close()

    assert client.get("/api/data", headers=alice_headers).status_code == 401
