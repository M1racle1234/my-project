"""Cross-cutting security checks: headers, hashing, JSON error handling."""

import sqlite3

from tests.conftest import SEED_PASSWORD


def test_security_headers_on_success(client, alice_headers):
    response = client.get("/api/data", headers=alice_headers)

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_security_headers_on_errors(client):
    response = client.get("/api/data")

    assert response.status_code == 401
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_passwords_are_stored_as_bcrypt_hashes(client, app):
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        hashes = [row[0] for row in connection.execute("SELECT password_hash FROM users")]
    finally:
        connection.close()

    assert len(hashes) == 2
    for value in hashes:
        assert value != SEED_PASSWORD
        assert value.startswith(("$2a$", "$2b$", "$2y$"))
        assert len(value) == 60


def test_password_hashes_are_unique_per_user(client, app):
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        hashes = [row[0] for row in connection.execute("SELECT password_hash FROM users")]
    finally:
        connection.close()

    assert hashes[0] != hashes[1]


def test_not_found_returns_json(client):
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.get_json() == {"error": "Not found"}


def test_method_not_allowed_returns_json(client):
    response = client.get("/auth/login")

    assert response.status_code == 405
    assert response.get_json() == {"error": "Method not allowed"}


def test_oversized_body_is_rejected(client, alice_headers):
    response = client.post(
        "/api/notes",
        json={"title": "t", "content": "a" * 20000},
        headers=alice_headers,
    )

    assert response.status_code == 413
    assert response.get_json() == {"error": "Request body too large"}


def test_malformed_json_returns_400(client):
    response = client.post(
        "/auth/login",
        data="{not valid json",
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "Request body must be a JSON object"}
