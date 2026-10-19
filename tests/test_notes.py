"""Tests for note creation/listing, tenant isolation and XSS handling."""

import sqlite3

import pytest


def _stored_titles(app):
    connection = sqlite3.connect(app.config["DATABASE"])
    try:
        return [row[0] for row in connection.execute("SELECT title FROM notes")]
    finally:
        connection.close()


def test_notes_require_authentication(client):
    assert client.post("/api/notes", json={"title": "t", "content": "c"}).status_code == 401
    assert client.get("/api/notes").status_code == 401


def test_create_note_returns_escaped_payload(client, alice_headers):
    payload = {
        "title": "<script>alert('xss')</script>",
        "content": "<img src=x onerror=alert(1)>",
    }
    response = client.post("/api/notes", json=payload, headers=alice_headers)

    assert response.status_code == 201
    note = response.get_json()["note"]
    assert "<script>" not in note["title"]
    assert "&lt;script&gt;" in note["title"]
    assert "<img" not in note["content"]
    assert "&lt;img" in note["content"]


def test_database_stores_original_text(client, app, alice_headers):
    payload = {"title": "<b>hello</b>", "content": "<i>world</i>"}
    client.post("/api/notes", json=payload, headers=alice_headers)

    # Output encoding must not destroy the stored value.
    assert _stored_titles(app) == ["<b>hello</b>"]


def test_list_returns_escaped_notes(client, alice_headers):
    client.post(
        "/api/notes",
        json={"title": "<script>bad()</script>", "content": "safe body"},
        headers=alice_headers,
    )

    body = client.get("/api/notes", headers=alice_headers).get_json()
    assert body["count"] == 1
    assert "&lt;script&gt;" in body["items"][0]["title"]
    assert "<script>" not in body["items"][0]["title"]


def test_notes_are_isolated_between_users(client, alice_headers, bob_headers):
    client.post(
        "/api/notes", json={"title": "alice private", "content": "secret"}, headers=alice_headers
    )

    bob_notes = client.get("/api/notes", headers=bob_headers).get_json()
    alice_notes = client.get("/api/notes", headers=alice_headers).get_json()

    assert bob_notes["count"] == 0
    assert alice_notes["count"] == 1


def test_sql_injection_in_note_content_is_stored_as_text(client, alice_headers):
    payload = {
        "title": "x'); DROP TABLE notes; --",
        "content": "' UNION SELECT password_hash FROM users --",
    }
    assert client.post("/api/notes", json=payload, headers=alice_headers).status_code == 201
    # The table is intact and still lists the note.
    assert client.get("/api/notes", headers=alice_headers).get_json()["count"] == 1


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"title": "only title"},
        {"content": "only content"},
        {"title": 1, "content": "c"},
        {"title": "t", "content": None},
        {"title": "", "content": "c"},
        {"title": "   ", "content": "c"},
        {"title": "t", "content": ""},
        {"title": "a" * 121, "content": "c"},
        {"title": "t", "content": "a" * 5001},
    ],
)
def test_note_validation(client, alice_headers, payload):
    response = client.post("/api/notes", json=payload, headers=alice_headers)

    assert response.status_code == 400
