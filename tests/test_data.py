"""Tests for the protected data endpoint (access control + SQLi-safe search)."""

import pytest


def test_data_requires_authentication(client):
    response = client.get("/api/data")

    assert response.status_code == 401
    assert response.get_json()["error"] == "Authentication required"


def test_data_returns_user_directory(client, alice_headers):
    response = client.get("/api/data", headers=alice_headers)

    assert response.status_code == 200
    body = response.get_json()
    assert body["count"] == 2
    assert [item["username"] for item in body["items"]] == ["alice", "bob"]


def test_data_does_not_expose_credentials(client, alice_headers):
    body = client.get("/api/data", headers=alice_headers).get_json()

    for item in body["items"]:
        assert set(item) == {"id", "username", "bio"}
    assert "password" not in str(body).lower()


def test_data_search_filters_with_bound_parameter(client, alice_headers):
    response = client.get("/api/data?q=ali", headers=alice_headers)

    body = response.get_json()
    assert body["count"] == 1
    assert body["items"][0]["username"] == "alice"


@pytest.mark.parametrize(
    "payload",
    ["' OR '1'='1", "%' OR 1=1 --", "alice' UNION SELECT password_hash FROM users --"],
)
def test_data_search_is_immune_to_sql_injection(client, alice_headers, payload):
    response = client.get("/api/data", headers=alice_headers, query_string={"q": payload})

    assert response.status_code == 200
    assert response.get_json()["count"] == 0


def test_data_search_rejects_overlong_query(client, alice_headers):
    response = client.get("/api/data", headers=alice_headers, query_string={"q": "a" * 65})

    assert response.status_code == 400
