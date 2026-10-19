"""Shared pytest fixtures."""

import os
import shutil
import sys
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests-do-not-use-0123456789")

from app import create_app  # noqa: E402

SEED_PASSWORD = "ChangeMe#2024"


@pytest.fixture()
def db_path():
    """A unique database path under the project directory.

    ``tmp_path`` is avoided on purpose: some sandboxed Windows environments deny
    access to directories created through ``tempfile``/``pytest`` helpers.
    """
    directory = PROJECT_ROOT / ".test_data" / uuid.uuid4().hex
    os.makedirs(directory)
    try:
        yield directory / "test.db"
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture()
def app(db_path):
    """A fresh application with an isolated SQLite database per test."""
    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(db_path),
            "JWT_SECRET": "test-secret-for-unit-tests-do-not-use-0123456789",
            "JWT_TTL_SECONDS": 3600,
            "BCRYPT_ROUNDS": 4,
            "SEED_PASSWORD": SEED_PASSWORD,
        }
    )
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def alice_token(client):
    response = client.post(
        "/auth/login", json={"username": "alice", "password": SEED_PASSWORD}
    )
    assert response.status_code == 200
    return response.get_json()["access_token"]


@pytest.fixture()
def alice_headers(alice_token):
    return {"Authorization": f"Bearer {alice_token}"}


@pytest.fixture()
def bob_headers(client):
    response = client.post(
        "/auth/login", json={"username": "bob", "password": SEED_PASSWORD}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['access_token']}"}
