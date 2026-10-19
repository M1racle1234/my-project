"""Application configuration.

Every security-relevant value is supplied through the environment so that no
secret is committed to the repository.  ``JWT_SECRET`` is mandatory and is
validated in :func:`app.create_app`.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE = BASE_DIR / "instance" / "app.db"


class Config:
    # --- Authentication -------------------------------------------------
    JWT_SECRET = os.environ.get("JWT_SECRET", "")
    JWT_ALGORITHM = "HS256"
    JWT_TTL_SECONDS = int(os.environ.get("JWT_TTL_SECONDS", "3600"))
    BCRYPT_ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

    # --- Storage --------------------------------------------------------
    DATABASE = os.environ.get("DATABASE_PATH", str(DEFAULT_DATABASE))
    SEED_PASSWORD = os.environ.get("SEED_PASSWORD", "ChangeMe#2024")

    # --- Request handling ----------------------------------------------
    MAX_CONTENT_LENGTH = 16 * 1024
