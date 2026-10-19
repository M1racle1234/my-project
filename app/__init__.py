"""Application factory for the Secure Notes API."""

import os

from flask import Flask, jsonify

from .config import Config
from .db import close_db, init_db
from .routes.auth import bp as auth_bp
from .routes.data import bp as data_bp
from .routes.notes import bp as notes_bp


def create_app(test_config: dict | None = None) -> Flask:
    """Build and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if not app.config.get("JWT_SECRET"):
        raise RuntimeError(
            "JWT_SECRET is not set. Export a long random value before starting, e.g. "
            "PowerShell: $env:JWT_SECRET = -join ((48..57)+(65..90)+(97..122) | "
            "Get-Random -Count 64 | % {[char]$_})"
        )
    if len(app.config["JWT_SECRET"]) < 32:
        raise RuntimeError(
            "JWT_SECRET must be at least 32 characters (256 bits of entropy recommended)"
        )

    app.json.sort_keys = False
    os.makedirs(app.instance_path, exist_ok=True)
    database_dir = os.path.dirname(os.path.abspath(app.config["DATABASE"]))
    os.makedirs(database_dir, exist_ok=True)

    app.teardown_appcontext(close_db)
    app.register_blueprint(auth_bp)
    app.register_blueprint(data_bp)
    app.register_blueprint(notes_bp)

    with app.app_context():
        init_db()

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(400)
    def bad_request(_error):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify({"error": "Request body too large"}), 413

    @app.errorhandler(500)
    def internal_error(_error):
        # Never leak stack traces or database details to the client.
        return jsonify({"error": "Internal server error"}), 500

    return app
