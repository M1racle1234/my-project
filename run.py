"""Development entry point.

Run with ``python run.py`` after exporting ``JWT_SECRET``.  For production use a
WSGI server (gunicorn/waitress) importing ``app`` from this module.
"""

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
