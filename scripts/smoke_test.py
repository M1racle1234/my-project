"""End-to-end smoke test against a running instance.

Usage:
    python scripts/smoke_test.py --base-url http://127.0.0.1:5000

The script uses only the standard library so it can be run without installing
the project dependencies.  It exits with status 0 when every check passes.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

PASSED = 0
FAILED = 0


def request(method, url, payload=None, token=None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        body = error.read()
        try:
            return error.code, json.loads(body or b"{}")
        except json.JSONDecodeError:
            return error.code, {"raw": body.decode(errors="replace")}


def check(name, condition, detail=""):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"PASS  {name}")
    else:
        FAILED += 1
        print(f"FAIL  {name}  {detail}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--username", default="alice")
    parser.add_argument("--password", default="ChangeMe#2024")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    status, body = request("GET", f"{base}/api/data")
    check("unauthenticated /api/data is rejected (401)", status == 401, f"got {status}")

    status, body = request(
        "POST",
        f"{base}/auth/login",
        {"username": args.username, "password": args.password},
    )
    check("login returns 200", status == 200, f"got {status}")
    token = body.get("access_token", "")
    check("login returns a JWT", token.count(".") == 2)

    status, body = request(
        "POST", f"{base}/auth/login", {"username": args.username, "password": "wrong-password"}
    )
    check("wrong password is rejected (401)", status == 401, f"got {status}")

    status, body = request(
        "POST",
        f"{base}/auth/login",
        {"username": "alice' OR '1'='1", "password": args.password},
    )
    check("SQL injection login is rejected (401)", status == 401, f"got {status}")

    status, body = request("GET", f"{base}/api/data", token=token)
    check("authenticated /api/data returns 200", status == 200, f"got {status}")
    check("data contains seeded users", body.get("count", 0) >= 2, str(body))

    status, body = request(
        "GET", f"{base}/api/data?q=%27%20OR%20%271%27%3D%271", token=token
    )
    check(
        "SQL injection in search returns no rows",
        status == 200 and body.get("count") == 0,
        str(body),
    )

    payload = {
        "title": "<script>alert('xss')</script>",
        "content": "<img src=x onerror=alert(1)>",
    }
    status, body = request("POST", f"{base}/api/notes", payload, token=token)
    check("note creation returns 201", status == 201, f"got {status}")
    note = body.get("note", {})
    check("XSS payload is HTML-escaped", "&lt;script&gt;" in note.get("title", ""))
    check("raw script tag is absent", "<script>" not in json.dumps(body))

    status, body = request("GET", f"{base}/api/notes", token=token)
    check(
        "note listing works and stays escaped",
        status == 200 and body.get("count", 0) >= 1 and "&lt;script&gt;" in json.dumps(body),
        str(body),
    )

    status, body = request("GET", f"{base}/api/notes")
    check("note listing without token is rejected (401)", status == 401, f"got {status}")

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
