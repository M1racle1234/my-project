# Screenshot checklist

The report needs screenshots from the **public repository's Actions tab**, not from a
local terminal, for the SAST/SCA evidence. Put the final images in this folder using
the names below; the report references them.

## 1. CI pipeline (required by the assignment)

| File | What to capture | Where |
| --- | --- | --- |
| `01-actions-run.png` | The whole workflow run: three green jobs (`test`, `sast`, `sca`) | Repository → **Actions** → latest `Security CI` run |
| `02-bandit-summary.png` | Bandit report rendered in the run summary (`No issues identified`) | Same run → **Summary** |
| `03-pip-audit-summary.png` | pip-audit JSON/summary showing no vulnerabilities | Same run → **Summary** |
| `04-artifacts.png` | The two uploaded artifacts (`bandit-report`, `pip-audit-report`) | Run page → **Artifacts** |

## 2. API behaviour (Postman or curl)

| File | What to capture |
| --- | --- |
| `05-login-200.png` | `POST /auth/login` returning `200` with `access_token` |
| `06-data-401.png` | `GET /api/data` without a token returning `401 {"error":"Authentication required"}` |
| `07-data-200.png` | `GET /api/data` with `Bearer` token returning the user list |
| `08-notes-xss.png` | `POST /api/notes` with `<script>alert(1)</script>` and the escaped `&lt;script&gt;` in the response |
| `09-pytest-local.png` | Local `pytest` run with `59 passed` (optional, complements the CI run) |

## 3. CVE stage (already executed)

The experiment has been run; the console transcripts are in
[`../evidence/cve/`](../evidence/cve/). Capture the same moments as screen images:

| File | What to capture |
| --- | --- |
| `10-vulhub-up.png` | `docker compose ps` with the vulnerable (2.3.30) and fixed (2.3.32) containers |
| `11-exploit-before.png` | **Captured** — `vulhub: 54289` and `uid=0(root)` on the vulnerable build |
| `12-fix-config.png` | `cve/s2-045/Dockerfile.fixed` showing the 2.3.30 → 2.3.32 change (optional) |
| `13-exploit-after.png` | **Captured** — same requests on the fixed build: no `vulhub` header, no `uid` |
| `14-regression.png` | The normal Struts upload page still loading on the fixed build (optional) |

If a live screen capture is not possible, quote the transcript files in the report; they
are real command output, not reconstructions.

## Rules

- Do not include tokens, passwords, API keys or personal data in screenshots; blur or
  crop them.
- Keep the browser address bar visible where it proves the repository/URL.
- Name files exactly as above so the report placeholders can be replaced mechanically.
- PNG is preferred; keep the full window rather than a cropped fragment where the
  context (Actions tab, HTTP status) matters.
