# Testing

## Suites

| Suite | Location | Count | What it covers |
| --- | --- | --- | --- |
| Importer unit tests | `backend/tests/test_importers.py` | 22 | Every format, field extraction, malformed input, size limits, XXE, entity expansion, pickle/zip rejection, sanitization, truncation |
| Guard / execution tests | `backend/tests/test_guard.py` | 19 | Allowlist, scheme/credential checks, same-target enforcement, blocked IP ranges, DNS rebinding, IPv4-mapped IPv6, IP pinning, redirects, budgets, cancellation, response caps |
| Definition & regression tests | `backend/tests/test_testdef_regression.py` | 13 | Schema validation, destructive payloads, templating, secret redaction, comparison and classification matrix, status-only and incomplete remediation |
| API security tests | `backend/tests/test_api.py` | 13 | Authentication, JWT forgery and `alg=none`, generic errors, login rate limit, RBAC, target validation, upload restrictions, redaction, CORS, SQL injection probes, production config |
| End-to-end lab tests | `backend/tests/test_e2e_lab.py` | 7 | Full lifecycle against **live** vulnerable, partial and patched lab servers: reproduce, store baseline, detect incomplete fix, verify fix, detect regression, reports (JSON/HTML/PDF), comparison, assistant, versioning, export. Five more categories reproduce and then verify. CLI with baseline, SARIF and exit codes. |
| Frontend component/integration | `frontend/src/test/app.test.tsx` | 10 | Login, API auth header, navigation (11 pages), loading and error states, file upload as multipart, server validation errors, forms, inert evidence rendering, classification badges, step results, diff panel |
| Browser E2E (Playwright) | `frontend/e2e/app.spec.ts` | 9 | Real browser against a running stack: dashboard, library filters, React Flow scenario, timeline and compare, code renderings, live execution, evidence upload, assistant, settings/CI pages. Also captures the README screenshots. |

**Total automated tests: 74 backend + 10 frontend + 9 browser E2E = 93.**

## Running

```bash
# Backend (SQLite by default)
cd backend
pip install -e ".[dev]"
pytest
# Same suite on PostgreSQL
VULNREPLAY_TEST_DATABASE_URL=postgresql+psycopg://user:pw@localhost/vr_test pytest

# Static analysis and audits
ruff check . && ruff format --check .
mypy
bandit -c pyproject.toml -r vulnreplay
python -m venv /tmp/audit && /tmp/audit/bin/pip install . pip-audit && /tmp/audit/bin/pip-audit -l --skip-editable
alembic upgrade head && alembic check     # against PostgreSQL

# Frontend
cd ../frontend
npm ci && npm audit && npm run typecheck && npm test && npm run build

# Browser E2E against a running, seeded stack (docker compose or native)
VULNREPLAY_ADMIN_PASSWORD=… python ../scripts/seed_demo.py
E2E_PASSWORD=… npx playwright test
#   PW_CHROME_PATH=/usr/bin/google-chrome   use a locally installed Chrome
#   E2E_SCREENSHOT_DIR=../docs/screenshots  capture README screenshots
```

The end-to-end backend tests start the three lab builds in-process on random localhost ports, so they need no
Docker and no network.

## Results of the release verification (2026-11-21)

All of the following were **executed** in the build environment (Linux, Python 3.13.18, Node 22.23.5,
PostgreSQL 16).

| Check | Result |
| --- | --- |
| `pytest`, SQLite, Python 3.13 | 74 passed |
| `pytest`, PostgreSQL 16, Python 3.13 | 74 passed |
| `pytest` on Python 3.11 and 3.12 (fresh virtualenvs) | 74 passed each (one upstream Starlette deprecation warning about its test client) |
| `ruff check` / `ruff format --check` | clean |
| `mypy` (27 source files) | no issues |
| `bandit -r vulnreplay` | 0 issues (Low 0 / Medium 0 / High 0) |
| `pip-audit` (project dependency tree) | no known vulnerabilities |
| `alembic upgrade head` → `downgrade base` → `upgrade head`, then `alembic check` on PostgreSQL | OK, no drift |
| `npm audit` | 0 vulnerabilities |
| `tsc -b` | no errors |
| `vitest run` | 10 passed |
| `vite build` (production) | success |
| Playwright E2E (local Google Chrome, production-mode backend on PostgreSQL) | 9 passed |
| `scripts/seed_demo.py` against the running stack | 13 executions, all classified as expected (see README) |
| CLI against the lab (`vulnreplay run`) | vulnerable → exit 1 (reproduced); patched → exit 0 (verified); vulnerable again → exit 1 (`regression_detected`); non-allowlisted host → exit 2 |
| Composite action script (`action.yml`), run locally | exit 0 against the patched build |
| `actionlint` on both workflows | clean |
| `docker compose config` | valid |

## Environmental limitations

* **Docker images couldn't be built or started** in the build environment: its network proxy blocks Docker
  Hub (`registry-1.docker.io`). The Compose file was validated with `docker compose config`, and every service
  was run natively with the same configuration instead: PostgreSQL 16, backend in `production` mode with Alembic,
  three lab builds, and the built frontend. The Dockerfiles and the Compose stack themselves haven't been
  executed.
* **Playwright's bundled Chromium couldn't be downloaded** (CDN blocked), so the E2E suite ran on the
  locally installed Google Chrome via `PW_CHROME_PATH`. CI installs Playwright's Chromium normally.
* **GitHub Actions workflows haven't been run on GitHub yet.** They were linted with actionlint, and their
  commands were exercised locally.
* **No local LLM was available.** The Ollama integration is covered by code review and its fallback path,
  not by a live model run.
