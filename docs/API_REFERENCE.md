# API reference

Base path: `/api/v1`. Every endpoint except `POST /auth/login` requires `Authorization: Bearer <jwt>`.
Interactive OpenAPI documentation is served at `/api/docs` (`/api/openapi.json`).

Roles: **V** = viewer, **A** = analyst, **Ad** = admin. A higher role includes lower ones.

## Authentication & users

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/auth/login` | — | `{email, password}` → `{access_token, token_type, user}`. Rate-limited per IP. |
| GET | `/auth/me` | V | Current user |
| GET | `/users` | Ad | List users |
| POST | `/users` | Ad | `{email, password (≥10), role}` |
| PATCH | `/users/{id}` | Ad | `{role?, is_active?}`. Admins can't demote themselves. |
| GET | `/audit?limit=` | Ad | Security audit events |

## Projects, targets, settings

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/dashboard?project_id=` | V | Counts, latest classification per test, severities, recent executions |
| GET / POST | `/projects` | V / A | List (with stats) / create `{name, description}` |
| GET | `/projects/{id}` | V | Project |
| GET / POST | `/projects/{id}/targets` | V / A | List / create `{name, base_url, environment, variables}`. Host must be allowlisted. New targets are unauthorized. |
| POST | `/targets/{id}/authorization` | Ad | `{authorized, authorization_note, allow_private_network}` |
| GET | `/settings` | V | Effective safety limits and LLM status |

## Evidence & findings

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/projects/{id}/evidence` | A | Multipart `file` + `format` (`auto`, `har`, `burp`, `zap`, `sarif`, `raw-http`, `json`, `incident-log`). Returns evidence + auto-created findings. Errors: 413 too large, 422 malformed/unsafe, 429 upload rate. |
| GET | `/projects/{id}/evidence` | V | List (without exchanges) |
| GET | `/evidence/{id}` | V | Evidence with redacted exchanges |
| GET | `/evidence/{id}/original` | A | Original bytes as an inert attachment, with `X-Evidence-SHA256` |
| GET / POST | `/projects/{id}/findings` | V / A | List (`?severity=&category=`) / create manual finding linked to evidence exchanges |
| GET / PATCH | `/findings/{id}` | V / A | Detail with redacted exchanges / update `{status, category, severity}` |

## Scenarios, tests, library

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/projects/{id}/scenarios` | A | `{finding_id, options}`. Options: `auth_mode` (`static_secret`, `login_flow`, `none`), `login {path, username_field, password_field, token_path}`, `owner_username`, `attacker_username`, `owner_password_secret`, `attacker_password_secret`, `rate_limit_requests`. |
| GET | `/projects/{id}/scenarios`, `/scenarios/{id}` | V | List / detail |
| POST | `/projects/{id}/tests/generate` | A | `{scenario_id, use_ai, name?, tags?}` → draft test (v1) |
| POST | `/projects/{id}/tests` | A | Create from a hand-written definition |
| GET | `/projects/{id}/tests?q=&category=&tag=&status=` | V | Library search with latest classification |
| GET / PATCH | `/tests/{id}` | V / A | Detail with current definition and version history / `{tags, status:"archived"}` |
| POST | `/tests/{id}/versions` | A | `{definition, change_note}`. Creates a new version and resets approval. |
| GET | `/tests/{id}/versions/{n}` | V | A specific version |
| POST | `/tests/{id}/approve` | A | Human approval required before execution |
| GET | `/tests/{id}/render?format=json\|pytest\|playwright` | V | Code rendering |
| GET | `/projects/{id}/tests-export?status=approved` | V | Suite JSON for the CLI and CI |

## Executions, comparison, reports, assistant

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/executions` | A | `{test_id, target_id, label, wait}`. 403 unless test approved, target authorized and host allowlisted. `wait=false` runs in the background. |
| GET | `/projects/{id}/executions?test_id=` | V | History with summaries |
| GET | `/executions/{id}` | V | Full redacted result, classification, comparison and reasons |
| POST | `/executions/{id}/cancel` | A | Cooperative cancellation |
| POST | `/executions/{id}/baseline` | A | Mark a vulnerable run as the baseline |
| GET | `/compare?before=&after=` | V | Structured diff of two executions of the same test |
| GET | `/tests/{id}/report?format=json\|html\|pdf` | V | Evidence-backed report with hashes |
| POST | `/assistant` | V | `{task, finding_id?, execution_id?, provider}`. Tasks: `explain_finding`, `summarize_evidence`, `explain_result`, `suggest_remediation`, `report_summary`. |

## Errors

Errors use FastAPI's `{"detail": ...}` shape. `401` means missing or invalid token, `403` means insufficient
role or a safety gate refused, `404` not found, `413` upload too large, `422` validation, `429` rate limit
(with `Retry-After` on the global limiter).
