# Security design and self-audit

This document describes the security controls in VulnReplay itself and the results of auditing them. For the
threat-by-threat analysis see [THREAT_MODEL.md](THREAT_MODEL.md). To report a vulnerability see
[../SECURITY.md](../SECURITY.md).

## Controls

**Authentication.** Argon2id password hashes (argon2-cffi defaults). Passwords must be at least 10
characters. Short-lived HS256 JWTs (60 min) with `iss` and `exp` checked; `alg=none` and foreign keys are
rejected. Login failures look identical whether or not the account exists, and run a dummy hash
verification to equalise timing.

**Authorization.** Three roles. Every route declares its minimum role through a FastAPI dependency. Target
authorization and user management are admin-only.

**Execution safety.** See the threat model (T1–T3, T7). Summary: operator allowlist plus admin authorization,
relative paths only, per-request DNS validation with IP pinning, blocked ranges, same-target redirects only,
request budgets, throttling, timeouts, response size caps, cancellation.

**Input handling.** Upload size enforced while streaming; magic-byte blocklist for pickle, zip, PE and ELF;
defusedxml for XML; strict JSON; UTF-8 required; control characters removed; header names validated; only
http(s) URLs and standard methods accepted.

**Output handling.** React text rendering, Jinja2 autoescape, CSP on the API (`default-src 'none'`), on HTML
reports and in nginx. Original evidence is downloadable only as an `application/octet-stream` attachment.

**Secret handling.** `{{secret:NAME}}` placeholders resolved from the environment at run time. Redaction of
sensitive headers, resolved secret values, extracted tokens, bearer/JWT patterns and `password`/`token`
keys in logs, results, reports, JSON and SARIF.

**HTTP hardening.** `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store` on API responses. CORS allowlist without credentials. Global and login rate
limits.

**Supply chain.** Dependencies pinned to maintained major versions; `pip-audit` and `npm audit` in CI;
containers run as non-root users.

## Audit results (2026-11-21)

Every check below was executed in the build environment. Commands are in [TESTING.md](TESTING.md).

| Area | Method | Result |
| --- | --- | --- |
| Authentication, JWT forgery, `alg=none`, generic errors | pytest `test_api.py` | Pass |
| RBAC on users, targets, projects, audit | pytest `test_rbac`, `test_admin_cannot_demote_self` | Pass |
| SQL injection via filters | pytest `test_sql_injection_in_filters_is_harmless` | Pass (ORM bound parameters) |
| XSS through evidence | Vitest "renders evidence as inert text"; CSP headers asserted | Pass |
| CSRF | Design review: bearer header only, no cookies, CORS without credentials | Not applicable by design |
| SSRF, DNS rebinding, metadata IPs, IPv4-mapped IPv6 | pytest `test_guard.py` (19 tests) | Pass |
| Insecure redirects | pytest redirect tests | Pass |
| Path traversal | Upload filename sanitised (test). No user-controlled filesystem paths exist. Report templates are fixed. | Pass |
| Command injection | No subprocess or shell use in the backend (Bandit clean). The GitHub Action passes inputs through env vars. | Pass |
| File upload security, XXE, entity expansion, pickle/zip | pytest `test_importers.py`, `test_upload_restrictions` | Pass |
| Unsafe deserialization | Only `json` and defusedxml are used. Pickle signatures are rejected. | Pass |
| Credential exposure | pytest `test_secrets_never_appear_in_results`, e2e lifecycle and CLI assertions | Pass |
| Rate limiting | pytest `test_login_rate_limited`; observed live during the Playwright run | Pass |
| CORS | pytest `test_cors_only_allows_configured_origins` | Pass |
| Resource exhaustion | Size and response caps, request budget tests | Pass |
| Sensitive log exposure | Execution logs are redacted (e2e asserts no passwords or tokens in results/logs) | Pass |
| Static analysis | Bandit 1.9.4 on `vulnreplay/` | 0 issues (after replacing `assert` guards with explicit checks) |
| Type safety / lint | mypy (27 files), ruff | 0 issues |
| Python dependencies | pip-audit on a clean venv with project dependencies only | No known vulnerabilities |
| JavaScript dependencies | `npm audit` | 0 vulnerabilities |

Fixes made during the audit: Bandit B101 (`assert` used for runtime checks) replaced with explicit exceptions in
five places. Mypy found three type gaps that could have produced `None` categories. An evidence upload field was
marked `required`, which broke non-interactive submission; the client-side check now relies on the
disabled-state logic instead.
