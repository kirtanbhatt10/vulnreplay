# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [0.1.1] - 2026-11-24

### Fixed
- CI: the `pip-audit` step now upgrades the audit virtualenv's own `pip` before auditing. Every earlier CI run
  failed because the bundled `pip` 25.0.1 has known advisories, which also kept the Playwright job from running.
- README: corrected setup commands (`pip install -e ".[dev]"`, `uvicorn vulnreplay.main:app`, `/api/docs`, the
  required `VULNREPLAY_ADMIN_PASSWORD` for Docker Compose) and the project structure.

### Changed
- Frontend pages are lazy-loaded, so the initial JavaScript bundle drops from 571 kB to 277 kB and the Vite
  chunk-size warning is gone.
- README now documents environment variables, an example replay, CLI and API usage, integrations and security
  limitations.

## [0.1.0] - 2026-11-21

### Added
- Evidence import engine for Burp XML, OWASP ZAP JSON, HAR, SARIF 2.1.0, raw HTTP, JSON reports and JSONL
  incident logs, with validation, size limits, sanitization, SHA-256 fingerprints and provenance.
- Attack scenario reconstruction for IDOR/BOLA, access control, authorization bypass, authentication,
  SQL injection verification, input validation, security headers, rate limiting, CORS and session management.
- Multi-step owner-vs-attacker authorization replay with value extraction.
- Test generation: JSON definitions, Pytest/HTTPX and Playwright renderings.
- Controlled execution engine with operator allowlist, admin target authorization, SSRF/DNS-rebinding
  protection via per-request IP pinning, redirect validation, budgets, throttling and cancellation.
- Regression engine comparing status, structure, sensitive data, auth behaviour, headers, errors and timing.
  Five-way classification with incomplete-remediation detection.
- Versioned regression library with approval workflow, search and suite export.
- Optional AI security assistant (deterministic by default, local Ollama-compatible LLM optional).
- CLI and reusable GitHub Action with JSON/SARIF output, baselines and failure thresholds.
- HTML, PDF and JSON reports with integrity hashes.
- React/TypeScript frontend with eleven pages, React Flow attack visualisation and comparison panels.
- Deliberately vulnerable demo lab (vulnerable, partial and patched builds) and Docker Compose setup.
- Test suites: 74 backend tests, 10 frontend tests and 9 Playwright end-to-end tests.
