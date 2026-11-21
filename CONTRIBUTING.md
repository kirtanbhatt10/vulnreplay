# Contributing

Thanks for helping make security fixes stick.

## Development setup

```bash
# backend
cd backend && pip install -e ".[dev]"
pytest && ruff check . && ruff format --check . && mypy && bandit -c pyproject.toml -r vulnreplay

# frontend
cd frontend && npm ci && npm test && npm run build
```

End-to-end tests need a running stack. See [docs/TESTING.md](docs/TESTING.md).

## Ground rules

* **Safety first.** Changes to `execution/`, `importers/`, `testdef.py` or redaction need tests that show
  the protection still holds (SSRF, rebinding, redirects, uploads, secrets).
* **No destructive capabilities.** VulnReplay verifies fixes; it isn't an exploitation framework. Pull
  requests that add uncontrolled scanning, payload libraries or destructive actions won't be accepted.
* **Evidence-grounded AI only.** Assistant features must use stored evidence and results, keep facts and
  hypotheses separate, and never trigger execution.
* **Synthetic data only** in fixtures, samples and the lab (`*.vulnreplay.test`, `*.invalid`).
* Add a database migration (`alembic revision --autogenerate`) for every model change, and check it with
  `alembic check`.

## Pull requests

1. Open an issue first for larger changes.
2. Keep commits focused, using conventional prefixes (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `chore:`).
3. Update docs and `CHANGELOG.md` when behaviour changes.
4. CI (`ci` and `security-regression` workflows) must pass.

## Adding an evidence format

Add a parser to `backend/vulnreplay/importers/formats.py` that returns `ParsedEvidence` using
`build_exchange()` (it validates and sanitizes for you), register detection in `importers/__init__.py`, add a
synthetic sample to `samples/` and tests to `tests/test_importers.py`.

## Code of conduct

Be respectful and constructive. Harassment of any kind isn't tolerated.
