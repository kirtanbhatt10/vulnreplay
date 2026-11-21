# Regression library

Approved VulnReplay tests exported from the demo-lab project (`GET /projects/{id}/tests-export`).

* `suite.json`: six test definitions (IDOR, security headers, rate limiting, SQL injection verification, CORS,
  admin authorization bypass).
* `baselines.json`: per-test baselines produced by running the suite against the vulnerable build
  (`--write-baseline`) and then the patched build (which marks each test `verified`).

The `security-regression` workflow runs this suite on every pull request against the patched demo app, and
checks that the vulnerable build is reported as `regression_detected`.

Secrets referenced by the suite: `OWNER_USERNAME`, `OWNER_PASSWORD`, `ATTACKER_USERNAME`, `ATTACKER_PASSWORD`,
`CAROL_PASSWORD`. Provide them as `VULNREPLAY_SECRET_<NAME>`.
