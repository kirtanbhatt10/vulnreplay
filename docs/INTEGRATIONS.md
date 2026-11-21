# Integrations

## Evidence sources

| Source | How to export | VulnReplay format |
| --- | --- | --- |
| Burp Suite | Proxy history / Repeater → select items → *Save items* (keep "Base64-encode requests and responses" checked) | `burp` (XML) |
| OWASP ZAP | *Report → Generate report* → "Traditional JSON" or the `report` job in the Automation Framework | `zap` |
| Browsers / proxies | DevTools → Network → *Save all as HAR* | `har` |
| SAST/DAST producing SARIF 2.1.0 | Any tool. `webRequest` / `webResponse` objects are used when present. | `sarif` |
| Manual notes | Paste the raw HTTP request, optionally followed by a blank line and the raw response | `raw-http` |
| Other scanners | `{"tool": "...", "findings": [...], "exchanges": [{"request": {...}, "response": {...}}]}` | `json` |
| Logs / SIEM exports | JSON Lines with `method`, `url`, `status`, optional `timestamp`, `actor`, `request_body`, `response_body` | `incident-log` |

Detection is automatic (`format=auto`) by file extension and content. Imported content is parsed, never executed.

## GitHub Actions

Use the composite action published at the repository root:

```yaml
- uses: kirtanbhatt10/vulnreplay@main
  with:
    suite: regression-library/suite.json
    target-url: http://localhost:8001
    baseline: regression-library/baselines.json
    fail-on: regression_detected,vulnerability_reproduced
    sarif: vulnreplay.sarif
  env:
    VULNREPLAY_SECRET_OWNER_PASSWORD: ${{ secrets.VR_OWNER_PASSWORD }}
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: vulnreplay.sarif }
```

Inputs: `suite`, `target-url`, `allowed-hosts` (JSON list, default localhost), `baseline`, `fail-on`, `select`,
`json`, `sarif`, `python-version`. All inputs reach the shell as environment variables, never interpolated
into the script, so a malicious input can't inject commands.

Secrets:

* pass test credentials only as `VULNREPLAY_SECRET_*` from encrypted secrets
* every value VulnReplay resolves is redacted from stdout, JSON and SARIF output
* `security-events: write` is only needed for SARIF upload

### Baselines

`--baseline file.json --write-baseline` stores the first vulnerable result per test and marks it `verified`
once a later run passes. With a baseline, a vulnerable result after verification is a
**`regression_detected`**. Without one, it's `vulnerability_reproduced`. Commit the baseline file next to the suite.

### Failure thresholds

`--fail-on` accepts any of `vulnerability_reproduced`, `regression_detected`, `inconclusive`,
`execution_failed`, `remediation_verified`. Exit code `1` if any result matches, `2` for configuration or
allowlist errors.

## Pytest and Playwright

Each test can be rendered as standalone code (`GET /tests/{id}/render?format=pytest|playwright` or the Test
Generator page):

```bash
VULNREPLAY_TARGET_URL=http://localhost:8001 VULNREPLAY_SECRET_OWNER_PASSWORD=… pytest test_idor.py
VULNREPLAY_TARGET_URL=http://localhost:8001 npx playwright test idor.spec.ts
```

The renderings don't include VulnReplay's target guard. Run them only against environments you're
authorized to test. The JSON definition run through `vulnreplay run` is the recommended CI path.

## Local LLM (Ollama)

See [DEPLOYMENT.md](DEPLOYMENT.md#optional-local-llm). The integration uses `POST /api/chat` with
`format: json`, sends only redacted evidence, and validates and grounds every answer.
