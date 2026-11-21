# Sample evidence

Synthetic evidence files that target the [demo lab](../lab/README.md). No real systems, users or credentials.
Tokens in these files are fake placeholders, and VulnReplay replaces them with secret references anyway.

| File | Format | Demonstrates |
| --- | --- | --- |
| `idor-invoice-burp.xml` | Burp Suite "Save items" export | IDOR: bob reads alice's invoice |
| `idor-report.json` | Generic JSON report | Same IDOR as a pentest report with a finding |
| `missing-headers-zap.json` | OWASP ZAP traditional JSON | Missing CSP / X-Content-Type-Options |
| `cors-reflection.har` | HAR 1.2 | Reflected `Origin` with credentials |
| `admin-authz-bypass.sarif` | SARIF 2.1.0 with `webRequest`/`webResponse` | Missing function-level authorization |
| `password-reset-burst.jsonl` | JSON Lines incident log | No rate limiting on password reset |
| `sqli-products.http` | Raw HTTP request + response | SQL error leakage (verification only) |
