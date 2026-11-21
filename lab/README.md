# Demo lab — deliberately vulnerable

`demo_app/app.py` is a small FastAPI service with **intentional vulnerabilities**, used to demonstrate and
test VulnReplay. One codebase runs in three modes:

| `DEMO_MODE` | Behaviour |
| --- | --- |
| `vulnerable` | IDOR on invoices, missing admin check, no rate limit on password reset, SQL error leakage, reflected CORS with credentials, no security headers |
| `partial` | An *incomplete* IDOR fix: returns 403 but still serializes the invoice in the error body. Other issues fixed. |
| `patched` | All issues fixed |

All users and records are synthetic (`alice`, `bob`, `carol` @ `lab.vulnreplay.test`). Default lab passwords
can be overridden with `DEMO_ALICE_PASSWORD`, `DEMO_BOB_PASSWORD` and `DEMO_CAROL_PASSWORD`.

**Never expose this application to a network you don't control.** In `docker-compose.yml` it runs on an
internal-only network without published ports.

```bash
DEMO_MODE=vulnerable uvicorn app:app --port 8001
```
