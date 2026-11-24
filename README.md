# ⚡ VulnReplay

### Reproduce. Verify. Prevent.

**Turn every security finding into a permanent, repeatable security test.**

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Frontend-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge)
![Security](https://img.shields.io/badge/Focus-Application%20Security-red?style=for-the-badge)

</p>

---

## 🛡️ What is VulnReplay?

**VulnReplay** is an open-source application security testing platform that transforms vulnerability findings into reusable, automated security regression tests.

Security teams discover vulnerabilities, fix them and move on. But what happens when a future update accidentally introduces the same vulnerability again?

VulnReplay aims to solve this problem.

Import security evidence, reconstruct the original attack scenario, generate reproducible tests and verify whether the vulnerability has actually been fixed.

**Don't just fix vulnerabilities. Make sure they never return.**

---

## 🎯 The Problem We're Solving

Imagine a penetration tester discovers an IDOR vulnerability in an application.

The development team fixes it. The security team verifies the patch. Everything looks good.

Three months later, a new API update accidentally breaks the authorization logic.

The same vulnerability returns.

This is exactly the kind of problem VulnReplay is designed to prevent.

| Traditional workflow | VulnReplay workflow |
|---|---|
| Discover vulnerability | Import vulnerability evidence |
| Manually reproduce | Reconstruct attack scenario |
| Fix the vulnerability | Generate reusable regression test |
| Manually verify patch | Automatically compare behavior |
| Close the security ticket | Preserve test permanently |
| Risk recurrence | Continuously validate security |

---

## ⚡ Core Capabilities

### 🔍 01. Evidence Intelligence

Import security evidence from multiple sources.

- Burp Suite-compatible HTTP exports
- OWASP ZAP reports
- HAR files
- JSON and SARIF reports
- Raw HTTP requests and responses
- Structured incident logs

Extract endpoints, methods, parameters, authentication context and response information.

### 🧠 02. Attack Scenario Reconstruction

Transform security evidence into structured attack scenarios.

- Identify affected endpoints.
- Extract request sequences.
- Understand authentication contexts.
- Identify vulnerable parameters.
- Preserve reproduction steps.
- Organize supporting evidence.

### ⚙️ 03. Automated Test Generation

Turn discovered vulnerabilities into reusable security tests.

- Python HTTPX tests
- Pytest test cases
- Playwright browser tests
- Parameterized test definitions
- Reusable regression templates

### 🔥 04. Vulnerability Regression Detection

The heart of VulnReplay.

Compare application behavior before and after remediation.

Detect:

- Broken access control
- IDOR / BOLA
- Authentication regressions
- Authorization bypass
- Missing security headers
- Rate-limiting regressions
- CORS misconfigurations
- Unexpected data exposure

### 🔄 05. Multi-Step Attack Replay

Reconstruct complex application workflows.

Example:

```text
User A authenticates
       |
       v
Accesses personal resource
       |
       v
User B authenticates
       |
       v
Attempts to access User A's resource
       |
       v
Authorization behavior verified
       |
       v
Security regression result generated
```

### 🤖 06. AI-Assisted Security Analysis

An optional AI assistant helps security engineers:

- Understand vulnerability evidence.
- Explain request/response behavior.
- Suggest safe verification tests.
- Generate structured test definitions.
- Explain regression findings.
- Recommend remediation improvements.

AI-generated findings must always be supported by actual evidence.

### 📚 07. Regression Test Library

Build a permanent collection of security knowledge.

- Save discovered vulnerabilities.
- Version test cases.
- Categorize security scenarios.
- Track previous executions.
- Compare historical results.
- Reuse tests across deployments.

### 🚀 08. CI/CD Security Integration

Bring security regression testing into development workflows.

- GitHub Actions integration
- Pull-request security checks
- Automated regression execution
- JSON and SARIF reports
- Configurable deployment policies

---

## 🏗️ System Architecture

```mermaid
flowchart TB
    A["🔍 Security Evidence"] --> B["Evidence Import Engine"]
    B --> C["Attack Scenario Reconstruction"]

    C --> D["Test Generation Engine"]
    D --> E["Controlled Execution Engine"]

    E --> F["Regression Analysis"]
    F --> G["Evidence Comparison"]
    G --> H["Security Reports"]

    I["AI Analysis Assistant"] --> C
    I --> D
    I --> F

    J["Regression Test Library"] --> D
    J --> E

    K["GitHub Actions / CI-CD"] --> E

    L["React Dashboard"] --> M["FastAPI Backend"]
    M --> B
    M --> C
    M --> D
    M --> E
    M --> F
    M --> H
```

---

## 🧰 Technology Stack

| Layer | Technologies |
|---|---|
| Backend | Python, FastAPI |
| Frontend | React, TypeScript, Vite |
| Styling | Tailwind CSS |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Migrations | Alembic |
| HTTP Testing | HTTPX |
| Browser Testing | Playwright |
| Test Framework | Pytest |
| AI Integration | Optional local LLM |
| Deployment | Docker, Docker Compose |
| CI/CD | GitHub Actions |

---

## 📁 Project Structure

```text
vulnreplay/
├── backend/                 FastAPI service, CLI, Alembic migrations
│   ├── vulnreplay/
│   │   ├── api/             REST routes (auth, projects, evidence, tests, executions)
│   │   ├── importers/       Burp, ZAP, HAR, SARIF, raw HTTP, JSON and JSONL parsers
│   │   ├── execution/       Execution engine and target guard (allowlist, SSRF, redirects)
│   │   ├── reports/         HTML, PDF and JSON report generation
│   │   ├── scenarios.py     Attack scenario reconstruction
│   │   ├── generator.py     Test generation (JSON, Pytest/HTTPX, Playwright)
│   │   ├── regression.py    Before/after comparison and classification
│   │   ├── ai.py            Optional evidence-grounded assistant
│   │   ├── cli.py           `vulnreplay` command-line interface
│   │   └── main.py          Application entry point
│   ├── migrations/
│   └── tests/
├── frontend/                React + TypeScript + Vite + Tailwind CSS
│   ├── src/pages/           The eleven application pages
│   ├── src/test/            Vitest component tests
│   └── e2e/                 Playwright end-to-end tests
├── lab/demo_app/            Deliberately vulnerable demo app (vulnerable, partial, patched modes)
├── samples/                 Synthetic evidence files for every supported format
├── regression-library/      Exported regression suite and baselines used by CI
├── scripts/seed_demo.py     Seeds a running instance with the full demo walkthrough
├── docs/                    Architecture, threat model, testing, API, deployment, integrations
├── .github/workflows/       CI and security-regression workflows
├── action.yml               Reusable GitHub Action
└── docker-compose.yml       Local lab: backend, frontend, PostgreSQL, three demo apps
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 20+
- PostgreSQL 16 (SQLite works for local development)
- Git
- Docker and Docker Compose (for the one-command lab)

### Option A: One-command lab with Docker

```bash
git clone https://github.com/kirtanbhatt10/vulnreplay.git
cd vulnreplay
VULNREPLAY_ADMIN_PASSWORD='choose-a-long-password' docker compose up --build
```

- UI: http://localhost:8080 (sign in as `admin@vulnreplay.local`)
- API docs: http://localhost:8000/api/docs

Load the demo walkthrough (vulnerable baseline, partial fix, real fix, reintroduced regression):

```bash
VULNREPLAY_ADMIN_PASSWORD='choose-a-long-password' python scripts/seed_demo.py --lab-host-style compose
```

The demo apps run on an internal-only Docker network with no published ports and only synthetic data.

### Option B: Run natively

**Backend**

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp ../.env.example .env            # then set VULNREPLAY_ADMIN_PASSWORD
alembic upgrade head
uvicorn vulnreplay.main:app --reload --port 8000
```

**Demo lab apps** (optional, in separate terminals from `lab/demo_app`)

```bash
DEMO_MODE=vulnerable uvicorn app:app --port 8001
DEMO_MODE=patched    uvicorn app:app --port 8002
DEMO_MODE=partial    uvicorn app:app --port 8003
```

**Frontend**

```bash
cd frontend
npm ci
npm run dev                         # http://localhost:5173, proxies /api to :8000
```

### Environment variables

All backend settings use the `VULNREPLAY_` prefix. See [`.env.example`](.env.example) and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

| Variable | Purpose | Default |
|---|---|---|
| `VULNREPLAY_DATABASE_URL` | SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host/db` | `sqlite:///./vulnreplay.db` |
| `VULNREPLAY_SECRET_KEY` | JWT signing key; 32+ random characters required in production | development placeholder |
| `VULNREPLAY_ENVIRONMENT` | `development`, `test` or `production` | `development` |
| `VULNREPLAY_ADMIN_EMAIL` / `VULNREPLAY_ADMIN_PASSWORD` | Bootstrap administrator, created only when no users exist | unset |
| `VULNREPLAY_ALLOWED_HOSTS` | JSON list of hosts tests may ever reach | `["localhost","127.0.0.1","::1"]` |
| `VULNREPLAY_CORS_ORIGINS` | JSON list of allowed UI origins (no wildcard in production) | local dev origins |
| `VULNREPLAY_MAX_UPLOAD_BYTES` | Evidence upload size limit | 5 MiB |
| `VULNREPLAY_MAX_REQUESTS_PER_EXECUTION` | Request budget per execution | 200 |
| `VULNREPLAY_LLM_BASE_URL` | Optional Ollama-compatible local LLM; empty means deterministic analysis only | unset |
| `VULNREPLAY_SECRET_<NAME>` | Test credentials referenced in tests as `{{secret:NAME}}`, never stored or reported | unset |

---

## 🎬 Example Vulnerability Replay

The demo lab reproduces an IDOR on `GET /api/invoices/{id}`, in which Bob can read Alice's invoice. Running the
seed script and then the IDOR regression test gives this history:

| Release | Demo mode | Classification |
|---|---|---|
| baseline | `vulnerable` | `vulnerability_reproduced` |
| hotfix-1 | `partial` (returns 403 but still serializes the invoice) | `vulnerability_reproduced` |
| hotfix-2 | `patched` | `remediation_verified` |
| release-2.4 | `vulnerable` again | `regression_detected` |

Hotfix-1 shows why a status-code change alone is never treated as proof of remediation: VulnReplay still finds
Alice's data in the 403 response body.

---

## 💻 CLI Usage

```bash
vulnreplay import-check samples/idor-invoice-burp.xml     # parse evidence without storing it
vulnreplay validate regression-library/suite.json          # validate an exported suite
vulnreplay run regression-library/suite.json \
  --target-url http://localhost:8002 \
  --baseline regression-library/baselines.json \
  --fail-on regression_detected,vulnerability_reproduced,execution_failed \
  --json results.json --sarif results.sarif
```

`run` exits `0` when no configured classification occurs, `1` when one does, and `2` for configuration
errors, such as a target outside the allowlist.

---

## 🔌 API Usage

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@vulnreplay.local","password":"<password>"}' | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/dashboard
curl -s -H "Authorization: Bearer $TOKEN" -F file=@samples/cors-reflection.har \
  localhost:8000/api/v1/projects/<project_id>/evidence
curl -s -H "Authorization: Bearer $TOKEN" "localhost:8000/api/v1/tests/<test_id>/report?format=pdf" -o report.pdf
```

The full reference is in [docs/API_REFERENCE.md](docs/API_REFERENCE.md), and interactive docs are at `/api/docs`.

---

## 🔗 Integrations

**GitHub Actions**: run the saved regression library on every pull request:

```yaml
- uses: kirtanbhatt10/vulnreplay@main
  with:
    suite: regression-library/suite.json
    target-url: http://localhost:8001
    baseline: regression-library/baselines.json
    fail-on: regression_detected,vulnerability_reproduced,execution_failed
  env:
    VULNREPLAY_SECRET_OWNER_PASSWORD: ${{ secrets.VR_OWNER_PASSWORD }}
```

Results are written as JSON and SARIF 2.1.0 (uploadable to GitHub code scanning). Supported evidence sources are
Burp Suite XML exports, OWASP ZAP JSON reports, HAR, SARIF, raw HTTP and JSON/JSONL incident logs. See
[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

---

## 🧪 Testing & Quality Assurance

| Suite | Location | Tests |
|---|---|---|
| Backend unit, integration and security | `backend/tests` | 74 |
| Frontend component and integration | `frontend/src/test` | 10 |
| Browser end-to-end (Playwright) | `frontend/e2e` | 9 |

```bash
cd backend && pytest && ruff check . && mypy && bandit -r vulnreplay -c pyproject.toml && pip-audit
cd frontend && npm test && npm run build && npm audit
E2E_PASSWORD='<admin password>' npx playwright test   # against a running, seeded stack
```

Executed results and environment limitations are recorded in [docs/TESTING.md](docs/TESTING.md).

---

## 🔐 Security First

VulnReplay is designed for authorized application security testing.

Security controls include:

- Explicit, admin-approved target authorization on top of an operator allowlist.
- SSRF and DNS rebinding protection: every resolved address is revalidated and pinned per request.
- Redirects to unapproved destinations are never followed.
- Request budgets, throttling, timeouts, response size caps and cancellation.
- Role-based access control (admin, analyst, viewer) and login/API rate limiting.
- Test credentials injected from the environment and redacted from logs, results and reports.
- Uploaded evidence is validated, size-limited, sanitized, fingerprinted and never executed.
- Human approval is required before AI-generated tests can run.
- Audit logging.

**Never test systems without appropriate authorization.**

### Security limitations

- VulnReplay verifies the specific behaviour a test encodes. A passing suite doesn't prove an application is free of vulnerabilities.
- Timing comparisons are informational and can be noisy on shared infrastructure.
- The optional AI assistant can be wrong. Its output is labelled as facts, hypotheses, suggestions and unknowns, and it never runs tests itself.
- The demo lab is deliberately vulnerable and must never be exposed to a network you don't control.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/SECURITY.md](docs/SECURITY.md).

---

## 🗺️ Roadmap

**Implemented in 0.1.0**

- [x] Evidence import engine (Burp, ZAP, HAR, SARIF, raw HTTP, JSON, JSONL)
- [x] Attack scenario reconstruction and multi-step replay
- [x] Test generation (JSON, Pytest/HTTPX, Playwright)
- [x] Regression engine with incomplete-remediation detection
- [x] Regression library with versioning and approval
- [x] Optional evidence-grounded AI assistant
- [x] Dashboard with eleven pages
- [x] CLI, GitHub Action, JSON and SARIF output
- [x] HTML, PDF and JSON reports
- [x] Docker Compose lab

**Next**

- [ ] Direct Burp Suite extension and OWASP ZAP add-on
- [ ] GraphQL and WebSocket replay
- [ ] Scheduled regression runs against staging
- [ ] SSO (OIDC) and per-project roles
- [ ] Published container images

---

## 🤝 Contributing

Contributions are welcome!

Areas where developers and security researchers can contribute:

- New vulnerability test templates
- Additional evidence formats
- Regression detection improvements
- Security integrations
- Test execution improvements
- Documentation and testing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

---

## 📜 License

Distributed under the MIT License.

See [LICENSE](LICENSE) for more information.

---

## ⚠️ Disclaimer

VulnReplay is intended for authorized security testing, application security research and remediation verification.

It does not guarantee that an application is completely free of vulnerabilities.

All testing must be conducted against systems for which appropriate authorization has been obtained.

---

## 💡 Project Philosophy

**A vulnerability should not have to be discovered twice.**

Every discovered security weakness should become a reusable test.

Every security fix should be verified.

Every regression should be caught before it reaches production.

### Discover. Reproduce. Verify. Prevent.

---

<p align="center">

**Built for security engineers, penetration testers and developers who believe security should never be a one-time activity.**

⭐ If you find VulnReplay useful, consider giving the project a star!

</p>
