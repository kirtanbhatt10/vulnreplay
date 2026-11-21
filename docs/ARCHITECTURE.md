# Architecture

## Components

```mermaid
flowchart TB
  UI[Frontend<br/>React 19 · TypeScript · Vite · Tailwind 4 · React Flow] -->|/api/v1 bearer JWT| API
  CLI[vulnreplay CLI / GitHub Action] --> ENG
  subgraph API [Backend — FastAPI]
    AUTH[security.py<br/>JWT · Argon2 · RBAC · redaction · rate limit]
    IMP[importers/<br/>format parsers]
    SCN[scenarios.py]
    GEN[generator.py]
    TD[testdef.py<br/>schema · templating · json paths]
    SVC[services.py<br/>versions · jobs · executions]
    ENG[execution/<br/>guard.py · engine.py]
    REG[regression.py]
    REP[reports/]
    AI[ai.py]
  end
  API --> DB[(PostgreSQL<br/>SQLAlchemy 2 · Alembic)]
  ENG -->|guarded, pinned HTTP| TGT[[Authorized targets]]
```

| Path | Responsibility |
| --- | --- |
| `backend/vulnreplay/config.py` | Settings from `VULNREPLAY_*` env vars; refuses unsafe production config |
| `backend/vulnreplay/models.py` | ORM: users, projects, targets, evidence, findings, scenarios, tests + versions, executions, audit events |
| `backend/vulnreplay/importers/` | Format detection, parsing, sanitization, fingerprinting, provenance |
| `backend/vulnreplay/scenarios.py` | `AttackScenario` model and deterministic reconstruction |
| `backend/vulnreplay/testdef.py` | Test definition schema (the executable artifact), safe templating, JSON paths |
| `backend/vulnreplay/generator.py` | Scenario → definition; definition → pytest / Playwright code |
| `backend/vulnreplay/execution/guard.py` | `TargetGuard` and `GuardedTransport` (SSRF / DNS rebinding defences) |
| `backend/vulnreplay/execution/engine.py` | Step runner: throttling, budgets, extraction, assertions, redirects, cancellation |
| `backend/vulnreplay/regression.py` | Result comparison and classification |
| `backend/vulnreplay/reports/` | Report model, Jinja2 HTML (autoescaped), fpdf2 PDF |
| `backend/vulnreplay/ai.py` | Deterministic assistant + optional grounded local LLM |
| `backend/vulnreplay/api/` | REST routers |
| `backend/vulnreplay/cli.py` | CI entry point |
| `lab/demo_app/` | Deliberately vulnerable / partial / patched demo application |

## Data model

```mermaid
erDiagram
  PROJECT ||--o{ TARGET : has
  PROJECT ||--o{ EVIDENCE : has
  EVIDENCE ||--o{ FINDING : yields
  FINDING ||--o{ SCENARIO : reconstructs
  SCENARIO ||--o{ REGRESSION_TEST : generates
  REGRESSION_TEST ||--|{ TEST_VERSION : versions
  REGRESSION_TEST ||--o{ EXECUTION : runs
  TARGET ||--o{ EXECUTION : "runs against"
```

* **Evidence** stores the original bytes (`original`), the normalized exchanges, SHA-256 and provenance.
  This includes the parser metadata and a hash per exchange.
* **RegressionTest** has an approval status. Every new **TestVersion** resets the status to `draft`.
* **Execution** stores the pinned test version, the redacted result, the classification, an `is_baseline`
  flag and the comparison with its reasons.

## Request lifecycle of an execution

```mermaid
sequenceDiagram
  participant U as Analyst
  participant API
  participant S as services
  participant E as engine
  participant G as GuardedTransport
  participant T as Target
  U->>API: POST /executions {test, target}
  API->>S: create_execution
  S-->>API: refuse unless test approved, target authorized, host allowlisted
  API->>S: perform (background thread or wait=true)
  loop each step × repeat
    E->>E: throttle, budget, cancellation check
    E->>G: request (relative path joined to target base URL)
    G->>G: check scheme/host/port == target
    G->>G: resolve DNS, validate every address, pin IP
    G->>T: connect to pinned IP (Host header + SNI preserved)
    T-->>E: response (streamed, size-capped)
    E->>E: evaluate assertions on raw response, store redacted copy
  end
  S->>S: compare with baseline, classify, store
```

## Classification logic

```mermaid
flowchart TD
  A{run state} -->|error| F[execution_failed]
  A -->|vulnerable| B{verified after baseline before?}
  B -->|yes| RG[regression_detected]
  B -->|no| RP[vulnerability_reproduced<br/>+ incomplete-remediation note if more assertions pass than baseline]
  A -->|secure| C{baseline exists?}
  C -->|no| IN1[inconclusive: never reproduced here]
  C -->|yes| D{status-only change and only status assertions?}
  D -->|yes| IN2[inconclusive]
  D -->|no| V[remediation_verified]
```

The first `vulnerability_reproduced` run of a test becomes its **baseline** automatically. An analyst can
choose a different baseline with `POST /executions/{id}/baseline`.

## Frontend

A single-page app with eleven routes (Overview, Projects, Findings, Evidence, Scenarios, Test Generator,
Test Execution, Regression Library, Comparison Reports, CI/CD, Settings). Every number shown comes from the
API. The JWT is kept in `sessionStorage` and sent as a bearer header; no cookies are used, so the API is not
exposed to CSRF. React Flow draws attack sequences. All evidence is rendered as text nodes, never as HTML.
