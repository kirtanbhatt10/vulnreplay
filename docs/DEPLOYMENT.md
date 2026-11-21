# Deployment

## Local lab (Docker Compose)

```bash
VULNREPLAY_ADMIN_PASSWORD='choose-a-long-password' docker compose up --build
```

| Service | Exposure | Notes |
| --- | --- | --- |
| `db` (postgres:16-alpine) | internal | Data in the `dbdata` volume |
| `backend` | `127.0.0.1:8000` | Runs `alembic upgrade head`, then uvicorn as a non-root user |
| `frontend` (nginx-unprivileged) | `127.0.0.1:8080` | Serves the SPA, proxies `/api`, sets CSP and security headers |
| `demo-vulnerable`, `demo-patched`, `demo-partial` | none | `lab` network is `internal: true`: no published ports, no egress |

Ports bind to `127.0.0.1` only. Stop and wipe with `docker compose down -v`.

## Production checklist

1. **Secrets:** set `VULNREPLAY_ENVIRONMENT=production` and a random `VULNREPLAY_SECRET_KEY`
   (`python -c "import secrets;print(secrets.token_urlsafe(48))"`). The app refuses to start with the default key.
2. **Database:** PostgreSQL 14+. Run `alembic upgrade head` on deploy. Production mode never calls `create_all`.
3. **Allowlist:** set `VULNREPLAY_ALLOWED_HOSTS` to the exact staging or test hosts you own. This is the
   operator-level gate. Admin authorization in the UI is the second gate.
4. **TLS:** terminate TLS in front of the frontend/nginx and add `Strict-Transport-Security` there.
5. **CORS:** set `VULNREPLAY_CORS_ORIGINS` to the UI origin only.
6. **Test credentials:** provide `VULNREPLAY_SECRET_*` through your secret manager. Never store them as
   target variables (the API rejects secret-looking names).
7. **Replicas:** rate limiting and cancellation are in-process. Run one backend replica, or put a shared
   rate limiter and job queue in front (see the roadmap).
8. **Network egress:** give the backend egress only to the allowlisted test environments. Defence in depth
   beyond the application-level guard.
9. **Backups and retention:** evidence can contain sensitive data. Encrypt the database volume and define a
   retention policy.
10. **Bootstrap:** use `VULNREPLAY_ADMIN_EMAIL`/`VULNREPLAY_ADMIN_PASSWORD` for the first start, or
    `vulnreplay create-admin --email …` (password from `VULNREPLAY_NEW_ADMIN_PASSWORD` or a prompt). Then
    remove the bootstrap variables.

## Running without Docker

```bash
# backend
cd backend && pip install . && alembic upgrade head
uvicorn vulnreplay.main:app --host 127.0.0.1 --port 8000 --proxy-headers
# frontend
cd frontend && npm ci && npm run build   # serve dist/ with any static server; proxy /api to the backend
```

`frontend/nginx.conf` is a ready-made reverse proxy configuration.

## Optional local LLM

Run an Ollama-compatible server on the same host or as a Compose service named `ollama`, then set
`VULNREPLAY_LLM_BASE_URL=http://ollama:11434` (or `http://127.0.0.1:11434`) and `VULNREPLAY_LLM_MODEL`. Non-local
endpoints are rejected. With no LLM configured, the assistant uses its deterministic analyser.
