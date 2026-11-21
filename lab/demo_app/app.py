"""VulnReplay demo lab application — DELIBERATELY VULNERABLE. For isolated local testing only.

One codebase, three behaviours selected with ``DEMO_MODE``:

* ``vulnerable`` — the original incident: IDOR, missing admin check, no rate limit, missing headers,
  reflected CORS, SQL error leakage.
* ``patched``    — correct fixes.
* ``partial``    — an *incomplete* fix: the IDOR endpoint returns 403 but still includes the invoice in the
  body. Used to show that a status-code change alone does not prove remediation.

All accounts and records are synthetic. Never expose this application to a network you do not control.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

MODE = os.environ.get("DEMO_MODE", "vulnerable")
if MODE not in {"vulnerable", "patched", "partial"}:
    raise SystemExit("DEMO_MODE must be vulnerable, patched or partial")

# Synthetic lab credentials (overridable). Not real accounts.
USERS = {
    "alice": {"password": os.environ.get("DEMO_ALICE_PASSWORD", "alice-lab-password"), "role": "user"},  # nosec B105
    "bob": {"password": os.environ.get("DEMO_BOB_PASSWORD", "bob-lab-password"), "role": "user"},  # nosec B105
    "carol": {"password": os.environ.get("DEMO_CAROL_PASSWORD", "carol-lab-password"), "role": "admin"},  # nosec B105
}
INVOICES = {
    1001: {"id": 1001, "owner": "alice", "owner_email": "alice@lab.vulnreplay.test", "amount": 1250.00,
           "card_last4": "4242", "memo": "Synthetic invoice A"},
    1002: {"id": 1002, "owner": "bob", "owner_email": "bob@lab.vulnreplay.test", "amount": 87.50,
           "card_last4": "1881", "memo": "Synthetic invoice B"},
}
TOKENS: dict[str, str] = {}
ALLOWED_ORIGINS = {"http://localhost:5173"}

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT)")
db.executemany("INSERT INTO products (name) VALUES (?)", [("lab widget",), ("lab gadget",)])

app = FastAPI(title=f"VulnReplay demo lab ({MODE})", docs_url=None, redoc_url=None)
_hits: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def mode_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    origin = request.headers.get("origin")
    if MODE == "vulnerable" and origin:
        response.headers["Access-Control-Allow-Origin"] = origin  # reflected: vulnerable
        response.headers["Access-Control-Allow-Credentials"] = "true"
    elif origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    if MODE != "vulnerable":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Demo-Mode"] = MODE
    return response


class LoginIn(BaseModel):
    username: str
    password: str


def current_user(authorization: str = Header(default="")) -> str:
    token = authorization.removeprefix("Bearer ").strip()
    user = TOKENS.get(token)
    if not user:
        raise HTTPException(401, "authentication required")
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": MODE}


@app.post("/api/login")
def login(body: LoginIn) -> dict[str, str]:
    user = USERS.get(body.username)
    if not user or not secrets.compare_digest(user["password"], body.password):
        raise HTTPException(401, "invalid credentials")
    token = secrets.token_urlsafe(24)
    TOKENS[token] = body.username
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user: str = Depends(current_user)) -> JSONResponse:
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        raise HTTPException(404, "not found")
    if invoice["owner"] != user:
        if MODE == "patched":
            raise HTTPException(404, "not found")
        if MODE == "partial":
            # Incomplete fix: correct status code, but the object is still serialized into the error.
            return JSONResponse({"detail": "forbidden", "invoice": invoice}, status_code=403)
    return JSONResponse(invoice)


@app.get("/api/admin/users")
def admin_users(user: str = Depends(current_user)) -> list[dict[str, str]]:
    if MODE != "vulnerable" and USERS[user]["role"] != "admin":
        raise HTTPException(403, "admin role required")
    return [{"username": u, "role": d["role"], "email": f"{u}@lab.vulnreplay.test"} for u, d in USERS.items()]


@app.post("/api/password-reset")
def password_reset(request: Request) -> dict[str, str]:
    key = request.client.host if request.client else "x"
    hits = _hits[key]
    now = time.monotonic()
    while hits and now - hits[0] > 60:
        hits.popleft()
    hits.append(now)
    if MODE != "vulnerable" and len(hits) > 5:
        raise HTTPException(429, "too many requests")
    return {"status": "if the account exists, an email was sent"}


@app.get("/api/profile")
def profile(user: str = Depends(current_user)) -> dict[str, str]:
    return {"username": user, "role": USERS[user]["role"]}


@app.get("/api/products")
def products(q: str = "") -> JSONResponse:
    try:
        if MODE == "vulnerable":
            rows = db.execute(f"SELECT id, name FROM products WHERE name LIKE '%{q}%'").fetchall()  # nosec B608
        else:
            rows = db.execute("SELECT id, name FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
    except sqlite3.Error as exc:
        if MODE == "vulnerable":
            return JSONResponse({"error": f"sqlite3.OperationalError: {exc}"}, status_code=500)
        return JSONResponse({"error": "bad request"}, status_code=400)
    return JSONResponse([{"id": r[0], "name": r[1]} for r in rows])
