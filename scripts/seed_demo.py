#!/usr/bin/env python3
"""Populate a running VulnReplay instance with the demo-lab walkthrough, using only the public API.

    python scripts/seed_demo.py --api http://localhost:8000 --email admin@vulnreplay.local
    # docker compose lab (targets reachable only from the backend container):
    python scripts/seed_demo.py --lab-host-style compose

The admin password is read from VULNREPLAY_ADMIN_PASSWORD. Every step uses synthetic lab data.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
LOGIN = {"auth_mode": "login_flow", "login": {"path": "/api/login", "token_path": "access_token"}}
SCENARIOS = [
    # (sample, category, title, reconstruction options, run order)
    ("idor-invoice-burp.xml", "idor", "IDOR: invoices readable by other users", LOGIN,
     ["vulnerable:baseline", "partial:hotfix-1", "patched:hotfix-2", "vulnerable:release-2.4"]),
    ("missing-headers-zap.json", "security_headers", None, {"auth_mode": "none"},
     ["vulnerable:baseline", "patched:post-fix"]),
    ("password-reset-burst.jsonl", "rate_limiting", "No rate limit on password reset",
     {"auth_mode": "none", "rate_limit_requests": 12}, ["vulnerable:baseline", "patched:post-fix"]),
    ("sqli-products.http", "sql_injection", "SQL error leakage in product search", {"auth_mode": "none"},
     ["vulnerable:baseline", "patched:post-fix"]),
    ("cors-reflection.har", "cors_misconfiguration", "CORS origin reflection with credentials",
     {"auth_mode": "none"}, ["vulnerable:baseline"]),
    ("admin-authz-bypass.sarif", "authorization_bypass", None,
     {**LOGIN, "owner_username": "carol", "owner_password_secret": "CAROL_PASSWORD"},
     ["vulnerable:baseline", "patched:post-fix"]),
]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--api", default="http://localhost:8000")
    p.add_argument("--email", default="admin@vulnreplay.local")
    p.add_argument("--lab-host-style", choices=["local", "compose"], default="local")
    args = p.parse_args()
    password = os.environ.get("VULNREPLAY_ADMIN_PASSWORD")
    if not password:
        print("Set VULNREPLAY_ADMIN_PASSWORD", file=sys.stderr)
        return 2
    c = httpx.Client(base_url=args.api.rstrip("/") + "/api/v1", timeout=120)
    token = c.post("/auth/login", json={"email": args.email, "password": password}).raise_for_status().json()
    c.headers["Authorization"] = f"Bearer {token['access_token']}"

    def ok(r: httpx.Response) -> Any:
        if r.status_code >= 400:
            raise SystemExit(f"{r.request.method} {r.request.url.path} -> {r.status_code}: {r.text}")
        return r.json()

    pid = ok(c.post("/projects", json={"name": "Invoice API (demo lab)",
                                       "description": "Synthetic lab application with vulnerable, partially "
                                                      "fixed and patched builds."}))["id"]
    urls = ({"vulnerable": "http://localhost:8001", "patched": "http://localhost:8002",
             "partial": "http://localhost:8003"} if args.lab_host_style == "local" else
            {m: f"http://demo-{m}:8000" for m in ("vulnerable", "patched", "partial")})
    targets = {}
    for mode, url in urls.items():
        t = ok(c.post(f"/projects/{pid}/targets", json={"name": f"lab-{mode}", "base_url": url, "environment": "lab"}))
        ok(c.post(f"/targets/{t['id']}/authorization", json={
            "authorized": True, "authorization_note": "Isolated local demo lab owned by the operator",
            "allow_private_network": args.lab_host_style == "compose"}))
        targets[mode] = t["id"]

    for sample, category, title, options, runs in SCENARIOS:
        raw = (ROOT / "samples" / sample).read_bytes()
        ev = ok(c.post(f"/projects/{pid}/evidence", files={"file": (sample, raw)}))
        if ev["findings"]:
            fid = ev["findings"][0]["id"]
        else:
            fid = ok(c.post(f"/projects/{pid}/findings", json={
                "title": title, "category": category, "severity": "high", "evidence_id": ev["id"],
                "exchange_indexes": list(range(ev["exchange_count"]))}))["id"]
        scn = ok(c.post(f"/projects/{pid}/scenarios", json={"finding_id": fid, "options": options}))
        test = ok(c.post(f"/projects/{pid}/tests/generate", json={"scenario_id": scn["id"]}))
        ok(c.post(f"/tests/{test['id']}/approve"))
        for run in runs:
            mode, label = run.split(":")
            ex = ok(c.post("/executions", json={"test_id": test["id"], "target_id": targets[mode], "label": label,
                                                "wait": True}))
            print(f"{test['name'][:55]:55} {label:14} {ex['classification']}")
    print(f"project {pid} seeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
