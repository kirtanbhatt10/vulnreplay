"""API security: authentication, RBAC, upload restrictions, rate limiting, CORS, headers."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnreplay.config import get_settings

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def make_project(client: TestClient, headers: dict[str, str]) -> str:
    r = client.post("/api/v1/projects", json={"name": "Lab"}, headers=headers)
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def test_health_and_security_headers(app_client: TestClient) -> None:
    r = app_client.get("/healthz")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_authentication_required(app_client: TestClient) -> None:
    for path in ("/api/v1/projects", "/api/v1/dashboard", "/api/v1/settings", "/api/v1/auth/me"):
        assert app_client.get(path).status_code == 401
    assert app_client.get("/api/v1/projects", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_forged_and_alg_none_tokens_rejected(app_client: TestClient) -> None:
    import jwt

    forged = jwt.encode(
        {"sub": "x", "iss": "vulnreplay", "exp": 9999999999}, "wrong-key-wrong-key-wrong-key-00", algorithm="HS256"
    )
    none_tok = jwt.encode({"sub": "x", "iss": "vulnreplay", "exp": 9999999999}, key=None, algorithm="none")
    for tok in (forged, none_tok):
        assert app_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_login_failures_are_generic(app_client: TestClient) -> None:
    a = app_client.post("/api/v1/auth/login", json={"email": "nobody@example.test", "password": "x" * 12})
    b = app_client.post("/api/v1/auth/login", json={"email": "admin@example.test", "password": "x" * 12})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_login_rate_limited(app_client: TestClient) -> None:
    codes = [
        app_client.post(
            "/api/v1/auth/login", json={"email": "admin@example.test", "password": "bad-password!"}
        ).status_code
        for _ in range(get_settings().login_rate_per_minute + 2)
    ]
    assert codes[-1] == 429


def test_rbac(app_client: TestClient, admin: dict[str, str], analyst: dict[str, str], viewer: dict[str, str]) -> None:
    assert app_client.post("/api/v1/projects", json={"name": "x"}, headers=viewer).status_code == 403
    pid = make_project(app_client, analyst)
    assert app_client.get("/api/v1/projects", headers=viewer).status_code == 200
    assert app_client.get("/api/v1/users", headers=analyst).status_code == 403
    assert app_client.get("/api/v1/users", headers=admin).status_code == 200
    t = app_client.post(
        f"/api/v1/projects/{pid}/targets", json={"name": "local", "base_url": "http://localhost:9"}, headers=analyst
    ).json()
    body = {"authorized": True, "authorization_note": "lab owner approved"}
    assert app_client.post(f"/api/v1/targets/{t['id']}/authorization", json=body, headers=analyst).status_code == 403
    assert app_client.post(f"/api/v1/targets/{t['id']}/authorization", json=body, headers=admin).status_code == 200
    assert app_client.get("/api/v1/audit", headers=admin).status_code == 200
    r = app_client.post(
        "/api/v1/users", json={"email": "new@example.test", "password": "short", "role": "viewer"}, headers=admin
    )
    assert r.status_code == 422


def test_admin_cannot_demote_self(app_client: TestClient, admin: dict[str, str]) -> None:
    me = app_client.get("/api/v1/auth/me", headers=admin).json()
    assert app_client.patch(f"/api/v1/users/{me['id']}", json={"role": "viewer"}, headers=admin).status_code == 400


def test_target_validation_blocks_external_hosts(app_client: TestClient, analyst: dict[str, str]) -> None:
    pid = make_project(app_client, analyst)
    for url in (
        "https://example.com",
        "http://169.254.169.254",
        "http://user:pw@localhost:1",
        "file:///etc",
        "http://localhost:1/path",
    ):
        r = app_client.post(f"/api/v1/projects/{pid}/targets", json={"name": "x", "base_url": url}, headers=analyst)
        assert r.status_code == 422, url
    r = app_client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"name": "x", "base_url": "http://localhost:1", "variables": {"api_token": "x"}},
        headers=analyst,
    )
    assert r.status_code == 422


def test_upload_restrictions(app_client: TestClient, analyst: dict[str, str]) -> None:
    pid = make_project(app_client, analyst)
    url = f"/api/v1/projects/{pid}/evidence"
    ok = app_client.post(
        url, files={"file": ("x.har", (SAMPLES / "cors-reflection.har").read_bytes())}, headers=analyst
    )
    assert ok.status_code == 201
    assert len(ok.json()["sha256"]) == 64
    big = b"{" + b" " * (get_settings().max_upload_bytes + 10) + b"}"
    assert app_client.post(url, files={"file": ("big.json", big)}, headers=analyst).status_code == 413
    assert app_client.post(url, files={"file": ("p.pkl", b"\x80\x04\x95...")}, headers=analyst).status_code == 422
    assert app_client.post(url, files={"file": ("x.json", b"{bad")}, headers=analyst).status_code == 422
    assert (
        app_client.post(url, files={"file": ("x.json", b"{}")}, data={"format": "exe"}, headers=analyst).status_code
        == 422
    )
    # path traversal in filename is neutralised
    r = app_client.post(
        url, files={"file": ("../../etc/passwd.har", (SAMPLES / "cors-reflection.har").read_bytes())}, headers=analyst
    )
    assert "/" not in r.json()["filename"]


def test_evidence_view_redacts_credentials(app_client: TestClient, analyst: dict[str, str]) -> None:
    pid = make_project(app_client, analyst)
    up = app_client.post(
        f"/api/v1/projects/{pid}/evidence",
        files={"file": ("b.xml", (SAMPLES / "idor-invoice-burp.xml").read_bytes())},
        headers=analyst,
    ).json()
    ev = app_client.get(f"/api/v1/evidence/{up['id']}", headers=analyst).json()
    assert ev["exchanges"][0]["headers"]["Authorization"] == "[REDACTED]"
    assert "bob-captured-token" not in str(ev)
    original = app_client.get(f"/api/v1/evidence/{up['id']}/original", headers=analyst)
    assert original.headers["content-type"] == "application/octet-stream"
    assert "attachment" in original.headers["content-disposition"]


def test_cors_only_allows_configured_origins(app_client: TestClient) -> None:
    bad = app_client.options(
        "/api/v1/projects", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"}
    )
    assert "access-control-allow-origin" not in bad.headers
    good = app_client.options(
        "/api/v1/projects", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"}
    )
    assert good.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_sql_injection_in_filters_is_harmless(app_client: TestClient, analyst: dict[str, str]) -> None:
    pid = make_project(app_client, analyst)
    r = app_client.get(f"/api/v1/projects/{pid}/findings", params={"severity": "' OR 1=1 --"}, headers=analyst)
    assert r.status_code == 200 and r.json() == []
    r = app_client.get(f"/api/v1/projects/{pid}/tests", params={"q": "'; DROP TABLE users; --"}, headers=analyst)
    assert r.status_code == 200
    assert app_client.get("/api/v1/projects", headers=analyst).status_code == 200


def test_production_refuses_default_secret() -> None:
    import pytest

    from vulnreplay.config import Settings

    with pytest.raises(RuntimeError):
        Settings(environment="production", secret_key="too-short").assert_safe_for_production()
