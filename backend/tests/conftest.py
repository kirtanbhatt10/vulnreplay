"""Shared fixtures: isolated database, API client, users and live demo-lab servers."""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("VULNREPLAY_ENVIRONMENT", "test")
os.environ["VULNREPLAY_SECRET_KEY"] = "test-secret-key-for-pytest-only-0123456789"
os.environ["VULNREPLAY_MIN_REQUEST_INTERVAL_MS"] = "0"
os.environ["VULNREPLAY_ALLOWED_HOSTS"] = '["localhost","127.0.0.1"]'
# Synthetic lab credentials used by generated tests.
os.environ.update(
    {
        "VULNREPLAY_SECRET_OWNER_USERNAME": "alice",
        "VULNREPLAY_SECRET_OWNER_PASSWORD": "alice-lab-password",
        "VULNREPLAY_SECRET_ATTACKER_USERNAME": "bob",
        "VULNREPLAY_SECRET_ATTACKER_PASSWORD": "bob-lab-password",
    }
)

from fastapi.testclient import TestClient  # noqa: E402

from vulnreplay import db as dbmod  # noqa: E402
from vulnreplay.config import get_settings  # noqa: E402
from vulnreplay.security import limiter  # noqa: E402

PASSWORDS = {"admin": "admin-password-123", "analyst": "analyst-password-123", "viewer": "viewer-password-123"}


@pytest.fixture()
def app_client(tmp_path: Path) -> Iterator[TestClient]:
    get_settings.cache_clear()
    url = os.environ.get("VULNREPLAY_TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'test.db'}"
    engine = dbmod.init_engine(url)
    if not url.startswith("sqlite"):
        from vulnreplay import models  # noqa: F401

        dbmod.Base.metadata.drop_all(engine)
    limiter.reset()
    from vulnreplay.main import create_app

    with TestClient(create_app()) as client:
        from vulnreplay import models as m
        from vulnreplay.security import hash_password

        s = dbmod.session_factory()()
        for role, pw in PASSWORDS.items():
            s.add(m.User(email=f"{role}@example.test", password_hash=hash_password(pw), role=role))
        s.commit()
        s.close()
        yield client


def login(client: TestClient, role: str) -> dict[str, str]:
    r = client.post("/api/v1/auth/login", json={"email": f"{role}@example.test", "password": PASSWORDS[role]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def admin(app_client: TestClient) -> dict[str, str]:
    return login(app_client, "admin")


@pytest.fixture()
def analyst(app_client: TestClient) -> dict[str, str]:
    return login(app_client, "analyst")


@pytest.fixture()
def viewer(app_client: TestClient) -> dict[str, str]:
    return login(app_client, "viewer")


# ---------------------------------------------------------------- live demo lab


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _start_lab(mode: str) -> str:
    import uvicorn

    os.environ["DEMO_MODE"] = mode
    spec = importlib.util.spec_from_file_location(f"lab_app_{mode}", ROOT / "lab" / "demo_app" / "app.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(module.app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return f"http://localhost:{port}"


@pytest.fixture(scope="session")
def lab() -> dict[str, str]:
    return {mode: _start_lab(mode) for mode in ("vulnerable", "patched", "partial")}
