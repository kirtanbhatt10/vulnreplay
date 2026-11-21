"""Authentication, RBAC, secret redaction and rate limiting."""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import User

_hasher = PasswordHasher()
_bearer = HTTPBearer(auto_error=False)

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

# ---------------------------------------------------------------- passwords / tokens


def hash_password(password: str) -> str:
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def create_access_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": user.id,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
        "iss": "vulnreplay",
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token, get_settings().secret_key, algorithms=["HS256"], issuer="vulnreplay", options={"require": ["exp"]}
    )


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer), db: Session = Depends(get_db)
) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", {"WWW-Authenticate": "Bearer"})
    if creds is None or creds.scheme.lower() != "bearer":
        raise unauthorized
    try:
        payload = decode_token(creds.credentials)
    except jwt.PyJWTError as exc:
        raise unauthorized from exc
    user = db.get(User, payload.get("sub"))
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_role(minimum: str):  # noqa: ANN201 - returns a FastAPI dependency
    def _dep(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK.get(user.role, -1) < ROLE_RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role '{minimum}'")
        return user

    return _dep


# ---------------------------------------------------------------- redaction

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-amz-security-token",
}
REDACTED = "[REDACTED]"
_TOKEN_PATTERNS = [
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWT
    re.compile(r"(?i)(\"?(?:access_token|refresh_token|password|api_key|secret)\"?\s*[:=]\s*\"?)([^\"&,\s}]+)"),
]


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}


def redact_text(text: str, secrets: list[str] | None = None) -> str:
    for secret in secrets or []:
        if secret and len(secret) >= 4:
            text = text.replace(secret, REDACTED)
    text = _TOKEN_PATTERNS[0].sub(r"\1 " + REDACTED, text)
    text = _TOKEN_PATTERNS[1].sub(REDACTED, text)
    text = _TOKEN_PATTERNS[2].sub(lambda m: m.group(1) + REDACTED, text)
    return text


def redact_obj(obj: Any, secrets: list[str] | None = None) -> Any:
    """Recursively redact sensitive values in a JSON-like structure."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            lowered = str(key).lower()
            if lowered in SENSITIVE_HEADERS or lowered in {"password", "access_token", "refresh_token", "secret"}:
                out[key] = REDACTED
            else:
                out[key] = redact_obj(value, secrets)
        return out
    if isinstance(obj, list):
        return [redact_obj(v, secrets) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj, secrets)
    return obj


# ---------------------------------------------------------------- rate limiting


class SlidingWindowLimiter:
    """Simple in-process sliding-window limiter keyed by client identity."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def login_rate_limit(request: Request) -> None:
    if not limiter.check("login:" + client_key(request), get_settings().login_rate_per_minute):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts, try again later")
