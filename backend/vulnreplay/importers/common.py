"""Shared helpers for evidence importers: normalized exchanges, sanitization, category inference."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import parse_qsl, urlsplit

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")


class EvidenceError(ValueError):
    """Raised when uploaded evidence is malformed or unsafe."""


@dataclass
class ParsedEvidence:
    format: str
    exchanges: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def sanitize_text(value: str | bytes | None, limit: int) -> tuple[str | None, bool]:
    """Decode, strip control characters and truncate. Returns (text, truncated)."""
    if value is None:
        return None, False
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = _CONTROL_CHARS.sub("", value)
    if len(value) > limit:
        return value[:limit], True
    return value, False


def sanitize_headers(headers: dict[str, Any] | list[tuple[str, str]] | None) -> dict[str, str]:
    items = headers.items() if isinstance(headers, dict) else (headers or [])
    out: dict[str, str] = {}
    for name, value in items:
        name = str(name).strip()
        if not _HEADER_NAME.match(name) or name.startswith(":"):
            continue  # drop HTTP/2 pseudo headers and invalid names
        clean, _ = sanitize_text(str(value), 8192)
        out[name] = (clean or "").replace("\r", "").replace("\n", " ")
    return out


def parse_cookies(headers: dict[str, str]) -> dict[str, str]:
    raw = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
    jar: SimpleCookie = SimpleCookie()
    try:
        jar.load(raw)
    except CookieError:
        return {}
    return {k: m.value for k, m in jar.items()}


def build_exchange(
    *,
    index: int,
    method: str,
    url: str,
    headers: dict[str, Any] | list[tuple[str, str]] | None = None,
    body: str | bytes | None = None,
    response_status: int | None = None,
    response_headers: dict[str, Any] | list[tuple[str, str]] | None = None,
    response_body: str | bytes | None = None,
    timestamp: str | None = None,
    source_ref: str = "",
    body_limit: int = 65536,
) -> dict[str, Any]:
    method = (method or "").upper().strip()
    if method not in ALLOWED_METHODS:
        raise EvidenceError(f"Unsupported HTTP method in evidence: {method!r}")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise EvidenceError(f"Evidence URL must be absolute http(s): {url[:120]!r}")
    req_headers = sanitize_headers(headers)
    req_body, req_trunc = sanitize_text(body, body_limit)
    exchange: dict[str, Any] = {
        "index": index,
        "method": method,
        "url": url,
        "path": parts.path or "/",
        "headers": req_headers,
        "cookies": parse_cookies(req_headers),
        "query": dict(parse_qsl(parts.query, keep_blank_values=True)),
        "body": req_body,
        "body_truncated": req_trunc,
        "timestamp": timestamp,
        "source_ref": source_ref,
        "response": None,
    }
    if response_status is not None or response_body is not None:
        resp_body, resp_trunc = sanitize_text(response_body, body_limit)
        exchange["response"] = {
            "status": int(response_status) if response_status is not None else None,
            "headers": sanitize_headers(response_headers),
            "body": resp_body,
            "body_truncated": resp_trunc,
        }
    return exchange


def parse_raw_http_request(text: str) -> tuple[str, str, list[tuple[str, str]], str]:
    """Parse a raw HTTP/1.x request. Returns (method, target, headers, body)."""
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [ln for ln in head.split("\n") if ln.strip()]
    if not lines:
        raise EvidenceError("Empty HTTP request")
    parts = lines[0].split()
    if len(parts) < 2 or not re.match(r"^[A-Z]+$", parts[0]):
        raise EvidenceError("Malformed HTTP request line")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            raise EvidenceError("Malformed HTTP header line")
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return parts[0], parts[1], headers, body


def parse_raw_http_response(text: str) -> tuple[int, list[tuple[str, str]], str]:
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [ln for ln in head.split("\n") if ln.strip()]
    if not lines:
        raise EvidenceError("Empty HTTP response")
    match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
    if not match:
        raise EvidenceError("Malformed HTTP status line")
    headers = []
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
    return int(match.group(1)), headers, body


def absolute_url(target: str, headers: list[tuple[str, str]], default_scheme: str = "https") -> str:
    if target.startswith(("http://", "https://")):
        return target
    host = next((v for k, v in headers if k.lower() == "host"), None)
    if not host:
        raise EvidenceError("Request has no absolute URL and no Host header")
    return f"{default_scheme}://{host}{target}"


CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("idor", ("idor", "bola", "insecure direct object", "object level authorization", "cwe-639")),
    (
        "authorization_bypass",
        (
            "authorization bypass",
            "privilege escalation",
            "missing authorization",
            "cwe-285",
            "cwe-862",
            "cwe-863",
            "function level",
        ),
    ),
    ("broken_access_control", ("access control", "forced browsing", "cwe-284")),
    ("authentication_failure", ("authentication", "brute force", "credential", "cwe-287", "cwe-307")),
    ("sql_injection", ("sql injection", "sqli", "cwe-89")),
    ("cors_misconfiguration", ("cors", "cross-origin", "access-control-allow-origin", "cwe-942")),
    ("rate_limiting", ("rate limit", "rate-limit", "throttl", "cwe-770", "cwe-799")),
    (
        "security_headers",
        (
            "header",
            "content-security-policy",
            "hsts",
            "strict-transport",
            "x-frame-options",
            "x-content-type-options",
            "clickjacking",
            "cwe-693",
            "cwe-1021",
        ),
    ),
    ("session_management", ("session", "cookie", "cwe-384", "cwe-613", "cwe-614", "cwe-1004")),
    ("input_validation", ("input validation", "injection", "xss", "cross site scripting", "cwe-20", "cwe-79")),
]

SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "information": "info",
    "note": "low",
    "warning": "medium",
    "error": "high",
    "none": "info",
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}


def infer_category(*texts: str | None) -> str:
    haystack = " ".join(t for t in texts if t).lower()
    for category, words in CATEGORY_KEYWORDS:
        if any(w in haystack for w in words):
            return category
    return "other"


def normalize_severity(value: Any) -> str:
    return SEVERITY_ALIASES.get(str(value).strip().lower(), "medium")
