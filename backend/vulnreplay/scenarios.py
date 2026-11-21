"""Attack scenario model and reconstruction from imported evidence.

Reconstruction is deterministic and evidence-grounded: every request in a scenario comes from an
imported exchange, credentials are replaced by named secret placeholders, and the secure
expectation is derived from the vulnerability category plus what the original response exposed.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from .security import SENSITIVE_HEADERS
from .testdef import DESTRUCTIVE_PATTERNS

CATEGORIES = [
    "broken_access_control",
    "idor",
    "authentication_failure",
    "authorization_bypass",
    "sql_injection",
    "input_validation",
    "security_headers",
    "rate_limiting",
    "cors_misconfiguration",
    "session_management",
    "other",
]
RISK_TEXT = {
    "idor": "Users can read or modify objects belonging to other users (OWASP API1 BOLA).",
    "broken_access_control": "Resources are reachable without the required permissions (OWASP A01).",
    "authorization_bypass": "Privileged functionality is reachable by lower-privileged users (OWASP API5).",
    "authentication_failure": "Protected endpoints can be used without valid authentication (OWASP A07).",
    "sql_injection": "User input reaches SQL queries unsafely; data disclosure or tampering possible (A03).",
    "input_validation": "Untrusted input is accepted or reflected without validation.",
    "security_headers": "Missing browser security controls increase exposure to client-side attacks (A05).",
    "rate_limiting": "Missing throttling enables brute force, enumeration and resource exhaustion (API4).",
    "cors_misconfiguration": "Untrusted origins may read authenticated responses cross-origin.",
    "session_management": "Session tokens are not adequately protected or invalidated.",
    "other": "Impact must be assessed manually.",
}
DEFAULT_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]
SQL_ERRORS = [
    "SQL syntax",
    "SQLSTATE",
    "sqlite3.OperationalError",
    "unterminated quoted string",
    "ORA-01756",
    "psycopg",
    "Unclosed quotation mark",
]
SENSITIVE_KEYS = re.compile(
    r"(?i)(email|ssn|phone|address|card|iban|dob|birth|salary|owner|secret|token|"
    r"account|balance|password)"
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
UNTRUSTED_ORIGIN = "https://untrusted-origin.vulnreplay.invalid"


class ScenarioStep(BaseModel):
    order: int
    actor: str = "attacker"
    purpose: str
    method: str
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    evidence_ref: str | None = None
    observed_status: int | None = None
    repeat: int = 1


class AttackScenario(BaseModel):
    scenario_id: str = Field(default_factory=lambda: "scn_" + uuid.uuid4().hex[:12])
    title: str
    category: str
    target_endpoint: str
    method: str
    authentication_context: dict[str, Any]
    preconditions: list[str]
    request_sequence: list[ScenarioStep]
    expected_behavior: str
    observed_behavior: str
    evidence_references: list[str]
    reproduction_instructions: list[str]
    risk_assessment: dict[str, Any]
    secure_expectations: list[dict[str, Any]]
    sensitive_markers: list[str] = Field(default_factory=list)
    multi_step: bool = False
    login_flow: dict[str, Any] | None = None
    review_notes: list[str] = Field(default_factory=list)


class LoginFlow(BaseModel):
    path: str = "/api/login"
    username_field: str = "username"
    password_field: str = "password"  # noqa: S105 - JSON field name, not a secret
    token_path: str = "access_token"  # noqa: S105 - JSON path, not a secret


class ReconstructOptions(BaseModel):
    auth_mode: Literal["static_secret", "login_flow", "none"] = "static_secret"
    login: LoginFlow | None = None
    owner_username: str = "{{secret:OWNER_USERNAME}}"
    attacker_username: str = "{{secret:ATTACKER_USERNAME}}"
    owner_password_secret: str = Field(default="OWNER_PASSWORD", pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    attacker_password_secret: str = Field(default="ATTACKER_PASSWORD", pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    rate_limit_requests: int = Field(default=20, ge=2, le=100)


def _auth_context(exchange: dict[str, Any], actor: str | None) -> dict[str, Any]:
    headers = {k.lower(): v for k, v in exchange.get("headers", {}).items()}
    if headers.get("authorization", "").lower().startswith("bearer"):
        kind = "bearer"
    elif "authorization" in headers:
        kind = "authorization-header"
    elif exchange.get("cookies"):
        kind = "cookie-session"
    elif any(h in headers for h in ("x-api-key", "x-auth-token")):
        kind = "api-key"
    else:
        kind = "none"
    return {
        "type": kind,
        "principal": actor or ("authenticated user" if kind != "none" else "anonymous"),
        "credentials": "replaced with secret placeholders" if kind != "none" else "none",
    }


def _placeholder_headers(exchange: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in exchange.get("headers", {}).items():
        low = name.lower()
        if low in {"host", "content-length", "connection", "accept-encoding"}:
            continue
        if low == "authorization":
            out[name] = (
                "Bearer {{secret:ATTACKER_TOKEN}}" if value.lower().startswith("bearer") else "{{secret:AUTH_HEADER}}"
            )
        elif low == "cookie":
            out[name] = "{{secret:SESSION_COOKIE}}"
        elif low in SENSITIVE_HEADERS:
            out[name] = "{{secret:" + re.sub(r"[^A-Z0-9]", "_", name.upper()) + "}}"
        else:
            out[name] = value
    return out


def _markers_from_response(exchange: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Find values in the original response that prove data exposure. Returns (markers, json_paths)."""
    body = (exchange.get("response") or {}).get("body") or ""
    markers: list[str] = []
    paths: list[str] = []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        data = None

    def walk(obj: Any, prefix: str) -> None:
        if len(markers) >= 3:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = f"{prefix}.{k}" if prefix else k
                if SENSITIVE_KEYS.search(k) and isinstance(v, str | int) and len(str(v)) >= 4:
                    markers.append(str(v))
                    if not prefix:
                        paths.append(p)
                walk(v, p)
        elif isinstance(obj, list) and obj:
            walk(obj[0], prefix + "[0]")

    walk(data, "")
    if not markers:
        markers = EMAIL.findall(body)[:2]
    return list(dict.fromkeys(markers)), paths[:3]


def _payload_is_safe(exchange: dict[str, Any]) -> bool:
    blob = " ".join([exchange.get("url", ""), exchange.get("body") or ""])
    return not DESTRUCTIVE_PATTERNS.search(blob)


def _expectations(
    category: str, exchange: dict[str, Any], markers: list[str], paths: list[str], opts: ReconstructOptions
) -> tuple[list[dict[str, Any]], str, list[str]]:
    notes: list[str] = []
    resp_headers = {k.lower() for k in ((exchange.get("response") or {}).get("headers") or {})}
    if category in {"idor", "broken_access_control", "authorization_bypass"}:
        exp: list[dict[str, Any]] = [
            {
                "type": "status_in",
                "values": [401, 403, 404],
                "description": "access to another principal's resource is denied",
            }
        ]
        exp += [
            {"type": "body_not_contains", "value": m, "description": f"exposed value #{i + 1} is not returned"}
            for i, m in enumerate(markers)
        ]
        exp += [{"type": "json_path_absent", "path": p, "description": f"field '{p}' is not returned"} for p in paths]
        if not markers:
            notes.append("No sensitive marker found in the original response; add a body assertion manually.")
        text = "Requests for objects owned by another user are rejected and return none of the owner's data."
    elif category == "authentication_failure":
        exp = [{"type": "status_in", "values": [401, 403], "description": "unauthenticated request is rejected"}]
        exp += [
            {"type": "body_not_contains", "value": m, "description": "protected data is not returned"} for m in markers
        ]
        text = "The endpoint requires valid authentication."
    elif category == "sql_injection":
        exp = [{"type": "status_not_in", "values": [500], "description": "no server error on injected input"}]
        exp += [
            {"type": "body_not_contains", "value": s, "description": f"no database error signature '{s}'"}
            for s in SQL_ERRORS
        ]
        text = "Injected input is handled as data: no database errors and no unexpected data."
    elif category == "security_headers":
        missing = [h for h in DEFAULT_HEADERS if h.lower() not in resp_headers] or DEFAULT_HEADERS[:3]
        exp = [{"type": "header_present", "name": h, "description": f"{h} header is set"} for h in missing]
        text = "The response sets the expected browser security headers."
    elif category == "cors_misconfiguration":
        exp = [
            {
                "type": "header_not_equals",
                "name": "Access-Control-Allow-Origin",
                "value": UNTRUSTED_ORIGIN,
                "description": "untrusted origin is not reflected",
            },
            {
                "type": "header_not_equals",
                "name": "Access-Control-Allow-Origin",
                "value": "*",
                "description": "wildcard origin is not allowed",
            },
        ]
        text = "Untrusted origins are not granted cross-origin read access."
    elif category == "rate_limiting":
        exp = [
            {
                "type": "sequence_any_status_in",
                "values": [429],
                "description": f"throttling (HTTP 429) is enforced within {opts.rate_limit_requests} requests",
            }
        ]
        text = "Repeated requests are throttled."
    elif category == "session_management":
        exp = [
            {
                "type": "header_contains",
                "name": "set-cookie",
                "value": "HttpOnly",
                "description": "session cookie is HttpOnly",
            },
            {
                "type": "header_contains",
                "name": "set-cookie",
                "value": "SameSite",
                "description": "session cookie sets SameSite",
            },
        ]
        text = "Session cookies carry protective attributes."
    elif category == "input_validation":
        exp = [{"type": "status_in", "values": [400, 422], "description": "invalid input is rejected"}]
        text = "Invalid input is rejected with a client error."
    else:
        exp = [{"type": "status_not_in", "values": [500], "description": "no server error"}]
        notes.append("Category 'other': secure expectations must be reviewed and refined manually.")
        text = "To be defined by the reviewer."
    return exp, text, notes


def reconstruct(
    finding: dict[str, Any], exchanges: list[dict[str, Any]], evidence_id: str, opts: ReconstructOptions | None = None
) -> AttackScenario:
    opts = opts or ReconstructOptions()
    if not exchanges:
        raise ValueError("finding has no HTTP exchanges to reconstruct from")
    category: str = str(finding.get("category")) if finding.get("category") in CATEGORIES else "other"
    if category == "rate_limiting":
        exchanges = exchanges[-1:]  # a burst is replayed as one repeated, bounded request
    primary = exchanges[-1]
    parts = urlsplit(primary["url"])
    markers, paths = _markers_from_response(primary)
    secure, expected_text, notes = _expectations(category, primary, markers, paths, opts)
    auth = _auth_context(primary, primary.get("actor"))
    resp = primary.get("response") or {}
    observed = (
        (
            f"HTTP {resp.get('status')} with {len(resp.get('body') or '')} bytes"
            + (f"; exposed {len(markers)} sensitive value(s)" if markers else "")
        )
        if resp
        else "no response captured"
    )

    steps: list[ScenarioStep] = []
    multi = category in {"idor", "broken_access_control", "authorization_bypass"} and opts.auth_mode == "login_flow"
    if multi:
        login = opts.login or LoginFlow()
        steps = [
            ScenarioStep(
                order=1,
                actor="owner",
                purpose="authenticate as resource owner (User A)",
                method="POST",
                path=login.path,
            ),
            ScenarioStep(
                order=2,
                actor="owner",
                purpose="owner reads own resource (control request)",
                method=primary["method"],
                path=parts.path,
                query=primary.get("query", {}),
            ),
            ScenarioStep(
                order=3,
                actor="attacker",
                purpose="authenticate as a different user (User B)",
                method="POST",
                path=login.path,
            ),
            ScenarioStep(
                order=4,
                actor="attacker",
                purpose="attempt to access User A's resource",
                method=primary["method"],
                path=parts.path,
                query=primary.get("query", {}),
                evidence_ref=f"{evidence_id}#{primary['index']}",
                observed_status=resp.get("status"),
            ),
        ]
    else:
        for n, ex in enumerate(exchanges, start=1):
            if not _payload_is_safe(ex):
                notes.append(f"Exchange {ex['index']} contains a destructive payload and was excluded.")
                continue
            steps.append(
                ScenarioStep(
                    order=n,
                    actor=ex.get("actor") or "attacker",
                    purpose="replay original request" if ex is primary else "preparatory request",
                    method=ex["method"],
                    path=urlsplit(ex["url"]).path or "/",
                    query=ex.get("query", {}),
                    headers=_placeholder_headers(ex) if opts.auth_mode != "none" else {},
                    body=ex.get("body"),
                    evidence_ref=f"{evidence_id}#{ex['index']}",
                    observed_status=(ex.get("response") or {}).get("status"),
                )
            )
        if category == "cors_misconfiguration" and steps:
            steps[-1].headers["Origin"] = UNTRUSTED_ORIGIN
        if category == "rate_limiting" and steps:
            steps[-1].repeat = opts.rate_limit_requests
        if category == "authentication_failure" and steps:
            steps[-1].headers = {
                k: v for k, v in steps[-1].headers.items() if k.lower() not in {"authorization", "cookie"}
            }
    if not steps:
        raise ValueError("no safe requests remain after filtering destructive payloads")

    preconditions = [
        "Target environment is explicitly authorized for testing",
        "Only synthetic test accounts and data are used",
    ]
    if auth["type"] != "none" or multi:
        preconditions.append("Test credentials are provided through VULNREPLAY_SECRET_* variables")
    if multi:
        preconditions.append("User A owns the resource under test; User B is a distinct non-privileged user")

    return AttackScenario(
        title=finding.get("title") or f"{category} on {parts.path}",
        category=category,
        target_endpoint=parts.path or "/",
        method=primary["method"],
        authentication_context=auth,
        preconditions=preconditions,
        request_sequence=steps,
        expected_behavior=expected_text,
        observed_behavior=observed,
        evidence_references=[f"{evidence_id}#{ex['index']}" for ex in exchanges],
        reproduction_instructions=[f"{s.order}. As {s.actor}: {s.purpose} — {s.method} {s.path}" for s in steps],
        risk_assessment={
            "severity": finding.get("severity", "medium"),
            "impact": RISK_TEXT[category],
            "cwe": finding.get("cwe"),
        },
        secure_expectations=secure,
        sensitive_markers=markers,
        multi_step=multi,
        login_flow=(
            {
                **(opts.login or LoginFlow()).model_dump(),
                "owner_username": opts.owner_username,
                "attacker_username": opts.attacker_username,
                "marker_paths": paths,
                "owner_password_secret": opts.owner_password_secret,
                "attacker_password_secret": opts.attacker_password_secret,
            }
            if multi
            else None
        ),
        review_notes=notes,
    )
