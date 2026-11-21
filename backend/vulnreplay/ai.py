"""Optional, evidence-grounded AI security assistant.

Two providers:

* ``deterministic`` (default, offline): rule-based analysis built only from stored evidence and
  execution results. Always available, never invents facts.
* ``ollama``: a local LLM reached over an Ollama-compatible HTTP API on a loopback address. The model
  receives only redacted evidence, must answer in a fixed JSON schema, and its output is validated
  and grounded: claimed verified facts must quote text that exists in the evidence, otherwise they
  are downgraded to hypotheses.

The assistant never executes anything; any test definition it proposes is stored as an unapproved
draft that requires human approval.
"""

from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field, ValidationError

from .config import get_settings
from .regression import CLASSIFICATIONS
from .scenarios import RISK_TEXT
from .security import redact_obj

Task = Literal["explain_finding", "summarize_evidence", "explain_result", "suggest_remediation", "report_summary"]

REMEDIATION = {
    "idor": [
        "Enforce object ownership checks server-side on every read/write (not only in the UI).",
        "Derive the owner from the authenticated session, never from a client-supplied id.",
        "Return 404 for foreign objects to avoid confirming existence, and never include the object body.",
    ],
    "broken_access_control": [
        "Deny by default; centralise authorization middleware.",
        "Add policy tests for every role/resource pair.",
    ],
    "authorization_bypass": [
        "Check the caller's role in the handler or a shared dependency for admin functions.",
        "Do not rely on hidden routes or client-side flags.",
    ],
    "authentication_failure": [
        "Require authentication middleware on every protected route.",
        "Validate token signature, expiry, issuer and audience.",
    ],
    "sql_injection": [
        "Use parameterised queries / ORM bind parameters exclusively.",
        "Return generic error messages; log details server-side only.",
    ],
    "security_headers": [
        "Set headers centrally (middleware or reverse proxy) so new routes inherit them.",
        "Add HSTS, CSP, X-Content-Type-Options: nosniff and frame protections.",
    ],
    "rate_limiting": [
        "Apply per-account and per-IP limits on authentication and expensive endpoints.",
        "Return 429 with Retry-After; monitor limit hits.",
    ],
    "cors_misconfiguration": [
        "Use an explicit origin allowlist; never reflect the Origin header.",
        "Do not combine wildcard origins with credentials.",
    ],
    "session_management": [
        "Set HttpOnly, Secure and SameSite on session cookies.",
        "Rotate session ids on login and invalidate them on logout.",
    ],
    "input_validation": ["Validate input against a strict schema and reject unknown fields."],
    "other": ["Review the finding manually and define the expected secure behaviour."],
}


class AssistantAnswer(BaseModel):
    summary: str
    verified_facts: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    suggested_tests: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "low"
    provider: str = "deterministic"
    grounding_notes: list[str] = Field(default_factory=list)


def _exchange_facts(exchanges: list[dict[str, Any]]) -> list[str]:
    facts = []
    for ex in exchanges[:10]:
        resp = ex.get("response") or {}
        line = f"Evidence #{ex['index']}: {ex['method']} {ex.get('path', ex['url'])}"
        if resp.get("status") is not None:
            line += f" returned HTTP {resp['status']}"
        if resp.get("body"):
            line += f" with a {len(resp['body'])}-byte body"
        auth = [h for h in ex.get("headers", {}) if h.lower() in {"authorization", "cookie", "x-api-key"}]
        if auth:
            line += f"; request carried credentials ({', '.join(auth)})"
        facts.append(line + ".")
    return facts


def deterministic(task: Task, ctx: dict[str, Any]) -> AssistantAnswer:
    finding = ctx.get("finding") or {}
    category = finding.get("category") or ctx.get("category") or "other"
    exchanges = ctx.get("exchanges") or []
    execution = ctx.get("execution") or {}
    facts = _exchange_facts(exchanges)
    if finding:
        facts.insert(
            0,
            f"Finding '{finding.get('title')}' was imported from {finding.get('source_tool')} with "
            f"severity {finding.get('severity')}.",
        )
    unknowns = []
    if not any((e.get("response") or {}).get("body") for e in exchanges):
        unknowns.append("The original response body was not captured, so data exposure cannot be confirmed.")
    unknowns.append("Whether the vulnerable behaviour exists in other endpoints or environments has not been tested.")
    hypotheses = [RISK_TEXT.get(category, RISK_TEXT["other"])]
    tests = []
    if category in {"idor", "broken_access_control", "authorization_bypass"}:
        tests.append(
            "Replay the request as a second synthetic user and assert 403/404 plus absence of the "
            "owner's data in the body (not just the status code)."
        )
    if category == "rate_limiting":
        tests.append("Send a bounded burst (e.g. 20 requests) and assert at least one HTTP 429.")
    if category == "security_headers":
        tests.append("Assert presence of each missing header on this and sibling routes.")
    if not tests:
        tests.append("Replay the original request and assert the secure expectation defined in the scenario.")

    summary = f"{finding.get('title', 'This finding')} is categorised as {category.replace('_', ' ')}."
    confidence: Literal["low", "medium", "high"] = "medium" if exchanges else "low"
    if task == "explain_result" and execution:
        cls = execution.get("classification")
        reasons = (execution.get("comparison") or {}).get("reasons") or execution.get("result", {}).get("reasons", [])
        summary = f"The execution was classified as '{cls}'."
        facts = [f"Classification: {cls} (one of {', '.join(CLASSIFICATIONS)})."]
        facts += [str(r) for r in (reasons or [])][:10]
        for step in (execution.get("result") or {}).get("steps", []):
            for a in step.get("assertions", []):
                facts.append(
                    f"Step {step['id']}: '{a.get('description') or a['type']}' "
                    f"{'passed' if a['passed'] else 'failed'} ({a.get('detail')})."
                )
        hypotheses = []
        if cls == "regression_detected":
            hypotheses.append("A recent change (code, configuration or dependency) likely reintroduced the issue.")
        if cls == "inconclusive":
            hypotheses.append("The test may not assert enough of the response to distinguish fixed from vulnerable.")
        confidence = (
            "high" if cls in {"vulnerability_reproduced", "remediation_verified", "regression_detected"} else "low"
        )
    elif task == "summarize_evidence":
        summary = f"{len(exchanges)} HTTP exchange(s) imported."
    return AssistantAnswer(
        summary=summary,
        verified_facts=facts,
        hypotheses=hypotheses,
        suggested_tests=tests,
        unknowns=unknowns,
        recommendations=REMEDIATION.get(category, REMEDIATION["other"]),
        confidence=confidence,
        provider="deterministic",
    )


SYSTEM_PROMPT = (
    "You are a security analysis assistant. Use ONLY the JSON evidence provided. Respond with a single JSON "
    "object with keys: summary, verified_facts, hypotheses, suggested_tests, unknowns, recommendations, "
    "confidence (low|medium|high). verified_facts must only contain statements directly supported by the "
    "evidence and should quote the exact supporting text in double quotes. Never claim a vulnerability was "
    "exploited or fixed unless an execution result in the evidence says so. Suggested tests must be safe and "
    "non-destructive. If information is missing, list it under unknowns."
)


def _ground(answer: AssistantAnswer, evidence_blob: str) -> AssistantAnswer:
    kept, moved = [], []
    for fact in answer.verified_facts:
        quotes = [q for q in fact.split('"')[1::2] if len(q) >= 3]
        if quotes and all(q in evidence_blob for q in quotes):
            kept.append(fact)
        else:
            moved.append(fact)
    answer.verified_facts = kept
    answer.hypotheses = answer.hypotheses + [f"(unverified) {m}" for m in moved]
    if moved:
        answer.grounding_notes.append(f"{len(moved)} claimed fact(s) lacked supporting quotes and were downgraded.")
    return answer


def _ollama(task: Task, ctx: dict[str, Any]) -> AssistantAnswer:
    settings = get_settings()
    base = settings.llm_base_url or ""
    host = (urlsplit(base).hostname or "").lower()
    if host not in {"localhost", "127.0.0.1", "::1", "ollama"}:
        raise RuntimeError("LLM endpoint must be a local address")
    evidence = redact_obj(ctx)
    blob = json.dumps(evidence, default=str)[:24000]
    payload = {
        "model": settings.llm_model,
        "stream": False,
        "format": "json",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Task: {task}\nEvidence JSON:\n{blob}"},
        ],
    }
    resp = httpx.post(
        base.rstrip("/") + "/api/chat", json=payload, timeout=settings.llm_timeout_seconds, follow_redirects=False
    )
    resp.raise_for_status()
    content = resp.json().get("message", {}).get("content", "{}")
    answer = AssistantAnswer.model_validate({**json.loads(content), "provider": f"ollama:{settings.llm_model}"})
    return _ground(answer, blob)


def assist(task: Task, ctx: dict[str, Any], provider: str = "auto") -> AssistantAnswer:
    settings = get_settings()
    if provider == "ollama" or (provider == "auto" and settings.llm_base_url):
        try:
            return _ollama(task, ctx)
        except (httpx.HTTPError, RuntimeError, ValidationError, json.JSONDecodeError) as exc:
            fallback = deterministic(task, ctx)
            fallback.grounding_notes.append(
                f"Local LLM unavailable ({type(exc).__name__}); used deterministic analysis."
            )
            return fallback
    return deterministic(task, ctx)


TEST_PROMPT = (
    "Produce a VulnReplay test definition as JSON for the attack scenario provided. Schema: "
    '{"schema_version":"1","id":str,"name":str,"category":str,"steps":[{"id":str,"role":"setup|probe",'
    '"request":{"method":str,"path":"/relative","headers":{},"query":{},"json":any},'
    '"assert_secure":[{"type":"status_in|body_not_contains|header_present|json_path_absent|...",'
    '"values":[int],"value":str,"name":str,"path":str,"description":str}]}]}. '
    "Use only endpoints present in the scenario. Use {{secret:NAME}} for credentials. Never include destructive "
    "payloads. Respond with JSON only."
)


def ai_generate_definition(scenario: dict[str, Any], fallback: Any) -> tuple[dict[str, Any], str]:
    """Ask the local LLM for a test definition; fall back to the deterministic generator.

    Returns (definition_dict, origin). The result is validated by the caller and is always stored as an
    unapproved draft.
    """
    settings = get_settings()
    if not settings.llm_base_url:
        return fallback, "generated"
    try:
        host = (urlsplit(settings.llm_base_url).hostname or "").lower()
        if host not in {"localhost", "127.0.0.1", "::1", "ollama"}:
            raise RuntimeError("LLM endpoint must be a local address")
        payload = {
            "model": settings.llm_model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": TEST_PROMPT},
                {"role": "user", "content": json.dumps(redact_obj(scenario))[:20000]},
            ],
        }
        resp = httpx.post(
            settings.llm_base_url.rstrip("/") + "/api/chat",
            json=payload,
            timeout=settings.llm_timeout_seconds,
            follow_redirects=False,
        )
        resp.raise_for_status()
        data = json.loads(resp.json().get("message", {}).get("content", "{}"))
        allowed_paths = {s["path"] for s in scenario.get("request_sequence", [])}
        if not isinstance(data, dict) or any(
            st.get("request", {}).get("path") not in allowed_paths and st.get("role") == "probe"
            for st in data.get("steps", [])
        ):
            raise RuntimeError("AI test referenced endpoints outside the scenario")
        return data, "ai"
    except (httpx.HTTPError, RuntimeError, json.JSONDecodeError, AttributeError):
        return fallback, "generated"
