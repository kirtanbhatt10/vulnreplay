"""Test definition validation, templating, credential handling and regression classification."""

from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from vulnreplay.execution import ExecutionLimits, TargetGuard, run_test
from vulnreplay.regression import (
    FAILED,
    INCONCLUSIVE,
    REGRESSION,
    REPRODUCED,
    VERIFIED,
    classify,
    compare_results,
)
from vulnreplay.security import REDACTED, redact_obj, redact_text
from vulnreplay.testdef import Context, TemplateError, TestDefinition


def defn(**overrides):  # type: ignore[no-untyped-def]
    base = {
        "id": "t",
        "name": "t",
        "steps": [
            {
                "id": "p",
                "role": "probe",
                "request": {"path": "/x"},
                "assert_secure": [{"type": "status_in", "values": [403]}],
            }
        ],
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize("path", ["http://evil.test/x", "//evil.test/x", "x"])
def test_absolute_urls_rejected(path: str) -> None:
    d = defn()
    d["steps"][0]["request"]["path"] = path
    with pytest.raises(ValidationError):
        TestDefinition.model_validate(d)


@pytest.mark.parametrize("payload", ["1; DROP TABLE users", "x' OR pg_sleep(30)--", "rm -rf /"])
def test_destructive_payloads_rejected(payload: str) -> None:
    d = defn()
    d["steps"][0]["request"]["query"] = {"q": payload}
    with pytest.raises(ValidationError, match="destructive"):
        TestDefinition.model_validate(d)


def test_probe_requires_assertions_and_request_budget() -> None:
    d = defn()
    d["steps"][0]["assert_secure"] = []
    with pytest.raises(ValidationError):
        TestDefinition.model_validate(d)
    d = defn(safety={"max_requests": 5})
    d["steps"][0]["repeat"] = 10
    with pytest.raises(ValidationError, match="max_requests"):
        TestDefinition.model_validate(d)


def test_templating_secrets_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNREPLAY_SECRET_API_KEY", "s3cr3t-value")
    ctx = Context(variables={"id": 7})
    assert ctx.render({"h": "Bearer {{secret:API_KEY}}", "p": "/a/{{id}}"}) == {"h": "Bearer s3cr3t-value", "p": "/a/7"}
    assert "s3cr3t-value" in ctx.secret_values
    with pytest.raises(TemplateError):
        ctx.render("{{secret:MISSING_ONE}}")
    with pytest.raises(TemplateError):
        ctx.render("{{undefined}}")


def test_secrets_never_appear_in_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNREPLAY_SECRET_TOKEN", "very-secret-token-123")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"echo": request.headers["authorization"]}, headers={"Set-Cookie": "sid=abc"})

    d = defn()
    d["steps"][0]["request"]["headers"] = {"Authorization": "Bearer {{secret:TOKEN}}"}
    res = run_test(
        TestDefinition.model_validate(d),
        TargetGuard("http://localhost:1", ["localhost"]),
        Context(),
        ExecutionLimits(min_interval_ms=0),
        transport=httpx.MockTransport(handler),
    )
    assert "very-secret-token-123" not in repr(res)
    assert res["steps"][0]["requests"][0]["headers"]["set-cookie"] == REDACTED


def test_redaction_helpers() -> None:
    assert "abc.def" not in redact_text("Authorization: Bearer abc.def")
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert jwt not in redact_text(f"token={jwt}")
    assert redact_obj({"password": "x", "nested": {"Cookie": "a=b"}}) == {
        "password": REDACTED,
        "nested": {"Cookie": REDACTED},
    }


# ---------------------------------------------------------------- classification


def result(
    state: str,
    passed: int,
    total: int,
    status: int = 200,
    body: str = "",
    json: object = None,
    assertions: list[dict] | None = None,
) -> dict:
    return {
        "state": state,
        "summary": {"assertions_passed": passed, "assertions_total": total},
        "steps": [
            {
                "id": "p",
                "role": "probe",
                "assertions": assertions or [],
                "requests": [
                    {"status": status, "body_preview": body, "json": json, "security_headers": {}, "duration_ms": 5}
                ],
            }
        ],
    }


def test_classify_matrix() -> None:
    vuln = result(
        "vulnerable",
        0,
        2,
        assertions=[
            {"type": "status_in", "description": "d", "passed": False, "detail": ""},
            {"type": "body_not_contains", "description": "m", "passed": False, "detail": ""},
        ],
        json={"id": 1, "email": "a@b.c"},
    )
    fixed = result(
        "secure",
        2,
        2,
        status=404,
        json={"detail": "nf"},
        assertions=[
            {"type": "status_in", "description": "d", "passed": True, "detail": ""},
            {"type": "body_not_contains", "description": "m", "passed": True, "detail": ""},
        ],
    )
    assert classify(vuln, None, False)[0] == REPRODUCED
    assert classify(fixed, None, False)[0] == INCONCLUSIVE
    comp = compare_results(vuln, fixed)
    assert comp["meaningful_change"] and not comp["status_only_change"]
    assert classify(fixed, vuln, False, comp)[0] == VERIFIED
    assert classify(vuln, vuln, True)[0] == REGRESSION
    assert classify({"state": "error", "error": "boom"}, vuln, True) == (FAILED, ["boom"])


def test_status_only_change_is_inconclusive() -> None:
    before = result(
        "vulnerable",
        0,
        1,
        status=200,
        json={"id": 1},
        assertions=[{"type": "status_in", "description": "s", "passed": False, "detail": ""}],
    )
    after = result(
        "secure",
        1,
        1,
        status=403,
        json={"id": 1},
        assertions=[{"type": "status_in", "description": "s", "passed": True, "detail": ""}],
    )
    comp = compare_results(before, after)
    assert comp["status_only_change"] is True
    cls, reasons = classify(after, before, False, comp)
    assert cls == INCONCLUSIVE and "status alone" in reasons[0]


def test_incomplete_remediation_reported() -> None:
    base = result("vulnerable", 0, 2)
    partial = result(
        "vulnerable",
        1,
        2,
        assertions=[{"type": "body_not_contains", "description": "m", "passed": False, "detail": "present"}],
    )
    cls, reasons = classify(partial, base, False)
    assert cls == REPRODUCED and reasons[0].startswith("incomplete remediation")
