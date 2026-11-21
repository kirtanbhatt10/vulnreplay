"""Vulnerability regression engine: compares executions and classifies the outcome.

A status-code change on its own is never treated as proof of remediation: the comparison
looks at response structure, sensitive fields, exposed markers, security headers and errors.
"""

from __future__ import annotations

from typing import Any

REPRODUCED = "vulnerability_reproduced"
VERIFIED = "remediation_verified"
REGRESSION = "regression_detected"
INCONCLUSIVE = "inconclusive"
FAILED = "execution_failed"
CLASSIFICATIONS = (REPRODUCED, VERIFIED, REGRESSION, INCONCLUSIVE, FAILED)

ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "sqlstate",
    "syntax error",
    "sqlite3.",
    "psycopg",
    "ora-0",
    "stack trace",
    "exception in thread",
    "internal server error",
)
STATUS_ONLY_TYPES = {"status_in", "status_not_in", "sequence_any_status_in"}


def _keys(obj: Any, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out.add(path)
            out |= _keys(v, path)
    elif isinstance(obj, list) and obj:
        out |= _keys(obj[0], prefix + "[]")
    return out


def _status_class(status: int | None) -> str:
    if status is None:
        return "none"
    if status in (401, 407):
        return "unauthenticated"
    if status in (403, 404):
        return "denied"
    if 200 <= status < 300:
        return "allowed"
    if 300 <= status < 400:
        return "redirect"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "server_error"
    return "client_error"


def _probe_steps(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["id"]: s for s in result.get("steps", []) if s.get("role") == "probe"}


def compare_results(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Structured diff between a baseline execution result and a current one."""
    steps_out: list[dict[str, Any]] = []
    signals: list[str] = []
    meaningful_non_status = False
    any_status_change = False
    base_steps, cur_steps = _probe_steps(baseline), _probe_steps(current)
    for step_id, cur in cur_steps.items():
        base = base_steps.get(step_id)
        if not base or not base.get("requests") or not cur.get("requests"):
            steps_out.append({"step": step_id, "comparable": False})
            continue
        b, c = base["requests"][-1], cur["requests"][-1]
        b_keys, c_keys = _keys(b.get("json")), _keys(c.get("json"))
        removed, added = sorted(b_keys - c_keys), sorted(c_keys - b_keys)
        b_hdr, c_hdr = b.get("security_headers", {}), c.get("security_headers", {})
        hdr_added = sorted(h for h, v in c_hdr.items() if v and not b_hdr.get(h))
        hdr_removed = sorted(h for h, v in b_hdr.items() if v and not c_hdr.get(h))
        b_assert = {(a["type"], a["description"]): a["passed"] for a in base.get("assertions", [])}
        exposure_before = [
            a for a in base.get("assertions", []) if a["type"] == "body_not_contains" and not a["passed"]
        ]
        exposure_after = [a for a in cur.get("assertions", []) if a["type"] == "body_not_contains" and not a["passed"]]
        flipped = [
            {
                "type": a["type"],
                "description": a["description"],
                "before": b_assert.get((a["type"], a["description"])),
                "after": a["passed"],
            }
            for a in cur.get("assertions", [])
            if b_assert.get((a["type"], a["description"])) is not None
            and b_assert[(a["type"], a["description"])] != a["passed"]
        ]
        b_err = any(sig in (b.get("body_preview") or "").lower() for sig in ERROR_SIGNATURES)
        c_err = any(sig in (c.get("body_preview") or "").lower() for sig in ERROR_SIGNATURES)
        status_changed = b["status"] != c["status"]
        any_status_change |= status_changed
        if removed or hdr_added or (exposure_before and not exposure_after) or (b_err and not c_err):
            meaningful_non_status = True
        if any(f["after"] and f["type"] not in STATUS_ONLY_TYPES for f in flipped):
            meaningful_non_status = True
        if status_changed:
            signals.append(f"{step_id}: status {b['status']} -> {c['status']}")
        if removed:
            signals.append(f"{step_id}: {len(removed)} response field(s) no longer returned")
        if added:
            signals.append(f"{step_id}: {len(added)} new response field(s)")
        if exposure_before and not exposure_after:
            signals.append(f"{step_id}: previously exposed data is no longer present")
        if exposure_after:
            signals.append(f"{step_id}: sensitive data still present in response")
        if hdr_added:
            signals.append(f"{step_id}: security headers added: {', '.join(hdr_added)}")
        if hdr_removed:
            signals.append(f"{step_id}: security headers removed: {', '.join(hdr_removed)}")
        steps_out.append(
            {
                "step": step_id,
                "comparable": True,
                "status": {"before": b["status"], "after": c["status"], "changed": status_changed},
                "auth_behavior": {"before": _status_class(b["status"]), "after": _status_class(c["status"])},
                "structure": {"removed_fields": removed[:50], "added_fields": added[:50]},
                "security_headers": {"added": hdr_added, "removed": hdr_removed},
                "error_response": {"before": b_err, "after": c_err},
                "data_exposure": {"before": len(exposure_before), "after": len(exposure_after)},
                "timing_ms": {"before": b.get("duration_ms"), "after": c.get("duration_ms")},
                "assertion_changes": flipped,
            }
        )
    return {
        "steps": steps_out,
        "signals": signals,
        "status_only_change": any_status_change and not meaningful_non_status,
        "meaningful_change": meaningful_non_status,
        "summary_before": baseline.get("summary"),
        "summary_after": current.get("summary"),
    }


def classify(
    current: dict[str, Any],
    baseline: dict[str, Any] | None,
    previously_verified: bool,
    comparison: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Classify an execution. Returns (classification, reasons)."""
    reasons: list[str] = []
    state = current.get("state")
    if state == "error":
        return FAILED, [current.get("error") or "execution did not complete"]
    summary = current.get("summary", {})
    passed, total = summary.get("assertions_passed", 0), summary.get("assertions_total", 0)
    if state == "vulnerable":
        failed = [
            a
            for s in current.get("steps", [])
            if s.get("role") == "probe"
            for a in s.get("assertions", [])
            if not a["passed"]
        ]
        reasons += [f"failed: {a['description'] or a['type']} ({a['detail']})" for a in failed[:10]]
        if previously_verified:
            return REGRESSION, ["behaviour previously verified as fixed is vulnerable again", *reasons]
        if baseline is not None and passed > baseline.get("summary", {}).get("assertions_passed", 0):
            reasons.insert(0, f"incomplete remediation: {passed}/{total} security assertions now pass")
        return REPRODUCED, reasons
    # state == secure
    probe_types = {
        a["type"] for s in current.get("steps", []) if s.get("role") == "probe" for a in s.get("assertions", [])
    }
    if baseline is None:
        return INCONCLUSIVE, [
            "secure behaviour observed, but no vulnerable baseline exists for this test, "
            "so the original issue was never reproduced here"
        ]
    if comparison and comparison.get("status_only_change") and probe_types <= STATUS_ONLY_TYPES:
        return INCONCLUSIVE, [
            "only the HTTP status changed; status alone does not prove remediation — "
            "add body, field or header assertions"
        ]
    reasons.append(f"all {total} security assertions pass where the baseline failed")
    if comparison:
        reasons += comparison.get("signals", [])[:10]
    return VERIFIED, reasons
