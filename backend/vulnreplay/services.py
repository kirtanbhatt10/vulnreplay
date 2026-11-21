"""Application services shared by the API and the CLI."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models as m
from .config import get_settings
from .execution import ExecutionLimits, TargetGuard, TargetNotAllowed, run_test
from .regression import REPRODUCED, VERIFIED, classify, compare_results
from .testdef import Context, TestDefinition


def to_dict(obj: Any, exclude: set[str] | None = None) -> dict[str, Any]:
    exclude = (exclude or set()) | {"password_hash", "original"}
    out: dict[str, Any] = {}
    for col in obj.__table__.columns:
        if col.name in exclude:
            continue
        value = getattr(obj, col.name)
        out[col.name] = value.isoformat() if isinstance(value, datetime) else value
    return out


def audit(db: Session, actor: str | None, action: str, subject: str = "", **detail: Any) -> None:
    db.add(m.AuditEvent(actor_id=actor, action=action, subject=subject, detail=detail))


def current_definition(test: m.RegressionTest) -> dict[str, Any]:
    version = next(v for v in test.versions if v.version == test.current_version)
    return version.definition


def add_version(db: Session, test: m.RegressionTest, definition: dict[str, Any], note: str) -> m.TestVersion:
    TestDefinition.model_validate(definition)
    new_version = (max((v.version for v in test.versions), default=0)) + 1
    tv = m.TestVersion(test_id=test.id, version=new_version, definition=definition, change_note=note)
    test.versions.append(tv)
    test.current_version = new_version
    test.status = "draft"  # every change must be reviewed again
    test.approved_by = None
    db.add(tv)
    return tv


def build_guard(target: m.Target) -> TargetGuard:
    return TargetGuard(
        base_url=target.base_url,
        allowed_hosts=get_settings().allowed_hosts,
        allow_private_network=target.allow_private_network,
    )


def validate_target_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("base_url must be an absolute http(s) URL")
    if parts.username or parts.password:
        raise ValueError("credentials must not be embedded in URLs")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise ValueError("base_url must not contain a path, query or fragment")
    if parts.hostname.lower() not in {h.lower() for h in get_settings().allowed_hosts}:
        raise ValueError(
            f"host '{parts.hostname}' is not in VULNREPLAY_ALLOWED_HOSTS; ask the operator to "
            "add it before it can be authorized"
        )


class Jobs:
    """In-process registry of running executions for cancellation."""

    def __init__(self) -> None:
        self._events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def register(self, execution_id: str) -> threading.Event:
        with self._lock:
            ev = threading.Event()
            self._events[execution_id] = ev
            return ev

    def cancel(self, execution_id: str) -> bool:
        with self._lock:
            ev = self._events.get(execution_id)
        if ev:
            ev.set()
            return True
        return False

    def done(self, execution_id: str) -> None:
        with self._lock:
            self._events.pop(execution_id, None)


jobs = Jobs()


class ExecutionRefused(PermissionError):
    pass


def create_execution(
    db: Session, test: m.RegressionTest, target: m.Target, label: str, user_id: str | None
) -> m.Execution:
    if test.status != "approved":
        raise ExecutionRefused("test must be reviewed and approved before execution")
    if not target.authorized:
        raise ExecutionRefused("target is not authorized for testing")
    if target.project_id != test.project_id:
        raise ExecutionRefused("target belongs to a different project")
    try:
        build_guard(target)
    except TargetNotAllowed as exc:
        raise ExecutionRefused(str(exc)) from exc
    ex = m.Execution(
        project_id=test.project_id,
        test_id=test.id,
        test_version=test.current_version,
        target_id=target.id,
        label=label[:64],
        status="queued",
        started_by=user_id,
    )
    db.add(ex)
    audit(db, user_id, "execution.created", ex.id, test=test.id, target=target.id)
    db.commit()
    return ex


def perform_execution(
    db: Session, execution_id: str, secrets: dict[str, str] | None = None, transport: httpx.BaseTransport | None = None
) -> m.Execution:
    ex = db.get(m.Execution, execution_id)
    if ex is None:
        raise LookupError(f"execution {execution_id} not found")
    test = db.get(m.RegressionTest, ex.test_id)
    target = db.get(m.Target, ex.target_id)
    if test is None or target is None:
        raise LookupError("execution references a missing test or target")
    version = next(v for v in test.versions if v.version == ex.test_version)
    cancel = jobs.register(ex.id)
    ex.status = "running"
    db.commit()
    settings = get_settings()
    try:
        definition = TestDefinition.model_validate(version.definition)
        guard = build_guard(target)
        limits = ExecutionLimits(
            timeout_seconds=settings.request_timeout_seconds,
            max_requests=settings.max_requests_per_execution,
            min_interval_ms=settings.min_request_interval_ms,
            max_response_bytes=settings.max_response_bytes,
        )
        ctx = Context(variables=dict(target.variables or {}), secrets=secrets)
        result = run_test(definition, guard, ctx, limits, cancel=cancel, transport=transport)
    except (TargetNotAllowed, ValueError) as exc:
        result = {"state": "error", "error": str(exc), "steps": [], "summary": {}, "log": []}
    finally:
        jobs.done(ex.id)

    baseline = db.scalars(
        select(m.Execution).where(m.Execution.test_id == test.id, m.Execution.is_baseline.is_(True))
    ).first()
    previously_verified = False
    if baseline is not None:
        previously_verified = (
            db.scalars(
                select(m.Execution).where(
                    m.Execution.test_id == test.id,
                    m.Execution.classification == VERIFIED,
                    m.Execution.created_at > baseline.created_at,
                )
            ).first()
            is not None
        )
    comparison = None
    if baseline is not None and result.get("state") != "error":
        comparison = compare_results(baseline.result, result)
    classification, reasons = classify(result, baseline.result if baseline else None, previously_verified, comparison)
    if classification == REPRODUCED and baseline is None:
        ex.is_baseline = True
        reasons.insert(0, "stored as the vulnerable baseline for this test")
    ex.result = result
    ex.state = result.get("state")
    ex.classification = classification
    ex.comparison = {"baseline_id": baseline.id if baseline else None, "reasons": reasons, "diff": comparison}
    ex.status = "cancelled" if result.get("error") == "execution cancelled" else "completed"
    ex.finished_at = datetime.now(UTC)
    audit(db, ex.started_by, "execution.finished", ex.id, classification=classification)
    db.commit()
    return ex


def run_in_background(execution_id: str) -> None:
    from .db import session_factory

    def _work() -> None:
        db = session_factory()()
        try:
            perform_execution(db, execution_id)
        finally:
            db.close()

    threading.Thread(target=_work, name=f"exec-{execution_id[:8]}", daemon=True).start()


def dashboard(db: Session, project_id: str | None = None) -> dict[str, Any]:
    def q(model: Any) -> Any:
        stmt = select(model)
        if project_id:
            stmt = stmt.where(model.project_id == project_id)
        return list(db.scalars(stmt))

    findings, tests, executions = q(m.Finding), q(m.RegressionTest), q(m.Execution)
    evidence = q(m.Evidence)
    latest: dict[str, m.Execution] = {}
    for ex in sorted(executions, key=lambda e: e.created_at):
        latest[ex.test_id] = ex
    by_class: dict[str, int] = {}
    for ex in latest.values():
        by_class[ex.classification or "running"] = by_class.get(ex.classification or "running", 0) + 1
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    recent = sorted(executions, key=lambda e: e.created_at, reverse=True)[:10]
    return {
        "counts": {
            "projects": db.query(m.Project).count() if not project_id else 1,
            "evidence": len(evidence),
            "findings": len(findings),
            "tests": len(tests),
            "approved_tests": sum(1 for t in tests if t.status == "approved"),
            "executions": len(executions),
        },
        "latest_status_by_test": by_class,
        "findings_by_severity": by_sev,
        "recent_executions": [to_dict(e, {"result", "comparison"}) for e in recent],
    }
