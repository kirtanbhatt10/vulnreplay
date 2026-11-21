"""Controlled execution, regression comparison, reports and the AI assistant."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models as m
from ..ai import assist
from ..db import get_db
from ..regression import compare_results
from ..reports import build_report, render_html, render_pdf
from ..security import get_current_user, redact_obj, require_role
from ..services import (
    ExecutionRefused,
    create_execution,
    current_definition,
    jobs,
    perform_execution,
    run_in_background,
    to_dict,
)
from .tests import get_test

router = APIRouter(tags=["executions & reports"])


class ExecuteIn(BaseModel):
    test_id: str
    target_id: str
    label: str = Field(default="", max_length=64)
    wait: bool = False


class AssistIn(BaseModel):
    task: Literal["explain_finding", "summarize_evidence", "explain_result", "suggest_remediation", "report_summary"]
    finding_id: str | None = None
    execution_id: str | None = None
    provider: Literal["auto", "deterministic", "ollama"] = "auto"


def execution_view(ex: m.Execution, db: Session) -> dict[str, Any]:
    d = to_dict(ex)
    target = db.get(m.Target, ex.target_id)
    test = db.get(m.RegressionTest, ex.test_id)
    d["target_name"] = target.name if target else None
    d["test_name"] = test.name if test else None
    return d


@router.post("/executions", status_code=202)
def start_execution(
    body: ExecuteIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    test = get_test(db, body.test_id)
    target = db.get(m.Target, body.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    try:
        ex = create_execution(db, test, target, body.label, user.id)
    except ExecutionRefused as exc:
        raise HTTPException(403, str(exc)) from exc
    if body.wait:
        ex = perform_execution(db, ex.id)
    else:
        run_in_background(ex.id)
    return execution_view(ex, db)


@router.get("/projects/{project_id}/executions", dependencies=[Depends(get_current_user)])
def list_executions(
    project_id: str, test_id: str | None = None, limit: int = 100, db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    stmt = select(m.Execution).where(m.Execution.project_id == project_id)
    if test_id:
        stmt = stmt.where(m.Execution.test_id == test_id)
    rows = db.scalars(stmt.order_by(m.Execution.created_at.desc()).limit(min(limit, 500)))
    out = []
    for ex in rows:
        d = execution_view(ex, db)
        d.pop("result", None)
        d["summary"] = (ex.result or {}).get("summary")
        out.append(d)
    return out


@router.get("/executions/{execution_id}", dependencies=[Depends(get_current_user)])
def read_execution(execution_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    ex = db.get(m.Execution, execution_id)
    if not ex:
        raise HTTPException(404, "Execution not found")
    return execution_view(ex, db)


@router.post("/executions/{execution_id}/cancel")
def cancel_execution(
    execution_id: str, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    ex = db.get(m.Execution, execution_id)
    if not ex:
        raise HTTPException(404, "Execution not found")
    return {"cancel_requested": jobs.cancel(execution_id), "status": ex.status}


@router.post("/executions/{execution_id}/baseline")
def mark_baseline(
    execution_id: str, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    ex = db.get(m.Execution, execution_id)
    if not ex:
        raise HTTPException(404, "Execution not found")
    if ex.state != "vulnerable":
        raise HTTPException(422, "only an execution that reproduced the vulnerability can be the baseline")
    for other in db.scalars(select(m.Execution).where(m.Execution.test_id == ex.test_id)):
        other.is_baseline = other.id == ex.id
    db.commit()
    return execution_view(ex, db)


@router.get("/compare", dependencies=[Depends(get_current_user)])
def compare(before: str, after: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    a, b = db.get(m.Execution, before), db.get(m.Execution, after)
    if not a or not b:
        raise HTTPException(404, "Execution not found")
    if a.test_id != b.test_id:
        raise HTTPException(422, "executions belong to different tests")
    return {
        "before": execution_view(a, db),
        "after": execution_view(b, db),
        "diff": compare_results(a.result, b.result),
    }


def _report_for(test_id: str, db: Session) -> dict[str, Any]:
    t = get_test(db, test_id)
    project = db.get(m.Project, t.project_id)
    finding = db.get(m.Finding, t.finding_id) if t.finding_id else None
    evidence = db.get(m.Evidence, finding.evidence_id) if finding and finding.evidence_id else None
    scenario = db.get(m.Scenario, t.scenario_id) if t.scenario_id else None
    executions = [
        execution_view(e, db)
        for e in db.scalars(select(m.Execution).where(m.Execution.test_id == t.id).order_by(m.Execution.created_at))
    ]
    if project is None:
        raise HTTPException(404, "Project not found")
    ev_dict = None
    if evidence:
        ev_dict = to_dict(evidence)
        ev_dict["exchanges"] = evidence.exchanges
    return build_report(
        project=to_dict(project),
        test=to_dict(t),
        definition=current_definition(t),
        finding=to_dict(finding) if finding else None,
        evidence=ev_dict,
        scenario=scenario.data if scenario else None,
        executions=executions,
    )


@router.get("/tests/{test_id}/report", dependencies=[Depends(get_current_user)])
def report(test_id: str, format: Literal["json", "html", "pdf"] = "json", db: Session = Depends(get_db)) -> Response:
    data = _report_for(test_id, db)
    if format == "html":
        return HTMLResponse(
            render_html(data), headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}
        )
    if format == "pdf":
        return Response(
            render_pdf(data),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="vulnreplay-{test_id}.pdf"'},
        )
    return JSONResponse(data)


@router.post("/assistant", dependencies=[Depends(get_current_user)])
def assistant(body: AssistIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    ctx: dict[str, Any] = {}
    if body.finding_id:
        f = db.get(m.Finding, body.finding_id)
        if not f:
            raise HTTPException(404, "Finding not found")
        ctx["finding"] = to_dict(f)
        ev = db.get(m.Evidence, f.evidence_id) if f.evidence_id else None
        if ev:
            ctx["exchanges"] = redact_obj(
                [ev.exchanges[i] for i in f.exchange_indexes if i < len(ev.exchanges)] or ev.exchanges[:10]
            )
    if body.execution_id:
        ex = db.get(m.Execution, body.execution_id)
        if not ex:
            raise HTTPException(404, "Execution not found")
        ctx["execution"] = to_dict(ex)
        t = db.get(m.RegressionTest, ex.test_id)
        ctx["category"] = t.category if t else None
    if not ctx:
        raise HTTPException(422, "provide finding_id and/or execution_id")
    return assist(body.task, ctx, body.provider).model_dump()
