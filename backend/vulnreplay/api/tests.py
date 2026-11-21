"""Attack scenarios, test generation and the regression library."""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models as m
from ..ai import ai_generate_definition
from ..db import get_db
from ..generator import render, scenario_to_definition
from ..scenarios import AttackScenario, ReconstructOptions, reconstruct
from ..security import get_current_user, require_role
from ..services import add_version, audit, current_definition, to_dict
from ..testdef import TestDefinition
from .projects import get_project

router = APIRouter(tags=["scenarios & tests"])


class ReconstructIn(BaseModel):
    finding_id: str
    options: ReconstructOptions = Field(default_factory=ReconstructOptions)


class GenerateIn(BaseModel):
    scenario_id: str
    use_ai: bool = False
    name: str | None = None
    tags: list[str] = Field(default_factory=list)


class TestIn(BaseModel):
    definition: dict[str, Any]
    tags: list[str] = Field(default_factory=list)
    finding_id: str | None = None


class VersionIn(BaseModel):
    definition: dict[str, Any]
    change_note: str = Field(min_length=3, max_length=2000)


class TestPatch(BaseModel):
    tags: list[str] | None = None
    status: Literal["archived"] | None = None


def _validation_error(exc: ValidationError) -> HTTPException:
    return HTTPException(422, [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()])


def test_view(t: m.RegressionTest, include_definition: bool = True) -> dict[str, Any]:
    d = to_dict(t)
    if include_definition:
        d["definition"] = current_definition(t)
    d["versions"] = [
        {"version": v.version, "change_note": v.change_note, "created_at": v.created_at.isoformat()} for v in t.versions
    ]
    return d


def get_test(db: Session, test_id: str) -> m.RegressionTest:
    t = db.get(m.RegressionTest, test_id)
    if not t:
        raise HTTPException(404, "Test not found")
    return t


# ---------------------------------------------------------------- scenarios


@router.post("/projects/{project_id}/scenarios", status_code=201)
def create_scenario(
    project_id: str, body: ReconstructIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    get_project(db, project_id)
    finding = db.get(m.Finding, body.finding_id)
    if not finding or finding.project_id != project_id:
        raise HTTPException(404, "Finding not found in project")
    ev = db.get(m.Evidence, finding.evidence_id) if finding.evidence_id else None
    if not ev:
        raise HTTPException(422, "Finding has no linked evidence to reconstruct from")
    idxs = finding.exchange_indexes or list(range(len(ev.exchanges)))
    exchanges = [ev.exchanges[i] for i in idxs if i < len(ev.exchanges)]
    try:
        scn = reconstruct(to_dict(finding), exchanges, ev.id, body.options)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    row = m.Scenario(
        project_id=project_id,
        finding_id=finding.id,
        title=scn.title,
        category=scn.category,
        data=scn.model_dump(mode="json"),
    )
    db.add(row)
    audit(db, user.id, "scenario.created", row.id, finding=finding.id)
    db.commit()
    return to_dict(row)


@router.get("/projects/{project_id}/scenarios", dependencies=[Depends(get_current_user)])
def list_scenarios(project_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(m.Scenario).where(m.Scenario.project_id == project_id).order_by(m.Scenario.created_at.desc())
    )
    return [to_dict(s) for s in rows]


@router.get("/scenarios/{scenario_id}", dependencies=[Depends(get_current_user)])
def read_scenario(scenario_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    s = db.get(m.Scenario, scenario_id)
    if not s:
        raise HTTPException(404, "Scenario not found")
    return to_dict(s)


# ---------------------------------------------------------------- generation


@router.post("/projects/{project_id}/tests/generate", status_code=201)
def generate_test(
    project_id: str, body: GenerateIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    scn_row = db.get(m.Scenario, body.scenario_id)
    if not scn_row or scn_row.project_id != project_id:
        raise HTTPException(404, "Scenario not found in project")
    scn = AttackScenario.model_validate(scn_row.data)
    deterministic = scenario_to_definition(scn).model_dump(by_alias=True, mode="json")
    definition, origin = (
        ai_generate_definition(scn_row.data, deterministic) if body.use_ai else (deterministic, "generated")
    )
    try:
        definition = TestDefinition.model_validate(definition).model_dump(by_alias=True, mode="json")
    except ValidationError:
        definition, origin = deterministic, "generated"
    if body.name:
        definition["name"] = body.name
    test = m.RegressionTest(
        project_id=project_id,
        scenario_id=scn_row.id,
        finding_id=scn_row.finding_id,
        name=definition["name"],
        category=definition["category"],
        tags=sorted(set(definition.get("tags", []) + body.tags)),
        origin=origin,
        status="draft",
    )
    db.add(test)
    db.flush()
    add_version(db, test, definition, "initial version generated from scenario")
    audit(db, user.id, "test.generated", test.id, origin=origin)
    db.commit()
    return test_view(test)


@router.get("/tests/{test_id}/render", dependencies=[Depends(get_current_user)])
def render_test(
    test_id: str, format: Literal["json", "pytest", "playwright"] = "pytest", db: Session = Depends(get_db)
) -> PlainTextResponse:
    t = get_test(db, test_id)
    code = render(TestDefinition.model_validate(current_definition(t)), format)
    return PlainTextResponse(code, media_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------- regression library


@router.get("/projects/{project_id}/tests", dependencies=[Depends(get_current_user)])
def list_tests(
    project_id: str,
    q: str | None = None,
    category: str | None = None,
    tag: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    rows = list(
        db.scalars(
            select(m.RegressionTest)
            .where(m.RegressionTest.project_id == project_id)
            .order_by(m.RegressionTest.created_at.desc())
        )
    )
    latest: dict[str, m.Execution] = {}
    for ex in db.scalars(
        select(m.Execution).where(m.Execution.project_id == project_id).order_by(m.Execution.created_at)
    ):
        latest[ex.test_id] = ex
    out = []
    for t in rows:
        if q and q.lower() not in t.name.lower():
            continue
        if category and t.category != category:
            continue
        if tag and tag not in (t.tags or []):
            continue
        if status and t.status != status:
            continue
        d = test_view(t, include_definition=False)
        last = latest.get(t.id)
        d["latest_classification"] = last.classification if last else None
        d["latest_execution_at"] = last.created_at.isoformat() if last else None
        out.append(d)
    return out


@router.post("/projects/{project_id}/tests", status_code=201)
def create_test(
    project_id: str, body: TestIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    get_project(db, project_id)
    try:
        defn = TestDefinition.model_validate(body.definition)
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    test = m.RegressionTest(
        project_id=project_id,
        finding_id=body.finding_id,
        name=defn.name,
        category=defn.category,
        tags=sorted(set(defn.tags + body.tags)),
        origin="manual",
    )
    db.add(test)
    db.flush()
    add_version(db, test, defn.model_dump(by_alias=True, mode="json"), "created manually")
    audit(db, user.id, "test.created", test.id)
    db.commit()
    return test_view(test)


@router.get("/tests/{test_id}", dependencies=[Depends(get_current_user)])
def read_test(test_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return test_view(get_test(db, test_id))


@router.get("/tests/{test_id}/versions/{version}", dependencies=[Depends(get_current_user)])
def read_version(test_id: str, version: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    t = get_test(db, test_id)
    v = next((v for v in t.versions if v.version == version), None)
    if not v:
        raise HTTPException(404, "Version not found")
    return to_dict(v)


@router.post("/tests/{test_id}/versions", status_code=201)
def new_version(
    test_id: str, body: VersionIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    t = get_test(db, test_id)
    try:
        defn = TestDefinition.model_validate(body.definition)
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    add_version(db, t, defn.model_dump(by_alias=True, mode="json"), body.change_note)
    t.name, t.category = defn.name, defn.category
    audit(db, user.id, "test.versioned", t.id, version=t.current_version)
    db.commit()
    return test_view(t)


@router.post("/tests/{test_id}/approve")
def approve_test(
    test_id: str, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    t = get_test(db, test_id)
    TestDefinition.model_validate(current_definition(t))  # must still be valid
    t.status = "approved"
    t.approved_by = user.id
    audit(db, user.id, "test.approved", t.id, version=t.current_version, origin=t.origin)
    db.commit()
    return test_view(t)


@router.patch("/tests/{test_id}")
def update_test(
    test_id: str, body: TestPatch, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    t = get_test(db, test_id)
    if body.tags is not None:
        t.tags = sorted({x.strip()[:40] for x in body.tags if x.strip()})
    if body.status:
        t.status = body.status
    audit(db, user.id, "test.updated", t.id)
    db.commit()
    return test_view(t)


@router.get("/projects/{project_id}/tests-export", dependencies=[Depends(get_current_user)])
def export_tests(project_id: str, status: str = "approved", db: Session = Depends(get_db)) -> PlainTextResponse:
    rows = db.scalars(
        select(m.RegressionTest).where(m.RegressionTest.project_id == project_id, m.RegressionTest.status == status)
    )
    bundle = {
        "format": "vulnreplay-suite",
        "version": "1",
        "tests": [
            {**current_definition(t), "x-vulnreplay": {"test_id": t.id, "version": t.current_version}} for t in rows
        ],
    }
    return PlainTextResponse(
        json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="vulnreplay-suite.json"'},
    )
