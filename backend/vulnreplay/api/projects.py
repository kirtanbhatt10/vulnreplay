"""Projects and authorized target environments."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models as m
from ..config import get_settings
from ..db import get_db
from ..security import get_current_user, require_role
from ..services import audit, dashboard, to_dict, validate_target_url

router = APIRouter(tags=["projects"])


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)


class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    base_url: str = Field(max_length=500)
    environment: Literal["local", "staging", "lab"] = "staging"
    variables: dict[str, str] = Field(default_factory=dict)


class AuthorizeIn(BaseModel):
    authorized: bool
    authorization_note: str = Field(
        min_length=5, max_length=2000, description="Who approved testing and under what scope"
    )
    allow_private_network: bool = False


def get_project(db: Session, project_id: str) -> m.Project:
    project = db.get(m.Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.get("/dashboard", dependencies=[Depends(get_current_user)])
def get_dashboard(project_id: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    return dashboard(db, project_id)


@router.get("/projects", dependencies=[Depends(get_current_user)])
def list_projects(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    out = []
    for p in db.scalars(select(m.Project).order_by(m.Project.created_at.desc())):
        d = to_dict(p)
        d["stats"] = dashboard(db, p.id)["counts"]
        out.append(d)
    return out


@router.post("/projects", status_code=201)
def create_project(
    body: ProjectIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    project = m.Project(name=body.name, description=body.description, created_by=user.id)
    db.add(project)
    audit(db, user.id, "project.created", project.id)
    db.commit()
    return to_dict(project)


@router.get("/projects/{project_id}", dependencies=[Depends(get_current_user)])
def read_project(project_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    return to_dict(get_project(db, project_id))


@router.get("/projects/{project_id}/targets", dependencies=[Depends(get_current_user)])
def list_targets(project_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    get_project(db, project_id)
    return [to_dict(t) for t in db.scalars(select(m.Target).where(m.Target.project_id == project_id))]


@router.post("/projects/{project_id}/targets", status_code=201)
def create_target(
    project_id: str, body: TargetIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    get_project(db, project_id)
    try:
        validate_target_url(body.base_url)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if any("secret" in k.lower() or "password" in k.lower() or "token" in k.lower() for k in body.variables):
        raise HTTPException(422, "Secrets must not be stored as target variables; use VULNREPLAY_SECRET_* env vars")
    target = m.Target(
        project_id=project_id,
        name=body.name,
        base_url=body.base_url.rstrip("/"),
        environment=body.environment,
        variables=body.variables,
        authorized=False,
    )
    db.add(target)
    audit(db, user.id, "target.created", target.id, base_url=target.base_url)
    db.commit()
    return to_dict(target)


@router.post("/targets/{target_id}/authorization")
def authorize_target(
    target_id: str, body: AuthorizeIn, db: Session = Depends(get_db), admin: m.User = Depends(require_role("admin"))
) -> dict[str, Any]:
    target = db.get(m.Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    target.authorized = body.authorized
    target.authorization_note = body.authorization_note
    target.allow_private_network = body.allow_private_network
    target.authorized_by = admin.id if body.authorized else None
    audit(
        db,
        admin.id,
        "target.authorization",
        target.id,
        authorized=body.authorized,
        allow_private_network=body.allow_private_network,
    )
    db.commit()
    return to_dict(target)


@router.get("/settings", dependencies=[Depends(get_current_user)])
def read_settings() -> dict[str, Any]:
    s = get_settings()
    return {
        "environment": s.environment,
        "allowed_hosts": s.allowed_hosts,
        "max_upload_bytes": s.max_upload_bytes,
        "request_timeout_seconds": s.request_timeout_seconds,
        "max_requests_per_execution": s.max_requests_per_execution,
        "min_request_interval_ms": s.min_request_interval_ms,
        "llm_enabled": bool(s.llm_base_url),
        "llm_model": s.llm_model if s.llm_base_url else None,
    }


@router.get("/audit", dependencies=[Depends(require_role("admin"))])
def audit_log(limit: int = 100, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(select(m.AuditEvent).order_by(m.AuditEvent.created_at.desc()).limit(min(limit, 500)))
    return [to_dict(r) for r in rows]
