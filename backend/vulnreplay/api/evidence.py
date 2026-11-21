"""Evidence import and vulnerability findings."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models as m
from ..config import get_settings
from ..db import get_db
from ..importers import SUPPORTED_FORMATS, EvidenceError, import_evidence
from ..importers.common import normalize_severity
from ..scenarios import CATEGORIES
from ..security import client_key, get_current_user, limiter, redact_obj, require_role
from ..services import audit, to_dict
from .projects import get_project

router = APIRouter(tags=["evidence"])


class FindingIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    category: str = "other"
    severity: str = "medium"
    description: str = Field(default="", max_length=20000)
    cwe: str | None = Field(default=None, max_length=32)
    evidence_id: str | None = None
    exchange_indexes: list[int] = Field(default_factory=list)


class FindingPatch(BaseModel):
    status: str | None = Field(default=None, pattern="^(open|fixed|accepted|false_positive)$")
    category: str | None = None
    severity: str | None = None


def evidence_view(ev: m.Evidence, include_exchanges: bool = True) -> dict[str, Any]:
    d = to_dict(ev, {"exchanges"} if not include_exchanges else None)
    if include_exchanges:
        d["exchanges"] = redact_obj(ev.exchanges)
    d["exchange_count"] = len(ev.exchanges)
    return d


async def _read_limited(file: UploadFile, limit: int) -> bytes:
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"File exceeds the {limit} byte limit")
    return data


@router.post("/projects/{project_id}/evidence", status_code=201)
async def upload_evidence(
    project_id: str,
    request: Request,
    file: UploadFile = File(...),
    format: str = Form("auto"),
    db: Session = Depends(get_db),
    user: m.User = Depends(require_role("analyst")),
) -> dict[str, Any]:
    get_project(db, project_id)
    if not limiter.check("upload:" + client_key(request), 30):
        raise HTTPException(429, "Too many uploads, slow down")
    settings = get_settings()
    if format not in SUPPORTED_FORMATS:
        raise HTTPException(422, f"format must be one of {', '.join(SUPPORTED_FORMATS)}")
    raw = await _read_limited(file, settings.max_upload_bytes)
    filename = (file.filename or "upload").replace("/", "_").replace("\\", "_")[:255]
    try:
        parsed, provenance = import_evidence(
            filename,
            raw,
            format,
            max_bytes=settings.max_upload_bytes,
            body_limit=settings.max_body_preview_bytes,
            actor=user.email,
        )
    except EvidenceError as exc:
        raise HTTPException(422, str(exc)) from exc
    ev = m.Evidence(
        project_id=project_id,
        filename=filename,
        format=parsed.format,
        sha256=provenance["sha256"],
        size_bytes=len(raw),
        original=raw,
        exchanges=parsed.exchanges,
        provenance=provenance,
        imported_by=user.id,
    )
    db.add(ev)
    db.flush()
    created = []
    for f in parsed.findings:
        finding = m.Finding(project_id=project_id, evidence_id=ev.id, **f)
        db.add(finding)
        created.append(finding)
    audit(db, user.id, "evidence.imported", ev.id, sha256=ev.sha256, format=ev.format)
    db.commit()
    out = evidence_view(ev, include_exchanges=False)
    out["findings"] = [to_dict(f) for f in created]
    return out


@router.get("/projects/{project_id}/evidence", dependencies=[Depends(get_current_user)])
def list_evidence(project_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(m.Evidence).where(m.Evidence.project_id == project_id).order_by(m.Evidence.created_at.desc())
    )
    return [evidence_view(e, include_exchanges=False) for e in rows]


@router.get("/evidence/{evidence_id}", dependencies=[Depends(get_current_user)])
def read_evidence(evidence_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    ev = db.get(m.Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    return evidence_view(ev)


@router.get("/evidence/{evidence_id}/original", dependencies=[Depends(require_role("analyst"))])
def download_original(evidence_id: str, db: Session = Depends(get_db)) -> Response:
    ev = db.get(m.Evidence, evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    # Served as an inert attachment: never rendered by the browser.
    return Response(
        ev.original,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="evidence-{ev.id}.bin"',
            "X-Evidence-SHA256": ev.sha256,
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/projects/{project_id}/findings", dependencies=[Depends(get_current_user)])
def list_findings(
    project_id: str, severity: str | None = None, category: str | None = None, db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    stmt = select(m.Finding).where(m.Finding.project_id == project_id)
    if severity:
        stmt = stmt.where(m.Finding.severity == severity)
    if category:
        stmt = stmt.where(m.Finding.category == category)
    return [to_dict(f) for f in db.scalars(stmt.order_by(m.Finding.created_at.desc()))]


@router.post("/projects/{project_id}/findings", status_code=201)
def create_finding(
    project_id: str, body: FindingIn, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    get_project(db, project_id)
    if body.category not in CATEGORIES:
        raise HTTPException(422, f"category must be one of {', '.join(CATEGORIES)}")
    if body.evidence_id:
        ev = db.get(m.Evidence, body.evidence_id)
        if not ev or ev.project_id != project_id:
            raise HTTPException(422, "evidence_id does not belong to this project")
        if any(i < 0 or i >= len(ev.exchanges) for i in body.exchange_indexes):
            raise HTTPException(422, "exchange index out of range")
    finding = m.Finding(
        project_id=project_id,
        source_tool="manual",
        **{**body.model_dump(), "severity": normalize_severity(body.severity)},
    )
    db.add(finding)
    audit(db, user.id, "finding.created", finding.id)
    db.commit()
    return to_dict(finding)


@router.get("/findings/{finding_id}", dependencies=[Depends(get_current_user)])
def read_finding(finding_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    f = db.get(m.Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    d = to_dict(f)
    if f.evidence_id:
        ev = db.get(m.Evidence, f.evidence_id)
        if ev:
            d["exchanges"] = redact_obj([ev.exchanges[i] for i in f.exchange_indexes if i < len(ev.exchanges)])
    return d


@router.patch("/findings/{finding_id}")
def update_finding(
    finding_id: str, body: FindingPatch, db: Session = Depends(get_db), user: m.User = Depends(require_role("analyst"))
) -> dict[str, Any]:
    f = db.get(m.Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    if body.category is not None:
        if body.category not in CATEGORIES:
            raise HTTPException(422, "invalid category")
        f.category = body.category
    if body.severity is not None:
        f.severity = normalize_severity(body.severity)
    if body.status is not None:
        f.status = body.status
    audit(db, user.id, "finding.updated", f.id)
    db.commit()
    return to_dict(f)
