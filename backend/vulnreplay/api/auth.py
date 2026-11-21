"""Authentication and user management endpoints."""

from __future__ import annotations

from typing import Literal

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models as m
from ..db import get_db
from ..security import (
    create_access_token,
    get_current_user,
    hash_password,
    login_rate_limit,
    require_role,
    verify_password,
)
from ..services import audit, to_dict

router = APIRouter(tags=["auth"])
BEARER_SCHEME = "bearer"
# Constant dummy hash used to equalise timing when the user does not exist.
_DUMMY_HASH = PasswordHasher().hash("timing-equalisation-placeholder")


class LoginIn(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=256)


class UserIn(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=255)
    password: str = Field(min_length=10, max_length=256)
    role: Literal["admin", "analyst", "viewer"] = "viewer"


class UserPatch(BaseModel):
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None


@router.post("/auth/login", dependencies=[Depends(login_rate_limit)])
def login(body: LoginIn, db: Session = Depends(get_db)) -> dict[str, object]:
    user = db.scalars(select(m.User).where(m.User.email == body.email.lower())).first()
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok or not user.is_active:
        audit(db, None, "auth.login_failed", body.email.lower()[:128])
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    audit(db, user.id, "auth.login", user.email)
    db.commit()
    return {"access_token": create_access_token(user), "token_type": BEARER_SCHEME, "user": to_dict(user)}


@router.get("/auth/me")
def me(user: m.User = Depends(get_current_user)) -> dict[str, object]:
    return to_dict(user)


@router.get("/users", dependencies=[Depends(require_role("admin"))])
def list_users(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return [to_dict(u) for u in db.scalars(select(m.User).order_by(m.User.created_at))]


@router.post("/users", status_code=201)
def create_user(
    body: UserIn, db: Session = Depends(get_db), admin: m.User = Depends(require_role("admin"))
) -> dict[str, object]:
    if db.scalars(select(m.User).where(m.User.email == body.email.lower())).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "User already exists")
    user = m.User(email=body.email.lower(), password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    audit(db, admin.id, "user.created", body.email.lower(), role=body.role)
    db.commit()
    return to_dict(user)


@router.patch("/users/{user_id}")
def update_user(
    user_id: str, body: UserPatch, db: Session = Depends(get_db), admin: m.User = Depends(require_role("admin"))
) -> dict[str, object]:
    user = db.get(m.User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == admin.id and (body.role not in (None, "admin") or body.is_active is False):
        raise HTTPException(400, "Administrators cannot demote or deactivate themselves")
    if body.role:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    audit(db, admin.id, "user.updated", user.email, **body.model_dump(exclude_none=True))
    db.commit()
    return to_dict(user)
