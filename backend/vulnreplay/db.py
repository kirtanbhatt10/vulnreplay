"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False})
    return create_engine(url, pool_pre_ping=True)


def init_engine(url: str | None = None) -> Engine:
    global _engine, _SessionLocal
    _engine = _make_engine(url or get_settings().database_url)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        init_engine()
    if _engine is None:
        raise RuntimeError("database engine not initialised")
    return _engine


def session_factory() -> sessionmaker[Session]:
    if _SessionLocal is None:
        init_engine()
    if _SessionLocal is None:
        raise RuntimeError("session factory not initialised")
    return _SessionLocal


def get_db() -> Iterator[Session]:
    db = session_factory()()
    try:
        yield db
    finally:
        db.close()


def create_all() -> None:
    from . import models  # noqa: F401  (register models)

    Base.metadata.create_all(get_engine())
