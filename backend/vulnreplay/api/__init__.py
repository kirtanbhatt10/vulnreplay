"""HTTP API routers."""

from fastapi import APIRouter

from . import auth, evidence, executions, projects, tests

api_router = APIRouter(prefix="/api/v1")
for module in (auth, projects, evidence, tests, executions):
    api_router.include_router(module.router)

__all__ = ["api_router"]
