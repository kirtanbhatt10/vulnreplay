"""The VulnReplay test definition format (JSON), its validation and safe templating.

A test definition is declarative data. It is never evaluated as code: variables are substituted
with a fixed ``{{name}}`` / ``{{secret:NAME}}`` syntax and assertions come from a closed set.
"""

from __future__ import annotations

import os
import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

AssertionType = Literal[
    "status_in",
    "status_not_in",
    "body_contains",
    "body_not_contains",
    "json_path_absent",
    "json_path_present",
    "json_path_equals",
    "json_path_not_equals",
    "header_present",
    "header_absent",
    "header_equals",
    "header_not_equals",
    "header_contains",
    "max_duration_ms",
    "sequence_any_status_in",
]

DESTRUCTIVE_PATTERNS = re.compile(
    r"(?i)\b(drop\s+table|truncate\s+table|delete\s+from|shutdown|xp_cmdshell|rm\s+-rf|"
    r"benchmark\s*\(|pg_sleep\s*\(\s*\d{2,}|waitfor\s+delay|load_file\s*\(|into\s+outfile)\b"
)


class Assertion(BaseModel):
    type: AssertionType
    description: str = ""
    values: list[int] | None = None
    value: str | None = None
    path: str | None = None
    name: str | None = None
    expected: Any = None

    @model_validator(mode="after")
    def _required_fields(self) -> Assertion:
        needs = {
            "status_in": "values",
            "status_not_in": "values",
            "sequence_any_status_in": "values",
            "body_contains": "value",
            "body_not_contains": "value",
            "json_path_absent": "path",
            "json_path_present": "path",
            "json_path_equals": "path",
            "json_path_not_equals": "path",
            "header_present": "name",
            "header_absent": "name",
            "header_equals": "name",
            "header_not_equals": "name",
            "header_contains": "name",
            "max_duration_ms": "expected",
        }
        field_name = needs[self.type]
        if getattr(self, field_name) is None:
            raise ValueError(f"assertion '{self.type}' requires '{field_name}'")
        return self


class Extract(BaseModel):
    source: Literal["json", "header", "status"] = "json"
    path: str = ""


class RequestSpec(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = "GET"
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, str] = Field(default_factory=dict)
    json_body: Any = Field(default=None, alias="json")
    body: str | None = None

    model_config = {"populate_by_name": True}

    @field_validator("path")
    @classmethod
    def _relative_path(cls, value: str) -> str:
        # Tests always run relative to an authorized target; absolute URLs are not allowed.
        if not value.startswith("/") or value.startswith("//") or "://" in value:
            raise ValueError("request.path must be a path starting with '/' (no absolute URLs)")
        return value


class Step(BaseModel):
    id: str
    name: str = ""
    role: Literal["setup", "probe", "cleanup"] = "probe"
    request: RequestSpec
    repeat: int = Field(default=1, ge=1, le=100)
    follow_redirects: bool = False
    expect: list[Assertion] = Field(default_factory=list)
    assert_secure: list[Assertion] = Field(default_factory=list)
    extract: dict[str, Extract] = Field(default_factory=dict)
    compare_fields: list[str] = Field(default_factory=list)


class Safety(BaseModel):
    destructive: bool = False
    max_requests: int = Field(default=50, ge=1, le=500)


class TestDefinition(BaseModel):
    __test__ = False
    schema_version: Literal["1"] = "1"
    id: str
    name: str
    category: str = "other"
    severity: str = "medium"
    description: str = ""
    preconditions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    variables: dict[str, str] = Field(default_factory=dict)
    secrets: list[str] = Field(default_factory=list)
    steps: list[Step]
    cleanup: list[Step] = Field(default_factory=list)
    safety: Safety = Field(default_factory=Safety)
    evidence_refs: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> TestDefinition:
        if not self.steps:
            raise ValueError("a test needs at least one step")
        if not any(s.role == "probe" for s in self.steps):
            raise ValueError("a test needs at least one probe step with security assertions")
        ids = [s.id for s in self.steps + self.cleanup]
        if len(ids) != len(set(ids)):
            raise ValueError("step ids must be unique")
        total = sum(s.repeat for s in self.steps + self.cleanup)
        if total > self.safety.max_requests:
            raise ValueError(f"test would send {total} requests, above safety.max_requests")
        if self.safety.destructive:
            raise ValueError("destructive tests are not supported")
        for step in self.steps + self.cleanup:
            blob = " ".join(
                [
                    step.request.path,
                    str(step.request.json_body or ""),
                    step.request.body or "",
                    " ".join(step.request.query.values()),
                ]
            )
            if DESTRUCTIVE_PATTERNS.search(blob):
                raise ValueError(f"step '{step.id}' contains a destructive payload pattern")
            if step.role == "probe" and not step.assert_secure:
                raise ValueError(f"probe step '{step.id}' has no assert_secure assertions")
        return self


# ---------------------------------------------------------------- templating

_TEMPLATE = re.compile(r"\{\{\s*(secret:)?([A-Za-z_][A-Za-z0-9_]{0,63})\s*\}\}")


class TemplateError(KeyError):
    pass


class Context:
    """Holds variables and secrets for one execution. Secrets are tracked so they can be redacted."""

    def __init__(self, variables: dict[str, Any] | None = None, secrets: dict[str, str] | None = None) -> None:
        self.variables: dict[str, Any] = dict(variables or {})
        self._secrets: dict[str, str] = dict(secrets or {})

    def secret(self, name: str) -> str:
        if name in self._secrets:
            return self._secrets[name]
        env_value = os.environ.get(f"VULNREPLAY_SECRET_{name}")
        if env_value is None:
            raise TemplateError(f"secret '{name}' is not configured (set VULNREPLAY_SECRET_{name})")
        self._secrets[name] = env_value
        return env_value

    @property
    def secret_values(self) -> list[str]:
        values = list(self._secrets.values())
        # Extracted tokens are secrets too.
        values += [str(v) for k, v in self.variables.items() if "token" in k.lower() and isinstance(v, str)]
        return values

    def render(self, value: Any) -> Any:
        if isinstance(value, str):
            return _TEMPLATE.sub(self._replace, value)
        if isinstance(value, dict):
            return {self.render(k): self.render(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.render(v) for v in value]
        return value

    def _replace(self, match: re.Match[str]) -> str:
        is_secret, name = match.group(1), match.group(2)
        if is_secret:
            return self.secret(name)
        if name not in self.variables:
            raise TemplateError(f"variable '{name}' is not defined")
        return str(self.variables[name])


# ---------------------------------------------------------------- json paths

_PATH_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d+)\]")
_MISSING = object()


def json_path_get(data: Any, path: str) -> Any:
    """Resolve a dotted path like ``items[0].owner.email``. Returns a sentinel when missing."""
    current = data
    if not path:
        return current
    for name, idx in _PATH_TOKEN.findall(path):
        if idx:
            if not isinstance(current, list) or int(idx) >= len(current):
                return _MISSING
            current = current[int(idx)]
        else:
            if not isinstance(current, dict) or name not in current:
                return _MISSING
            current = current[name]
    return current


def is_missing(value: Any) -> bool:
    return value is _MISSING
