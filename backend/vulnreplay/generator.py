"""Test generation engine: scenario -> JSON definition -> pytest/HTTPX and Playwright code.

The JSON definition is the canonical, executable artifact. Code renderings are generated from it
for teams that prefer to keep tests in their own suites. No generated artifact contains secrets:
credentials are always referenced as ``{{secret:NAME}}`` and read from environment variables.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .scenarios import AttackScenario
from .testdef import TestDefinition


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:60] or "test"


def _secrets_in(obj: Any) -> list[str]:
    return sorted(set(re.findall(r"\{\{\s*secret:([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", json.dumps(obj))))


def scenario_to_definition(scn: AttackScenario, test_id: str | None = None) -> TestDefinition:
    steps: list[dict[str, Any]] = []
    if scn.multi_step and scn.login_flow:
        lf = scn.login_flow
        target = scn.request_sequence[-1]
        marker_paths: list[str] = lf.get("marker_paths") or []
        owner_extract = {"owner_marker": {"source": "json", "path": marker_paths[0]}} if marker_paths else {}
        secure = list(scn.secure_expectations)
        if marker_paths:
            secure.append(
                {
                    "type": "body_not_contains",
                    "value": "{{owner_marker}}",
                    "description": "value read by the owner in the control request is not exposed",
                }
            )

        def login(step_id: str, user: str, password_secret: str, token_var: str) -> dict[str, Any]:
            return {
                "id": step_id,
                "name": f"authenticate {step_id.split('_')[1]}",
                "role": "setup",
                "request": {
                    "method": "POST",
                    "path": lf["path"],
                    "json": {lf["username_field"]: user, lf["password_field"]: password_secret},
                },
                "expect": [{"type": "status_in", "values": [200, 201], "description": "login succeeds"}],
                "extract": {token_var: {"source": "json", "path": lf["token_path"]}},
            }

        steps = [
            login(
                "login_owner",
                lf["owner_username"],
                "{{secret:" + lf.get("owner_password_secret", "OWNER_PASSWORD") + "}}",
                "owner_token",
            ),
            {
                "id": "owner_access",
                "name": "owner reads own resource",
                "role": "setup",
                "request": {
                    "method": target.method,
                    "path": target.path,
                    "query": target.query,
                    "headers": {"Authorization": "Bearer {{owner_token}}"},
                },
                "expect": [{"type": "status_in", "values": [200], "description": "owner can read the resource"}],
                "extract": owner_extract,
            },
            login(
                "login_attacker",
                lf["attacker_username"],
                "{{secret:" + lf.get("attacker_password_secret", "ATTACKER_PASSWORD") + "}}",
                "attacker_token",
            ),
            {
                "id": "cross_user_access",
                "name": "other user attempts access",
                "role": "probe",
                "request": {
                    "method": target.method,
                    "path": target.path,
                    "query": target.query,
                    "headers": {"Authorization": "Bearer {{attacker_token}}"},
                },
                "assert_secure": secure,
                "compare_fields": marker_paths,
            },
        ]
    else:
        last = len(scn.request_sequence) - 1
        for i, s in enumerate(scn.request_sequence):
            step: dict[str, Any] = {
                "id": f"step_{s.order}",
                "name": s.purpose,
                "role": "probe" if i == last else "setup",
                "repeat": s.repeat,
                "request": {"method": s.method, "path": s.path, "query": s.query, "headers": s.headers},
            }
            if s.body:
                try:
                    step["request"]["json"] = json.loads(s.body)
                except (json.JSONDecodeError, ValueError):
                    step["request"]["body"] = s.body
            if i == last:
                step["assert_secure"] = scn.secure_expectations
            else:
                step["expect"] = [
                    {"type": "status_not_in", "values": [500, 502, 503], "description": "preparatory request succeeds"}
                ]
            steps.append(step)

    total = sum(s.get("repeat", 1) for s in steps)
    raw = {
        "schema_version": "1",
        "id": test_id or f"vr-{scn.category}-{_slug(scn.target_endpoint)}",
        "name": scn.title,
        "category": scn.category,
        "severity": scn.risk_assessment.get("severity", "medium"),
        "description": f"Expected: {scn.expected_behavior} Observed originally: {scn.observed_behavior}",
        "preconditions": scn.preconditions,
        "tags": [scn.category, *(["multi-step"] if scn.multi_step else [])],
        "steps": steps,
        "safety": {"destructive": False, "max_requests": max(50, total + 5)},
        "evidence_refs": scn.evidence_references,
    }
    raw["secrets"] = _secrets_in(raw)
    return TestDefinition.model_validate(raw)


# ---------------------------------------------------------------- pytest / HTTPX rendering

_PY_TEMPLATE_HELPERS = """
import json
import os
import re

import httpx
import pytest

BASE_URL = os.environ.get("VULNREPLAY_TARGET_URL", "http://localhost:8001")
_VARS: dict = {}


def _secret(name: str) -> str:
    value = os.environ.get(f"VULNREPLAY_SECRET_{name}")
    if value is None:
        pytest.skip(f"secret {name} not configured")
    return value


def _render(value):
    if isinstance(value, str):
        def repl(m):
            return _secret(m.group(2)) if m.group(1) else str(_VARS[m.group(2)])
        return re.sub(r"\\{\\{\\s*(secret:)?([A-Za-z_][A-Za-z0-9_]*)\\s*\\}\\}", repl, value)
    if isinstance(value, dict):
        return {k: _render(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v) for v in value]
    return value


def _get(data, path):
    for name, idx in re.findall(r"([^.\\[\\]]+)|\\[(\\d+)\\]", path):
        data = data[int(idx)] if idx else data[name]
    return data
"""


def _py_assert(a: dict[str, Any]) -> str:
    t = a["type"]
    v = json.dumps(a.get("value"))
    desc = json.dumps(a.get("description") or t)
    if t == "status_in":
        return f"assert resp.status_code in {a['values']}, {desc}"
    if t == "status_not_in":
        return f"assert resp.status_code not in {a['values']}, {desc}"
    if t == "sequence_any_status_in":
        return f"assert any(s in {a['values']} for s in statuses), {desc}"
    if t == "body_contains":
        return f"assert _render({v}) in resp.text, {desc}"
    if t == "body_not_contains":
        return f"assert _render({v}) not in resp.text, {desc}"
    if t == "json_path_absent":
        return f"assert {json.dumps(a['path'].split('.')[0])} not in (resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {{}}), {desc}"  # noqa: E501
    if t == "header_present":
        return f"assert {json.dumps(a['name'])} in resp.headers, {desc}"
    if t == "header_absent":
        return f"assert {json.dumps(a['name'])} not in resp.headers, {desc}"
    if t == "header_equals":
        return f"assert resp.headers.get({json.dumps(a['name'])}) == {v}, {desc}"
    if t == "header_not_equals":
        return f"assert resp.headers.get({json.dumps(a['name'])}) != {v}, {desc}"
    if t == "header_contains":
        return f"assert {v}.lower() in '; '.join(resp.headers.get_list({json.dumps(a['name'])})).lower(), {desc}"
    if t == "max_duration_ms":
        return f"assert resp.elapsed.total_seconds() * 1000 <= {a['expected']}, {desc}"
    return f"# unsupported in code rendering: {t} (run via the VulnReplay engine)"


def render_pytest(defn: TestDefinition) -> str:
    lines = [
        f'"""VulnReplay regression test: {defn.name}',
        "",
        f"Category: {defn.category} | Severity: {defn.severity} | Test id: {defn.id}",
        "Generated from imported evidence. Review before running; run only against authorized targets.",
        "Secrets are read from VULNREPLAY_SECRET_<NAME> environment variables.",
        '"""',
        _PY_TEMPLATE_HELPERS,
        "",
    ]
    lines.append(f"def test_{_slug(defn.id)}():")
    lines.append("    with httpx.Client(base_url=BASE_URL, timeout=10, follow_redirects=False) as client:")
    for step in defn.steps:
        d = step.model_dump(by_alias=True)
        req = d["request"]
        lines.append(f"        # {step.role}: {step.name or step.id}")
        lines.append("        statuses = []")
        lines.append(f"        for _ in range({step.repeat}):")
        args = [
            json.dumps(req["method"]),
            f"_render({json.dumps(req['path'])})",
            f"headers=_render({json.dumps(req['headers'])})",
            f"params=_render({json.dumps(req['query'])})",
        ]
        if req.get("json") is not None:
            args.append(f"json=_render({json.dumps(req['json'])})")
        elif req.get("body") is not None:
            args.append(f"content=_render({json.dumps(req['body'])})")
        lines.append(f"            resp = client.request({', '.join(args)})")
        lines.append("            statuses.append(resp.status_code)")
        for a in d["expect"] + d["assert_secure"]:
            lines.append(f"        {_py_assert(a)}")
        for var, ext in d["extract"].items():
            if ext["source"] == "json":
                lines.append(f"        _VARS[{json.dumps(var)}] = _get(resp.json(), {json.dumps(ext['path'])})")
            elif ext["source"] == "header":
                lines.append(f"        _VARS[{json.dumps(var)}] = resp.headers[{json.dumps(ext['path'])}]")
            else:
                lines.append(f"        _VARS[{json.dumps(var)}] = resp.status_code")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- Playwright rendering


def _ts_assert(a: dict[str, Any]) -> str:
    t = a["type"]
    v = json.dumps(a.get("value"))
    if t == "status_in":
        return f"expect({json.dumps(a['values'])}).toContain(resp.status());"
    if t == "status_not_in":
        return f"expect({json.dumps(a['values'])}).not.toContain(resp.status());"
    if t == "sequence_any_status_in":
        return f"expect(statuses.some((s) => {json.dumps(a['values'])}.includes(s))).toBeTruthy();"
    if t == "body_contains":
        return f"expect(await resp.text()).toContain(render({v}));"
    if t == "body_not_contains":
        return f"expect(await resp.text()).not.toContain(render({v}));"
    if t == "header_present":
        return f"expect(resp.headers()[{json.dumps(a['name'].lower())}]).toBeDefined();"
    if t == "header_absent":
        return f"expect(resp.headers()[{json.dumps(a['name'].lower())}]).toBeUndefined();"
    if t == "header_not_equals":
        return f"expect(resp.headers()[{json.dumps(a['name'].lower())}]).not.toBe({v});"
    if t == "header_equals":
        return f"expect(resp.headers()[{json.dumps(a['name'].lower())}]).toBe({v});"
    if t == "header_contains":
        return f"expect((resp.headers()[{json.dumps(a['name'].lower())}] ?? '').toLowerCase()).toContain({v}.toLowerCase());"  # noqa: E501
    return f"// {t}: evaluate with the VulnReplay engine"


def render_playwright(defn: TestDefinition) -> str:
    out = [
        "// VulnReplay regression test (Playwright API testing)",
        f"// {defn.name} | category: {defn.category} | id: {defn.id}",
        "// Run only against authorized targets. Secrets come from VULNREPLAY_SECRET_<NAME>.",
        "import { test, expect } from '@playwright/test';",
        "",
        "const BASE_URL = process.env.VULNREPLAY_TARGET_URL ?? 'http://localhost:8001';",
        "const vars: Record<string, string> = {};",
        "function render<T>(value: T): T {",
        "  const s = JSON.stringify(value).replace(/\\{\\{\\s*(secret:)?([A-Za-z_][A-Za-z0-9_]*)\\s*\\}\\}/g,",
        "    (_m, sec, name) => JSON.stringify(sec ? process.env[`VULNREPLAY_SECRET_${name}`] ?? '' : vars[name] ?? '').slice(1, -1));",  # noqa: E501
        "  return JSON.parse(s) as T;",
        "}",
        "",
        f"test({json.dumps(defn.name)}, async ({{ request }}) => {{",
    ]
    for step in defn.steps:
        d = step.model_dump(by_alias=True)
        req = d["request"]
        out.append(f"  // {step.role}: {step.name or step.id}")
        out.append("  {")
        out.append("    const statuses: number[] = [];")
        out.append("    let resp!: Awaited<ReturnType<typeof request.fetch>>;")
        out.append(f"    for (let i = 0; i < {step.repeat}; i++) {{")
        opts = [
            f"method: {json.dumps(req['method'])}",
            f"headers: render({json.dumps(req['headers'])})",
            f"params: render({json.dumps(req['query'])})",
            "maxRedirects: 0",
        ]
        if req.get("json") is not None:
            opts.append(f"data: render({json.dumps(req['json'])})")
        out.append(
            f"      resp = await request.fetch(BASE_URL + render({json.dumps(req['path'])}), {{ {', '.join(opts)} }});"
        )  # noqa: E501
        out.append("      statuses.push(resp.status());")
        out.append("    }")
        for a in d["expect"] + d["assert_secure"]:
            out.append(f"    {_ts_assert(a)}")
        for var, ext in d["extract"].items():
            if ext["source"] == "json":
                path = ".".join(f"[{p}]" if p.isdigit() else p for p in re.split(r"[.\[\]]+", ext["path"]) if p)
                out.append(f"    vars[{json.dumps(var)}] = String((await resp.json()).{path});")
        out.append("  }")
    out.append("});")
    return "\n".join(out) + "\n"


def render(defn: TestDefinition, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(defn.model_dump(by_alias=True, mode="json"), indent=2)
    if fmt == "pytest":
        return render_pytest(defn)
    if fmt == "playwright":
        return render_playwright(defn)
    raise ValueError(f"unknown format {fmt}")
