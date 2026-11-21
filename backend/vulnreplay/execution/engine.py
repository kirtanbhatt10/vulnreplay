"""Controlled execution engine: runs a validated test definition against one authorized target."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

import httpx

from ..security import redact_headers, redact_obj, redact_text
from ..testdef import Assertion, Context, Step, TemplateError, TestDefinition, is_missing, json_path_get
from .guard import GuardedTransport, TargetGuard, TargetNotAllowed

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
]
MAX_REDIRECTS = 5


class ExecutionCancelled(Exception):
    pass


class RequestBudgetExceeded(Exception):
    pass


@dataclass
class ExecutionLimits:
    timeout_seconds: float = 10.0
    max_requests: int = 200
    min_interval_ms: int = 50
    max_response_bytes: int = 2 * 1024 * 1024
    verify_tls: bool = True


@dataclass
class Observed:
    status: int
    headers: httpx.Headers
    body: str
    duration_ms: float
    url: str


def _parse_json(body: str) -> Any:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def evaluate(assertion: Assertion, obs: Observed, ctx: Context, sequence: list[int] | None = None) -> dict[str, Any]:
    """Evaluate one assertion against an observed response. Returns a serializable result."""
    a = assertion
    passed = False
    detail = ""
    try:
        value = ctx.render(a.value) if a.value is not None else None
        expected = ctx.render(a.expected) if a.expected is not None else None
    except TemplateError as exc:
        return {"type": a.type, "description": a.description, "passed": False, "detail": f"template error: {exc}"}
    header_val = obs.headers.get(a.name) if a.name else None
    data = _parse_json(obs.body) if a.path else None
    if a.type == "status_in":
        passed, detail = obs.status in (a.values or []), f"status {obs.status}"
    elif a.type == "status_not_in":
        passed, detail = obs.status not in (a.values or []), f"status {obs.status}"
    elif a.type == "sequence_any_status_in":
        seq = sequence or [obs.status]
        passed, detail = any(s in (a.values or []) for s in seq), f"statuses {seq}"
    elif a.type == "body_contains":
        passed = bool(value) and str(value) in obs.body
        detail = "found" if passed else "not found"
    elif a.type == "body_not_contains":
        passed = not value or str(value) not in obs.body
        detail = "absent" if passed else "sensitive value present in response body"
    elif a.type in {"json_path_absent", "json_path_present", "json_path_equals", "json_path_not_equals"}:
        found = json_path_get(data, a.path or "") if data is not None else None
        missing = data is None or is_missing(found)
        if a.type == "json_path_absent":
            passed, detail = missing, "absent" if missing else f"present ({str(found)[:60]})"
        elif a.type == "json_path_present":
            passed, detail = not missing, "present" if not missing else "absent"
        elif a.type == "json_path_equals":
            passed, detail = (not missing and found == expected), f"value {str(found)[:60]}"
        else:
            passed, detail = (missing or found != expected), f"value {str(found)[:60]}"
    elif a.type == "header_present":
        passed, detail = header_val is not None, "present" if header_val is not None else "missing"
    elif a.type == "header_absent":
        passed, detail = header_val is None, "absent" if header_val is None else "present"
    elif a.type == "header_equals":
        passed, detail = header_val == value, f"value {header_val!r}"
    elif a.type == "header_not_equals":
        passed, detail = header_val != value, f"value {header_val!r}"
    elif a.type == "header_contains":
        joined = "; ".join(obs.headers.get_list(a.name or ""))
        passed, detail = bool(value) and str(value).lower() in joined.lower(), "checked"
    elif a.type == "max_duration_ms":
        passed, detail = obs.duration_ms <= float(expected or 0), f"{obs.duration_ms:.0f} ms"
    return {
        "type": a.type,
        "description": a.description,
        "passed": bool(passed),
        "detail": redact_text(detail, ctx.secret_values),
    }


class Runner:
    def __init__(
        self,
        definition: TestDefinition,
        guard: TargetGuard,
        ctx: Context,
        limits: ExecutionLimits,
        cancel: threading.Event | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.defn = definition
        self.guard = guard
        self.ctx = ctx
        self.limits = limits
        self.cancel = cancel or threading.Event()
        self.request_count = 0
        self.log: list[str] = []
        self._last_request = 0.0
        self._client = httpx.Client(
            transport=transport or GuardedTransport(guard, verify=limits.verify_tls),
            timeout=limits.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "VulnReplay/0.1 (+authorized security regression test)"},
        )

    def _log(self, message: str) -> None:
        stamp = datetime.now(UTC).strftime("%H:%M:%S.%f")[:-3]
        self.log.append(f"{stamp} {redact_text(message, self.ctx.secret_values)}")

    def _throttle(self) -> None:
        if self.cancel.is_set():
            raise ExecutionCancelled()
        if self.request_count >= min(self.limits.max_requests, self.defn.safety.max_requests):
            raise RequestBudgetExceeded("maximum request count reached")
        wait = self.limits.min_interval_ms / 1000 - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()
        self.request_count += 1

    def _send(self, method: str, url: str, **kwargs: Any) -> Observed:
        self._throttle()
        start = time.perf_counter()
        request = self._client.build_request(method, url, **kwargs)
        response = self._client.send(request, stream=True)
        try:
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > self.limits.max_response_bytes:
                    break
                chunks.append(chunk)
            body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
        finally:
            response.close()
        duration = (time.perf_counter() - start) * 1000
        self._log(f"{method} {url} -> {response.status_code} ({duration:.0f} ms)")
        return Observed(response.status_code, response.headers, body, duration, url)

    def _request(self, step: Step) -> Observed:
        spec = step.request
        url = urljoin(self.guard.base_url.rstrip("/") + "/", self.ctx.render(spec.path).lstrip("/"))
        kwargs: dict[str, Any] = {"headers": self.ctx.render(spec.headers), "params": self.ctx.render(spec.query)}
        if spec.json_body is not None:
            kwargs["json"] = self.ctx.render(spec.json_body)
        elif spec.body is not None:
            kwargs["content"] = self.ctx.render(spec.body)
        obs = self._send(spec.method, url, **kwargs)
        hops = 0
        while step.follow_redirects and 300 <= obs.status < 400 and obs.headers.get("location"):
            hops += 1
            nxt = urljoin(obs.url, obs.headers["location"])
            try:
                self.guard.check_url(nxt)
            except TargetNotAllowed as exc:
                self._log(f"redirect blocked: {exc}")
                break
            if hops > MAX_REDIRECTS:
                self._log("redirect limit reached")
                break
            obs = self._send("GET", nxt, headers=kwargs["headers"])
        return obs

    def _record(self, obs: Observed) -> dict[str, Any]:
        secrets = self.ctx.secret_values
        data = _parse_json(obs.body)
        return {
            "url": redact_text(obs.url, secrets),
            "status": obs.status,
            "duration_ms": round(obs.duration_ms, 1),
            "headers": redact_headers(dict(obs.headers)),
            "security_headers": {h: (h in obs.headers) for h in SECURITY_HEADERS},
            "body_preview": redact_text(obs.body[:4096], secrets),
            "body_length": len(obs.body),
            "json": redact_obj(data, secrets) if data is not None and len(obs.body) < 65536 else None,
        }

    def _run_step(self, step: Step) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": step.id,
            "name": step.name,
            "role": step.role,
            "requests": [],
            "expectations": [],
            "assertions": [],
            "error": None,
        }
        statuses: list[int] = []
        last: Observed | None = None
        for _ in range(step.repeat):
            last = self._request(step)
            statuses.append(last.status)
            result["requests"].append(self._record(last))
        if last is None:
            raise RuntimeError("step produced no response")
        result["statuses"] = statuses
        result["expectations"] = [evaluate(a, last, self.ctx, statuses) for a in step.expect]
        result["assertions"] = [evaluate(a, last, self.ctx, statuses) for a in step.assert_secure]
        for var, ext in step.extract.items():
            if ext.source == "status":
                self.ctx.variables[var] = last.status
            elif ext.source == "header":
                value = last.headers.get(ext.path)
                if value is None:
                    raise TemplateError(f"extract '{var}': header '{ext.path}' missing")
                self.ctx.variables[var] = value
            else:
                value = json_path_get(_parse_json(last.body), ext.path)
                if is_missing(value) or value is None:
                    raise TemplateError(f"extract '{var}': json path '{ext.path}' missing")
                self.ctx.variables[var] = value
        return result

    def run(self) -> dict[str, Any]:
        started = datetime.now(UTC)
        steps: list[dict[str, Any]] = []
        error: str | None = None
        state = "secure"
        try:
            for step in self.defn.steps:
                self._log(f"step {step.id} ({step.role}) started")
                try:
                    res = self._run_step(step)
                except TemplateError as exc:
                    steps.append(
                        {
                            "id": step.id,
                            "name": step.name,
                            "role": step.role,
                            "requests": [],
                            "expectations": [],
                            "assertions": [],
                            "error": str(exc),
                        }
                    )
                    raise
                steps.append(res)
                if not all(e["passed"] for e in res["expectations"]):
                    failed = [e for e in res["expectations"] if not e["passed"]]
                    raise PreconditionFailed(
                        f"step '{step.id}' precondition failed: "
                        f"{failed[0]['description'] or failed[0]['type']} ({failed[0]['detail']})"
                    )
                if step.role == "probe" and not all(a["passed"] for a in res["assertions"]):
                    state = "vulnerable"
        except ExecutionCancelled:
            error, state = "execution cancelled", "error"
        except (PreconditionFailed, TemplateError, RequestBudgetExceeded, TargetNotAllowed) as exc:
            error, state = str(exc), "error"
        except httpx.HTTPError as exc:
            error, state = f"network error: {type(exc).__name__}: {exc}", "error"
        finally:
            for step in self.defn.cleanup:
                try:
                    steps.append(self._run_step(step))
                except Exception as exc:  # noqa: BLE001 - cleanup must never mask the main result
                    self._log(f"cleanup step {step.id} failed: {type(exc).__name__}")
            self._client.close()
        probe_results = [a for s in steps if s["role"] == "probe" for a in s["assertions"]]
        if error:
            self._log(f"error: {error}")
        return {
            "state": state,
            "error": redact_text(error, self.ctx.secret_values) if error else None,
            "started_at": started.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            "request_count": self.request_count,
            "steps": steps,
            "summary": {
                "assertions_total": len(probe_results),
                "assertions_passed": sum(1 for a in probe_results if a["passed"]),
            },
            "log": self.log,
        }


class PreconditionFailed(Exception):
    pass


def run_test(
    definition: TestDefinition,
    guard: TargetGuard,
    ctx: Context,
    limits: ExecutionLimits,
    cancel: threading.Event | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    ctx.variables = {**definition.variables, **ctx.variables}
    return Runner(definition, guard, ctx, limits, cancel, transport).run()
