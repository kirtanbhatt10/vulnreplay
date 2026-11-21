"""Target allowlisting, SSRF, DNS rebinding and redirect protections."""

from __future__ import annotations

import threading

import httpx
import pytest

from vulnreplay.execution import ExecutionLimits, TargetGuard, TargetNotAllowed, run_test
from vulnreplay.execution.guard import GuardedTransport
from vulnreplay.testdef import Context, TestDefinition


def fixed(*ips: str):  # type: ignore[no-untyped-def]
    return lambda host, port: list(ips)


def test_host_must_be_allowlisted() -> None:
    with pytest.raises(TargetNotAllowed, match="allowlist"):
        TargetGuard("https://example.com", ["localhost"])


@pytest.mark.parametrize("url", ["ftp://localhost/", "http://user:pw@localhost/", "localhost:80"])
def test_bad_base_urls(url: str) -> None:
    with pytest.raises(TargetNotAllowed):
        TargetGuard(url, ["localhost"])


def test_requests_cannot_leave_target() -> None:
    g = TargetGuard("http://localhost:8001", ["localhost", "127.0.0.1"])
    g.check_url("http://localhost:8001/api/x")
    for other in (
        "http://localhost:8002/",
        "https://localhost:8001/",
        "http://127.0.0.1:8001/",
        "http://evil.test/",
        "http://a@localhost:8001/",
    ):
        with pytest.raises(TargetNotAllowed):
            g.check_url(other)


@pytest.mark.parametrize("ip", ["169.254.169.254", "0.0.0.0", "224.0.0.1", "fe80::1", "100.64.0.1"])
def test_always_blocked_addresses(ip: str) -> None:
    g = TargetGuard("http://staging.app.test", ["staging.app.test"], allow_private_network=True, resolver=fixed(ip))
    with pytest.raises(TargetNotAllowed, match="disallowed"):
        g.resolve("staging.app.test", 80)


def test_dns_rebinding_to_private_or_loopback_blocked() -> None:
    g = TargetGuard("http://staging.app.test", ["staging.app.test"], resolver=fixed("93.184.216.34", "10.0.0.5"))
    with pytest.raises(TargetNotAllowed):
        g.resolve("staging.app.test", 80)
    g2 = TargetGuard("http://staging.app.test", ["staging.app.test"], resolver=fixed("127.0.0.1"))
    with pytest.raises(TargetNotAllowed):
        g2.resolve("staging.app.test", 80)


def test_ipv4_mapped_ipv6_is_normalised() -> None:
    g = TargetGuard("http://staging.app.test", ["staging.app.test"], resolver=fixed("::ffff:169.254.169.254"))
    with pytest.raises(TargetNotAllowed):
        g.resolve("staging.app.test", 80)


def test_localhost_target_cannot_resolve_public() -> None:
    g = TargetGuard("http://localhost:9", ["localhost"], resolver=fixed("93.184.216.34"))
    with pytest.raises(TargetNotAllowed):
        g.resolve("localhost", 9)


def test_private_allowed_only_when_flagged() -> None:
    g = TargetGuard(
        "http://demo-vulnerable:8000", ["demo-vulnerable"], allow_private_network=True, resolver=fixed("172.18.0.4")
    )
    assert g.resolve("demo-vulnerable", 8000) == "172.18.0.4"


def test_transport_revalidates_every_request_and_pins_ip() -> None:
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])  # second lookup "rebinds" to loopback
    seen: list[str] = []

    class Inner(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            seen.append(f"{request.url.host}|{request.headers['host']}")
            return httpx.Response(200, text="ok")

    g = TargetGuard("http://staging.app.test", ["staging.app.test"], resolver=lambda h, p: next(answers))
    t = GuardedTransport(g)
    t._inner = Inner()  # type: ignore[assignment]
    client = httpx.Client(transport=t)
    assert client.get("http://staging.app.test/a").status_code == 200
    assert seen == ["93.184.216.34|staging.app.test"]
    with pytest.raises(TargetNotAllowed):
        client.get("http://staging.app.test/b")


def _redirect_definition() -> TestDefinition:
    return TestDefinition.model_validate(
        {
            "id": "redir",
            "name": "redirect",
            "steps": [
                {
                    "id": "p",
                    "role": "probe",
                    "follow_redirects": True,
                    "request": {"path": "/start"},
                    "assert_secure": [{"type": "status_in", "values": [200], "description": "final"}],
                }
            ],
        }
    )


def test_redirect_to_unapproved_destination_is_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    g = TargetGuard("http://localhost:8001", ["localhost"])
    res = run_test(
        _redirect_definition(), g, Context(), ExecutionLimits(min_interval_ms=0), transport=httpx.MockTransport(handler)
    )
    assert calls == ["http://localhost:8001/start"]
    assert any("redirect blocked" in line for line in res["log"])
    assert res["steps"][0]["requests"][0]["status"] == 302


def test_same_target_redirect_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/done"})
        return httpx.Response(200, text="done")

    g = TargetGuard("http://localhost:8001", ["localhost"])
    res = run_test(
        _redirect_definition(), g, Context(), ExecutionLimits(min_interval_ms=0), transport=httpx.MockTransport(handler)
    )
    assert res["state"] == "secure"


def test_request_budget_and_cancellation() -> None:
    defn = TestDefinition.model_validate(
        {
            "id": "b",
            "name": "b",
            "steps": [
                {
                    "id": "p",
                    "role": "probe",
                    "repeat": 10,
                    "request": {"path": "/"},
                    "assert_secure": [{"type": "status_in", "values": [200]}],
                }
            ],
        }
    )
    g = TargetGuard("http://localhost:8001", ["localhost"])
    mock = httpx.MockTransport(lambda r: httpx.Response(200))
    res = run_test(defn, g, Context(), ExecutionLimits(min_interval_ms=0, max_requests=3), transport=mock)
    assert res["state"] == "error" and "maximum request count" in res["error"]
    cancel = threading.Event()
    cancel.set()
    res = run_test(defn, g, Context(), ExecutionLimits(min_interval_ms=0), cancel=cancel, transport=mock)
    assert res["error"] == "execution cancelled"


def test_response_size_cap() -> None:
    defn = TestDefinition.model_validate(
        {
            "id": "s",
            "name": "s",
            "steps": [
                {
                    "id": "p",
                    "role": "probe",
                    "request": {"path": "/"},
                    "assert_secure": [{"type": "body_not_contains", "value": "TAIL"}],
                }
            ],
        }
    )
    g = TargetGuard("http://localhost:8001", ["localhost"])
    mock = httpx.MockTransport(lambda r: httpx.Response(200, content=b"A" * 5000 + b"TAIL"))
    res = run_test(defn, g, Context(), ExecutionLimits(min_interval_ms=0, max_response_bytes=1000), transport=mock)
    assert res["steps"][0]["requests"][0]["body_length"] <= 1000
