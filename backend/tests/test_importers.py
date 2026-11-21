from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from vulnreplay.importers import EvidenceError, detect_format, import_evidence

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
LIMITS = {"max_bytes": 5 * 1024 * 1024, "body_limit": 65536}


@pytest.mark.parametrize(
    ("name", "fmt", "exchanges"),
    [
        ("idor-invoice-burp.xml", "burp", 1),
        ("missing-headers-zap.json", "zap", 2),
        ("cors-reflection.har", "har", 1),
        ("admin-authz-bypass.sarif", "sarif", 1),
        ("password-reset-burst.jsonl", "incident-log", 8),
        ("sqli-products.http", "raw-http", 1),
        ("idor-report.json", "json", 1),
    ],
)
def test_samples_parse(name: str, fmt: str, exchanges: int) -> None:
    raw = (SAMPLES / name).read_bytes()
    parsed, prov = import_evidence(name, raw, **LIMITS)
    assert parsed.format == fmt
    assert len(parsed.exchanges) == exchanges
    assert prov["sha256"] == __import__("hashlib").sha256(raw).hexdigest()
    assert len(prov["exchange_hashes"]) == exchanges


def test_burp_extracts_request_and_response() -> None:
    parsed, _ = import_evidence("x.xml", (SAMPLES / "idor-invoice-burp.xml").read_bytes(), **LIMITS)
    ex = parsed.exchanges[0]
    assert ex["method"] == "GET" and ex["path"] == "/api/invoices/1001"
    assert ex["headers"]["Authorization"].startswith("Bearer ")
    assert ex["response"]["status"] == 200
    assert "alice@lab.vulnreplay.test" in ex["response"]["body"]


def test_zap_findings_and_metadata() -> None:
    parsed, _ = import_evidence("z.json", (SAMPLES / "missing-headers-zap.json").read_bytes(), **LIMITS)
    assert {f["category"] for f in parsed.findings} == {"security_headers"}
    assert parsed.findings[0]["cwe"] == "CWE-693"
    assert parsed.findings[0]["severity"] == "medium"


def test_sarif_finding_category() -> None:
    parsed, _ = import_evidence("a.sarif", (SAMPLES / "admin-authz-bypass.sarif").read_bytes(), **LIMITS)
    assert parsed.findings[0]["category"] == "authorization_bypass"
    assert parsed.findings[0]["exchange_indexes"] == [0]


def test_har_extracts_cookies_query_and_timestamp() -> None:
    har = {
        "log": {
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "request": {
                        "method": "GET",
                        "url": "https://app.test/a?x=1&y=2",
                        "headers": [{"name": "Cookie", "value": "sid=abc; t=1"}],
                    },
                    "response": {
                        "status": 302,
                        "headers": [],
                        "content": {"text": base64.b64encode(b"hi").decode(), "encoding": "base64"},
                    },
                }
            ]
        }
    }
    parsed, _ = import_evidence("a.har", json.dumps(har).encode(), **LIMITS)
    ex = parsed.exchanges[0]
    assert ex["query"] == {"x": "1", "y": "2"}
    assert ex["cookies"] == {"sid": "abc", "t": "1"}
    assert ex["timestamp"] == "2026-01-01T00:00:00Z"
    assert ex["response"]["body"] == "hi"


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x80\x04\x95pickle",
        b"PK\x03\x04zipfile",
        b"{not json",
        b'{"log": {"entries": "nope"}}',
        b"NOTAMETHOD / HTTP/1.1\n\n",
    ],
)
def test_malformed_rejected(payload: bytes) -> None:
    with pytest.raises(EvidenceError):
        import_evidence("bad.json", payload, **LIMITS)


def test_size_limit() -> None:
    with pytest.raises(EvidenceError, match="limit"):
        import_evidence("big.json", b"{" + b" " * 100 + b"}", max_bytes=50, body_limit=10)


def test_xxe_and_entity_expansion_rejected() -> None:
    xxe = b'<?xml version="1.0"?><!DOCTYPE items [<!ENTITY x SYSTEM "file:///etc/passwd">]><items>&x;</items>'
    with pytest.raises(EvidenceError):
        import_evidence("x.xml", xxe, **LIMITS)
    bomb = b'<?xml version="1.0"?><!DOCTYPE items [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><items>&b;</items>'
    with pytest.raises(EvidenceError):
        import_evidence("b.xml", bomb, **LIMITS)


def test_control_characters_sanitized_and_bodies_truncated() -> None:
    raw = b"POST /x HTTP/1.1\nHost: a.test\n\n" + b"A\x00B\x07C" + b"D" * 200
    parsed, _ = import_evidence("r.http", raw, max_bytes=10000, body_limit=50)
    body = parsed.exchanges[0]["body"]
    assert "\x00" not in body and "\x07" not in body
    assert parsed.exchanges[0]["body_truncated"] is True


def test_non_http_urls_rejected() -> None:
    report = {"exchanges": [{"request": {"method": "GET", "url": "file:///etc/passwd"}}]}
    with pytest.raises(EvidenceError, match="http"):
        import_evidence("r.json", json.dumps(report).encode(), **LIMITS)


def test_detect_format() -> None:
    assert detect_format("x.har", b"{}") == "har"
    assert detect_format("x.txt", b'{"runs": [], "version": "2.1.0"}') == "sarif"
    assert detect_format("x.txt", b"GET / HTTP/1.1\n") == "raw-http"
