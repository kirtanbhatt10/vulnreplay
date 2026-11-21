"""Evidence import engine: format detection, validation, fingerprinting and provenance."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from .common import EvidenceError, ParsedEvidence
from .formats import (
    parse_burp_xml,
    parse_har,
    parse_incident_log,
    parse_json_report,
    parse_raw_http,
    parse_sarif,
    parse_zap_json,
)

SUPPORTED_FORMATS = ("auto", "har", "burp", "zap", "sarif", "raw-http", "json", "incident-log")
BLOCKED_SIGNATURES = (b"\x80\x04", b"\x80\x05", b"PK\x03\x04", b"MZ", b"\x7fELF")  # pickle, zip, PE, ELF

__all__ = ["EvidenceError", "ParsedEvidence", "SUPPORTED_FORMATS", "fingerprint", "import_evidence"]


def fingerprint(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def detect_format(filename: str, raw: bytes) -> str:
    name = filename.lower()
    head = raw.lstrip()[:200]
    if name.endswith(".har"):
        return "har"
    if name.endswith(".sarif") or name.endswith(".sarif.json"):
        return "sarif"
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        return "incident-log"
    if head.startswith(b"<?xml") or head.startswith(b"<items"):
        return "burp"
    if head.startswith(b"{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Could be JSON Lines with a single object per line.
            return "incident-log"
        if isinstance(data, dict):
            if "log" in data and "entries" in data.get("log", {}):
                return "har"
            if "runs" in data and str(data.get("version", "")).startswith("2."):
                return "sarif"
            if "site" in data:
                return "zap"
            return "json"
    if head[:10].split(b" ")[0].isupper():
        return "raw-http"
    raise EvidenceError("Could not detect evidence format; specify it explicitly")


def import_evidence(
    filename: str, raw: bytes, fmt: str = "auto", *, max_bytes: int, body_limit: int, actor: str | None = None
) -> tuple[ParsedEvidence, dict[str, Any]]:
    """Validate and parse uploaded evidence. Returns (parsed, provenance)."""
    if not raw:
        raise EvidenceError("Uploaded file is empty")
    if len(raw) > max_bytes:
        raise EvidenceError(f"File exceeds the {max_bytes} byte limit")
    if any(raw.startswith(sig) for sig in BLOCKED_SIGNATURES):
        raise EvidenceError("Binary, archive or serialized-object uploads are not accepted")
    if fmt not in SUPPORTED_FORMATS:
        raise EvidenceError(f"Unsupported format {fmt!r}")
    if fmt == "auto":
        fmt = detect_format(filename, raw)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("Evidence must be UTF-8 text") from exc

    if fmt in {"har", "zap", "sarif", "json"}:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"Invalid JSON: {exc.msg} (line {exc.lineno})") from exc
        if not isinstance(data, dict):
            raise EvidenceError("Top-level JSON value must be an object")
        parser = {"har": parse_har, "zap": parse_zap_json, "sarif": parse_sarif, "json": parse_json_report}[fmt]
        parsed = parser(data, body_limit)
    elif fmt == "burp":
        parsed = parse_burp_xml(raw, body_limit)
    elif fmt == "raw-http":
        parsed = parse_raw_http(text, body_limit)
    else:
        parsed = parse_incident_log(text, body_limit)

    provenance = {
        "filename": filename[:255],
        "detected_format": parsed.format,
        "sha256": fingerprint(raw),
        "size_bytes": len(raw),
        "imported_at": datetime.now(UTC).isoformat(),
        "imported_by": actor,
        "exchange_count": len(parsed.exchanges),
        "finding_count": len(parsed.findings),
        "parser_metadata": parsed.metadata,
        "exchange_hashes": [
            hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() for e in parsed.exchanges
        ],
    }
    return parsed, provenance
