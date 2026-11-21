"""Parsers for each supported evidence format. None of these execute imported content."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from .common import (
    EvidenceError,
    ParsedEvidence,
    absolute_url,
    build_exchange,
    infer_category,
    normalize_severity,
    parse_raw_http_request,
    parse_raw_http_response,
)

MAX_EXCHANGES = 2000


def _check_count(n: int) -> None:
    if n > MAX_EXCHANGES:
        raise EvidenceError(f"Evidence contains more than {MAX_EXCHANGES} exchanges")


# ------------------------------------------------------------------ HAR


def parse_har(data: dict[str, Any], limit: int) -> ParsedEvidence:
    entries = data.get("log", {}).get("entries")
    if not isinstance(entries, list):
        raise EvidenceError("HAR file has no log.entries array")
    _check_count(len(entries))
    out = ParsedEvidence(format="har", metadata={"creator": data.get("log", {}).get("creator", {})})
    for i, entry in enumerate(entries):
        req, resp = entry.get("request", {}), entry.get("response", {})
        headers = [(h.get("name", ""), h.get("value", "")) for h in req.get("headers", [])]
        resp_headers = [(h.get("name", ""), h.get("value", "")) for h in resp.get("headers", [])]
        content = resp.get("content", {}) or {}
        resp_body = content.get("text")
        if resp_body and content.get("encoding") == "base64":
            try:
                resp_body = base64.b64decode(resp_body, validate=True).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                resp_body = None
        out.exchanges.append(
            build_exchange(
                index=i,
                method=req.get("method", ""),
                url=req.get("url", ""),
                headers=headers,
                body=(req.get("postData") or {}).get("text"),
                response_status=resp.get("status"),
                response_headers=resp_headers,
                response_body=resp_body,
                timestamp=entry.get("startedDateTime"),
                source_ref=f"log.entries[{i}]",
                body_limit=limit,
            )
        )
    return out


# ------------------------------------------------------------------ Burp Suite XML ("Save items")


def _b64_or_text(node: Any) -> str:
    text = node.text or ""
    if node.get("base64") == "true":
        try:
            return base64.b64decode(text, validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError) as exc:
            raise EvidenceError("Invalid base64 in Burp export") from exc
    return text


def parse_burp_xml(raw: bytes, limit: int) -> ParsedEvidence:
    try:
        root = ElementTree.fromstring(raw)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise EvidenceError(f"Invalid or unsafe XML: {exc}") from exc
    if root.tag != "items":
        raise EvidenceError("Burp export must have an <items> root element")
    items = root.findall("item")
    _check_count(len(items))
    out = ParsedEvidence(format="burp", metadata={"burpVersion": root.get("burpVersion")})
    for i, item in enumerate(items):
        req_node = item.find("request")
        if req_node is None:
            raise EvidenceError(f"Burp item {i} has no <request>")
        method, target, headers, body = parse_raw_http_request(_b64_or_text(req_node))
        url_node = item.find("url")
        url = (url_node.text or "").strip() if url_node is not None else ""
        if not url.startswith(("http://", "https://")):
            scheme = (item.findtext("protocol") or "https").strip()
            url = absolute_url(target, headers, scheme)
        status = resp_headers = resp_body = None
        resp_node = item.find("response")
        if resp_node is not None and (resp_node.text or "").strip():
            status, resp_headers, resp_body = parse_raw_http_response(_b64_or_text(resp_node))
        out.exchanges.append(
            build_exchange(
                index=i,
                method=method,
                url=url,
                headers=headers,
                body=body or None,
                response_status=status,
                response_headers=resp_headers,
                response_body=resp_body,
                timestamp=item.findtext("time"),
                source_ref=f"items/item[{i}]",
                body_limit=limit,
            )
        )
    return out


# ------------------------------------------------------------------ OWASP ZAP JSON report


def parse_zap_json(data: dict[str, Any], limit: int) -> ParsedEvidence:
    sites = data.get("site")
    if not isinstance(sites, list):
        raise EvidenceError("ZAP report has no 'site' array")
    out = ParsedEvidence(
        format="zap",
        metadata={
            "programName": data.get("@programName"),
            "version": data.get("@version"),
            "generated": data.get("@generated"),
        },
    )
    for site in sites:
        for alert in site.get("alerts", []):
            idxs: list[int] = []
            for inst in alert.get("instances", []):
                _check_count(len(out.exchanges) + 1)
                url = inst.get("uri", "")
                try:
                    exch = build_exchange(
                        index=len(out.exchanges),
                        method=inst.get("method", "GET"),
                        url=url,
                        headers={},
                        body=None,
                        response_status=None,
                        response_body=inst.get("evidence") or None,
                        source_ref=f"alert {alert.get('pluginid')} instance",
                        body_limit=limit,
                    )
                except EvidenceError:
                    continue
                exch["zap"] = {
                    "param": inst.get("param"),
                    "attack": inst.get("attack"),
                    "evidence": inst.get("evidence"),
                }
                out.exchanges.append(exch)
                idxs.append(exch["index"])
            cwe = alert.get("cweid")
            name = alert.get("name") or alert.get("alert") or "ZAP alert"
            out.findings.append(
                {
                    "title": name,
                    "severity": normalize_severity(
                        str(alert.get("riskdesc", "")).split(" ")[0] or alert.get("riskcode")
                    ),
                    "description": _strip_html(alert.get("desc", "")),
                    "cwe": f"CWE-{cwe}" if cwe and str(cwe) not in {"-1", "0"} else None,
                    "category": infer_category(name, alert.get("desc"), f"cwe-{cwe}"),
                    "exchange_indexes": idxs,
                    "source_tool": "owasp-zap",
                }
            )
    return out


def _strip_html(text: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", text or "").strip()


# ------------------------------------------------------------------ SARIF 2.1.0


def parse_sarif(data: dict[str, Any], limit: int) -> ParsedEvidence:
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise EvidenceError("SARIF file has no 'runs' array")
    out = ParsedEvidence(format="sarif", metadata={"version": data.get("version")})
    for run in runs:
        tool = run.get("tool", {}).get("driver", {}) or {}
        rules = {r.get("id"): r for r in tool.get("rules", []) if isinstance(r, dict)}
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId"), {})
            idxs: list[int] = []
            web_req, web_resp = res.get("webRequest"), res.get("webResponse")
            if isinstance(web_req, dict) and web_req.get("target"):
                _check_count(len(out.exchanges) + 1)
                exch = build_exchange(
                    index=len(out.exchanges),
                    method=web_req.get("method", "GET"),
                    url=web_req["target"],
                    headers=web_req.get("headers") or {},
                    body=(web_req.get("body") or {}).get("text"),
                    response_status=(web_resp or {}).get("statusCode"),
                    response_headers=(web_resp or {}).get("headers") or {},
                    response_body=((web_resp or {}).get("body") or {}).get("text"),
                    source_ref=f"result {res.get('ruleId')}",
                    body_limit=limit,
                )
                out.exchanges.append(exch)
                idxs.append(exch["index"])
            message = (res.get("message") or {}).get("text", "")
            tags = " ".join((rule.get("properties") or {}).get("tags", []))
            title = (rule.get("shortDescription") or {}).get("text") or res.get("ruleId") or "SARIF result"
            out.findings.append(
                {
                    "title": title,
                    "severity": normalize_severity(res.get("level", "warning")),
                    "description": message,
                    "cwe": next((t.upper() for t in tags.split() if t.lower().startswith("cwe-")), None),
                    "category": infer_category(title, message, tags),
                    "exchange_indexes": idxs,
                    "source_tool": tool.get("name", "sarif"),
                }
            )
    return out


# ------------------------------------------------------------------ Raw HTTP

RESPONSE_SEPARATOR = "\n\nHTTP/"


def parse_raw_http(text: str, limit: int) -> ParsedEvidence:
    normalized = text.replace("\r\n", "\n").strip("\n")
    resp_text = None
    split_at = normalized.find(RESPONSE_SEPARATOR)
    if split_at != -1:
        req_text, resp_text = normalized[:split_at], normalized[split_at + 2 :]
    else:
        req_text = normalized
    method, target, headers, body = parse_raw_http_request(req_text)
    status = resp_headers = resp_body = None
    if resp_text:
        status, resp_headers, resp_body = parse_raw_http_response(resp_text)
    out = ParsedEvidence(format="raw-http")
    out.exchanges.append(
        build_exchange(
            index=0,
            method=method,
            url=absolute_url(target, headers),
            headers=headers,
            body=body or None,
            response_status=status,
            response_headers=resp_headers,
            response_body=resp_body,
            source_ref="raw",
            body_limit=limit,
        )
    )
    return out


# ------------------------------------------------------------------ VulnReplay JSON report / incident logs


def parse_json_report(data: dict[str, Any], limit: int) -> ParsedEvidence:
    """Generic JSON report: {"findings": [...], "exchanges": [{request, response}]}."""
    exchanges = data.get("exchanges", [])
    if not isinstance(exchanges, list):
        raise EvidenceError("'exchanges' must be an array")
    _check_count(len(exchanges))
    out = ParsedEvidence(format="json", metadata={"tool": data.get("tool")})
    for i, ex in enumerate(exchanges):
        req, resp = ex.get("request", {}), ex.get("response") or {}
        out.exchanges.append(
            build_exchange(
                index=i,
                method=req.get("method", ""),
                url=req.get("url", ""),
                headers=req.get("headers", {}),
                body=req.get("body"),
                response_status=resp.get("status"),
                response_headers=resp.get("headers", {}),
                response_body=resp.get("body")
                if not isinstance(resp.get("body"), dict | list)
                else json.dumps(resp.get("body")),
                timestamp=ex.get("timestamp"),
                source_ref=f"exchanges[{i}]",
                body_limit=limit,
            )
        )
    for f in data.get("findings", []):
        out.findings.append(
            {
                "title": str(f.get("title", "Imported finding"))[:300],
                "severity": normalize_severity(f.get("severity", "medium")),
                "description": str(f.get("description", "")),
                "cwe": f.get("cwe"),
                "category": f.get("category") or infer_category(f.get("title"), f.get("description"), f.get("cwe")),
                "exchange_indexes": [int(x) for x in f.get("exchange_indexes", []) if int(x) < len(out.exchanges)],
                "source_tool": str(data.get("tool") or "json"),
            }
        )
    return out


def parse_incident_log(text: str, limit: int) -> ParsedEvidence:
    """JSON Lines structured access/incident log: one object per line with method/url/status fields."""
    out = ParsedEvidence(format="incident-log")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"Invalid JSON on log line {lineno}") from exc
        if not isinstance(rec, dict):
            raise EvidenceError(f"Log line {lineno} is not an object")
        _check_count(len(out.exchanges) + 1)
        exch = build_exchange(
            index=len(out.exchanges),
            method=rec.get("method", ""),
            url=rec.get("url", ""),
            headers=rec.get("headers", {}),
            body=rec.get("request_body"),
            response_status=rec.get("status"),
            response_body=rec.get("response_body"),
            timestamp=rec.get("timestamp"),
            source_ref=f"line {lineno}",
            body_limit=limit,
        )
        exch["actor"] = rec.get("user") or rec.get("actor")
        out.exchanges.append(exch)
    if not out.exchanges:
        raise EvidenceError("Incident log contains no records")
    return out
