"""Report generation (JSON, HTML, PDF). All content is redacted before rendering."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..ai import REMEDIATION
from ..security import redact_obj

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=select_autoescape(["html"]),
)

LABELS = {
    "vulnerability_reproduced": "Vulnerability reproduced",
    "remediation_verified": "Remediation verified",
    "regression_detected": "Regression detected",
    "inconclusive": "Inconclusive",
    "execution_failed": "Execution failed",
}


def build_report(
    *,
    project: dict[str, Any],
    test: dict[str, Any],
    definition: dict[str, Any],
    finding: dict[str, Any] | None,
    evidence: dict[str, Any] | None,
    scenario: dict[str, Any] | None,
    executions: list[dict[str, Any]],
) -> dict[str, Any]:
    latest = executions[-1] if executions else None
    baseline = next((e for e in executions if e.get("is_baseline")), None)
    category = test.get("category", "other")
    remaining: list[str] = []
    if latest is None:
        remaining.append("The test has never been executed.")
    elif latest.get("classification") in {"vulnerability_reproduced", "regression_detected"}:
        remaining.append("The vulnerability is currently reproducible in the tested environment.")
    elif latest.get("classification") == "inconclusive":
        remaining.append("The latest result does not prove remediation; strengthen assertions or re-run.")
    elif latest.get("classification") == "remediation_verified":
        remaining.append("Verified for the tested endpoint and environment only; sibling endpoints untested.")
    if evidence and any(
        (ex.get("body_truncated") or (ex.get("response") or {}).get("body_truncated"))
        for ex in evidence.get("exchanges", [])
    ):
        remaining.append("Some original evidence bodies were truncated at import.")
    report = {
        "report_version": "1",
        "generated_at": datetime.now(UTC).isoformat(),
        "project": {"id": project["id"], "name": project["name"]},
        "vulnerability": {
            "title": (finding or {}).get("title") or test["name"],
            "category": category,
            "severity": (finding or {}).get("severity") or definition.get("severity"),
            "cwe": (finding or {}).get("cwe"),
            "description": (finding or {}).get("description", ""),
            "source_tool": (finding or {}).get("source_tool"),
        },
        "original_evidence": {
            "evidence_id": (evidence or {}).get("id"),
            "filename": (evidence or {}).get("filename"),
            "format": (evidence or {}).get("format"),
            "sha256": (evidence or {}).get("sha256"),
            "provenance": (evidence or {}).get("provenance"),
            "exchanges": [
                ex
                for ex in (evidence or {}).get("exchanges", [])
                if not finding or not finding.get("exchange_indexes") or ex["index"] in finding["exchange_indexes"]
            ][:10],
        },
        "reproduction_steps": (scenario or {}).get("reproduction_instructions")
        or [f"{s['role']}: {s['request']['method']} {s['request']['path']}" for s in definition.get("steps", [])],
        "test": {
            "id": test["id"],
            "name": test["name"],
            "version": test.get("current_version"),
            "status": test.get("status"),
            "definition_sha256": hashlib.sha256(json.dumps(definition, sort_keys=True).encode()).hexdigest(),
        },
        "executions": [
            {
                "id": e["id"],
                "label": e.get("label"),
                "target": e.get("target_name"),
                "created_at": e.get("created_at"),
                "classification": e.get("classification"),
                "state": e.get("state"),
                "is_baseline": e.get("is_baseline"),
                "summary": (e.get("result") or {}).get("summary"),
                "reasons": (e.get("comparison") or {}).get("reasons"),
                "result_sha256": hashlib.sha256(
                    json.dumps(e.get("result"), sort_keys=True, default=str).encode()
                ).hexdigest(),
            }
            for e in executions
        ],
        "before_after": {
            "baseline_execution": baseline["id"] if baseline else None,
            "latest_execution": latest["id"] if latest else None,
            "comparison": (latest or {}).get("comparison", {}).get("diff"),
        },
        "remediation_verification": {
            "status": (latest or {}).get("classification") or "not_run",
            "label": LABELS.get((latest or {}).get("classification") or "", "Not run"),
        },
        "remaining_risks": remaining,
        "recommendations": REMEDIATION.get(category, REMEDIATION["other"]),
    }
    report = redact_obj(report)
    body = json.dumps(report, sort_keys=True, default=str).encode()
    report["report_sha256"] = hashlib.sha256(body).hexdigest()
    return report


def render_html(report: dict[str, Any]) -> str:
    return _env.get_template("report.html").render(r=report, labels=LABELS)


def _pdf_text(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.encode("latin-1", "replace").decode("latin-1")


def render_pdf(report: dict[str, Any]) -> bytes:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin

    def heading(text: str) -> None:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, _pdf_text(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)

    def para(text: Any) -> None:
        pdf.multi_cell(width, 5, _pdf_text(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    v = report["vulnerability"]
    pdf.set_font("Helvetica", "B", 17)
    para("VulnReplay Security Regression Report")
    pdf.set_font("Helvetica", "", 10)
    para(f"Project: {report['project']['name']}    Generated: {report['generated_at']}")
    heading("Vulnerability")
    para(f"{v['title']}\nCategory: {v['category']}   Severity: {v['severity']}   CWE: {v.get('cwe') or '-'}")
    if v.get("description"):
        para(v["description"][:1500])
    heading("Remediation verification")
    para(report["remediation_verification"]["label"])
    heading("Original evidence")
    ev = report["original_evidence"]
    para(f"File: {ev.get('filename')} ({ev.get('format')})\nSHA-256: {ev.get('sha256')}")
    for ex in ev.get("exchanges", [])[:5]:
        status = (ex.get("response") or {}).get("status")
        para(f"  #{ex['index']} {ex['method']} {ex['url']} -> {status}")
    heading("Reproduction steps")
    for step in report["reproduction_steps"]:
        para(f"- {step}")
    heading("Test executions")
    for e in report["executions"]:
        s = e.get("summary") or {}
        para(
            f"- {e.get('created_at')}  [{e.get('label') or '-'}] {e.get('target')}: "
            f"{LABELS.get(e.get('classification') or '', e.get('classification'))} "
            f"({s.get('assertions_passed', 0)}/{s.get('assertions_total', 0)} assertions)"
            f"{'  BASELINE' if e.get('is_baseline') else ''}\n  result sha256 {e['result_sha256']}"
        )
        for r in (e.get("reasons") or [])[:5]:
            para(f"    * {r}")
    heading("Before / after comparison")
    comp = report["before_after"].get("comparison") or {}
    for sig in comp.get("signals", []) or ["No comparison available."]:
        para(f"- {sig}")
    heading("Remaining risks")
    for r in report["remaining_risks"]:
        para(f"- {r}")
    heading("Recommendations")
    for r in report["recommendations"]:
        para(f"- {r}")
    heading("Integrity")
    para(f"Test definition SHA-256: {report['test']['definition_sha256']}\nReport SHA-256: {report['report_sha256']}")
    return bytes(pdf.output())
