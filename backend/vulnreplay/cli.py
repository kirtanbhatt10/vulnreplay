"""Command line interface, primarily for CI/CD pipelines.

vulnreplay run SUITE.json --target-url http://localhost:8001 --json out.json --sarif out.sarif
vulnreplay validate SUITE.json
vulnreplay import-check evidence.har
vulnreplay create-admin --email admin@example.test
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .config import get_settings
from .execution import ExecutionLimits, TargetGuard, TargetNotAllowed, run_test
from .regression import CLASSIFICATIONS, FAILED, REGRESSION, REPRODUCED, VERIFIED, classify, compare_results
from .security import redact_obj
from .testdef import Context, TestDefinition

DEFAULT_FAIL_ON = f"{REGRESSION},{REPRODUCED},{FAILED}"


def load_suite(path: Path) -> list[TestDefinition]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items: list[Any] = (
        list(data["tests"])
        if isinstance(data, dict) and "tests" in data
        else (data if isinstance(data, list) else [data])
    )
    return [TestDefinition.model_validate({k: v for k, v in t.items() if k != "x-vulnreplay"}) for t in items]


def to_sarif(results: list[dict[str, Any]], fail_on: set[str]) -> dict[str, Any]:
    rules, sarif_results = [], []
    for r in results:
        rules.append(
            {
                "id": r["test_id"],
                "name": r["name"],
                "shortDescription": {"text": r["name"]},
                "properties": {"category": r["category"], "tags": ["security", "regression"]},
            }
        )
        if r["classification"] in {VERIFIED}:
            continue
        level = "error" if r["classification"] in fail_on else "warning"
        sarif_results.append(
            {
                "ruleId": r["test_id"],
                "level": level,
                "message": {"text": f"{r['classification']}: " + "; ".join(r["reasons"][:3])},
                "properties": {"classification": r["classification"], "target": r["target"]},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnReplay",
                        "version": __version__,
                        "informationUri": "https://github.com/kirtanbhatt10/vulnreplay",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def cmd_run(args: argparse.Namespace) -> int:
    settings = get_settings()
    allowed = list(settings.allowed_hosts)
    suite = load_suite(Path(args.suite))
    if args.select:
        wanted = set(args.select.split(","))
        suite = [t for t in suite if t.id in wanted or wanted & set(t.tags) or t.category in wanted]
    try:
        guard = TargetGuard(args.target_url, allowed, allow_private_network=args.allow_private_network)
    except TargetNotAllowed as exc:
        print(f"error: {exc}. Add the host to VULNREPLAY_ALLOWED_HOSTS if it is authorized.", file=sys.stderr)
        return 2
    baselines: dict[str, Any] = {}
    if args.baseline and Path(args.baseline).exists():
        baselines = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    fail_on = {c.strip() for c in args.fail_on.split(",") if c.strip()}
    unknown = fail_on - set(CLASSIFICATIONS)
    if unknown:
        print(f"error: unknown classifications in --fail-on: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    limits = ExecutionLimits(
        timeout_seconds=settings.request_timeout_seconds,
        max_requests=settings.max_requests_per_execution,
        min_interval_ms=settings.min_request_interval_ms,
        max_response_bytes=settings.max_response_bytes,
    )
    results = []
    for defn in suite:
        ctx = Context()
        result = run_test(defn, guard, ctx, limits)
        base = baselines.get(defn.id, {})
        base_result = base.get("result")
        comparison = compare_results(base_result, result) if base_result and result["state"] != "error" else None
        classification, reasons = classify(result, base_result, bool(base.get("verified")), comparison)
        results.append(
            {
                "test_id": defn.id,
                "name": defn.name,
                "category": defn.category,
                "target": args.target_url,
                "classification": classification,
                "state": result["state"],
                "reasons": reasons,
                "summary": result["summary"],
                "request_count": result["request_count"],
                "comparison": comparison,
                "result": result if args.include_results else None,
            }
        )
        mark = "FAIL" if classification in fail_on else "ok  "
        print(
            f"[{mark}] {defn.id}: {classification} "
            f"({result['summary'].get('assertions_passed', 0)}/{result['summary'].get('assertions_total', 0)})"
        )
        if args.write_baseline and result["state"] == "vulnerable" and defn.id not in baselines:
            baselines[defn.id] = {"result": redact_obj(result), "verified": False}
        if args.write_baseline and classification == VERIFIED and defn.id in baselines:
            baselines[defn.id]["verified"] = True
    report = {
        "tool": "vulnreplay",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": args.target_url,
        "results": redact_obj(results),
    }
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(results, fail_on), indent=2), encoding="utf-8")
    if args.write_baseline and args.baseline:
        Path(args.baseline).write_text(json.dumps(baselines, indent=2), encoding="utf-8")
    failures = [r for r in results if r["classification"] in fail_on]
    print(f"{len(results)} test(s), {len(failures)} failing (fail-on: {', '.join(sorted(fail_on))})")
    return 1 if failures else 0


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        suite = load_suite(Path(args.suite))
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"invalid suite: {exc}", file=sys.stderr)
        return 1
    print(f"{len(suite)} valid test definition(s)")
    return 0


def cmd_import_check(args: argparse.Namespace) -> int:
    from .importers import EvidenceError, import_evidence

    settings = get_settings()
    raw = Path(args.file).read_bytes()
    try:
        parsed, prov = import_evidence(
            Path(args.file).name,
            raw,
            args.format,
            max_bytes=settings.max_upload_bytes,
            body_limit=settings.max_body_preview_bytes,
        )
    except EvidenceError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "format": parsed.format,
                "sha256": prov["sha256"],
                "exchanges": len(parsed.exchanges),
                "findings": [f["title"] for f in parsed.findings],
            },
            indent=2,
        )
    )
    return 0


def cmd_create_admin(args: argparse.Namespace) -> int:
    from . import models as m
    from .db import create_all, session_factory
    from .security import hash_password

    password = os.environ.get("VULNREPLAY_NEW_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    create_all()
    db = session_factory()()
    try:
        db.add(m.User(email=args.email.lower(), password_hash=hash_password(password), role="admin"))
        db.commit()
    finally:
        db.close()
    print(f"created admin {args.email}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnreplay", description="VulnReplay security regression CLI")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a test suite against an authorized target")
    run.add_argument("suite")
    run.add_argument("--target-url", required=True)
    run.add_argument(
        "--allow-private-network",
        action="store_true",
        help="allow private (RFC1918) addresses, e.g. a docker-compose lab network",
    )
    run.add_argument("--select", help="comma-separated test ids, tags or categories")
    run.add_argument("--baseline", help="baseline JSON file (per test id)")
    run.add_argument("--write-baseline", action="store_true", help="update the baseline file")
    run.add_argument("--fail-on", default=DEFAULT_FAIL_ON)
    run.add_argument("--json", help="write JSON results")
    run.add_argument("--sarif", help="write SARIF 2.1.0 results")
    run.add_argument("--include-results", action="store_true", help="include full (redacted) step results")
    run.set_defaults(func=cmd_run)

    val = sub.add_parser("validate", help="validate a suite file")
    val.add_argument("suite")
    val.set_defaults(func=cmd_validate)

    imp = sub.add_parser("import-check", help="parse an evidence file without storing it")
    imp.add_argument("file")
    imp.add_argument("--format", default="auto")
    imp.set_defaults(func=cmd_import_check)

    adm = sub.add_parser("create-admin", help="create an administrator account")
    adm.add_argument("--email", required=True)
    adm.set_defaults(func=cmd_create_admin)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
