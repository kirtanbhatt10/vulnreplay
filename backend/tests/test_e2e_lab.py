"""End-to-end: evidence -> scenario -> test -> vulnerable baseline -> fix -> regression, against live lab apps."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from vulnreplay.cli import main as cli_main

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


class Lab:
    def __init__(self, client: TestClient, analyst: dict[str, str], admin: dict[str, str], urls: dict[str, str]):
        self.c, self.analyst, self.admin = client, analyst, admin
        self.pid = client.post("/api/v1/projects", json={"name": "Demo lab"}, headers=analyst).json()["id"]
        self.targets: dict[str, str] = {}
        for mode, url in urls.items():
            t = client.post(
                f"/api/v1/projects/{self.pid}/targets",
                json={"name": f"lab-{mode}", "base_url": url, "environment": "lab"},
                headers=analyst,
            )
            assert t.status_code == 201, t.text
            self.targets[mode] = t.json()["id"]

    def authorize_all(self) -> None:
        for tid in self.targets.values():
            r = self.c.post(
                f"/api/v1/targets/{tid}/authorization",
                json={"authorized": True, "authorization_note": "Local isolated demo lab"},
                headers=self.admin,
            )
            assert r.status_code == 200

    def upload(self, name: str) -> dict[str, Any]:
        r = self.c.post(
            f"/api/v1/projects/{self.pid}/evidence",
            files={"file": (name, (SAMPLES / name).read_bytes())},
            headers=self.analyst,
        )
        assert r.status_code == 201, r.text
        return dict(r.json())

    def finding(self, ev: dict[str, Any], category: str, title: str, idx: list[int] | None = None) -> str:
        if ev["findings"]:
            return str(ev["findings"][0]["id"])
        r = self.c.post(
            f"/api/v1/projects/{self.pid}/findings",
            json={
                "title": title,
                "category": category,
                "severity": "high",
                "evidence_id": ev["id"],
                "exchange_indexes": idx if idx is not None else list(range(ev["exchange_count"])),
            },
            headers=self.analyst,
        )
        assert r.status_code == 201, r.text
        return str(r.json()["id"])

    def test_from(self, finding_id: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
        s = self.c.post(
            f"/api/v1/projects/{self.pid}/scenarios",
            json={"finding_id": finding_id, "options": options or {}},
            headers=self.analyst,
        )
        assert s.status_code == 201, s.text
        t = self.c.post(
            f"/api/v1/projects/{self.pid}/tests/generate", json={"scenario_id": s.json()["id"]}, headers=self.analyst
        )
        assert t.status_code == 201, t.text
        return dict(t.json())

    def run(self, test_id: str, mode: str, label: str = "") -> dict[str, Any]:
        r = self.c.post(
            "/api/v1/executions",
            json={"test_id": test_id, "target_id": self.targets[mode], "label": label or mode, "wait": True},
            headers=self.analyst,
        )
        assert r.status_code == 202, r.text
        return dict(r.json())


LOGIN = {"auth_mode": "login_flow", "login": {"path": "/api/login", "token_path": "access_token"}}


@pytest.fixture()
def labenv(app_client: TestClient, analyst: dict[str, str], admin: dict[str, str], lab: dict[str, str]) -> Lab:
    return Lab(app_client, analyst, admin, lab)


def test_idor_full_regression_lifecycle(labenv: Lab) -> None:
    ev = labenv.upload("idor-invoice-burp.xml")
    fid = labenv.finding(ev, "idor", "IDOR: invoice readable by other users")
    test = labenv.test_from(fid, LOGIN)
    definition = test["definition"]
    assert [s["role"] for s in definition["steps"]] == ["setup", "setup", "setup", "probe"]
    assert "bob-captured-token" not in json.dumps(definition)  # credentials never copied from evidence
    assert set(definition["secrets"]) == {"OWNER_USERNAME", "OWNER_PASSWORD", "ATTACKER_USERNAME", "ATTACKER_PASSWORD"}

    # Safety gates: unapproved test and unauthorized target are refused.
    r = labenv.c.post(
        "/api/v1/executions",
        json={"test_id": test["id"], "target_id": labenv.targets["vulnerable"]},
        headers=labenv.analyst,
    )
    assert r.status_code == 403 and "approved" in r.json()["detail"]
    assert labenv.c.post(f"/api/v1/tests/{test['id']}/approve", headers=labenv.analyst).status_code == 200
    r = labenv.c.post(
        "/api/v1/executions",
        json={"test_id": test["id"], "target_id": labenv.targets["vulnerable"]},
        headers=labenv.analyst,
    )
    assert r.status_code == 403 and "authorized" in r.json()["detail"]
    labenv.authorize_all()

    # 1. Detect the vulnerable behaviour and store the baseline.
    base = labenv.run(test["id"], "vulnerable", "baseline")
    assert base["classification"] == "vulnerability_reproduced", base["comparison"]
    assert base["is_baseline"] is True
    assert "alice-lab-password" not in json.dumps(base) and "access_token" not in json.dumps(base["result"]["log"])

    # 2. Incomplete fix: 403 status but data still in the body -> NOT treated as fixed.
    partial = labenv.run(test["id"], "partial", "partial-fix")
    assert partial["classification"] == "vulnerability_reproduced"
    assert any("incomplete remediation" in r for r in partial["comparison"]["reasons"])
    assert any("sensitive data still present" in s for s in partial["comparison"]["diff"]["signals"])

    # 3. Real fix verified.
    fixed = labenv.run(test["id"], "patched", "post-fix")
    assert fixed["classification"] == "remediation_verified", fixed["comparison"]
    diff = fixed["comparison"]["diff"]
    assert diff["meaningful_change"] and not diff["status_only_change"]
    assert diff["steps"][0]["auth_behavior"] == {"before": "allowed", "after": "denied"}

    # 4. Reintroduced bug detected as a regression.
    again = labenv.run(test["id"], "vulnerable", "release-2")
    assert again["classification"] == "regression_detected"

    # 5. Reports.
    rep = labenv.c.get(f"/api/v1/tests/{test['id']}/report", headers=labenv.analyst).json()
    assert rep["remediation_verification"]["status"] == "regression_detected"
    assert [e["classification"] for e in rep["executions"]] == [
        "vulnerability_reproduced",
        "vulnerability_reproduced",
        "remediation_verified",
        "regression_detected",
    ]
    assert rep["original_evidence"]["sha256"] == ev["sha256"]
    assert len(rep["report_sha256"]) == 64
    assert "bob-captured-token" not in json.dumps(rep)
    html = labenv.c.get(f"/api/v1/tests/{test['id']}/report?format=html", headers=labenv.analyst)
    assert html.status_code == 200 and "Regression detected" in html.text
    pdf = labenv.c.get(f"/api/v1/tests/{test['id']}/report?format=pdf", headers=labenv.analyst)
    assert pdf.content.startswith(b"%PDF")

    # Comparison endpoint + assistant explanation grounded in execution data.
    cmp = labenv.c.get(f"/api/v1/compare?before={base['id']}&after={fixed['id']}", headers=labenv.analyst).json()
    assert cmp["diff"]["steps"][0]["status"]["after"] == 404
    ai = labenv.c.post(
        "/api/v1/assistant",
        json={"task": "explain_result", "execution_id": again["id"], "provider": "deterministic"},
        headers=labenv.analyst,
    ).json()
    assert "regression_detected" in ai["summary"] and ai["confidence"] == "high"

    # Library: versioning resets approval; search & export.
    v2 = dict(definition)
    v2["tags"] = [*definition["tags"], "invoices"]
    r = labenv.c.post(
        f"/api/v1/tests/{test['id']}/versions",
        json={"definition": v2, "change_note": "add tag"},
        headers=labenv.analyst,
    )
    assert r.json()["current_version"] == 2 and r.json()["status"] == "draft"
    assert len(labenv.c.get(f"/api/v1/projects/{labenv.pid}/tests?category=idor", headers=labenv.analyst).json()) == 1
    for fmt in ("pytest", "playwright", "json"):
        code = labenv.c.get(f"/api/v1/tests/{test['id']}/render?format={fmt}", headers=labenv.analyst)
        assert code.status_code == 200 and "alice-lab-password" not in code.text


@pytest.mark.parametrize(
    ("sample", "category", "options", "idx"),
    [
        ("missing-headers-zap.json", "security_headers", {"auth_mode": "none"}, None),
        ("password-reset-burst.jsonl", "rate_limiting", {"auth_mode": "none", "rate_limit_requests": 12}, None),
        ("sqli-products.http", "sql_injection", {"auth_mode": "none"}, None),
        ("cors-reflection.har", "cors_misconfiguration", {"auth_mode": "none"}, None),
        (
            "admin-authz-bypass.sarif",
            "authorization_bypass",
            {**LOGIN, "owner_username": "carol", "owner_password_secret": "CAROL_PASSWORD"},
            None,
        ),
    ],
)
def test_other_categories_reproduce_then_verify(
    labenv: Lab,
    monkeypatch: pytest.MonkeyPatch,
    sample: str,
    category: str,
    options: dict[str, Any],
    idx: list[int] | None,
) -> None:
    monkeypatch.setenv("VULNREPLAY_SECRET_CAROL_PASSWORD", "carol-lab-password")
    labenv.authorize_all()
    ev = labenv.upload(sample)
    fid = labenv.finding(ev, category, f"{category} finding", idx)
    test = labenv.test_from(fid, options)
    assert test["category"] == category
    labenv.c.post(f"/api/v1/tests/{test['id']}/approve", headers=labenv.analyst)
    first = labenv.run(test["id"], "vulnerable")
    assert first["classification"] == "vulnerability_reproduced", first["result"]
    second = labenv.run(test["id"], "patched")
    assert second["classification"] == "remediation_verified", second["comparison"]


def test_cli_suite_with_baseline_sarif_and_exit_codes(labenv: Lab, tmp_path: Path) -> None:
    labenv.authorize_all()
    ev = labenv.upload("idor-invoice-burp.xml")
    test = labenv.test_from(labenv.finding(ev, "idor", "IDOR"), LOGIN)
    labenv.c.post(f"/api/v1/tests/{test['id']}/approve", headers=labenv.analyst)
    suite = labenv.c.get(f"/api/v1/projects/{labenv.pid}/tests-export", headers=labenv.analyst).text
    suite_path, baseline = tmp_path / "suite.json", tmp_path / "baseline.json"
    suite_path.write_text(suite)
    out_json, out_sarif = tmp_path / "out.json", tmp_path / "out.sarif"
    lab_urls = {
        m: labenv.c.get(f"/api/v1/projects/{labenv.pid}/targets", headers=labenv.analyst).json() for m in ["x"]
    }["x"]
    url = {t["name"]: t["base_url"] for t in lab_urls}
    # Vulnerable: reproduced -> exit 1, baseline written.
    code = cli_main(
        [
            "run",
            str(suite_path),
            "--target-url",
            url["lab-vulnerable"],
            "--baseline",
            str(baseline),
            "--write-baseline",
            "--json",
            str(out_json),
            "--sarif",
            str(out_sarif),
        ]
    )
    assert code == 1
    sarif = json.loads(out_sarif.read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["level"] == "error"
    assert "alice-lab-password" not in out_json.read_text()
    # Patched: verified -> exit 0, baseline marked verified.
    assert (
        cli_main(
            [
                "run",
                str(suite_path),
                "--target-url",
                url["lab-patched"],
                "--baseline",
                str(baseline),
                "--write-baseline",
            ]
        )
        == 0
    )
    assert json.loads(baseline.read_text())[test["definition"]["id"]]["verified"] is True
    # Regression -> exit 1 with classification regression_detected.
    assert (
        cli_main(
            [
                "run",
                str(suite_path),
                "--target-url",
                url["lab-vulnerable"],
                "--baseline",
                str(baseline),
                "--json",
                str(out_json),
            ]
        )
        == 1
    )
    assert json.loads(out_json.read_text())["results"][0]["classification"] == "regression_detected"
    # Unauthorized external host refused.
    assert cli_main(["run", str(suite_path), "--target-url", "https://example.com"]) == 2
