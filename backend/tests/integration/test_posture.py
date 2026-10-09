"""The explainable posture score (Phase 10, ADR-0022): coverage from the catalogue, live
deductions that name their records, planned categories shown as planned, and snapshots."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.helpers import audit_entries
from tests.integration.test_risk_governance import exception_body, people  # noqa: F401
from tests.integration.test_vulnerabilities import finding, report, run_import

pytestmark = [pytest.mark.security, pytest.mark.db]


def categories(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["key"]: c for c in body["categories"]}


def test_a_fresh_platform_scores_from_coverage_and_says_what_is_planned(
    db_app: FastAPI,
    db_client: TestClient,
    people: dict[str, Any],  # noqa: F811
) -> None:
    body = db_client.get("/api/v1/governance/posture", headers=people["viewer"]["h"]).json()
    cats = categories(body)
    assert len(cats) == 11
    identity = cats["identity"]
    assert (identity["state"], identity["score"], identity["planned"]) == ("measured", 100, 0)
    assert (
        identity["factors"][0]["label"]
        == f"{identity['implemented']} of {identity['implemented']} controls implemented"
    )
    # Built in Phase 9: every AI control implemented, so the category is measured in full.
    ai = cats["ai"]
    assert (ai["state"], ai["score"], ai["planned"]) == ("measured", 100, 0)
    # Still to come (Phase 5): a planned category scores 0 and names its controls.
    waf = cats["waf"]
    assert (waf["state"], waf["score"], waf["implemented"]) == ("planned", 0, 0)
    assert "C-WAF-01" in waf["factors"][0]["refs"]

    devsecops = cats["devsecops"]
    assert devsecops["factors"][-1]["label"] == "No scan imported yet"
    assert devsecops["score"] == devsecops["factors"][0]["points"] - 5

    scores = [c["score"] for c in body["categories"]]
    assert body["overall"] == round(sum(scores) / 11)
    measured = [c["score"] for c in body["categories"] if c["state"] == "measured"]
    assert body["built_scope"] == round(sum(measured) / len(measured))
    assert body["built_scope"] > body["overall"]
    assert "past their SLA" in body["method"]

    assert len(body["trend"]) == 1  # the day's automatic snapshot
    again = db_client.get("/api/v1/governance/posture", headers=people["viewer"]["h"]).json()
    assert len(again["trend"]) == 1


def test_live_signals_deduct_points_and_name_their_records(
    db_app: FastAPI,
    db_client: TestClient,
    people: dict[str, Any],  # noqa: F811
) -> None:
    past = datetime.now(UTC) - timedelta(days=30)
    run_import(
        db_app, report(finding("a", "critical"), finding("b", "high"), passed=False), now=past
    )
    lead, admin = people["lead"]["h"], people["admin"]["h"]
    e = db_client.post("/api/v1/exceptions", json=exception_body(), headers=lead).json()
    db_client.post(
        f"/api/v1/exceptions/{e['id']}/decision",
        json={"approve": True, "version": 1},
        headers=admin,
    )

    cats = categories(db_client.get("/api/v1/governance/posture", headers=lead).json())
    vuln = {f["label"]: f for f in cats["vulnerability"]["factors"][1:]}
    assert vuln["1 critical finding past the SLA"]["points"] == -10
    assert vuln["1 high finding past the SLA"]["points"] == -5
    assert vuln["1 critical finding past the SLA"]["refs"][0].startswith("VULN-")
    coverage = cats["vulnerability"]["factors"][0]["points"]
    assert cats["vulnerability"]["score"] == max(0, coverage - 15)

    gate = cats["devsecops"]["factors"][-1]
    assert gate["label"].endswith("failed the gate")
    assert gate["points"] == -10

    governance = cats["governance"]["factors"][-1]
    assert governance["label"] == "1 high or critical exception in force"
    assert governance["refs"] == [e["reference"]]

    monitoring = cats["monitoring"]["factors"][1:]
    assert monitoring  # the fixable critical finding opened an incident
    assert all(f["points"] < 0 and f["refs"] for f in monitoring)


def test_leads_take_snapshots_and_the_trend_records_them(
    db_app: FastAPI,
    db_client: TestClient,
    people: dict[str, Any],  # noqa: F811
) -> None:
    first = db_client.post("/api/v1/governance/posture/snapshots", headers=people["lead"]["h"])
    assert first.status_code == 201, first.text
    assert len(first.json()["trend"]) == 1  # a manual snapshot counts as the day's snapshot
    second = db_client.post("/api/v1/governance/posture/snapshots", headers=people["admin"]["h"])
    assert len(second.json()["trend"]) == 2
    taken, _ = audit_entries(db_app, "posture.snapshot_taken")
    assert taken.details["overall"] == first.json()["overall"]
    viewer = db_client.post("/api/v1/governance/posture/snapshots", headers=people["viewer"]["h"])
    assert viewer.status_code == 403
