"""Attack simulator (Phase 7, spec §23): every scenario produces labelled SIMULATED activity
that flows through the real detection code, never touches live data, uses only documentation
addresses and reserved names, and cannot be pointed at anything."""

from __future__ import annotations

import ipaddress
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.provenance import Provenance
from app.models.incident import Incident
from app.models.security_event import EventSource, Outcome, SecurityEvent
from app.models.user import Role
from app.services import simulator
from app.services.audit import RequestContext
from app.services.simulator import Scenario
from tests.helpers import audit_entries, bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]

DOCUMENTATION_NETS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


@pytest.fixture
def lead(db_app: FastAPI) -> dict[str, Any]:
    user = create_user(
        db_app, "lead@example.com", role=Role.SECURITY_ENGINEER, mfa_enabled=True, mfa_secret=b"x"
    )
    return {"user": user, "h": bearer(session_token(db_app, user))}


def run(client: TestClient, h: dict[str, str], scenario: Scenario) -> dict[str, Any]:
    response = client.post("/api/v1/simulator/runs", json={"scenario": scenario.value}, headers=h)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def all_events(app: FastAPI) -> list[SecurityEvent]:
    with app.state.session_factory() as db:
        return list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.seq)).all())


def all_incidents(app: FastAPI) -> list[Incident]:
    with app.state.session_factory() as db:
        return list(db.scalars(select(Incident)).all())


def rules(summary: dict[str, Any]) -> dict[str, str]:
    return {d["rule_id"]: d["severity"] for d in summary["detections"]}


@pytest.mark.parametrize("scenario", list(Scenario))
def test_every_scenario_produces_only_simulated_activity(
    db_app: FastAPI, db_client: TestClient, lead: dict[str, Any], scenario: Scenario
) -> None:
    result = run(db_client, lead["h"], scenario)
    assert result["reference"] == "SIM-0001"
    assert result["summary"]["events"] > 0
    events = all_events(db_app)
    assert events
    assert {e.provenance for e in events} == {Provenance.SIMULATED}
    assert {i.provenance for i in all_incidents(db_app)} <= {Provenance.SIMULATED}
    for event in events:
        if event.source_ip:
            address = ipaddress.ip_address(event.source_ip)
            assert any(address in net for net in DOCUMENTATION_NETS), event.source_ip
        if event.actor_label:
            assert event.actor_label.endswith(".example"), event.actor_label
    (record,) = audit_entries(db_app, "simulator.run")
    assert record.details["scenario"] == scenario.value
    assert record.actor_label == "lead@example.com"


def test_sql_injection_blocked_at_the_edge_is_detected_without_an_incident(
    db_app: FastAPI, db_client: TestClient, lead: dict[str, Any]
) -> None:
    summary = run(db_client, lead["h"], Scenario.SQL_INJECTION)["summary"]
    assert summary["requests"]["blocked_by_waf"] == 16
    assert summary["requests"]["reached_app"] == 0
    assert rules(summary) == {"COR-003": "medium"}  # every payload stopped at the edge
    assert summary["incidents"] == []
    waf = [e for e in all_events(db_app) if e.source is EventSource.WAF]
    assert {e.outcome for e in waf} == {Outcome.BLOCKED}
    assert {e.status_code for e in waf} == {403}
    assert waf[0].evidence["waf"]["action"] == "BLOCK"
    assert waf[0].evidence["waf"]["web_acl"] == "sentineledge-simulated-acl"


def test_switching_waf_rules_to_count_lets_payloads_reach_the_app(
    db_app: FastAPI, db_client: TestClient, lead: dict[str, Any]
) -> None:
    for rule in ("SQLI-001", "SQLI-002", "SQLI-003", "SQLI-004", "SQLI-005", "SQLI-006"):
        response = db_client.put(
            f"/api/v1/simulator/waf-rules/{rule}", json={"mode": "count"}, headers=lead["h"]
        )
        assert response.status_code == 200
    summary = run(db_client, lead["h"], Scenario.SQL_INJECTION)["summary"]
    assert summary["requests"]["blocked_by_waf"] == 0
    assert summary["requests"]["counted_by_waf"] == 16
    assert summary["requests"]["reached_app"] == 16
    assert rules(summary)["COR-003"] == "high"
    (incident,) = summary["incidents"]
    assert incident["opened"] is True
    sources = {e.source for e in all_events(db_app) if e.source is not EventSource.CORRELATION}
    assert sources == {EventSource.WAF, EventSource.HTTP_ANALYSIS}  # edge and app both saw it
    assert len(audit_entries(db_app, "simulator.waf_rule_changed")) == 6


@pytest.mark.parametrize(
    ("scenario", "expected_rules", "opens_incident"),
    [
        (Scenario.CREDENTIAL_STUFFING, {"COR-001": "high", "COR-007": "high"}, True),
        (Scenario.BOT_ACTIVITY, {"COR-006": "medium"}, False),
        (Scenario.API_ABUSE, {"COR-005": "medium", "COR-004": "high"}, True),
        (Scenario.SUSPICIOUS_AUTH, {}, True),
        (Scenario.CERTIFICATE_EXPIRY, {}, True),
        (Scenario.VULNERABLE_DEPENDENCY, {}, True),
    ],
)
def test_scenarios_exercise_the_real_detection_rules(
    db_client: TestClient,
    lead: dict[str, Any],
    scenario: Scenario,
    expected_rules: dict[str, str],
    opens_incident: bool,
) -> None:
    summary = run(db_client, lead["h"], scenario)["summary"]
    for rule_id, severity in expected_rules.items():
        assert rules(summary).get(rule_id) == severity, summary["detections"]
    assert bool(summary["incidents"]) is opens_incident


def test_simulations_never_appear_in_the_live_view(
    db_client: TestClient, lead: dict[str, Any]
) -> None:
    opened = {
        incident["reference"]
        for scenario in (Scenario.CREDENTIAL_STUFFING, Scenario.CERTIFICATE_EXPIRY)
        for incident in run(db_client, lead["h"], scenario)["summary"]["incidents"]
    }
    live = db_client.get("/api/v1/incidents", params={"view": "live"}, headers=lead["h"]).json()
    simulated = db_client.get(
        "/api/v1/incidents", params={"view": "simulated"}, headers=lead["h"]
    ).json()
    assert live["items"] == []
    # Credential stuffing from two addresses opens one incident per source; certificates one.
    assert {i["reference"] for i in simulated["items"]} == opened
    assert len(opened) == 3
    events = db_client.get(
        "/api/v1/security-events", params={"view": "live"}, headers=lead["h"]
    ).json()
    assert events["items"] == []


def test_runs_are_deterministic_for_a_seed(db_app: FastAPI, lead: dict[str, Any]) -> None:
    from app.core.authz import Principal
    from app.models.session import AuthSession

    def summary_for(seed: int) -> dict[str, Any]:
        with db_app.state.session_factory() as db:
            user = db.merge(lead["user"])
            principal = Principal(
                user=user, session=AuthSession(user_id=user.id), pending=frozenset()
            )
            record = simulator.run_scenario(
                db, principal, Scenario.XSS, RequestContext(), seed=seed
            )
            return dict(record.summary["requests"])

    assert summary_for(7) == summary_for(7)


def test_the_simulated_waf_is_visible_and_scoped(
    db_client: TestClient, lead: dict[str, Any], db_app: FastAPI
) -> None:
    run(db_client, lead["h"], Scenario.XSS)
    listing = db_client.get("/api/v1/simulator/waf-rules", headers=lead["h"]).json()
    assert "SIMULATED" in listing["note"]
    by_id = {r["rule_id"]: r for r in listing["items"]}
    assert len(by_id) == 17
    assert all(r["mode"] == "block" for r in by_id.values())
    assert sum(r["matches_24h"] for r in by_id.values() if r["category"] == "xss") > 0
    assert by_id["SQLI-001"]["comparable_group"] == "AWSManagedRulesSQLiRuleSet"
    off = db_client.put(
        "/api/v1/simulator/waf-rules/XSS-001", json={"mode": "off"}, headers=lead["h"]
    )
    assert off.json() == {"mode": "off"}
    updated = {
        r["rule_id"]: r
        for r in db_client.get("/api/v1/simulator/waf-rules", headers=lead["h"]).json()["items"]
    }
    assert updated["XSS-001"]["mode"] == "off"
    assert updated["XSS-001"]["updated_by_label"] == "lead@example.com"
    (change,) = audit_entries(db_app, "simulator.waf_rule_changed")
    assert change.details == {"from": "block", "to": "off", "provenance": "SIMULATED"}


@pytest.mark.parametrize(
    ("path", "body", "status"),
    [
        ("/api/v1/simulator/waf-rules/NOPE-001", {"mode": "off"}, 404),
        ("/api/v1/simulator/waf-rules/XSS-001", {"mode": "allow-all"}, 422),
        ("/api/v1/simulator/waf-rules/x;drop", {"mode": "off"}, 422),
    ],
)
def test_waf_rule_changes_are_validated(
    db_client: TestClient, lead: dict[str, Any], path: str, body: dict[str, str], status: int
) -> None:
    assert db_client.put(path, json=body, headers=lead["h"]).status_code == status


@pytest.mark.parametrize(
    "body",
    [
        {"scenario": "sql_injection", "target": "https://bank.example"},
        {"scenario": "sql_injection", "host": "10.0.0.1"},
        {"scenario": "port_scan"},
        {},
    ],
)
def test_a_simulation_cannot_be_given_a_target(
    db_client: TestClient, lead: dict[str, Any], body: dict[str, str]
) -> None:
    response = db_client.post("/api/v1/simulator/runs", json=body, headers=lead["h"])
    assert response.status_code == 422


def test_scenarios_and_runs_are_listed(db_client: TestClient, lead: dict[str, Any]) -> None:
    catalogue = db_client.get("/api/v1/simulator/scenarios", headers=lead["h"]).json()["items"]
    assert {s["scenario"] for s in catalogue} == {s.value for s in Scenario}
    run(db_client, lead["h"], Scenario.BOT_ACTIVITY)
    run(db_client, lead["h"], Scenario.API_ABUSE)
    runs = db_client.get("/api/v1/simulator/runs", headers=lead["h"]).json()["items"]
    assert [r["reference"] for r in runs] == ["SIM-0002", "SIM-0001"]
    assert runs[0]["started_by_label"] == "lead@example.com"


def test_every_scenario_has_a_handler_and_description() -> None:
    assert set(simulator.HANDLERS) == set(Scenario)
    assert {s.scenario for s in simulator.CATALOGUE} == set(Scenario)
