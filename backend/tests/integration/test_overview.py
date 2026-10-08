"""Security dashboard (Phase 7, spec §12): live and simulated views stay apart, figures come
from real records, and controls that do not exist yet say so."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.clock import utcnow
from app.models.api_metrics import ApiEndpointStat
from app.models.security_event import EventCategory, EventSource, Outcome, Severity
from app.models.user import Role
from app.services import security_events
from app.services.security_events import EventContext
from tests.helpers import bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]


@pytest.fixture
def lead_h(db_app: FastAPI) -> dict[str, str]:
    user = create_user(
        db_app, "lead@example.com", role=Role.SECURITY_ENGINEER, mfa_enabled=True, mfa_secret=b"x"
    )
    return bearer(session_token(db_app, user))


def overview(client: TestClient, h: dict[str, str], **params: Any) -> dict[str, Any]:
    response = client.get("/api/v1/security/overview", params=params, headers=h)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def seed_live(app: FastAPI) -> None:
    with app.state.session_factory() as db:
        for i in range(3):
            security_events.record_event(
                db,
                source=EventSource.HTTP_ANALYSIS,
                category=EventCategory.XSS,
                severity=Severity.MEDIUM,
                outcome=Outcome.REJECTED if i else Outcome.ALLOWED,
                title="Script tag",
                rule_id="XSS-001",
                ctx=EventContext(source_ip="203.0.113.9", endpoint="/api/v1/users"),
            )
        security_events.record_event(
            db,
            source=EventSource.AUTH,
            category=EventCategory.TOKEN_THEFT,
            severity=Severity.HIGH,
            outcome=Outcome.REJECTED,
            title="Rotated refresh token replayed",
            ctx=EventContext(source_ip="198.51.100.20", actor_label="kim@corp.example"),
        )
        hour = utcnow().replace(minute=0, second=0, microsecond=0)
        rows = [
            ("GET", "/api/v1/users", hour, 50, 6, 1, 2, 3, 1),
            ("POST", "/api/v1/auth/login", hour - timedelta(hours=2), 20, 5, 0, 5, 0, 0),
            ("GET", "(unmatched)", hour, 4, 4, 0, 0, 0, 0),
        ]
        for method, route, at, requests, c4, c5, r401, r403, r429 in rows:
            db.add(
                ApiEndpointStat(
                    method=method,
                    route=route,
                    hour=at,
                    requests=requests,
                    client_errors=c4,
                    server_errors=c5,
                    unauthenticated=r401,
                    forbidden=r403,
                    throttled=r429,
                )
            )
        db.commit()


def test_live_view_reflects_real_records(
    db_app: FastAPI, db_client: TestClient, lead_h: dict[str, str]
) -> None:
    seed_live(db_app)
    live = overview(db_client, lead_h)
    assert live["view"] == "live"
    assert live["events"]["total"] == 4
    assert live["events"]["by_category"] == {"xss": 3, "token_theft": 1}
    assert live["events"]["reached_app"] == 1  # the XSS request that got a success response
    assert live["incidents"]["open"] == 1  # token theft opens an incident by itself
    assert live["incidents"]["unassigned"] == 1
    assert live["recent_incidents"][0]["title"] == "Rotated refresh token replayed"
    assert live["status"]["level"] == "attention"
    assert any("without an owner" in r for r in live["status"]["reasons"])
    sources = {s["source_ip"]: s for s in live["top_sources"]}
    assert sources["203.0.113.9"]["events"] == 3
    assert sources["198.51.100.20"]["max_severity"] == "high"
    assert live["top_rules"] == [{"rule_id": "XSS-001", "events": 3}]

    traffic = live["traffic"]
    assert traffic["source"] == "api_metrics"
    assert (traffic["requests"], traffic["unknown_paths"]) == (74, 4)
    assert traffic["rejected"] == 11
    assert traffic["by_method"] == {"GET": 54, "POST": 20}
    assert len(traffic["series"]) == 24
    assert sum(p["requests"] for p in traffic["series"]) == 74
    assert traffic["top_endpoints"][0] == {
        "method": "GET",
        "endpoint": "/api/v1/users",
        "requests": 50,
    }
    assert len(live["series"]) == 24
    assert sum(p["events"] for p in live["series"]) == 4

    controls = live["controls"]
    assert controls["waf"]["status"] == "planned"
    assert controls["certificates"]["status"] == "planned"
    assert controls["api"]["status"] == "measured"
    assert controls["detection"]["values"] == {"http_rules": 17, "correlation_rules": 7}


def test_simulated_view_is_separate(
    db_app: FastAPI, db_client: TestClient, lead_h: dict[str, str]
) -> None:
    seed_live(db_app)
    for scenario in ("sql_injection", "certificate_expiry"):
        assert (
            db_client.post(
                "/api/v1/simulator/runs", json={"scenario": scenario}, headers=lead_h
            ).status_code
            == 201
        )
    simulated = overview(db_client, lead_h, view="simulated")
    assert simulated["view"] == "simulated"
    assert "token_theft" not in simulated["events"]["by_category"]
    assert simulated["events"]["by_category"]["sql_injection"] == 16
    assert simulated["traffic"]["source"] == "simulator"
    assert simulated["traffic"]["blocked_at_edge"] == 16
    assert simulated["controls"]["waf"]["status"] == "simulated"
    assert simulated["controls"]["waf"]["values"]["block"] == 17
    assert simulated["controls"]["certificates"]["values"] == {"critical": 1, "medium": 1}
    assert simulated["status"]["level"] == "critical"  # an expired certificate is critical
    assert {c["country"] for c in simulated["countries"]} <= {"NL", "BR", "SG", "US", "DE", "IN"}
    live = overview(db_client, lead_h)
    assert live["events"]["total"] == 4  # unchanged by the simulations


def test_quiet_platform_reports_ok(db_client: TestClient, lead_h: dict[str, str]) -> None:
    quiet = overview(db_client, lead_h, hours=1)
    assert quiet["status"] == {
        "level": "ok",
        "reasons": ["No open high-severity incidents in this view"],
    }
    assert len(quiet["series"]) == 1
    assert quiet["incidents"]["mean_minutes_to_close"] is None


@pytest.mark.parametrize("params", [{"hours": 0}, {"hours": 169}, {"view": "all"}])
def test_parameters_are_validated(
    db_client: TestClient, lead_h: dict[str, str], params: dict[str, Any]
) -> None:
    response = db_client.get("/api/v1/security/overview", params=params, headers=lead_h)
    assert response.status_code == 422


def test_response_times_are_measured(
    db_client: TestClient, lead_h: dict[str, str], db_app: FastAPI
) -> None:
    created = db_client.post(
        "/api/v1/incidents", json={"title": "Probe", "severity": "low"}, headers=lead_h
    ).json()
    triaged = db_client.post(
        f"/api/v1/incidents/{created['id']}/transitions",
        json={"version": created["version"], "to_status": "TRIAGED"},
        headers=lead_h,
    ).json()
    db_client.post(
        f"/api/v1/incidents/{created['id']}/transitions",
        json={
            "version": triaged["version"],
            "to_status": "CLOSED",
            "resolution": "false_positive",
            "note": "Test traffic.",
        },
        headers=lead_h,
    )
    stats = overview(db_client, lead_h)["incidents"]
    assert stats["closed_in_window"] == 1
    assert stats["mean_minutes_to_triage"] is not None
    assert stats["mean_minutes_to_close"] is not None
