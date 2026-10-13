"""The edge in AWS read back: real WAF blocks and ACM certificates (ADR-0029, C-EDGE-05/06).

AWS is replaced by fakes with the same call shapes as boto3's CloudWatch Logs and ACM clients.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.engine import Engine

from app.core.clock import utcnow
from app.core.provenance import Provenance
from app.main import create_app
from app.models.security_event import EventSource, Outcome, SecurityEvent
from app.models.user import Role
from app.services import aws_edge
from app.services.audit import AuditAction
from tests.conftest import TEST_ORIGIN, _truncate_all, make_settings
from tests.helpers import audit_entries, bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]
LOG_GROUP = "aws-waf-logs-sentineledge-test-edge"
EDGE_ARN = "arn:aws:acm:us-east-1:111122223333:certificate/edge"
ORIGIN_ARN = "arn:aws:acm:us-east-2:111122223333:certificate/origin"


def waf_message(rule: str, managed: str | None, ip: str, uri: str, at: datetime) -> str:
    groups = (
        [{"ruleGroupId": "AWS#X", "terminatingRule": {"ruleId": managed, "action": "BLOCK"}}]
        if managed
        else []
    )
    return json.dumps(
        {
            "timestamp": int(at.timestamp() * 1000),
            "action": "BLOCK",
            "terminatingRuleId": rule,
            "ruleGroupList": groups,
            "labels": [{"name": f"awswaf:managed:test:{managed or rule}"}],
            "httpRequest": {
                "clientIp": ip,
                "country": "NL",
                "uri": uri,
                "args": "id=1%27%20OR%20%271%27%3D%271",
                "httpMethod": "GET",
                "requestId": "req-1",
                "headers": [
                    {"name": "Host", "value": "sentineledge.example.com"},
                    {"name": "User-Agent", "value": "sqlmap/1.8"},
                ],
            },
        }
    )


class FakeLogs:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events
        self.calls: list[dict[str, Any]] = []

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        assert kwargs["logGroupName"] == LOG_GROUP
        assert kwargs["filterPattern"] == '{ $.action = "BLOCK" }'
        start = int(kwargs.get("nextToken", 0))
        page = self.events[start : start + 2]  # small pages: pagination is exercised
        out: dict[str, Any] = {"events": page}
        if start + 2 < len(self.events):
            out["nextToken"] = str(start + 2)
        return out


class FakeAcm:
    def __init__(self, certificates: list[dict[str, Any]]) -> None:
        self.certificates = certificates

    def list_certificates(self, **kwargs: Any) -> dict[str, Any]:
        assert "EC_prime256v1" in kwargs["Includes"]["keyTypes"]
        return {
            "CertificateSummaryList": [
                {"CertificateArn": c["CertificateArn"]} for c in self.certificates
            ]
        }

    def describe_certificate(self, CertificateArn: str) -> dict[str, Any]:  # noqa: N803 - boto3's name
        return {
            "Certificate": next(
                c for c in self.certificates if c["CertificateArn"] == CertificateArn
            )
        }


def certificate(arn: str, domain: str, days: int, **extra: Any) -> dict[str, Any]:
    now = utcnow()
    return {
        "CertificateArn": arn,
        "DomainName": domain,
        "SubjectAlternativeNames": [domain],
        "Status": "ISSUED",
        "Type": "AMAZON_ISSUED",
        "KeyAlgorithm": "EC_prime256v1",
        "Issuer": "Amazon",
        "NotBefore": now - timedelta(days=30),
        "NotAfter": now + timedelta(days=days),
        "RenewalEligibility": "ELIGIBLE",
        "InUseBy": ["arn:aws:cloudfront::111122223333:distribution/E1"],
        **extra,
    }


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    now = utcnow()
    logs = FakeLogs(
        [
            {
                "eventId": "e1",
                "message": waf_message(
                    "sql-injection",
                    "SQLi_QUERYARGUMENTS",
                    "203.0.113.7",
                    "/api/v1/health",
                    now - timedelta(minutes=3),
                ),
            },
            {
                "eventId": "e2",
                "message": waf_message(
                    "known-bad-inputs",
                    "Log4JRCE_HEADER",
                    "203.0.113.7",
                    "/api/v1/health",
                    now - timedelta(minutes=2),
                ),
            },
            {
                "eventId": "e3",
                "message": waf_message(
                    "ip-reputation",
                    None,
                    "198.51.100.9",
                    "/wp-login.php",
                    now - timedelta(minutes=1),
                ),
            },
            {"eventId": "e4", "message": json.dumps({"action": "ALLOW", "timestamp": 1})},
            {"eventId": "e5", "message": "not json"},
        ]
    )
    acm = {
        "us-east-1": FakeAcm([certificate(EDGE_ARN, "sentineledge.example.com", 300)]),
        "us-east-2": FakeAcm([certificate(ORIGIN_ARN, "origin.sentineledge.example.com", 10)]),
    }

    def factory(service: str, region: str) -> Any:
        if service == "logs":
            assert region == "us-east-1"
            return logs
        return acm[region]

    monkeypatch.setattr(aws_edge, "_client_factory", factory)
    aws_edge.reset_cache()
    yield {"logs": logs, "acm": acm}
    aws_edge.reset_cache()


@pytest.fixture
def edge_app(migrator_engine: Engine) -> Iterator[FastAPI]:
    application = create_app(
        make_settings(waf_log_group=LOG_GROUP, certificate_regions="us-east-1,us-east-2")
    )
    yield application
    application.state.engine.dispose()
    _truncate_all(migrator_engine)


@pytest.fixture
def edge_client(edge_app: FastAPI) -> TestClient:
    # No context manager: the lifespan timer stays off, so tests sync explicitly.
    return TestClient(
        edge_app,
        base_url=TEST_ORIGIN,
        raise_server_exceptions=False,
        headers={"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "1"},
    )


def _token(app: FastAPI, role: Role, email: str = "lead@example.com") -> dict[str, str]:
    user = create_user(app, email, role=role, mfa_enabled=True, mfa_secret=b"x")
    return bearer(session_token(app, user))


def _waf_events(app: FastAPI) -> list[SecurityEvent]:
    with app.state.session_factory() as db:
        return list(
            db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.source == EventSource.WAF)
                .order_by(SecurityEvent.occurred_at)
            ).all()
        )


def test_waf_blocks_become_real_events_once(edge_app: FastAPI, fakes: dict[str, Any]) -> None:
    status = aws_edge.sync(edge_app.state.session_factory, edge_app.state.settings)
    assert status.errors == []
    assert status.waf_records_read == 3  # the ALLOW record and the broken one are skipped
    assert status.waf_events_stored == 3

    sqli, log4j, reputation = _waf_events(edge_app)
    for event in (sqli, log4j, reputation):
        assert event.provenance == Provenance.REAL_AWS
        assert event.outcome == Outcome.BLOCKED
    assert (sqli.category, sqli.rule_id) == ("sql_injection", "SQLi_QUERYARGUMENTS")
    assert sqli.title == "AWS WAF blocked an SQL injection (SQLi_QUERYARGUMENTS)"
    assert sqli.source_ip == "203.0.113.7"
    assert sqli.user_agent == "sqlmap/1.8"
    assert sqli.evidence["web_acl_rule"] == "sql-injection"
    assert sqli.evidence["country"] == "NL"
    assert log4j.category == "command_injection"
    assert reputation.category == "bot"

    # A second sync reads the same records again (overlap) and stores none of them twice.
    again = aws_edge.sync(edge_app.state.session_factory, edge_app.state.settings)
    assert again.waf_records_read == 3
    assert again.waf_events_stored == 0
    assert len(_waf_events(edge_app)) == 3
    # It starts from the newest stored block, minus the overlap, not from a day ago.
    first, second = fakes["logs"].calls[0], fakes["logs"].calls[-1]
    assert second["startTime"] > first["startTime"]


def test_real_blocks_feed_correlation_but_never_simulated_detections(
    edge_app: FastAPI, fakes: dict[str, Any]
) -> None:
    now = utcnow()
    fakes["logs"].events = [
        {
            "eventId": f"burst-{i}",
            "message": waf_message(
                "sql-injection",
                "SQLi_BODY",
                "203.0.113.50",
                "/api/v1/x",
                now - timedelta(seconds=60 - i),
            ),
        }
        for i in range(5)
    ]
    aws_edge.sync(edge_app.state.session_factory, edge_app.state.settings)
    with edge_app.state.session_factory() as db:
        detections = db.scalars(
            select(SecurityEvent).where(SecurityEvent.source == EventSource.CORRELATION)
        ).all()
    (campaign,) = detections
    assert campaign.rule_id == "COR-003"
    assert campaign.provenance == Provenance.REAL_AWS
    # Every request was stopped at the edge, so the campaign is one level lower.
    assert campaign.severity == "medium"
    assert campaign.evidence["all_blocked_at_edge"] is True


def test_certificates_are_listed_and_an_expiring_one_raises_one_event_a_day(
    edge_app: FastAPI, edge_client: TestClient, fakes: dict[str, Any]
) -> None:
    headers = _token(edge_app, Role.SECURITY_ENGINEER)
    listing = edge_client.get("/api/v1/edge/certificates", headers=headers)
    assert listing.status_code == 200
    body = listing.json()
    assert body["enabled"] is True
    assert body["regions"] == ["us-east-1", "us-east-2"]
    origin, edge = body["items"]  # soonest expiry first
    assert origin["domain"] == "origin.sentineledge.example.com"
    assert origin["condition"] == "expiring"
    assert origin["severity"] == "high"
    assert origin["days_left"] in (9, 10)
    assert edge["condition"] is None
    assert edge["in_use_by"] == 1

    for _ in range(2):
        aws_edge.sync(edge_app.state.session_factory, edge_app.state.settings)
    with edge_app.state.session_factory() as db:
        alerts = db.scalars(
            select(SecurityEvent).where(SecurityEvent.source == EventSource.CERTIFICATE)
        ).all()
    (alert,) = alerts
    assert alert.provenance == Provenance.REAL_AWS
    assert alert.title.startswith("Certificate for origin.sentineledge.example.com expires in")
    assert alert.evidence["certificate_arn"] == ORIGIN_ARN


def test_sync_now_is_for_leads_and_audited(
    edge_app: FastAPI, edge_client: TestClient, fakes: dict[str, Any]
) -> None:
    analyst = _token(edge_app, Role.ANALYST, "analyst@example.com")
    assert edge_client.post("/api/v1/edge/sync", headers=analyst).status_code == 403

    lead = _token(edge_app, Role.SECURITY_ENGINEER)
    response = edge_client.post("/api/v1/edge/sync", headers=lead)
    assert response.status_code == 200
    assert response.json()["waf_events_stored"] == 3
    (entry,) = audit_entries(edge_app, AuditAction.EDGE_SYNCED)
    assert entry.details["waf_events_stored"] == 3

    status = edge_client.get("/api/v1/edge/status", headers=analyst).json()
    assert status["waf_logs_enabled"] is True
    assert status["waf_blocks_24h"] == 3
    assert {r["rule"] for r in status["waf_blocks_by_rule"]} == {
        "SQLi_QUERYARGUMENTS",
        "Log4JRCE_HEADER",
        "ip-reputation",
    }
    assert status["last_sync"]["waf_events_stored"] == 3


def test_an_aws_failure_is_reported_without_aws_details(
    edge_app: FastAPI, fakes: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(**_: Any) -> dict[str, Any]:
        raise PermissionError("User arn:aws:iam::111122223333:role/x is not authorized")

    monkeypatch.setattr(fakes["logs"], "filter_log_events", denied)
    status = aws_edge.sync(edge_app.state.session_factory, edge_app.state.settings)
    assert status.errors == ["WAF logs: PermissionError"]
    # The certificate feed still ran.
    assert status.certificates_checked == 2


def test_locally_there_is_no_aws_edge(db_app: FastAPI, db_client: TestClient) -> None:
    lead = _token(db_app, Role.ADMIN, "admin@example.com")
    certificates = db_client.get("/api/v1/edge/certificates", headers=lead).json()
    assert certificates == {"enabled": False, "regions": [], "items": [], "error": None}
    response = db_client.post("/api/v1/edge/sync", headers=lead)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "edge_not_configured"
    environment = db_client.get("/api/v1/platform/environment", headers=lead).json()
    assert environment == {"environment": "test", "deployed": False, "region": None}


def test_the_waf_record_parser_ignores_what_it_cannot_read() -> None:
    at = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)
    record = aws_edge.parse_waf_record(
        "x", waf_message("core-rule-set", "CrossSiteScripting_BODY", "192.0.2.1", "/", at)
    )
    assert record is not None
    assert record.mapping.category == "xss"
    assert record.occurred_at == at
    assert aws_edge.parse_waf_record("y", json.dumps({"action": "BLOCK"})) is None
    assert aws_edge.parse_waf_record("z", "[1, 2]") is None
