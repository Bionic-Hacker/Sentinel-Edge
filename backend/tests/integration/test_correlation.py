"""Correlation (Phase 7): detection rules fire at their thresholds and not below, stay within
their window and their provenance, fire once per window, and open or join incidents according
to the incident policy, exactly once even under concurrency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.clock import utcnow
from app.core.provenance import Provenance
from app.models.audit import AuditResult
from app.models.incident import Incident, IncidentStatus, IncidentTimelineEntry, TimelineKind
from app.models.security_event import (
    EventCategory,
    EventSource,
    Outcome,
    SecurityEvent,
    Severity,
)
from app.services import audit, correlation, security_events
from app.services.audit import AuditAction, RequestContext
from app.services.security_events import EventContext
from tests.helpers import create_user, login

pytestmark = [pytest.mark.security, pytest.mark.db]

C = EventCategory
ATTACKER = "203.0.113.66"


def signal(
    app: FastAPI,
    category: EventCategory,
    *,
    ip: str | None = ATTACKER,
    actor: str | None = None,
    provenance: Provenance = Provenance.LOCAL,
    at: datetime | None = None,
    severity: Severity = Severity.LOW,
    outcome: Outcome = Outcome.REJECTED,
    source: EventSource = EventSource.AUTH,
) -> SecurityEvent:
    with app.state.session_factory() as db:
        event = security_events.record_event(
            db,
            source=source,
            category=category,
            severity=severity,
            outcome=outcome,
            title=f"test {category}",
            provenance=provenance,
            occurred_at=at,
            ctx=EventContext(source_ip=ip, actor_label=actor, endpoint="/api/v1/auth/login"),
        )
        db.commit()
        return event


def detections(app: FastAPI, rule_id: str | None = None) -> list[SecurityEvent]:
    with app.state.session_factory() as db:
        query = select(SecurityEvent).where(SecurityEvent.source == EventSource.CORRELATION)
        if rule_id:
            query = query.where(SecurityEvent.rule_id == rule_id)
        return list(db.scalars(query.order_by(SecurityEvent.seq)).all())


def incidents(app: FastAPI) -> list[Incident]:
    with app.state.session_factory() as db:
        return list(db.scalars(select(Incident).order_by(Incident.number)).all())


def linked(app: FastAPI, incident: Incident) -> list[SecurityEvent]:
    with app.state.session_factory() as db:
        return list(
            db.scalars(select(SecurityEvent).where(SecurityEvent.incident_id == incident.id)).all()
        )


def stuffing(app: FastAPI, n: int, *, accounts: int = 3, **kwargs: object) -> None:
    for i in range(n):
        signal(app, C.AUTH_FAILURE, actor=f"user{i % accounts}@example.com", **kwargs)  # type: ignore[arg-type]


# --- Rules ------------------------------------------------------------------------------------


def test_credential_stuffing_fires_at_threshold_and_not_before(db_app: FastAPI) -> None:
    stuffing(db_app, 9)
    assert detections(db_app) == []
    stuffing(db_app, 1)
    (detection,) = detections(db_app, "COR-001")
    assert detection.category is C.CREDENTIAL_STUFFING
    assert detection.severity is Severity.HIGH
    assert detection.source_ip == ATTACKER
    assert detection.evidence["events"] == 10
    assert detection.evidence["distinct_accounts"] == 3
    assert len(detection.evidence["contributing_event_ids"]) == 10
    assert detection.title == f"Credential stuffing from {ATTACKER}"


def test_failures_against_too_few_accounts_are_not_stuffing(db_app: FastAPI) -> None:
    stuffing(db_app, 12, accounts=2)
    assert detections(db_app, "COR-001") == []


def test_sustained_guessing_against_one_account(db_app: FastAPI) -> None:
    for i in range(10):
        signal(db_app, C.AUTH_FAILURE, ip=f"198.51.100.{i}", actor="victim@example.com")
    (detection,) = detections(db_app, "COR-002")
    assert detection.category is C.BRUTE_FORCE
    assert detection.actor_label == "victim@example.com"
    assert detection.title == "Sustained password guessing against victim@example.com"


def test_injection_campaign_takes_the_dominant_category(db_app: FastAPI) -> None:
    for category in (C.SQL_INJECTION, C.SQL_INJECTION, C.SQL_INJECTION, C.XSS, C.PATH_TRAVERSAL):
        signal(db_app, category, severity=Severity.HIGH, source=EventSource.HTTP_ANALYSIS)
    (detection,) = detections(db_app, "COR-003")
    assert detection.category is C.SQL_INJECTION
    assert detection.severity is Severity.HIGH
    assert detection.evidence["categories"] == {"sql_injection": 3, "xss": 1, "path_traversal": 1}


def test_injection_that_succeeded_escalates_the_detection(db_app: FastAPI) -> None:
    for i in range(5):
        signal(
            db_app,
            C.SQL_INJECTION,
            severity=Severity.HIGH,
            source=EventSource.HTTP_ANALYSIS,
            outcome=Outcome.ALLOWED if i == 0 else Outcome.REJECTED,
        )
    (detection,) = detections(db_app, "COR-003")
    assert detection.severity is Severity.CRITICAL
    assert detection.outcome is Outcome.ALLOWED
    assert detection.evidence["any_allowed"] is True


@pytest.mark.parametrize(
    ("category", "count", "rule", "expected", "severity", "group"),
    [
        (C.BOLA, 5, "COR-004", C.BOLA, Severity.HIGH, "actor"),
        (C.RATE_LIMIT, 3, "COR-005", C.API_ABUSE, Severity.MEDIUM, "ip"),
        (C.SCANNER, 3, "COR-006", C.BOT, Severity.MEDIUM, "ip"),
    ],
)
def test_other_rules(
    db_app: FastAPI,
    category: EventCategory,
    count: int,
    rule: str,
    expected: EventCategory,
    severity: Severity,
    group: str,
) -> None:
    for i in range(count - 1):
        ip = ATTACKER if group == "ip" else f"198.51.100.{i}"
        signal(db_app, category, ip=ip, actor="prober@example.com")
    assert detections(db_app, rule) == []
    signal(db_app, category, actor="prober@example.com")
    (detection,) = detections(db_app, rule)
    assert (detection.category, detection.severity) == (expected, severity)


def test_events_outside_the_window_do_not_count(db_app: FastAPI) -> None:
    old = utcnow() - timedelta(minutes=11)
    stuffing(db_app, 9, at=old)
    stuffing(db_app, 1)
    assert detections(db_app) == []


def test_a_detection_fires_once_per_window(db_app: FastAPI) -> None:
    stuffing(db_app, 25)
    assert len(detections(db_app, "COR-001")) == 1


def test_detections_never_cross_provenance(db_app: FastAPI) -> None:
    stuffing(db_app, 9)
    stuffing(db_app, 9, provenance=Provenance.SIMULATED)
    assert detections(db_app) == []  # 18 failures, but neither stream has 10
    stuffing(db_app, 1, provenance=Provenance.SIMULATED)
    (detection,) = detections(db_app)
    assert detection.provenance is Provenance.SIMULATED
    (incident,) = incidents(db_app)
    assert incident.provenance is Provenance.SIMULATED
    assert {e.provenance for e in linked(db_app, incident)} == {Provenance.SIMULATED}


# --- Incident policy --------------------------------------------------------------------------


def test_high_detection_opens_an_incident_with_its_evidence(db_app: FastAPI) -> None:
    stuffing(db_app, 10)
    (incident,) = incidents(db_app)
    (detection,) = detections(db_app)
    assert incident.status is IncidentStatus.DETECTED
    assert (incident.severity, incident.category) == (Severity.HIGH, C.CREDENTIAL_STUFFING)
    assert incident.detection_rule == "COR-001"
    assert incident.trigger_event_id == detection.id
    assert incident.owner_id is None
    assert incident.dedupe_key == f"LOCAL|ip:{ATTACKER}"
    assert len(linked(db_app, incident)) == 11  # the detection and its ten events


@pytest.mark.parametrize(
    ("category", "severity", "opens"),
    [
        (C.TOKEN_THEFT, Severity.HIGH, True),
        (C.AUDIT_TAMPERING, Severity.CRITICAL, True),
        (C.SQL_INJECTION, Severity.CRITICAL, True),
        (C.SQL_INJECTION, Severity.HIGH, False),
        (C.BRUTE_FORCE, Severity.MEDIUM, False),
    ],
)
def test_single_events_follow_the_incident_policy(
    db_app: FastAPI, category: EventCategory, severity: Severity, opens: bool
) -> None:
    signal(db_app, category, severity=severity)
    assert len(incidents(db_app)) == (1 if opens else 0)


def test_medium_detections_do_not_open_incidents(db_app: FastAPI) -> None:
    for _ in range(3):
        signal(db_app, C.RATE_LIMIT)
    assert detections(db_app, "COR-005")
    assert incidents(db_app) == []


def test_refresh_token_reuse_through_the_audit_log_opens_an_incident(db_app: FastAPI) -> None:
    with db_app.state.session_factory() as db:
        audit.record(
            db,
            action=AuditAction.REFRESH_TOKEN_REUSE,
            result=AuditResult.DENIED,
            actor="victim@example.com",
            ctx=RequestContext(source_ip=ATTACKER),
        )
        db.commit()
    (incident,) = incidents(db_app)
    assert incident.category is C.TOKEN_THEFT
    assert incident.provenance is Provenance.LOCAL


def test_later_detections_join_the_open_incident_and_raise_severity(db_app: FastAPI) -> None:
    for _ in range(3):
        signal(db_app, C.RATE_LIMIT)  # COR-005, medium: no incident yet
    signal(db_app, C.TOKEN_THEFT, severity=Severity.HIGH)
    signal(db_app, C.SQL_INJECTION, severity=Severity.CRITICAL, source=EventSource.HTTP_ANALYSIS)
    (incident,) = incidents(db_app)
    assert incident.severity is Severity.CRITICAL
    with db_app.state.session_factory() as db:
        kinds = [
            e.kind
            for e in db.scalars(
                select(IncidentTimelineEntry)
                .where(IncidentTimelineEntry.incident_id == incident.id)
                .order_by(IncidentTimelineEntry.seq)
            ).all()
        ]
    assert kinds == [
        TimelineKind.CREATED,
        TimelineKind.EVENTS_LINKED,
        TimelineKind.SEVERITY_RAISED,
        TimelineKind.EVENTS_LINKED,
    ]


def test_a_closed_incident_is_not_reused(db_app: FastAPI) -> None:
    signal(db_app, C.TOKEN_THEFT, severity=Severity.HIGH)
    (first,) = incidents(db_app)
    with db_app.state.session_factory() as db:
        incident = db.get(Incident, first.id)
        assert incident is not None
        incident.status = IncidentStatus.CLOSED
        incident.resolution = "false_positive"  # type: ignore[assignment]
        incident.closed_at = utcnow()
        db.commit()
    signal(db_app, C.TOKEN_THEFT, severity=Severity.HIGH)
    assert len(incidents(db_app)) == 2


def test_incident_creation_is_audited_as_the_detection_engine(db_app: FastAPI) -> None:
    signal(db_app, C.TOKEN_THEFT, severity=Severity.HIGH)
    from tests.helpers import audit_entries

    (created,) = audit_entries(db_app, "incident.created")
    assert created.actor_label == "system:detection-engine"
    assert created.resource_type == "incident"
    assert len(created.details["digest"]) == 64


# --- Sign-in from a stuffing source (COR-007) --------------------------------------------------


@pytest.fixture
def stuffing_client(db_app: FastAPI) -> TestClient:
    from tests.conftest import TEST_ORIGIN

    return TestClient(
        db_app,
        base_url=TEST_ORIGIN,
        raise_server_exceptions=False,
        headers={"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "1"},
        client=(ATTACKER, 40000),
    )


def test_sign_in_from_a_stuffing_source_is_detected(
    db_app: FastAPI, stuffing_client: TestClient
) -> None:
    create_user(db_app, "victim@example.com")
    for name in ("a", "b", "c"):
        assert login(stuffing_client, f"{name}@example.com", "guess").status_code == 401
    assert login(stuffing_client, "victim@example.com").status_code == 200
    (detection,) = detections(db_app, "COR-007")
    assert detection.category is C.SUSPICIOUS_AUTH
    assert detection.outcome is Outcome.ALLOWED
    assert detection.actor_label == "victim@example.com"
    assert detection.evidence["other_accounts"] == 3
    (incident,) = incidents(db_app)
    assert incident.category is C.SUSPICIOUS_AUTH


def test_ordinary_sign_in_after_own_typos_is_not_flagged(
    db_app: FastAPI, stuffing_client: TestClient
) -> None:
    create_user(db_app, "user@example.com")
    for _ in range(3):
        login(stuffing_client, "user@example.com", "typo")
    assert login(stuffing_client, "user@example.com").status_code == 200
    assert detections(db_app, "COR-007") == []


# --- Exactly once -----------------------------------------------------------------------------


def test_concurrent_failures_raise_exactly_one_detection_and_incident(db_app: FastAPI) -> None:
    def fail(i: int) -> None:
        with db_app.state.session_factory() as db:
            audit.record(
                db,
                action=AuditAction.LOGIN,
                result=AuditResult.FAILURE,
                actor=f"user{i % 4}@example.com",
                ctx=RequestContext(source_ip=ATTACKER),
                details={"reason": "unknown_account"},
            )
            db.commit()

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(fail, range(30)))
    assert len(detections(db_app, "COR-001")) == 1
    assert len(incidents(db_app)) == 1
    with db_app.state.session_factory() as db:
        failures = db.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.category == C.AUTH_FAILURE)
        )
    assert failures == 30


def test_correlation_uses_the_audit_chain_lock() -> None:
    from app.services.audit import _AUDIT_LOCK_KEY

    assert correlation.AUDIT_CHAIN_LOCK == _AUDIT_LOCK_KEY


def test_every_rule_id_is_unique_and_documented() -> None:
    ids = [r.rule_id for r in correlation.ALL_RULES]
    assert len(ids) == len(set(ids))
    assert all(r.description and r.name for r in correlation.ALL_RULES)
