"""Security event collection (Phase 7): audit-fed events, HTTP analysis events, the events API,
and the guarantees around them (append-only storage, bounded recording, detection never
breaking a request)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError

from app.core.config import DbRole
from app.core.provenance import Provenance
from app.db.session import build_engine
from app.main import create_app
from app.models.audit import AuditResult
from app.models.security_event import (
    EventCategory,
    EventSource,
    Outcome,
    SecurityEvent,
    Severity,
)
from app.models.user import Role
from app.security.http_analysis import REDACTED
from app.services import audit
from app.services.audit import AuditAction, RequestContext
from tests.conftest import TEST_ORIGIN, _truncate_all, make_settings
from tests.helpers import bearer, create_user, login, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]

HEADERS = {"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "1"}


def events(app: FastAPI, **where: Any) -> list[SecurityEvent]:
    with app.state.session_factory() as db:
        query = select(SecurityEvent).order_by(SecurityEvent.seq)
        for column, value in where.items():
            query = query.where(getattr(SecurityEvent, column) == value)
        return list(db.scalars(query).all())


# --- Audit feed -------------------------------------------------------------------------------

CTX = RequestContext(
    source_ip="198.51.100.7",
    user_agent="pytest",
    correlation_id="corr-12345678",
    method="POST",
    endpoint="/api/v1/auth/login",
)


@pytest.mark.parametrize(
    ("action", "result", "kwargs", "expected"),
    [
        (AuditAction.LOGIN, AuditResult.FAILURE, {"details": {"reason": "bad_password"}},
         (EventSource.AUTH, EventCategory.AUTH_FAILURE, Severity.LOW, Outcome.REJECTED)),
        (AuditAction.LOGIN_MFA, AuditResult.FAILURE, {},
         (EventSource.AUTH, EventCategory.AUTH_FAILURE, Severity.LOW, Outcome.REJECTED)),
        (AuditAction.ACCOUNT_LOCKED, AuditResult.DENIED, {},
         (EventSource.AUTH, EventCategory.BRUTE_FORCE, Severity.MEDIUM, Outcome.REJECTED)),
        (AuditAction.REFRESH_TOKEN_REUSE, AuditResult.DENIED, {},
         (EventSource.AUTH, EventCategory.TOKEN_THEFT, Severity.HIGH, Outcome.REJECTED)),
        (AuditAction.ACCESS_DENIED, AuditResult.DENIED, {"resource_type": "endpoint"},
         (EventSource.AUTHZ, EventCategory.BFLA, Severity.MEDIUM, Outcome.REJECTED)),
        (AuditAction.ACCESS_DENIED, AuditResult.DENIED, {"resource_type": "user"},
         (EventSource.AUTHZ, EventCategory.BOLA, Severity.MEDIUM, Outcome.REJECTED)),
        (AuditAction.RATE_LIMITED, AuditResult.DENIED, {"details": {"policy": "login"}},
         (EventSource.RATE_LIMIT, EventCategory.RATE_LIMIT, Severity.MEDIUM, Outcome.THROTTLED)),
        (AuditAction.USER_UPDATED, AuditResult.SUCCESS, {"details": {"after": {"role": "ADMIN"}}},
         (EventSource.AUDIT, EventCategory.PRIVILEGE_CHANGE, Severity.MEDIUM, Outcome.ALLOWED)),
        (AuditAction.USER_MFA_RESET, AuditResult.SUCCESS, {},
         (EventSource.AUDIT, EventCategory.PRIVILEGE_CHANGE, Severity.LOW, Outcome.ALLOWED)),
        (AuditAction.AUDIT_VERIFIED, AuditResult.FAILURE, {"details": {"records_checked": 9}},
         (EventSource.AUDIT, EventCategory.AUDIT_TAMPERING, Severity.CRITICAL, Outcome.DETECTED)),
    ],
)  # fmt: skip
def test_security_relevant_audit_actions_become_events(
    db_app: FastAPI,
    action: AuditAction,
    result: AuditResult,
    kwargs: dict[str, Any],
    expected: tuple[EventSource, EventCategory, Severity, Outcome],
) -> None:
    with db_app.state.session_factory() as db:
        entry = audit.record(
            db, action=action, result=result, actor="mallory@example.com", ctx=CTX, **kwargs
        )
        db.commit()
        seq = entry.seq
    (event,) = events(db_app)
    assert (event.source, event.category, event.severity, event.outcome) == expected
    assert event.provenance is Provenance.LOCAL
    assert event.source_ip == "198.51.100.7"
    assert event.actor_label == "mallory@example.com"
    assert event.correlation_id == "corr-12345678"
    assert (event.method, event.endpoint) == ("POST", "/api/v1/auth/login")
    assert event.evidence["audit_action"] == action.value
    assert event.evidence["audit_seq"] == seq


@pytest.mark.parametrize(
    ("action", "result", "kwargs"),
    [
        (AuditAction.LOGIN, AuditResult.SUCCESS, {}),
        (AuditAction.LOGOUT, AuditResult.SUCCESS, {}),
        (AuditAction.AUDIT_VERIFIED, AuditResult.SUCCESS, {}),
        (
            AuditAction.USER_UPDATED,
            AuditResult.SUCCESS,
            {"details": {"after": {"role": "Role.VIEWER"}}},
        ),
        (AuditAction.USER_CREATED, AuditResult.SUCCESS, {}),
    ],
)
def test_routine_actions_are_not_events(
    db_app: FastAPI, action: AuditAction, result: AuditResult, kwargs: dict[str, Any]
) -> None:
    with db_app.state.session_factory() as db:
        audit.record(db, action=action, result=result, actor="x@example.com", ctx=CTX, **kwargs)
        db.commit()
    assert events(db_app) == []


def test_event_and_audit_record_commit_together(db_app: FastAPI) -> None:
    with db_app.state.session_factory() as db:
        audit.record(
            db, action=AuditAction.ACCOUNT_LOCKED, result=AuditResult.DENIED, actor="x", ctx=CTX
        )
        db.rollback()
    assert events(db_app) == []


def test_failed_sign_in_through_the_api(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, "victim@example.com")
    assert login(db_client, "victim@example.com", "wrong password").status_code == 401
    (event,) = events(db_app)
    assert event.category is EventCategory.AUTH_FAILURE
    assert event.actor_label == "victim@example.com"
    assert event.endpoint == "/api/v1/auth/login"
    assert event.evidence["reason"] == "bad_password"
    assert "password" not in str(event.evidence).lower().replace("bad_password", "")


def test_authorization_denials_through_the_api(db_app: FastAPI, db_client: TestClient) -> None:
    viewer = create_user(db_app, "viewer@example.com", role=Role.VIEWER)
    token = session_token(db_app, viewer)
    assert db_client.get("/api/v1/users", headers=bearer(token)).status_code == 403
    other = f"/api/v1/users/{uuid.uuid4()}"
    assert db_client.get(other, headers=bearer(token)).status_code == 404
    bfla, bola = events(db_app)
    assert (bfla.category, bfla.endpoint) == (EventCategory.BFLA, "/api/v1/users")
    assert (bola.category, bola.endpoint) == (EventCategory.BOLA, "/api/v1/users/{user_id}")
    assert bola.actor_label == "viewer@example.com"


# --- Storage guarantees -----------------------------------------------------------------------


@pytest.fixture
def app_engine(migrator_engine: Engine) -> Iterator[Engine]:
    engine = build_engine(make_settings(), DbRole.APP)
    yield engine
    engine.dispose()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE sentinel.security_events SET severity = 'info'",
        "DELETE FROM sentinel.security_events",
        "TRUNCATE sentinel.security_events",
    ],
)
def test_app_role_cannot_alter_or_remove_events(
    db_app: FastAPI, app_engine: Engine, statement: str
) -> None:
    with db_app.state.session_factory() as db:
        audit.record(
            db, action=AuditAction.ACCOUNT_LOCKED, result=AuditResult.DENIED, actor="x", ctx=CTX
        )
        db.commit()
    with app_engine.connect() as conn, pytest.raises(DBAPIError) as excinfo:
        conn.execute(text(statement))
    assert "permission denied" in str(excinfo.value).lower()


# --- HTTP analysis feed -----------------------------------------------------------------------


@pytest.fixture
def ha_app(migrator_engine: Engine) -> Iterator[FastAPI]:
    application = create_app(make_settings(http_analysis_enabled=True))
    yield application
    application.state.engine.dispose()
    _truncate_all(migrator_engine)


@pytest.fixture
def ha_client(ha_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(
        ha_app,
        base_url=TEST_ORIGIN,
        raise_server_exceptions=False,
        headers=HEADERS,
        client=("203.0.113.9", 50000),
    ) as c:
        yield c


def test_sql_injection_in_a_query_parameter_is_recorded(
    ha_app: FastAPI, ha_client: TestClient
) -> None:
    admin = create_user(
        ha_app, "admin@example.com", role=Role.ADMIN, mfa_enabled=True, mfa_secret=b"x"
    )
    token = session_token(ha_app, admin)
    response = ha_client.get(
        "/api/v1/audit-logs",
        params={"actor": "x' OR 1=1 --"},
        headers=bearer(token),
    )
    assert response.status_code == 200  # parameterized: the payload is just a non-matching filter
    (event,) = events(ha_app, source=EventSource.HTTP_ANALYSIS)
    assert event.category is EventCategory.SQL_INJECTION
    assert event.outcome is Outcome.ALLOWED
    assert event.severity is Severity.CRITICAL  # high, raised because it got a 200
    assert event.source_ip == "203.0.113.9"
    assert (event.method, event.endpoint, event.status_code) == ("GET", "/api/v1/audit-logs", 200)
    finding = event.evidence["findings"][0]
    assert (finding["location"], finding["field"]) == ("query", "actor")
    assert "OR 1=1" in finding["snippet"]
    assert event.evidence["mode"] == "detect-only"
    assert event.correlation_id == response.headers["X-Request-ID"]


def test_attack_in_a_rejected_body_is_recorded_as_rejected(
    ha_app: FastAPI, ha_client: TestClient
) -> None:
    response = ha_client.post(
        "/api/v1/auth/login",
        json={"email": "<script>alert(1)</script>@x.example", "password": "' OR '1'='1"},
    )
    assert response.status_code in (401, 422)
    (event,) = events(ha_app, source=EventSource.HTTP_ANALYSIS)
    assert event.outcome is Outcome.REJECTED
    by_field = {f["field"]: f for f in event.evidence["findings"]}
    assert by_field["password"]["snippet"] == REDACTED
    assert "<script>" in by_field["email"]["snippet"]


def test_recon_of_unknown_paths_is_recorded(ha_app: FastAPI, ha_client: TestClient) -> None:
    assert ha_client.get("/api/.git/config").status_code == 404
    (event,) = events(ha_app, source=EventSource.HTTP_ANALYSIS)
    assert event.category is EventCategory.RECON
    assert event.endpoint == "/api/.git/config"


def test_scanner_user_agent_is_recorded(ha_app: FastAPI, ha_client: TestClient) -> None:
    ha_client.get("/api/v1/health", headers={"User-Agent": "Nuclei - Open-source project"})
    (event,) = events(ha_app, source=EventSource.HTTP_ANALYSIS)
    assert event.category is EventCategory.SCANNER


def test_ordinary_traffic_records_nothing(ha_app: FastAPI, ha_client: TestClient) -> None:
    create_user(ha_app, "user@example.com")
    ha_client.get("/api/v1/health")
    ha_client.post(
        "/api/v1/auth/login", json={"email": "user@example.com", "password": "Tr0ub4dor&3;|x"}
    )
    assert events(ha_app, source=EventSource.HTTP_ANALYSIS) == []


def test_recording_is_throttled_per_source_ip(migrator_engine: Engine) -> None:
    application = create_app(make_settings(http_analysis_enabled=True, rate_limit_enabled=True))
    try:
        with TestClient(
            application, raise_server_exceptions=False, client=("203.0.113.50", 1)
        ) as c:
            for _ in range(40):
                c.get("/api/v1/health", params={"q": "<script>"})
        assert len(events(application, source=EventSource.HTTP_ANALYSIS)) == 30
    finally:
        application.state.engine.dispose()
        _truncate_all(migrator_engine)


def test_a_detection_failure_never_breaks_the_request(
    ha_app: FastAPI, ha_client: TestClient
) -> None:
    def broken(*_: object) -> bool:
        raise RuntimeError("event store unavailable")

    ha_app.state.event_recorder.inspect_and_record = broken
    response = ha_client.get("/api/v1/health", params={"q": "<script>"})
    assert response.status_code == 200


def test_disabled_analysis_records_nothing(db_app: FastAPI, db_client: TestClient) -> None:
    db_client.get("/api/v1/health", params={"q": "<script>"})
    assert events(db_app) == []


# --- Events API -------------------------------------------------------------------------------


def _seed(app: FastAPI, n: int) -> None:
    with app.state.session_factory() as db:
        for i in range(n):
            audit.record(
                db,
                action=AuditAction.LOGIN if i % 2 else AuditAction.ACCOUNT_LOCKED,
                result=AuditResult.FAILURE if i % 2 else AuditResult.DENIED,
                actor=f"user{i}@example.com",
                ctx=RequestContext(source_ip=f"198.51.100.{i % 3 + 1}"),
            )
        db.commit()


@pytest.fixture
def analyst_token(db_app: FastAPI) -> str:
    return session_token(db_app, create_user(db_app, "analyst@example.com", role=Role.ANALYST))


def test_events_are_listed_newest_first_with_keyset_pages(
    db_app: FastAPI, db_client: TestClient, analyst_token: str
) -> None:
    _seed(db_app, 7)
    first = db_client.get(
        "/api/v1/security-events", params={"limit": 4}, headers=bearer(analyst_token)
    )
    assert first.status_code == 200
    page = first.json()
    seqs = [item["seq"] for item in page["items"]]
    assert seqs == sorted(seqs, reverse=True)
    assert len(seqs) == 4
    rest = db_client.get(
        "/api/v1/security-events",
        params={"limit": 4, "before_seq": page["next_before_seq"]},
        headers=bearer(analyst_token),
    ).json()
    assert len(rest["items"]) == 3
    assert rest["next_before_seq"] is None
    assert "evidence" not in page["items"][0]  # the list is a summary


@pytest.mark.parametrize(
    ("params", "count"),
    [
        ({"min_severity": "medium"}, 4),
        ({"category": "auth_failure"}, 3),
        ({"source": "auth"}, 7),
        ({"source_ip": "198.51.100.1"}, 3),
        ({"provenance": "SIMULATED"}, 0),
        ({"view": "live"}, 7),
        ({"view": "simulated"}, 0),
        ({"since": "2000-01-01T00:00:00Z", "until": "2999-01-01T00:00:00Z"}, 7),
    ],
)
def test_events_can_be_filtered(
    db_app: FastAPI, db_client: TestClient, analyst_token: str, params: dict[str, str], count: int
) -> None:
    _seed(db_app, 7)
    response = db_client.get(
        "/api/v1/security-events", params=params, headers=bearer(analyst_token)
    )
    assert response.status_code == 200
    assert len(response.json()["items"]) == count


def test_filters_are_validated(db_client: TestClient, analyst_token: str) -> None:
    for params in ({"source_ip": "1.2.3.4' OR 1=1"}, {"category": "nope"}, {"limit": 1000}):
        response = db_client.get(
            "/api/v1/security-events", params=params, headers=bearer(analyst_token)
        )
        assert response.status_code == 422


def test_event_detail_includes_evidence(
    db_app: FastAPI, db_client: TestClient, analyst_token: str
) -> None:
    _seed(db_app, 1)
    item = db_client.get("/api/v1/security-events", headers=bearer(analyst_token)).json()["items"][
        0
    ]
    detail = db_client.get(f"/api/v1/security-events/{item['id']}", headers=bearer(analyst_token))
    assert detail.status_code == 200
    assert detail.json()["evidence"]["audit_action"] == "auth.account_locked"


def test_unknown_event_is_404(db_client: TestClient, analyst_token: str) -> None:
    response = db_client.get(
        f"/api/v1/security-events/{uuid.uuid4()}", headers=bearer(analyst_token)
    )
    assert response.status_code == 404
