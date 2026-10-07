"""Application rate limiting (ADR-0004, ADR-0017; OWASP API4 and API6).

Runs against real PostgreSQL: the limiter's correctness rests on one atomic SQL statement, so
it is tested against the database that executes it, including under concurrency.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.api_policy import LOGIN, LimitScope, RateLimitPolicy
from app.main import create_app
from app.models.user import Role
from app.security.rate_limit import RateLimiter
from app.services.audit import AuditAction
from tests.conftest import TEST_ORIGIN, _truncate_all, make_settings
from tests.helpers import audit_entries, bearer, create_user, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]

HEADERS = {"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "1"}
UNKNOWN = {"email": "nobody@example.com", "password": "not a real password"}


@pytest.fixture
def rl_app(migrator_engine: Engine) -> Iterator[FastAPI]:
    application = create_app(make_settings(rate_limit_enabled=True))
    yield application
    application.state.engine.dispose()
    _truncate_all(migrator_engine)


@pytest.fixture
def client_from(rl_app: FastAPI) -> Iterator[Callable[[str], TestClient]]:
    """A client whose requests come from a given IP address."""
    clients: list[TestClient] = []

    def _make(ip: str) -> TestClient:
        c = TestClient(
            rl_app,
            base_url=TEST_ORIGIN,
            raise_server_exceptions=False,
            headers=HEADERS,
            client=(ip, 50000),
        )
        clients.append(c)
        return c

    yield _make
    for c in clients:
        c.close()


def _login(client: TestClient) -> int:
    return client.post("/api/v1/auth/login", json=UNKNOWN).status_code


# --- Enforcement over HTTP ------------------------------------------------------------------


def test_login_is_limited_per_ip_with_retry_after(
    rl_app: FastAPI, client_from: Callable[[str], TestClient]
) -> None:
    attacker = client_from("203.0.113.10")
    statuses = [_login(attacker) for _ in range(LOGIN.capacity)]
    assert set(statuses) == {401}  # every attempt within the burst is processed normally

    blocked = attacker.post("/api/v1/auth/login", json=UNKNOWN)
    assert blocked.status_code == 429
    body = blocked.json()["error"]
    assert body["code"] == "rate_limited"
    assert body["correlation_id"]  # same safe envelope as every other error
    assert 1 <= int(blocked.headers["Retry-After"]) <= LOGIN.period_s
    assert blocked.headers["RateLimit-Limit"] == str(LOGIN.capacity)
    assert blocked.headers["RateLimit-Remaining"] == "0"
    # Security headers are still applied to throttled responses.
    assert blocked.headers["X-Content-Type-Options"] == "nosniff"

    # Another client IP is unaffected: the limit is per source, not global.
    assert _login(client_from("203.0.113.20")) == 401


def test_throttled_logins_do_no_password_work(
    rl_app: FastAPI, client_from: Callable[[str], TestClient]
) -> None:
    """Rejected before authentication: no credential check, so no account lockout either."""
    create_user(rl_app, "victim@example.com")
    attacker = client_from("203.0.113.11")
    for _ in range(LOGIN.capacity):
        _login(attacker)
    response = attacker.post(
        "/api/v1/auth/login", json={"email": "victim@example.com", "password": "guess"}
    )
    assert response.status_code == 429
    login_attempts = [
        e for e in audit_entries(rl_app, AuditAction.LOGIN) if e.actor_label == "victim@example.com"
    ]
    assert login_attempts == []


def test_a_flood_is_audited_once_not_per_request(
    rl_app: FastAPI, client_from: Callable[[str], TestClient]
) -> None:
    attacker = client_from("203.0.113.12")
    for _ in range(LOGIN.capacity + 5):
        _login(attacker)
    (entry,) = audit_entries(rl_app, AuditAction.RATE_LIMITED)
    assert entry.source_ip == "203.0.113.12"
    assert entry.resource_id == "POST /api/v1/auth/login"
    assert entry.details == {"policy": "login", "scope": "ip", "limit": LOGIN.description}


def test_bucket_refills_over_time(
    rl_app: FastAPI, client_from: Callable[[str], TestClient], migrator_engine: Engine
) -> None:
    attacker = client_from("203.0.113.13")
    for _ in range(LOGIN.capacity + 1):
        _login(attacker)
    assert _login(attacker) == 429
    # Wind the bucket's clock back by one refill interval instead of sleeping.
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE sentinel.rate_limit_buckets SET updated_at = updated_at - "
                "make_interval(secs => :s) WHERE bucket_key = 'login|ip:203.0.113.13'"
            ),
            {"s": LOGIN.period_s / LOGIN.capacity},
        )
    assert _login(attacker) == 401  # one token back: one more attempt is processed


def test_successful_responses_carry_ratelimit_headers(
    rl_app: FastAPI, client_from: Callable[[str], TestClient]
) -> None:
    response = client_from("203.0.113.14").get("/api/v1/health")
    assert response.status_code == 200
    assert response.headers["RateLimit-Limit"] == "120"
    assert int(response.headers["RateLimit-Remaining"]) == 119
    assert "Retry-After" not in response.headers


def test_user_limit_follows_the_account_across_ip_addresses(
    rl_app: FastAPI, client_from: Callable[[str], TestClient]
) -> None:
    """Rotating IPs does not reset a per-account limit (the audit-chain verify endpoint is
    limited to 6 per minute per user because it reads the whole log)."""
    auditor = create_user(
        rl_app,
        "auditor@example.com",
        role=Role.SECURITY_ENGINEER,
        mfa_enabled=True,
        mfa_secret=b"x",
    )
    token = session_token(rl_app, auditor)
    statuses = [
        client_from(f"198.51.100.{i}")
        .get("/api/v1/audit-logs/verify", headers=bearer(token))
        .status_code
        for i in range(1, 9)
    ]
    assert statuses == [200] * 6 + [429, 429]

    # A different account is unaffected.
    other = create_user(
        rl_app, "other@example.com", role=Role.ADMIN, mfa_enabled=True, mfa_secret=b"x"
    )
    response = client_from("198.51.100.1").get(
        "/api/v1/audit-logs/verify", headers=bearer(session_token(rl_app, other))
    )
    assert response.status_code == 200
    (entry,) = audit_entries(rl_app, AuditAction.RATE_LIMITED)
    assert entry.actor_label == "auditor@example.com"
    assert entry.details["scope"] == "user"


def test_disabled_limiter_adds_no_headers(db_client: TestClient) -> None:
    response = db_client.get("/api/v1/health")
    assert "RateLimit-Limit" not in response.headers


# --- The limiter itself ------------------------------------------------------------------------


@pytest.fixture
def limiter(rl_app: FastAPI) -> RateLimiter:
    limiter: RateLimiter = rl_app.state.rate_limiter
    return limiter


def test_concurrent_requests_never_overspend_a_bucket(limiter: RateLimiter) -> None:
    """The check is one atomic statement: 40 simultaneous requests against a bucket of 10
    must allow exactly 10, never more."""
    policy = RateLimitPolicy("concurrency_test", 10, 3600, LimitScope.IP)
    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(lambda _: limiter.check(policy, "ip:192.0.2.1"), range(40)))
    allowed = [d for d in decisions if d is not None and d.allowed]
    assert len(allowed) == 10


def test_first_denial_is_flagged_once_per_run(limiter: RateLimiter) -> None:
    policy = RateLimitPolicy("run_test", 2, 3600, LimitScope.IP)
    outcomes = [limiter.check(policy, "ip:192.0.2.2") for _ in range(5)]
    assert [(d.allowed, d.first_denial) for d in outcomes if d] == [
        (True, False),
        (True, False),
        (False, True),
        (False, False),
        (False, False),
    ]


def test_idle_buckets_are_pruned(limiter: RateLimiter, migrator_engine: Engine) -> None:
    policy = RateLimitPolicy("prune_test", 5, 60, LimitScope.IP)
    limiter.check(policy, "ip:192.0.2.3")
    limiter.check(policy, "ip:192.0.2.4")
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE sentinel.rate_limit_buckets SET updated_at = now() - interval '2 days' "
                "WHERE bucket_key = 'prune_test|ip:192.0.2.3'"
            )
        )
    assert limiter.prune() == 1
    with migrator_engine.connect() as conn:
        keys = conn.execute(text("SELECT bucket_key FROM sentinel.rate_limit_buckets")).scalars()
        assert set(keys) == {"prune_test|ip:192.0.2.4"}


def test_limiter_outage_fails_closed_with_503(rl_app: FastAPI) -> None:
    """If the limiter cannot reach its database, requests are refused (fail closed) with an
    honest 503 and Retry-After, not a generic 500."""
    from sqlalchemy.exc import OperationalError

    def unavailable() -> None:
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    rl_app.state.rate_limiter.session_factory = unavailable
    with TestClient(rl_app, raise_server_exceptions=False) as c:
        response = c.get("/api/v1/ready")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"
    assert response.headers["Retry-After"] == "5"
