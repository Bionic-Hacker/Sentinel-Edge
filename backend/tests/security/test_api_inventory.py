"""API inventory and endpoint metrics (spec §14; OWASP API9 improper inventory management)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.api_metrics import ApiMetrics
from app.core.api_policy import ALL_POLICIES, ENDPOINTS
from app.main import create_app
from app.models.user import Role
from tests.conftest import TEST_ORIGIN, _truncate_all, make_settings
from tests.helpers import bearer, create_user, session_token
from tests.security.test_authz_matrix import EXPECTED, PUBLIC, SETUP

pytestmark = pytest.mark.security

SPEC_FIELDS = {  # spec §14: for every endpoint display ...
    "method",
    "path",
    "authentication",
    "authorization",
    "risk",
    "rate_limit",
    "metrics",  # request count, error rate, attack count
    "last_scan",
    "status",
}


def _route_keys(app: FastAPI) -> set[tuple[str, str]]:
    return {
        (method, ctx.path)
        for ctx in iter_route_contexts(app.routes)
        if isinstance(ctx.route, APIRoute) and ctx.path and ctx.path.startswith("/api/")
        for method in ctx.methods or ()
    }


# --- Registry versus the route table (no database needed) ----------------------------------------


def test_registry_matches_the_route_table(app: FastAPI) -> None:
    """Every endpoint has a risk rating and rate limit; no entry outlives its endpoint."""
    routes = _route_keys(app)
    assert routes - set(ENDPOINTS) == set(), "endpoints missing from app/core/api_policy.py"
    assert set(ENDPOINTS) - routes == set(), "stale entries in app/core/api_policy.py"


def test_policy_names_are_unique() -> None:
    names = [p.name for p in ALL_POLICIES]
    assert len(names) == len(set(names))
    assert {e.rate_limit for e in ENDPOINTS.values()} <= set(ALL_POLICIES)


def test_every_endpoint_names_its_owasp_exposure() -> None:
    assert all(policy.owasp for policy in ENDPOINTS.values())


# --- The inventory endpoint ----------------------------------------------------------------------


@pytest.fixture
def metrics_app(migrator_engine: Engine) -> Iterator[FastAPI]:
    application = create_app(make_settings(api_metrics_enabled=True))
    yield application
    application.state.engine.dispose()
    _truncate_all(migrator_engine)


@pytest.fixture
def mclient(metrics_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(
        metrics_app,
        base_url=TEST_ORIGIN,
        raise_server_exceptions=False,
        headers={"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "1"},
    ) as c:
        yield c


def _token(app: FastAPI, role: Role = Role.SECURITY_ENGINEER) -> str:
    user = create_user(
        app, f"{role.value.lower()}@example.com", role=role, mfa_enabled=True, mfa_secret=b"x"
    )
    return session_token(app, user)


def _inventory(client: TestClient, token: str) -> dict[str, object]:
    response = client.get("/api/v1/api-security/inventory", headers=bearer(token))
    assert response.status_code == 200
    body: dict[str, object] = response.json()
    return body


def _item(body: dict[str, object], method: str, path: str) -> dict[str, object]:
    items = body["items"]
    assert isinstance(items, list)
    return next(i for i in items if i["method"] == method and i["path"] == path)


@pytest.mark.db
def test_inventory_lists_every_endpoint_with_the_spec_fields(
    metrics_app: FastAPI, mclient: TestClient
) -> None:
    body = _inventory(mclient, _token(metrics_app))
    items = body["items"]
    assert isinstance(items, list)
    assert len(items) == len(ENDPOINTS)
    for item in items:
        assert set(item) >= SPEC_FIELDS
        assert item["last_scan"] is None
        assert "Phase 8" in item["scan_note"]
    login = _item(body, "POST", "/api/v1/auth/login")
    assert login["authentication"] == "None (public)"
    assert login["authorization"] == "Same-origin request with CSRF header"
    assert login["risk"] == "critical"
    assert login["rate_limit"] == "20 / 2 min per IP"
    assert "API2" in login["owasp"]
    user = _item(body, "GET", "/api/v1/users/{user_id}")
    assert user["object_rule"]
    assert "404" in user["object_rule"]


@pytest.mark.db
def test_inventory_access_agrees_with_the_authorization_matrix(
    metrics_app: FastAPI, mclient: TestClient
) -> None:
    """The inventory reads guards from the code; the matrix test was written independently.
    If they ever disagree, one of them is wrong."""
    body = _inventory(mclient, _token(metrics_app))
    items = body["items"]
    assert isinstance(items, list)
    for item in items:
        expected = EXPECTED[(item["method"], item["path"])]
        if expected == PUBLIC:
            assert item["authentication"] == "None (public)"
        elif expected == SETUP:
            assert item["authorization"] == "Own account only"
        else:
            assert set(item["roles"]) == {r.value for r in expected}


@pytest.mark.db
def test_metrics_count_requests_errors_and_rejections(
    metrics_app: FastAPI, mclient: TestClient
) -> None:
    analyst = _token(metrics_app, Role.ANALYST)
    for _ in range(3):
        mclient.get("/api/v1/health")
    forbidden = 5
    for _ in range(forbidden):
        mclient.get("/api/v1/users", headers=bearer(analyst))  # 403
    mclient.get("/api/v1/users")  # 401
    body = _inventory(mclient, _token(metrics_app))

    health = _item(body, "GET", "/api/v1/health")
    assert health["metrics"]["requests"] == 3
    assert health["metrics"]["error_rate"] == 0.0
    assert health["status"] == "protected"

    users = _item(body, "GET", "/api/v1/users")
    m = users["metrics"]
    assert (m["requests"], m["forbidden"], m["unauthenticated"]) == (forbidden + 1, forbidden, 1)
    assert m["security_rejections"] == forbidden + 1
    assert m["error_rate"] == 1.0
    assert users["status"] == "elevated"
    assert any("forbidden" in r for r in users["status_reasons"])


@pytest.mark.db
def test_unmatched_requests_are_counted(metrics_app: FastAPI, mclient: TestClient) -> None:
    for path in ("/api/v1/admin", "/api/v2/users", "/api/v1/.env"):
        assert mclient.get(path).status_code == 404
    body = _inventory(mclient, _token(metrics_app))
    assert body["summary"]["unmatched_requests"] == 3


@pytest.mark.db
def test_metrics_store_route_templates_never_raw_paths(
    metrics_app: FastAPI, mclient: TestClient, migrator_engine: Engine
) -> None:
    token = _token(metrics_app, Role.ADMIN)
    mclient.get("/api/v1/users/0b3a7c52-9a2e-4c8e-9a7b-1d2e3f4a5b6c", headers=bearer(token))
    mclient.get("/api/v1/does-not-exist/<script>alert(1)</script>")
    with migrator_engine.connect() as conn:
        routes = set(conn.execute(text("SELECT route FROM sentinel.api_endpoint_stats")).scalars())
    assert routes == {"/api/v1/users/{user_id}", "(unmatched)"}


@pytest.mark.db
def test_server_errors_mark_an_endpoint_for_review(
    metrics_app: FastAPI, mclient: TestClient
) -> None:
    metrics: ApiMetrics = metrics_app.state.api_metrics
    metrics.record("GET", "/api/v1/ready", 503)
    body = _inventory(mclient, _token(metrics_app))
    ready = _item(body, "GET", "/api/v1/ready")
    assert ready["status"] == "review"
    assert body["summary"]["needs_attention"] >= 1


@pytest.mark.db
def test_a_metrics_failure_never_breaks_a_request(metrics_app: FastAPI) -> None:
    def broken_factory() -> None:
        raise RuntimeError("database unavailable")

    metrics_app.state.api_metrics.session_factory = broken_factory
    with TestClient(metrics_app) as c:
        assert c.get("/api/v1/health").status_code == 200


@pytest.mark.db
def test_owasp_coverage_endpoint(metrics_app: FastAPI, mclient: TestClient) -> None:
    response = mclient.get("/api/v1/api-security/owasp", headers=bearer(_token(metrics_app)))
    assert response.status_code == 200
    items = response.json()["items"]
    assert [i["code"] for i in items] == [f"API{n}" for n in range(1, 11)]
    api2 = next(i for i in items if i["code"] == "API2")
    assert api2["status"] == "mitigated"
    assert api2["exposed_endpoints"] >= 5
