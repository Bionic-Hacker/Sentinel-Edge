"""OWASP ASVS V14.4 / spec §26 — headers must be present on every response, not just 200s."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.security_headers import API_SECURITY_HEADERS

pytestmark = pytest.mark.security


def _boom() -> None:
    raise RuntimeError("synthetic failure")


@pytest.fixture
def client_with_failing_route(app: FastAPI) -> TestClient:
    app.add_api_route("/api/v1/_test/boom", _boom)
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [("/api/v1/health", 200), ("/api/v1/does-not-exist", 404)],
)
def test_headers_on_normal_and_error_responses(
    client: TestClient, path: str, expected_status: int
) -> None:
    response = client.get(path)
    assert response.status_code == expected_status
    for name, value in API_SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name


def test_headers_on_unhandled_exception(client_with_failing_route: TestClient) -> None:
    response = client_with_failing_route.get("/api/v1/_test/boom")
    assert response.status_code == 500
    for name, value in API_SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name


def test_headers_on_host_rejection(client: TestClient) -> None:
    response = client.get("/api/v1/health", headers={"Host": "evil.example"})
    assert response.status_code == 400
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_csp_is_maximally_restrictive_for_json_api(client: TestClient) -> None:
    csp = client.get("/api/v1/health").headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_server_header_not_disclosed(client: TestClient) -> None:
    assert "server" not in client.get("/api/v1/health").headers
