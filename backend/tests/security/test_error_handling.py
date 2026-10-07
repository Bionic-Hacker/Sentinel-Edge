"""Spec §47 — never expose stack traces, SQL errors, secrets, paths, or submitted input."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, Field

pytestmark = pytest.mark.security

SECRET_MARKER = "postgresql://sentinel:hunter2@db.internal:5432/prod"


class Probe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int = Field(ge=0)


def _leaky_failure() -> None:
    raise RuntimeError(f"connection failed: {SECRET_MARKER} at /srv/app/db.py")


def _probe(body: Probe) -> dict[str, int]:
    return {"count": body.count}


@pytest.fixture
def test_client(app: FastAPI) -> TestClient:
    app.add_api_route("/api/v1/_test/leak", _leaky_failure)
    app.add_api_route("/api/v1/_test/probe", _probe, methods=["POST"])
    return TestClient(app, raise_server_exceptions=False)


def test_unhandled_exception_returns_generic_envelope(test_client: TestClient) -> None:
    response = test_client.get("/api/v1/_test/leak")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["correlation_id"] == response.headers["X-Request-ID"]
    text = response.text
    for leak in (SECRET_MARKER, "hunter2", "Traceback", "RuntimeError", "/srv/app", ".py"):
        assert leak not in text


def test_unhandled_exception_is_logged_internally(
    test_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    test_client.get("/api/v1/_test/leak")
    assert any(r.name == "sentineledge.errors" and r.exc_info for r in caplog.records)


def test_validation_error_does_not_echo_input(test_client: TestClient) -> None:
    payload = "<script>alert(document.cookie)</script>"
    response = test_client.post("/api/v1/_test/probe", json={"count": payload})
    assert response.status_code == 422
    assert payload not in response.text
    assert "script" not in response.text
    details = response.json()["error"]["details"]
    assert details[0]["location"] == "body.count"


def test_mass_assignment_style_extra_field_rejected(test_client: TestClient) -> None:
    response = test_client.post("/api/v1/_test/probe", json={"count": 1, "role": "ADMIN"})
    assert response.status_code == 422
    assert "ADMIN" not in response.text


def test_404_uses_envelope_and_no_route_hints(client: TestClient) -> None:
    response = client.get("/api/v1/../../etc/passwd")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"
    assert "root:" not in response.text


def test_405_uses_envelope(client: TestClient) -> None:
    response = client.delete("/api/v1/health")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"
