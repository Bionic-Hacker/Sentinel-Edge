"""Correlation IDs: generated when absent, accepted when safe, replaced when hostile."""

import uuid

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.security


def test_generates_id_when_absent(client: TestClient) -> None:
    rid = client.get("/api/v1/health").headers["X-Request-ID"]
    assert uuid.UUID(rid)


def test_accepts_safe_upstream_id(client: TestClient) -> None:
    rid = "cf-edge-1a2b3c4d5e6f"
    response = client.get("/api/v1/health", headers={"X-Request-ID": rid})
    assert response.headers["X-Request-ID"] == rid


@pytest.mark.parametrize(
    "hostile",
    [
        "abc",  # too short
        "x" * 200,  # too long
        "id-123456; DROP TABLE audit_log",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
    ],
)
def test_replaces_hostile_upstream_id(client: TestClient, hostile: str) -> None:
    rid = client.get("/api/v1/health", headers={"X-Request-ID": hostile}).headers["X-Request-ID"]
    assert rid != hostile
    assert uuid.UUID(rid)
