"""Readiness reports database reachability without leaking anything about the database."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db


def test_ready_when_database_reachable(db_client: TestClient) -> None:
    response = db_client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
