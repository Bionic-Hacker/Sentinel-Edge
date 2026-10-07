"""The capability register is available to every signed-in role (spec §43 transparency)."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models.user import Role
from tests.helpers import bearer, create_user, session_token

pytestmark = pytest.mark.db


def test_signed_in_users_see_the_register(db_app: FastAPI, db_client: TestClient) -> None:
    token = session_token(db_app, create_user(db_app, "viewer@example.com", role=Role.VIEWER))
    response = db_client.get("/api/v1/platform/capabilities", headers=bearer(token))
    assert response.status_code == 200
    items = response.json()["items"]
    assert {"key", "provenance", "status", "phase"} <= items[0].keys()


def test_users_mid_setup_are_held_at_setup(db_app: FastAPI, db_client: TestClient) -> None:
    user = create_user(db_app, "new@example.com", role=Role.VIEWER, must_change_password=True)
    response = db_client.get(
        "/api/v1/platform/capabilities", headers=bearer(session_token(db_app, user))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "setup_required"
