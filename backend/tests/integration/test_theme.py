"""Each user's colour theme is saved with their account, not in the browser (ADR-0003 keeps web
storage out of the SPA). It is a display setting: own record only, two values, grants nothing."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models.user import Role, Theme
from tests.helpers import audit_entries, bearer, create_user, get_user, session_token

pytestmark = pytest.mark.db


def test_new_users_start_on_the_light_theme(db_app: FastAPI, db_client: TestClient) -> None:
    user = create_user(db_app, "viewer@example.com", role=Role.VIEWER)
    response = db_client.get("/api/v1/auth/me", headers=bearer(session_token(db_app, user)))
    assert response.status_code == 200
    assert response.json()["theme"] == "light"


def test_a_user_saves_their_theme_and_it_follows_them(
    db_app: FastAPI, db_client: TestClient
) -> None:
    user = create_user(db_app, "analyst@example.com")
    response = db_client.put(
        "/api/v1/auth/me/theme", headers=bearer(session_token(db_app, user)), json={"theme": "dark"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["theme"] == "dark"
    assert get_user(db_app, "analyst@example.com").theme is Theme.DARK

    # A new session (another device) gets the saved theme.
    again = db_client.get("/api/v1/auth/me", headers=bearer(session_token(db_app, user)))
    assert again.json()["theme"] == "dark"


def test_only_the_users_own_theme_changes(db_app: FastAPI, db_client: TestClient) -> None:
    me = create_user(db_app, "me@example.com")
    create_user(db_app, "other@example.com")
    db_client.put(
        "/api/v1/auth/me/theme", headers=bearer(session_token(db_app, me)), json={"theme": "dark"}
    )
    assert get_user(db_app, "other@example.com").theme is Theme.LIGHT


@pytest.mark.parametrize(
    "body",
    [{"theme": "blue"}, {"theme": ""}, {}, {"theme": "dark", "role": "ADMIN"}, {"theme": "DARK"}],
)
def test_only_light_or_dark_is_accepted_and_nothing_else_rides_along(
    db_app: FastAPI, db_client: TestClient, body: dict[str, str]
) -> None:
    user = create_user(db_app, "analyst@example.com")
    response = db_client.put(
        "/api/v1/auth/me/theme", headers=bearer(session_token(db_app, user)), json=body
    )
    assert response.status_code == 422
    stored = get_user(db_app, "analyst@example.com")
    assert stored.theme is Theme.LIGHT
    assert stored.role is Role.ANALYST


def test_signed_out_requests_are_refused(db_client: TestClient) -> None:
    assert db_client.put("/api/v1/auth/me/theme", json={"theme": "dark"}).status_code == 401


def test_a_theme_change_is_not_audited(db_app: FastAPI, db_client: TestClient) -> None:
    user = create_user(db_app, "analyst@example.com")
    before = len(audit_entries(db_app))
    db_client.put(
        "/api/v1/auth/me/theme", headers=bearer(session_token(db_app, user)), json={"theme": "dark"}
    )
    assert len(audit_entries(db_app)) == before
