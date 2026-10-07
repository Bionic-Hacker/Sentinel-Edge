"""Refresh-token rotation, reuse detection, logout and password change (ADR-0003, T-ID-03)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.audit import AuditAction
from tests.conftest import TEST_ORIGIN
from tests.helpers import DEFAULT_PASSWORD, access_token, audit_entries, bearer, create_user, login

pytestmark = [pytest.mark.security, pytest.mark.db]
EMAIL = "analyst@example.com"
COOKIE = "__Host-sentinel_refresh"


HEADERS = {"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "1"}


def _refresh(client: TestClient) -> object:
    """Refresh using whatever cookie this client's jar holds (the normal browser case)."""
    return client.post("/api/v1/auth/refresh")


def _refresh_with(app: FastAPI, cookie: str) -> object:
    """Refresh from a separate client that holds only `cookie` (e.g. an attacker's copy)."""
    other = TestClient(
        app,
        base_url=TEST_ORIGIN,
        headers=HEADERS,
        cookies={COOKIE: cookie},
        raise_server_exceptions=False,
    )
    return other.post("/api/v1/auth/refresh")


def test_refresh_rotates_both_tokens(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    first = login(db_client, EMAIL)
    old_cookie = db_client.cookies[COOKIE]

    second = _refresh(db_client)
    assert second.status_code == 200  # type: ignore[attr-defined]
    assert second.json()["access_token"] != first.json()["access_token"]  # type: ignore[attr-defined]
    assert db_client.cookies[COOKIE] != old_cookie
    me = db_client.get(
        "/api/v1/auth/me",
        headers=bearer(second.json()["access_token"]),  # type: ignore[attr-defined]
    )
    assert me.status_code == 200


def test_refresh_without_cookie_rejected(db_client: TestClient) -> None:
    response = _refresh(db_client)
    assert response.status_code == 401  # type: ignore[attr-defined]
    assert response.json()["error"]["code"] == "session_expired"  # type: ignore[attr-defined]


def test_refresh_with_unknown_cookie_rejected(db_app: FastAPI) -> None:
    assert _refresh_with(db_app, "made-up-token").status_code == 401  # type: ignore[attr-defined]


def test_reused_refresh_token_revokes_the_whole_session(
    db_app: FastAPI, db_client: TestClient
) -> None:
    """A stolen refresh token used after the victim has rotated it ends the session for both."""
    create_user(db_app, EMAIL)
    login(db_client, EMAIL)
    stolen = db_client.cookies[COOKIE]

    rotated = _refresh(db_client)  # the legitimate client rotates
    current_access = rotated.json()["access_token"]  # type: ignore[attr-defined]
    current_cookie = db_client.cookies[COOKIE]

    replay = _refresh_with(db_app, stolen)  # the attacker replays the old token
    assert replay.status_code == 401  # type: ignore[attr-defined]

    # Everything issued in that session is now dead: the newest refresh token and access token.
    assert _refresh_with(db_app, current_cookie).status_code == 401  # type: ignore[attr-defined]
    assert db_client.get("/api/v1/auth/me", headers=bearer(current_access)).status_code == 401
    (alert,) = audit_entries(db_app, AuditAction.REFRESH_TOKEN_REUSE)
    assert alert.result == "denied"
    assert alert.actor_label == EMAIL


def test_failed_refresh_clears_the_cookie(db_app: FastAPI) -> None:
    response = _refresh_with(db_app, "made-up-token")
    assert f"{COOKIE}=;" in response.headers["set-cookie"]  # type: ignore[attr-defined]


def test_logout_revokes_access_and_refresh(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    token = access_token(db_client, EMAIL)
    cookie = db_client.cookies[COOKIE]

    assert db_client.post("/api/v1/auth/logout", headers=bearer(token)).status_code == 204
    assert db_client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    assert _refresh_with(db_app, cookie).status_code == 401  # type: ignore[attr-defined]
    assert len(audit_entries(db_app, AuditAction.LOGOUT)) == 1


def test_sessions_are_independent(db_app: FastAPI) -> None:
    """Logging out on one device leaves the other signed in."""
    create_user(db_app, EMAIL)
    laptop = TestClient(db_app, base_url=TEST_ORIGIN, headers=HEADERS)
    phone = TestClient(db_app, base_url=TEST_ORIGIN, headers=HEADERS)
    laptop_token = access_token(laptop, EMAIL)
    phone_token = access_token(phone, EMAIL)

    laptop.post("/api/v1/auth/logout", headers=bearer(laptop_token))
    assert phone.get("/api/v1/auth/me", headers=bearer(phone_token)).status_code == 200


# --- Password change ------------------------------------------------------------------------

NEW_PASSWORD = "a different long passphrase 77"


def _change(client: TestClient, token: str, current: str, new: str) -> object:
    return client.post(
        "/api/v1/auth/password/change",
        headers=bearer(token),
        json={"current_password": current, "new_password": new},
    )


def test_password_change_requires_current_password(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    token = access_token(db_client, EMAIL)
    response = _change(db_client, token, "not my password", NEW_PASSWORD)
    assert response.status_code == 400  # type: ignore[attr-defined]
    assert response.json()["error"]["code"] == "current_password_incorrect"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "weak",
    ["short", "password1234", "analystanalyst99", DEFAULT_PASSWORD, "aaaaaaaaaaaaaaaa", "x" * 129],
)
def test_password_change_enforces_policy(db_app: FastAPI, db_client: TestClient, weak: str) -> None:
    create_user(db_app, EMAIL)
    token = access_token(db_client, EMAIL)
    response = _change(db_client, token, DEFAULT_PASSWORD, weak)
    assert response.status_code == 400  # type: ignore[attr-defined]
    assert response.json()["error"]["code"] == "weak_password"  # type: ignore[attr-defined]
    assert weak not in response.text  # type: ignore[attr-defined]


def test_password_change_signs_out_other_sessions_only(db_app: FastAPI) -> None:
    create_user(db_app, EMAIL)
    here = TestClient(db_app, base_url=TEST_ORIGIN, headers=HEADERS)
    elsewhere = TestClient(db_app, base_url=TEST_ORIGIN, headers=HEADERS)
    here_token = access_token(here, EMAIL)
    elsewhere_token = access_token(elsewhere, EMAIL)

    assert _change(here, here_token, DEFAULT_PASSWORD, NEW_PASSWORD).status_code == 204  # type: ignore[attr-defined]
    assert here.get("/api/v1/auth/me", headers=bearer(here_token)).status_code == 200
    assert elsewhere.get("/api/v1/auth/me", headers=bearer(elsewhere_token)).status_code == 401
    assert login(here, EMAIL, DEFAULT_PASSWORD).status_code == 401
    assert login(here, EMAIL, NEW_PASSWORD).status_code == 200


def test_password_change_clears_forced_change(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL, must_change_password=True)
    token = access_token(db_client, EMAIL)
    _change(db_client, token, DEFAULT_PASSWORD, NEW_PASSWORD)
    me = db_client.get("/api/v1/auth/me", headers=bearer(token))
    assert me.json()["pending_steps"] == []
