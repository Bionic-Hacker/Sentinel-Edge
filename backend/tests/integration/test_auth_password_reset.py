"""Password reset via the local outbox (ADR-0003, ASVS V2.5)."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.core.clock import utcnow
from app.models.session import PasswordResetToken
from app.services.audit import AuditAction
from tests.helpers import (
    DEFAULT_PASSWORD,
    access_token,
    audit_entries,
    bearer,
    create_user,
    login,
    outbox,
)

pytestmark = [pytest.mark.security, pytest.mark.db]
EMAIL = "analyst@example.com"
NEW_PASSWORD = "brand new long passphrase 2026"


def _forgot(client: TestClient, email: str) -> object:
    return client.post("/api/v1/auth/password/forgot", json={"email": email})


def _reset(client: TestClient, token: str, password: str = NEW_PASSWORD) -> object:
    return client.post(
        "/api/v1/auth/password/reset", json={"token": token, "new_password": password}
    )


def _token_from_outbox(app: FastAPI) -> str:
    (message,) = outbox(app)
    match = re.search(r"/reset-password#token=([A-Za-z0-9_-]+)", message.body)
    assert match, message.body
    return match.group(1)


def test_reset_request_writes_link_to_outbox(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    response = _forgot(db_client, EMAIL)
    assert response.status_code == 202  # type: ignore[attr-defined]
    (message,) = outbox(db_app)
    assert message.recipient == EMAIL
    # The token is in the URL fragment, which browsers never send to servers.
    assert "/reset-password#token=" in message.body


def test_unknown_email_gets_identical_response_and_no_message(
    db_app: FastAPI, db_client: TestClient
) -> None:
    create_user(db_app, EMAIL)
    known = _forgot(db_client, EMAIL)
    unknown = _forgot(db_client, "nobody@example.com")
    assert known.status_code == unknown.status_code == 202  # type: ignore[attr-defined]
    assert known.json() == unknown.json()  # type: ignore[attr-defined]
    assert len(outbox(db_app)) == 1
    results = {
        e.actor_label: e.result for e in audit_entries(db_app, AuditAction.PASSWORD_RESET_REQUESTED)
    }
    assert results == {EMAIL: "success", "nobody@example.com": "failure"}


def test_reset_token_hash_only_in_database(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    _forgot(db_client, EMAIL)
    token = _token_from_outbox(db_app)
    with db_app.state.session_factory() as db:
        stored = db.query(PasswordResetToken).one()
        assert stored.token_hash != token
        assert len(stored.token_hash) == 64


def test_reset_changes_password_and_ends_every_session(
    db_app: FastAPI, db_client: TestClient
) -> None:
    create_user(db_app, EMAIL)
    existing_session = access_token(db_client, EMAIL)
    _forgot(db_client, EMAIL)

    assert _reset(db_client, _token_from_outbox(db_app)).status_code == 204  # type: ignore[attr-defined]
    assert db_client.get("/api/v1/auth/me", headers=bearer(existing_session)).status_code == 401
    assert login(db_client, EMAIL, DEFAULT_PASSWORD).status_code == 401
    assert login(db_client, EMAIL, NEW_PASSWORD).status_code == 200
    assert len(audit_entries(db_app, AuditAction.PASSWORD_RESET)) == 1


def test_reset_token_is_single_use(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    _forgot(db_client, EMAIL)
    token = _token_from_outbox(db_app)
    _reset(db_client, token)
    again = _reset(db_client, token, "yet another long passphrase 9")
    assert again.status_code == 400  # type: ignore[attr-defined]
    assert again.json()["error"]["code"] == "invalid_reset_token"  # type: ignore[attr-defined]


def test_expired_reset_token_rejected(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    _forgot(db_client, EMAIL)
    with db_app.state.session_factory() as db:
        db.execute(update(PasswordResetToken).values(expires_at=utcnow() - timedelta(seconds=1)))
        db.commit()
    assert _reset(db_client, _token_from_outbox(db_app)).status_code == 400  # type: ignore[attr-defined]


@pytest.mark.parametrize("token", ["", "made-up", "x" * 500, "../../etc/passwd"])
def test_bogus_reset_tokens_rejected(db_client: TestClient, token: str) -> None:
    assert _reset(db_client, token).status_code in {400, 422}  # type: ignore[attr-defined]


def test_weak_password_leaves_token_usable(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    _forgot(db_client, EMAIL)
    token = _token_from_outbox(db_app)
    weak = _reset(db_client, token, "password1234")
    assert weak.status_code == 400  # type: ignore[attr-defined]
    assert weak.json()["error"]["code"] == "weak_password"  # type: ignore[attr-defined]
    assert _reset(db_client, token).status_code == 204  # type: ignore[attr-defined]


def test_reset_requests_are_rate_limited(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    _forgot(db_client, EMAIL)
    _forgot(db_client, EMAIL)
    assert len(outbox(db_app)) == 1
    denied = [
        e
        for e in audit_entries(db_app, AuditAction.PASSWORD_RESET_REQUESTED)
        if e.result == "denied"
    ]
    assert denied[0].details == {"reason": "rate_limited"}


def test_reset_unlocks_a_locked_account(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL, locked_until=utcnow() + timedelta(minutes=10))
    _forgot(db_client, EMAIL)
    _reset(db_client, _token_from_outbox(db_app))
    assert login(db_client, EMAIL, NEW_PASSWORD).status_code == 200
