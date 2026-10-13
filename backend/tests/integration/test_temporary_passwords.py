"""Account creation and recovery through an administrator only (ADR-0028, C-ID-07).

There is no email path: an administrator creates a user, or resets a forgotten password, and is
shown a generated temporary password once. It is stored only as a hash, never audited, expires,
and must be replaced at first sign-in.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.core.clock import utcnow
from app.models.user import Role, User
from app.services.audit import AuditAction
from tests.helpers import (
    access_token,
    audit_entries,
    bearer,
    create_user,
    get_user,
    login,
    session_token,
)

pytestmark = [pytest.mark.security, pytest.mark.db]
TEMPORARY = re.compile(r"^[a-z2-9]{5}(-[a-z2-9]{5}){3}$")
CHOSEN = "the new user chose this passphrase"


def _admin(app: FastAPI, email: str = "admin@example.com") -> tuple[User, str]:
    user = create_user(app, email, role=Role.ADMIN, mfa_enabled=True, mfa_secret=b"x")
    return user, session_token(app, user)


def _create(client: TestClient, token: str, email: str = "new.analyst@example.com") -> dict:
    response = client.post(
        "/api/v1/users",
        headers=bearer(token),
        json={"email": email, "display_name": "New Analyst", "role": "ANALYST"},
    )
    assert response.status_code == 201, response.text
    body: dict = response.json()
    return body


def _audit_text(app: FastAPI) -> str:
    return json.dumps([e.details for e in audit_entries(app)])


# --- Creating a user -----------------------------------------------------------------------


def test_admin_creates_user_and_is_shown_a_temporary_password_once(
    db_app: FastAPI, db_client: TestClient
) -> None:
    _, token = _admin(db_app)
    response = db_client.post(
        "/api/v1/users",
        headers=bearer(token),
        json={"email": "New.Analyst@Example.com", "display_name": "New Analyst", "role": "ANALYST"},
    )
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {"user", "temporary_password", "expires_at"}
    assert body["user"]["email"] == "new.analyst@example.com"
    assert body["user"]["must_change_password"] is True
    assert body["user"]["temporary_password_expires_at"] == body["expires_at"]
    password = body["temporary_password"]
    assert TEMPORARY.fullmatch(password)

    stored = get_user(db_app, "new.analyst@example.com")
    assert stored.password_hash.startswith("$argon2id$")
    assert password not in stored.password_hash
    assert stored.temporary_password_expires_at is not None
    lifetime = stored.temporary_password_expires_at - utcnow()
    assert timedelta(hours=71) < lifetime <= timedelta(hours=72)

    # It cannot be fetched again: the user record never carries it.
    again = db_client.get(f"/api/v1/users/{stored.id}", headers=bearer(token)).json()
    assert password not in json.dumps(again)
    # Audited as issued, with its expiry; the password itself never reaches the audit log.
    (created,) = audit_entries(db_app, AuditAction.USER_CREATED)
    assert created.details["temporary_password_expires_at"]
    assert password not in _audit_text(db_app)


def test_each_temporary_password_is_different(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    first = _create(db_client, token, "one@example.com")["temporary_password"]
    second = _create(db_client, token, "two@example.com")["temporary_password"]
    assert first != second


def test_new_user_must_replace_the_temporary_password_first(
    db_app: FastAPI, db_client: TestClient
) -> None:
    _, token = _admin(db_app)
    temporary = _create(db_client, token)["temporary_password"]

    user_token = access_token(db_client, "new.analyst@example.com", temporary)
    me = db_client.get("/api/v1/auth/me", headers=bearer(user_token)).json()
    assert me["pending_steps"] == ["password_change"]
    held = db_client.get("/api/v1/incidents", headers=bearer(user_token))
    assert held.status_code == 403
    assert held.json()["error"]["code"] == "setup_required"

    changed = db_client.post(
        "/api/v1/auth/password/change",
        headers=bearer(user_token),
        json={"current_password": temporary, "new_password": CHOSEN},
    )
    assert changed.status_code == 204
    stored = get_user(db_app, "new.analyst@example.com")
    assert stored.must_change_password is False
    assert stored.temporary_password_expires_at is None
    assert login(db_client, "new.analyst@example.com", temporary).status_code == 401
    assert login(db_client, "new.analyst@example.com", CHOSEN).status_code == 200


def test_an_expired_temporary_password_no_longer_signs_in(
    db_app: FastAPI, db_client: TestClient
) -> None:
    _, token = _admin(db_app)
    temporary = _create(db_client, token)["temporary_password"]
    with db_app.state.session_factory() as db:
        db.execute(
            update(User)
            .where(User.email == "new.analyst@example.com")
            .values(temporary_password_expires_at=utcnow() - timedelta(seconds=1))
        )
        db.commit()

    response = login(db_client, "new.analyst@example.com", temporary)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "temporary_password_expired"
    # Not a failed guess: it does not count towards lockout.
    assert get_user(db_app, "new.analyst@example.com").failed_login_count == 0
    denied = [e for e in audit_entries(db_app, AuditAction.LOGIN) if e.result.value == "denied"]
    assert denied[-1].details["reason"] == "temporary_password_expired"

    # A wrong password says nothing about the account's state.
    wrong = login(db_client, "new.analyst@example.com", "not the temporary password")
    assert wrong.json()["error"]["code"] == "invalid_credentials"


# --- Resetting a forgotten password -------------------------------------------------------------


def test_admin_resets_a_forgotten_password(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    member = create_user(
        db_app,
        "forgetful@example.com",
        role=Role.SECURITY_ENGINEER,
        mfa_enabled=True,
        mfa_secret=b"kept",
        failed_login_count=5,
        locked_until=utcnow() + timedelta(minutes=10),
    )
    live = session_token(db_app, member)

    response = db_client.post(f"/api/v1/users/{member.id}/password/reset", headers=bearer(token))
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    temporary = body["temporary_password"]
    assert TEMPORARY.fullmatch(temporary)
    assert body["user"]["must_change_password"] is True
    assert body["user"]["locked"] is False

    # The lockout is cleared and the second factor stays.
    stored = get_user(db_app, "forgetful@example.com")
    assert stored.mfa_enabled is True
    assert stored.mfa_secret == b"kept"
    assert stored.failed_login_count == 0
    assert stored.locked_until is None
    # Every session ends and the old password stops working.
    assert db_client.get("/api/v1/auth/me", headers=bearer(live)).status_code == 401
    assert login(db_client, "forgetful@example.com").status_code == 401
    challenge = login(db_client, "forgetful@example.com", temporary)
    assert challenge.status_code == 200
    assert "challenge_token" in challenge.json()  # MFA is still required

    (reset,) = audit_entries(db_app, AuditAction.USER_PASSWORD_RESET)
    assert reset.resource_id == str(member.id)
    assert temporary not in _audit_text(db_app)


def test_admins_cannot_reset_their_own_password(db_app: FastAPI, db_client: TestClient) -> None:
    admin, token = _admin(db_app)
    response = db_client.post(f"/api/v1/users/{admin.id}/password/reset", headers=bearer(token))
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "self_password_reset"


def test_reset_unknown_user_is_not_found(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    response = db_client.post(
        "/api/v1/users/00000000-0000-4000-8000-000000000000/password/reset",
        headers=bearer(token),
    )
    assert response.status_code == 404
    assert audit_entries(db_app, AuditAction.USER_PASSWORD_RESET) == []


def test_only_admins_reset_passwords(db_app: FastAPI, db_client: TestClient) -> None:
    target = create_user(db_app, "target@example.com")
    engineer = create_user(
        db_app, "eng@example.com", role=Role.SECURITY_ENGINEER, mfa_enabled=True, mfa_secret=b"x"
    )
    response = db_client.post(
        f"/api/v1/users/{target.id}/password/reset",
        headers=bearer(session_token(db_app, engineer)),
    )
    assert response.status_code == 403


# --- No email path ------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/v1/auth/password/forgot", "/api/v1/auth/password/reset"])
def test_there_is_no_self_service_reset(db_client: TestClient, path: str) -> None:
    response = db_client.post(path, json={"email": "anyone@example.com"})
    assert response.status_code in (404, 405)
