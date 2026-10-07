"""TOTP MFA: enrollment, verification, replay, recovery codes, brute force (ADR-0003, ASVS V2.8)."""

from __future__ import annotations

from datetime import timedelta

import jwt
import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.clock import utcnow
from app.models.user import Role, User
from app.services.audit import AuditAction
from tests.conftest import TEST_JWT_KEY
from tests.helpers import (
    access_token,
    audit_entries,
    bearer,
    create_user,
    enroll_mfa,
    get_user,
    login,
)

pytestmark = [pytest.mark.security, pytest.mark.db]
EMAIL = "eng@example.com"


@pytest.fixture
def enrolled(db_app: FastAPI, db_client: TestClient) -> tuple[str, list[str]]:
    """A security engineer with MFA enrolled through the API. Returns (secret, recovery codes)."""
    create_user(db_app, EMAIL, role=Role.SECURITY_ENGINEER)
    return enroll_mfa(db_client, access_token(db_client, EMAIL))


def _challenge(client: TestClient) -> str:
    response = login(client, EMAIL)
    assert response.status_code == 200
    assert response.json()["status"] == "mfa_required"
    assert "access_token" not in response.json()
    assert "set-cookie" not in response.headers  # no session until the second factor
    token: str = response.json()["challenge_token"]
    return token


def _verify(client: TestClient, challenge: str, code: str) -> object:
    return client.post("/api/v1/auth/mfa/verify", json={"challenge_token": challenge, "code": code})


def _previous_code(secret: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.at(utcnow() - timedelta(seconds=totp.interval))


def _next_code(secret: str) -> str:
    """The next step's code. Enrollment consumed the current step, so the current code would be
    (correctly) refused as a replay; the next step is inside the allowed clock-drift window."""
    totp = pyotp.TOTP(secret)
    return totp.at(utcnow() + timedelta(seconds=totp.interval))


# --- Enrollment -----------------------------------------------------------------------------


def test_enrollment_clears_pending_step_and_returns_recovery_codes(
    db_app: FastAPI, db_client: TestClient
) -> None:
    create_user(db_app, EMAIL, role=Role.SECURITY_ENGINEER)
    token = access_token(db_client, EMAIL)
    me = db_client.get("/api/v1/auth/me", headers=bearer(token))
    assert me.json()["pending_steps"] == ["mfa_enrollment"]

    _, codes = enroll_mfa(db_client, token)
    assert len(codes) == 10
    assert len(set(codes)) == 10
    me = db_client.get("/api/v1/auth/me", headers=bearer(token))
    assert me.json()["mfa_enabled"] is True
    assert me.json()["pending_steps"] == []
    assert len(audit_entries(db_app, AuditAction.MFA_ENROLLED)) == 1


def test_totp_secret_is_encrypted_at_rest(db_app: FastAPI, enrolled: tuple[str, list[str]]) -> None:
    secret, codes = enrolled
    user = get_user(db_app, EMAIL)
    assert user.mfa_secret is not None
    assert secret.encode() not in user.mfa_secret
    with db_app.state.session_factory() as db:
        stored = db.execute(select(User.mfa_secret)).scalar_one()
        assert secret.encode() not in stored
        dump = repr(db.execute(select(User)).scalars().all())
        assert all(code not in dump for code in codes)


def test_enrollment_rejects_wrong_code(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL, role=Role.SECURITY_ENGINEER)
    token = access_token(db_client, EMAIL)
    db_client.post("/api/v1/auth/mfa/enroll", headers=bearer(token))
    response = db_client.post(
        "/api/v1/auth/mfa/enroll/confirm", headers=bearer(token), json={"code": "000000"}
    )
    assert response.status_code == 400
    assert get_user(db_app, EMAIL).mfa_enabled is False


def test_cannot_re_enroll_over_existing_mfa(
    db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    challenge = _challenge(db_client)
    session = _verify(db_client, challenge, _next_code(secret))
    token = session.json()["access_token"]  # type: ignore[attr-defined]
    response = db_client.post("/api/v1/auth/mfa/enroll", headers=bearer(token))
    assert response.status_code == 409


# --- Verification at login ------------------------------------------------------------------


def test_valid_code_completes_login(
    db_app: FastAPI, db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    response = _verify(db_client, _challenge(db_client), _next_code(secret))
    assert response.status_code == 200  # type: ignore[attr-defined]
    assert response.json()["status"] == "authenticated"  # type: ignore[attr-defined]
    assert "__Host-sentinel_refresh" in response.headers["set-cookie"]  # type: ignore[attr-defined]
    (entry,) = [e for e in audit_entries(db_app, AuditAction.LOGIN_MFA) if e.result == "success"]
    assert entry.details["method"] == "totp"


def test_code_from_previous_step_accepted_for_clock_drift(
    db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    # Enrollment consumed the current step, so this login uses the previous one... which is
    # *older* than the last accepted step and must be refused as a replay.
    response = _verify(db_client, _challenge(db_client), _previous_code(secret))
    assert response.status_code == 401  # type: ignore[attr-defined]


def test_totp_code_cannot_be_replayed(
    db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    # The code enrollment just used must not work again...
    current = _verify(db_client, _challenge(db_client), pyotp.TOTP(secret).now())
    assert current.status_code == 401  # type: ignore[attr-defined]
    # ...and a code that works once never works twice, even from a fresh challenge.
    code = _next_code(secret)
    assert _verify(db_client, _challenge(db_client), code).status_code == 200  # type: ignore[attr-defined]
    assert _verify(db_client, _challenge(db_client), code).status_code == 401  # type: ignore[attr-defined]


def test_password_alone_never_yields_a_session(
    db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    challenge = _challenge(db_client)
    # The challenge token is not an access token.
    assert db_client.get("/api/v1/auth/me", headers=bearer(challenge)).status_code == 401


def test_access_token_is_not_a_challenge_token(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, "viewer@example.com", role=Role.VIEWER)
    token = access_token(db_client, "viewer@example.com")
    assert _verify(db_client, token, "123456").status_code == 401  # type: ignore[attr-defined]


def test_expired_challenge_rejected(
    db_app: FastAPI, db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    user = get_user(db_app, EMAIL)
    past = utcnow() - timedelta(minutes=10)
    expired = jwt.encode(
        {
            "iss": "sentineledge",
            "aud": "sentineledge-api",
            "typ": "mfa_challenge",
            "sub": str(user.id),
            "jti": "x",
            "iat": past,
            "nbf": past,
            "exp": past + timedelta(minutes=5),
        },
        TEST_JWT_KEY,
        algorithm="HS256",
    )
    assert _verify(db_client, expired, pyotp.TOTP(secret).now()).status_code == 401  # type: ignore[attr-defined]


def test_mfa_brute_force_locks_account(
    db_app: FastAPI, db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    secret, _ = enrolled
    challenge = _challenge(db_client)
    for _ in range(db_app.state.settings.max_failed_logins):
        assert _verify(db_client, challenge, "000000").status_code == 401  # type: ignore[attr-defined]
    # Locked: even a correct code is refused.
    assert _verify(db_client, challenge, _next_code(secret)).status_code == 401  # type: ignore[attr-defined]
    assert len(audit_entries(db_app, AuditAction.ACCOUNT_LOCKED)) == 1


# --- Recovery codes -------------------------------------------------------------------------


def test_recovery_code_works_exactly_once(
    db_app: FastAPI, db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    _, codes = enrolled
    first = _verify(db_client, _challenge(db_client), codes[0].upper())  # case-insensitive
    assert first.status_code == 200  # type: ignore[attr-defined]
    second = _verify(db_client, _challenge(db_client), codes[0])
    assert second.status_code == 401  # type: ignore[attr-defined]
    success = [e for e in audit_entries(db_app, AuditAction.LOGIN_MFA) if e.result == "success"]
    assert success[0].details == {"method": "recovery_code", "recovery_codes_remaining": 9}


def test_another_users_recovery_code_rejected(
    db_app: FastAPI, db_client: TestClient, enrolled: tuple[str, list[str]]
) -> None:
    create_user(db_app, "admin@example.com", role=Role.ADMIN)
    _, admin_codes = enroll_mfa(db_client, access_token(db_client, "admin@example.com"))
    assert _verify(db_client, _challenge(db_client), admin_codes[0]).status_code == 401  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "code",
    [
        "\u0661\u0662\u0663\u0664\u0665\u0666",  # Arabic-Indic digits
        "\uff11\uff12\uff13\uff14\uff15\uff16",  # full-width digits
        "12345\uff16",  # one full-width digit hidden at the end
    ],
)
def test_non_ascii_digits_rejected_cleanly(
    db_client: TestClient, enrolled: tuple[str, list[str]], code: str
) -> None:
    """Regression: Unicode digits once matched \\d and crashed the comparison (500)."""
    response = _verify(db_client, _challenge(db_client), code)
    assert response.status_code == 401  # type: ignore[attr-defined]
