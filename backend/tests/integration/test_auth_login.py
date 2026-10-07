"""Login, lockout, enumeration resistance, session tokens and CSRF (OWASP API2, ASVS V2/V3)."""

from __future__ import annotations

from datetime import timedelta

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.core.clock import utcnow
from app.models.session import AuthSession
from app.models.user import Role, User
from app.services.audit import AuditAction
from tests.conftest import TEST_JWT_KEY, TEST_ORIGIN
from tests.helpers import (
    DEFAULT_PASSWORD,
    access_token,
    audit_entries,
    bearer,
    create_user,
    get_user,
    login,
)

pytestmark = [pytest.mark.security, pytest.mark.db]
EMAIL = "analyst@example.com"


def _error(response: object) -> tuple[int, str, str]:
    body = response.json()["error"]  # type: ignore[attr-defined]
    return response.status_code, body["code"], body["message"]  # type: ignore[attr-defined]


# --- Successful login and the session it creates --------------------------------------------


def test_login_returns_access_token_and_secure_refresh_cookie(
    db_app: FastAPI, db_client: TestClient
) -> None:
    create_user(db_app, EMAIL)
    response = login(db_client, EMAIL)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "authenticated"
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == EMAIL
    assert "password_hash" not in response.text

    cookie = response.headers["set-cookie"]
    assert cookie.startswith("__Host-sentinel_refresh=")
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attribute.lower() in cookie.lower()
    assert "domain=" not in cookie.lower()  # __Host- cookies must be host-only


def test_access_token_reaches_protected_endpoint(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    me = db_client.get("/api/v1/auth/me", headers=bearer(access_token(db_client, EMAIL)))
    assert me.status_code == 200
    assert me.json()["role"] == "ANALYST"
    assert me.json()["pending_steps"] == []


def test_email_is_case_insensitive(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    assert login(db_client, "  Analyst@Example.COM ").status_code == 200


def test_successful_login_is_audited(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    login(db_client, EMAIL)
    (entry,) = audit_entries(db_app, AuditAction.LOGIN)
    assert entry.result == "success"
    assert entry.actor_label == EMAIL
    assert entry.correlation_id


# --- Failure is uniform: no account enumeration (API2, ASVS 2.2) ----------------------------


def test_failures_are_indistinguishable(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    create_user(db_app, "former@example.com", is_active=False)
    create_user(db_app, "locked@example.com", locked_until=utcnow() + timedelta(minutes=5))

    responses = [
        login(db_client, EMAIL, "wrong password entirely"),
        login(db_client, "nobody@example.com"),
        login(db_client, "former@example.com"),
        login(db_client, "locked@example.com"),  # correct password, but locked
    ]
    assert {_error(r) for r in responses} == {
        (401, "invalid_credentials", "Invalid email or password")
    }


def test_failed_logins_are_audited_with_reason(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    login(db_client, EMAIL, "wrong password entirely")
    login(db_client, "nobody@example.com")
    reasons = {(e.actor_label, e.details["reason"]) for e in audit_entries(db_app)}
    assert (EMAIL, "bad_password") in reasons
    assert ("nobody@example.com", "unknown_account") in reasons


# --- Lockout (credential stuffing, T-ID-01) -------------------------------------------------


def test_account_locks_after_repeated_failures(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    max_failed = db_app.state.settings.max_failed_logins
    for _ in range(max_failed):
        assert login(db_client, EMAIL, "wrong password entirely").status_code == 401

    # Even the correct password is refused while locked, with the same generic answer.
    assert _error(login(db_client, EMAIL)) == (
        401,
        "invalid_credentials",
        "Invalid email or password",
    )
    assert get_user(db_app, EMAIL).locked_until is not None
    assert len(audit_entries(db_app, AuditAction.ACCOUNT_LOCKED)) == 1


def test_lock_expires(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL, locked_until=utcnow() - timedelta(seconds=1))
    assert login(db_client, EMAIL).status_code == 200


def test_successful_login_resets_failure_count(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    login(db_client, EMAIL, "wrong password entirely")
    login(db_client, EMAIL)
    assert get_user(db_app, EMAIL).failed_login_count == 0


# --- Input validation -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"email": EMAIL, "password": DEFAULT_PASSWORD, "role": "ADMIN"},  # mass assignment
        {"email": EMAIL, "password": "x" * 129},  # bounded before any hashing (DoS)
        {"email": "not-an-email", "password": DEFAULT_PASSWORD},
        {"email": EMAIL},
    ],
)
def test_malformed_login_rejected_without_echo(db_client: TestClient, body: dict[str, str]) -> None:
    response = db_client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 422
    assert DEFAULT_PASSWORD not in response.text
    assert "ADMIN" not in response.text


# --- Bearer token validation (ASVS V3.5) ----------------------------------------------------


def _forge(claims: dict[str, object], key: str = TEST_JWT_KEY, alg: str = "HS256") -> str:
    now = utcnow()
    base: dict[str, object] = {
        "iss": "sentineledge",
        "aud": "sentineledge-api",
        "typ": "access",
        "jti": "x",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
    }
    return jwt.encode({**base, **claims}, key, algorithm=alg)


def _real_claims(db_app: FastAPI, db_client: TestClient) -> dict[str, object]:
    create_user(db_app, EMAIL)
    token = access_token(db_client, EMAIL)
    claims: dict[str, object] = jwt.decode(token, options={"verify_signature": False})
    return {"sub": claims["sub"], "sid": claims["sid"]}


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda c: _forge(c, key="a-different-key-of-sufficient-length!!"), id="wrong-key"
        ),
        pytest.param(lambda c: _forge({**c, "exp": utcnow() - timedelta(minutes=1)}), id="expired"),
        pytest.param(lambda c: _forge({**c, "aud": "another-service"}), id="wrong-audience"),
        pytest.param(lambda c: _forge({**c, "iss": "attacker"}), id="wrong-issuer"),
        pytest.param(lambda c: _forge({**c, "typ": "mfa_challenge"}), id="wrong-type"),
        pytest.param(lambda c: _forge({**c, "sid": None}), id="no-session"),
        pytest.param(
            lambda c: jwt.encode({**c, "typ": "access"}, key="", algorithm="none"), id="alg-none"
        ),
        pytest.param(
            lambda c: _forge(c, key=TEST_JWT_KEY, alg="HS512"), id="algorithm-substitution"
        ),
    ],
)
def test_forged_or_invalid_tokens_rejected(
    db_app: FastAPI, db_client: TestClient, mutate: object
) -> None:
    token = mutate(_real_claims(db_app, db_client))  # type: ignore[operator]
    response = db_client.get("/api/v1/auth/me", headers=bearer(token))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "header", ["", "Bearer", "Basic dXNlcjpwYXNz", "Bearer not.a.jwt.at.all", "bearer abc.def.ghi"]
)
def test_malformed_authorization_header_rejected(db_client: TestClient, header: str) -> None:
    response = db_client.get("/api/v1/auth/me", headers={"Authorization": header})
    assert response.status_code == 401


def test_token_rejected_once_user_deactivated(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    token = access_token(db_client, EMAIL)
    with db_app.state.session_factory() as db:
        db.execute(update(User).where(User.email == EMAIL).values(is_active=False))
        db.commit()
    assert db_client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_token_rejected_once_session_expired(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, EMAIL)
    token = access_token(db_client, EMAIL)
    with db_app.state.session_factory() as db:
        db.execute(update(AuthSession).values(expires_at=utcnow() - timedelta(seconds=1)))
        db.commit()
    assert db_client.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


# --- CSRF on cookie-bearing endpoints (T-ID-04) ---------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example", "X-SentinelEdge-CSRF": "1"},
        {"X-SentinelEdge-CSRF": "1"},  # no Origin
        {"Origin": TEST_ORIGIN},  # no custom header (a cross-site form cannot add one)
        {"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "0"},
    ],
)
@pytest.mark.parametrize("path", ["/api/v1/auth/login", "/api/v1/auth/refresh"])
def test_cross_site_requests_rejected(db_app: FastAPI, path: str, headers: dict[str, str]) -> None:
    create_user(db_app, EMAIL)
    client = TestClient(db_app, base_url=TEST_ORIGIN, raise_server_exceptions=False)
    response = client.post(
        path, json={"email": EMAIL, "password": DEFAULT_PASSWORD}, headers=headers
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_rejected"
    assert "set-cookie" not in response.headers


# --- Pending setup: forced password change and MFA enrollment --------------------------------


def test_new_admin_must_change_password_and_enroll_mfa(
    db_app: FastAPI, db_client: TestClient
) -> None:
    create_user(db_app, "admin@example.com", role=Role.ADMIN, must_change_password=True)
    me = db_client.get(
        "/api/v1/auth/me", headers=bearer(access_token(db_client, "admin@example.com"))
    )
    assert me.json()["pending_steps"] == ["mfa_enrollment", "password_change"]


def test_privileged_roles_require_mfa_enrollment(db_app: FastAPI, db_client: TestClient) -> None:
    create_user(db_app, "eng@example.com", role=Role.SECURITY_ENGINEER)
    create_user(db_app, "viewer@example.com", role=Role.VIEWER)
    eng = db_client.get(
        "/api/v1/auth/me", headers=bearer(access_token(db_client, "eng@example.com"))
    )
    viewer = db_client.get(
        "/api/v1/auth/me", headers=bearer(access_token(db_client, "viewer@example.com"))
    )
    assert eng.json()["pending_steps"] == ["mfa_enrollment"]
    assert viewer.json()["pending_steps"] == []
