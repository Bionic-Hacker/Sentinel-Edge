"""User management and the audit log API: BOLA, admin safety rules, invites, audit queries."""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models.user import Role, User
from app.services.audit import AuditAction
from tests.helpers import audit_entries, bearer, create_user, login, outbox, session_token

pytestmark = [pytest.mark.security, pytest.mark.db]


def _admin(app: FastAPI, email: str = "admin@example.com") -> tuple[User, str]:
    user = create_user(app, email, role=Role.ADMIN, mfa_enabled=True, mfa_secret=b"x")
    return user, session_token(app, user)


def _member(app: FastAPI, email: str, role: Role = Role.ANALYST) -> tuple[User, str]:
    user = create_user(app, email, role=role)
    return user, session_token(app, user, mfa_verified=False)


# --- Object-level authorization (OWASP API1 BOLA) -------------------------------------------


def test_users_can_read_only_their_own_record(db_app: FastAPI, db_client: TestClient) -> None:
    alice, alice_token = _member(db_app, "alice@example.com")
    bob, _ = _member(db_app, "bob@example.com")

    own = db_client.get(f"/api/v1/users/{alice.id}", headers=bearer(alice_token))
    assert own.status_code == 200
    assert own.json()["email"] == "alice@example.com"

    other = db_client.get(f"/api/v1/users/{bob.id}", headers=bearer(alice_token))
    missing = db_client.get(
        "/api/v1/users/00000000-0000-4000-8000-000000000000", headers=bearer(alice_token)
    )
    # Someone else's record and a non-existent one are indistinguishable: IDs can't be probed.
    assert other.status_code == missing.status_code == 404
    assert other.json()["error"]["message"] == missing.json()["error"]["message"]
    denied = [e for e in audit_entries(db_app, AuditAction.ACCESS_DENIED)]
    assert {e.resource_id for e in denied} >= {str(bob.id)}


def test_admin_can_read_any_record(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    bob, _ = _member(db_app, "bob@example.com")
    assert db_client.get(f"/api/v1/users/{bob.id}", headers=bearer(token)).status_code == 200


USER_FIELDS = {
    "id",
    "email",
    "display_name",
    "role",
    "is_active",
    "mfa_enabled",
    "must_change_password",
    "locked",
    "last_login_at",
    "created_at",
}


def test_user_records_expose_exactly_the_allowed_fields(
    db_app: FastAPI, db_client: TestClient
) -> None:
    """Allow-list, not deny-list: any new field must be added here deliberately (OWASP API3)."""
    _, token = _admin(db_app)
    response = db_client.get("/api/v1/users", headers=bearer(token))
    assert response.status_code == 200
    for item in response.json()["items"]:
        assert set(item) == USER_FIELDS
    assert "argon2" not in response.text


# --- Creating users: invites, not passwords --------------------------------------------------


def test_admin_invites_user_without_ever_knowing_their_password(
    db_app: FastAPI, db_client: TestClient
) -> None:
    _, token = _admin(db_app)
    response = db_client.post(
        "/api/v1/users",
        headers=bearer(token),
        json={"email": "New.Analyst@Example.com", "display_name": "New Analyst", "role": "ANALYST"},
    )
    assert response.status_code == 201
    assert response.json()["email"] == "new.analyst@example.com"
    assert set(response.json()) == USER_FIELDS  # no password, token or link in the response

    (invite,) = outbox(db_app)
    assert invite.recipient == "new.analyst@example.com"
    link = re.search(r"#token=([A-Za-z0-9_-]+)", invite.body)
    assert link
    chosen = "the invitee chose this passphrase"
    reset = db_client.post(
        "/api/v1/auth/password/reset", json={"token": link.group(1), "new_password": chosen}
    )
    assert reset.status_code == 204
    assert login(db_client, "new.analyst@example.com", chosen).status_code == 200


def test_duplicate_email_rejected(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    create_user(db_app, "taken@example.com")
    response = db_client.post(
        "/api/v1/users",
        headers=bearer(token),
        json={"email": "TAKEN@example.com", "display_name": "x", "role": "VIEWER"},
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    "body",
    [
        {"email": "a@example.com", "display_name": "A", "role": "SUPERUSER"},
        {"email": "a@example.com", "display_name": "A", "role": "VIEWER", "is_active": False},
        {"email": "a@example.com", "display_name": "A", "role": "VIEWER", "password_hash": "x"},
    ],
)
def test_create_rejects_unknown_roles_and_extra_fields(
    db_app: FastAPI, db_client: TestClient, body: dict[str, str]
) -> None:
    _, token = _admin(db_app)
    assert db_client.post("/api/v1/users", headers=bearer(token), json=body).status_code == 422


# --- Updating users: safety rules ------------------------------------------------------------


def test_role_change_takes_effect_immediately(db_app: FastAPI, db_client: TestClient) -> None:
    _, admin_token = _admin(db_app)
    bob, bob_token = _member(db_app, "bob@example.com", Role.SECURITY_ENGINEER)
    response = db_client.patch(
        f"/api/v1/users/{bob.id}", headers=bearer(admin_token), json={"role": "VIEWER"}
    )
    assert response.status_code == 200
    # Demotion ends the old session at once, rather than when its token would have expired.
    assert db_client.get("/api/v1/auth/me", headers=bearer(bob_token)).status_code == 401
    (entry,) = audit_entries(db_app, AuditAction.USER_UPDATED)
    assert entry.details == {"before": {"role": "SECURITY_ENGINEER"}, "after": {"role": "VIEWER"}}


def test_deactivation_ends_sessions(db_app: FastAPI, db_client: TestClient) -> None:
    _, admin_token = _admin(db_app)
    bob, bob_token = _member(db_app, "bob@example.com")
    db_client.patch(
        f"/api/v1/users/{bob.id}", headers=bearer(admin_token), json={"is_active": False}
    )
    assert db_client.get("/api/v1/auth/me", headers=bearer(bob_token)).status_code == 401
    assert login(db_client, "bob@example.com").status_code == 401


@pytest.mark.parametrize("change", [{"role": "VIEWER"}, {"is_active": False}])
def test_admin_cannot_lock_themselves_out(
    db_app: FastAPI, db_client: TestClient, change: dict[str, object]
) -> None:
    admin, token = _admin(db_app)
    _admin(db_app, "second-admin@example.com")  # not the last admin: self-protection still applies
    response = db_client.patch(f"/api/v1/users/{admin.id}", headers=bearer(token), json=change)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "self_lockout"


def test_last_active_admin_cannot_be_removed(db_app: FastAPI) -> None:
    """Defense in depth at the service layer. Over HTTP this is unreachable today (the only
    admin who could act on the last admin is that admin, and self-lockout stops them first);
    the invariant must still hold for any future caller (CLI, automation, a new endpoint)."""
    from app.core.authz import Principal
    from app.core.errors import ApiError
    from app.schemas.users import UserUpdate
    from app.services.audit import SYSTEM_CONTEXT
    from app.services.users import UserService

    sole_admin, _ = _admin(db_app)
    operator = create_user(db_app, "automation@example.com", role=Role.SECURITY_ENGINEER)
    with db_app.state.session_factory() as db:
        service = UserService(
            db=db, settings=db_app.state.settings, hasher=db_app.state.hasher, ctx=SYSTEM_CONTEXT
        )
        principal = Principal(user=operator, session=None, pending=frozenset())  # type: ignore[arg-type]
        for change in ({"role": Role.VIEWER}, {"is_active": False}):
            with pytest.raises(ApiError) as excinfo:
                service.update_user(principal, sole_admin.id, UserUpdate(**change))
            assert excinfo.value.code == "last_admin"


def test_update_rejects_email_and_password_changes(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    bob, _ = _member(db_app, "bob@example.com")
    for body in ({"email": "evil@example.com"}, {"password_hash": "x"}, {"mfa_enabled": False}):
        response = db_client.patch(f"/api/v1/users/{bob.id}", headers=bearer(token), json=body)
        assert response.status_code == 422


def test_admin_mfa_reset(db_app: FastAPI, db_client: TestClient) -> None:
    admin, token = _admin(db_app)
    eng = create_user(
        db_app, "eng@example.com", role=Role.SECURITY_ENGINEER, mfa_enabled=True, mfa_secret=b"x"
    )
    eng_token = session_token(db_app, eng)

    response = db_client.post(f"/api/v1/users/{eng.id}/mfa/reset", headers=bearer(token))
    assert response.status_code == 200
    assert response.json()["mfa_enabled"] is False
    assert db_client.get("/api/v1/auth/me", headers=bearer(eng_token)).status_code == 401
    assert len(audit_entries(db_app, AuditAction.USER_MFA_RESET)) == 1

    own = db_client.post(f"/api/v1/users/{admin.id}/mfa/reset", headers=bearer(token))
    assert own.status_code == 409


# --- Audit log API ----------------------------------------------------------------------------


def test_audit_log_filters_and_paginates(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    create_user(db_app, "bob@example.com")
    for _ in range(3):
        login(db_client, "bob@example.com", "wrong password value")
    login(db_client, "bob@example.com")

    failures = db_client.get(
        "/api/v1/audit-logs",
        headers=bearer(token),
        params={"action": "auth.login", "result": "failure", "actor": "BOB@example.com"},
    ).json()
    assert len(failures["items"]) == 3
    assert all(i["result"] == "failure" for i in failures["items"])

    page1 = db_client.get("/api/v1/audit-logs", headers=bearer(token), params={"limit": 2}).json()
    assert len(page1["items"]) == 2
    assert page1["items"][0]["seq"] > page1["items"][1]["seq"]  # newest first
    page2 = db_client.get(
        "/api/v1/audit-logs",
        headers=bearer(token),
        params={"limit": 2, "before_seq": page1["next_before_seq"]},
    ).json()
    assert page2["items"][0]["seq"] < page1["items"][-1]["seq"]


@pytest.mark.parametrize(
    "params",
    [{"limit": 1000}, {"limit": 0}, {"action": "auth.login' OR 1=1--"}, {"result": "anything"}],
)
def test_audit_query_parameters_validated(
    db_app: FastAPI, db_client: TestClient, params: dict[str, object]
) -> None:
    _, token = _admin(db_app)
    assert (
        db_client.get("/api/v1/audit-logs", headers=bearer(token), params=params).status_code == 422
    )


def test_audit_chain_verification_endpoint(db_app: FastAPI, db_client: TestClient) -> None:
    _, token = _admin(db_app)
    create_user(db_app, "bob@example.com")
    login(db_client, "bob@example.com", "wrong password value")
    status = db_client.get("/api/v1/audit-logs/verify", headers=bearer(token)).json()
    assert status["intact"] is True
    assert status["records_checked"] >= 1
    # Verifying is itself audited.
    assert len(audit_entries(db_app, AuditAction.AUDIT_VERIFIED)) == 1


def test_there_is_no_way_to_modify_audit_entries_over_http(
    db_app: FastAPI, db_client: TestClient
) -> None:
    _, token = _admin(db_app)
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = db_client.request(method, "/api/v1/audit-logs", headers=bearer(token), json={})
        assert response.status_code == 405
