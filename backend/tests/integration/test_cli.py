"""Operator CLI: first admin with no default credentials, outbox, audit verification."""

from __future__ import annotations

import io
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.cli import main
from app.services.audit import AuditAction
from tests.conftest import make_settings
from tests.helpers import audit_entries, bearer, create_user, get_user, login

pytestmark = [pytest.mark.security, pytest.mark.db]


def _run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), settings=make_settings(), out=out)
    return code, out.getvalue()


def test_create_admin_prints_one_time_password_and_forces_setup(
    db_app: FastAPI, db_client: TestClient
) -> None:
    code, output = _run("create-admin", "--email", "Admin@Example.com")
    assert code == 0
    password = re.search(r"One-time password: (\S+)", output)
    assert password

    user = get_user(db_app, "admin@example.com")
    assert user.role == "ADMIN"
    assert user.must_change_password
    assert password.group(1) not in user.password_hash

    token = login(db_client, "admin@example.com", password.group(1)).json()["access_token"]
    me = db_client.get("/api/v1/auth/me", headers=bearer(token)).json()
    assert me["pending_steps"] == ["mfa_enrollment", "password_change"]

    (entry,) = audit_entries(db_app, AuditAction.USER_CREATED)
    assert entry.actor_label == "system:cli"
    assert entry.details == {"email": "admin@example.com", "role": "ADMIN", "via": "cli"}


def test_create_admin_passwords_are_unique(db_app: FastAPI) -> None:
    _, first = _run("create-admin", "--email", "a1@example.com")
    _, second = _run("create-admin", "--email", "a2@example.com")
    assert (
        first.split("One-time password: ")[1].split()[0]
        != second.split("One-time password: ")[1].split()[0]
    )


def test_create_admin_refuses_duplicates_and_bad_email(db_app: FastAPI) -> None:
    create_user(db_app, "admin@example.com")
    assert _run("create-admin", "--email", "admin@example.com")[0] == 1
    assert _run("create-admin", "--email", "not-an-email")[0] == 2


def test_outbox_shows_reset_messages(db_app: FastAPI, db_client: TestClient) -> None:
    assert "empty" in _run("outbox")[1]
    create_user(db_app, "analyst@example.com")
    db_client.post("/api/v1/auth/password/forgot", json={"email": "analyst@example.com"})
    code, output = _run("outbox")
    assert code == 0
    assert "Reset your SentinelEdge password" in output
    assert "/reset-password#token=" in output


def test_verify_audit_reports_intact_and_broken(
    db_app: FastAPI, db_client: TestClient, migrator_engine: Engine
) -> None:
    create_user(db_app, "analyst@example.com")
    for _ in range(3):
        login(db_client, "analyst@example.com", "wrong password here")

    code, output = _run("verify-audit")
    assert code == 0
    assert "intact: 3 records" in output

    with migrator_engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE sentinel.audit_log DISABLE TRIGGER audit_log_no_update_delete")
        )
        conn.execute(text("UPDATE sentinel.audit_log SET result = 'success' WHERE seq = 2"))
        conn.execute(
            text("ALTER TABLE sentinel.audit_log ENABLE TRIGGER audit_log_no_update_delete")
        )
    code, output = _run("verify-audit")
    assert code == 1
    assert "BROKEN at record seq=2" in output


def test_prune_rate_limits(db_app: FastAPI, migrator_engine: Engine) -> None:
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO sentinel.rate_limit_buckets "
                "(bucket_key, tokens, updated_at, last_allowed) VALUES "
                "('login|ip:192.0.2.9', 3, now() - interval '3 days', true), "
                "('login|ip:192.0.2.10', 3, now(), true)"
            )
        )
    code, output = _run("prune-rate-limits")
    assert code == 0
    assert output.strip() == "Removed 1 idle rate-limit buckets."
