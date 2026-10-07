"""Test helpers: create users directly, sign in through the real API, read the audit log."""

from __future__ import annotations

from typing import Any

import pyotp
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.outbox import OutboxMessage
from app.models.user import Role, User
from app.security.passwords import PasswordHasher

DEFAULT_PASSWORD = "correct horse battery staple 42"


def create_user(
    app: FastAPI,
    email: str = "analyst@example.com",
    *,
    password: str = DEFAULT_PASSWORD,
    role: Role = Role.ANALYST,
    **fields: Any,
) -> User:
    hasher: PasswordHasher = app.state.hasher
    with app.state.session_factory() as db:
        user = User(
            email=email,
            display_name=email.split("@")[0].title(),
            role=role,
            password_hash=hasher.hash(password),
            **fields,
        )
        db.add(user)
        db.commit()
        return user


def login(client: TestClient, email: str, password: str = DEFAULT_PASSWORD) -> Any:
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def access_token(client: TestClient, email: str, password: str = DEFAULT_PASSWORD) -> str:
    response = login(client, email, password)
    assert response.status_code == 200, response.text
    token: str = response.json()["access_token"]
    return token


def enroll_mfa(client: TestClient, token: str) -> tuple[str, list[str]]:
    """Enroll TOTP through the API; returns (secret, recovery codes)."""
    start = client.post("/api/v1/auth/mfa/enroll", headers=bearer(token))
    assert start.status_code == 200, start.text
    secret: str = start.json()["secret"]
    confirm = client.post(
        "/api/v1/auth/mfa/enroll/confirm",
        headers=bearer(token),
        json={"code": pyotp.TOTP(secret).now()},
    )
    assert confirm.status_code == 200, confirm.text
    return secret, confirm.json()["recovery_codes"]


def audit_entries(app: FastAPI, action: str | None = None) -> list[AuditLog]:
    with app.state.session_factory() as db:
        query = select(AuditLog).order_by(AuditLog.seq)
        if action is not None:
            query = query.where(AuditLog.action == action)
        return list(db.scalars(query).all())


def outbox(app: FastAPI) -> list[OutboxMessage]:
    with app.state.session_factory() as db:
        return list(db.scalars(select(OutboxMessage).order_by(OutboxMessage.created_at)).all())


def get_user(app: FastAPI, email: str) -> User:
    with app.state.session_factory() as db:
        user = db.scalar(select(User).where(User.email == email))
        assert user is not None
        return user
