"""User management models. Responses list fields explicitly: secrets cannot leak by accident."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.user import Role
from app.schemas.auth import StrictModel


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    role: Role
    is_active: bool
    mfa_enabled: bool
    must_change_password: bool
    temporary_password_expires_at: datetime | None
    locked: bool
    last_login_at: datetime | None
    created_at: datetime


class UserList(BaseModel):
    items: list[UserOut]


class TemporaryPasswordIssued(BaseModel):
    """Returned once, when an administrator creates an account or resets its password
    (ADR-0028). The password is never stored in plain text and cannot be fetched again."""

    user: UserOut
    temporary_password: str
    expires_at: datetime


class UserCreate(StrictModel):
    email: EmailStr = Field(max_length=254)
    display_name: str = Field(min_length=1, max_length=100)
    role: Role


class UserUpdate(StrictModel):
    """Only these fields can change. Email, password and MFA have their own flows."""

    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    role: Role | None = None
    is_active: bool | None = None
