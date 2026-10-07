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
    locked: bool
    last_login_at: datetime | None
    created_at: datetime


class UserList(BaseModel):
    items: list[UserOut]


class UserCreate(StrictModel):
    email: EmailStr = Field(max_length=254)
    display_name: str = Field(min_length=1, max_length=100)
    role: Role


class UserUpdate(StrictModel):
    """Only these fields can change. Email, password and MFA have their own flows."""

    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    role: Role | None = None
    is_active: bool | None = None
