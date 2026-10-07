"""Authentication request and response models.

Requests reject unknown fields (mass assignment, ADR-0012) and bound every string, including
passwords: Argon2 cost grows with input length, so an unbounded password is a denial-of-service
vector.
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.authz import PendingStep
from app.models.user import Role


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class LoginRequest(StrictModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=1, max_length=128)


class MfaVerifyRequest(StrictModel):
    challenge_token: str = Field(min_length=1, max_length=2048)
    code: str = Field(min_length=6, max_length=32)


class MfaCodeRequest(StrictModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


class PasswordChangeRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=1024)


class PasswordForgotRequest(StrictModel):
    email: EmailStr = Field(max_length=254)


class PasswordResetRequest(StrictModel):
    token: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=1024)


class UserProfile(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    role: Role
    mfa_enabled: bool
    pending_steps: list[PendingStep]


class AuthenticatedResponse(BaseModel):
    status: Literal["authenticated"] = "authenticated"
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int
    user: UserProfile


class MfaRequiredResponse(BaseModel):
    status: Literal["mfa_required"] = "mfa_required"
    challenge_token: str
    expires_in: int


class MfaEnrollmentStartResponse(BaseModel):
    secret: str
    otpauth_uri: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class AcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"
