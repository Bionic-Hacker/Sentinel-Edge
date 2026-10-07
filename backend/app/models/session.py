"""Login sessions, refresh tokens, MFA recovery codes and password-reset tokens.

Opaque tokens (refresh, reset, recovery) are stored only as SHA-256 hashes: they are long random
values, so a fast hash is sufficient, and a database leak does not yield usable tokens.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models._types import created_at, timestamp, uuid_pk
from app.models.user import User


class AuthSession(Base):
    """One login. Its id is the `sid` claim of every access token issued for it, so revoking the
    session revokes those tokens immediately (they are checked against it on every request)."""

    __tablename__ = "auth_sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(User.id), nullable=False, index=True)
    created_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = timestamp(nullable=False)
    last_used_at: Mapped[datetime | None] = timestamp()
    revoked_at: Mapped[datetime | None] = timestamp()
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    mfa_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(256))

    user: Mapped[User] = relationship(lazy="joined", innerjoin=True)


class RefreshToken(Base):
    """A single-use refresh token. Rotated on every use; presenting a used one revokes the whole
    session (refresh-token reuse detection, ADR-0003)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(AuthSession.id), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    issued_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = timestamp(nullable=False)
    used_at: Mapped[datetime | None] = timestamp()

    session: Mapped[AuthSession] = relationship(lazy="joined", innerjoin=True)


class MfaRecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(User.id), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = created_at()
    used_at: Mapped[datetime | None] = timestamp()


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey(User.id), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = timestamp(nullable=False)
    used_at: Mapped[datetime | None] = timestamp()
    requested_ip: Mapped[str | None] = mapped_column(String(45))
