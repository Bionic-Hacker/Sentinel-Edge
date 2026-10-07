"""User administration (ADMIN only) and object-level access to user records.

Safety rules enforced here, not just in the UI:
- An administrator cannot demote or deactivate themselves (no accidental self-lockout).
- The last active ADMIN cannot be demoted or deactivated (the platform always has an owner).
- Changing someone's role or deactivating them ends all their sessions immediately.
- Admins never see or set another user's password: new users get a one-time setup link.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.config import Settings
from app.core.errors import ApiError
from app.models.audit import AuditResult
from app.models.outbox import OutboxMessage
from app.models.session import AuthSession, MfaRecoveryCode, PasswordResetToken
from app.models.user import Role, User
from app.schemas.users import UserCreate, UserOut, UserUpdate
from app.security.passwords import PasswordHasher
from app.security.tokens import hash_opaque_token, new_opaque_token
from app.services import audit
from app.services.audit import AuditAction, RequestContext


def not_found() -> ApiError:
    return ApiError(404, "not_found", "Not Found")


def to_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        must_change_password=user.must_change_password,
        locked=user.locked_until is not None and user.locked_until > utcnow(),
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


class UserService:
    def __init__(
        self, *, db: Session, settings: Settings, hasher: PasswordHasher, ctx: RequestContext
    ) -> None:
        self.db = db
        self.settings = settings
        self.hasher = hasher
        self.ctx = ctx

    def _audit(
        self, action: AuditAction, actor: User, target: User | uuid.UUID, **details: object
    ) -> None:
        target_id = target.id if isinstance(target, User) else target
        audit.record(
            self.db,
            action=action,
            result=AuditResult.SUCCESS,
            actor=actor,
            ctx=self.ctx,
            resource_type="user",
            resource_id=str(target_id),
            details=dict(details),
        )

    def _revoke_sessions(self, user: User, reason: str) -> None:
        self.db.execute(
            update(AuthSession)
            .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=utcnow(), revoked_reason=reason)
        )

    def _active_admin_count(self) -> int:
        return (
            self.db.scalar(
                select(func.count())
                .select_from(User)
                .where(User.role == Role.ADMIN, User.is_active)
            )
            or 0
        )

    # --- reads ----------------------------------------------------------------------------

    def list_users(self) -> list[UserOut]:
        return [to_out(u) for u in self.db.scalars(select(User).order_by(User.email)).all()]

    def get_user(self, principal: Principal, user_id: uuid.UUID) -> UserOut:
        """Object-level authorization (OWASP API1): admins see anyone; others see only
        themselves. Anything else is "not found", so IDs of other users cannot be probed."""
        if principal.user.role != Role.ADMIN and principal.user.id != user_id:
            audit.record(
                self.db,
                action=AuditAction.ACCESS_DENIED,
                result=AuditResult.DENIED,
                actor=principal.user,
                ctx=self.ctx,
                resource_type="user",
                resource_id=str(user_id),
                details={"reason": "not_owner"},
            )
            self.db.commit()
            raise not_found()
        user = self.db.get(User, user_id)
        if user is None:
            raise not_found()
        return to_out(user)

    # --- writes ---------------------------------------------------------------------------

    def create_user(self, principal: Principal, body: UserCreate) -> UserOut:
        email = str(body.email).strip().lower()
        if self.db.scalar(select(User.id).where(User.email == email)) is not None:
            raise ApiError(409, "email_in_use", "A user with this email already exists.")
        user = User(
            email=email,
            display_name=body.display_name,
            role=body.role,
            # Unusable until the invitee sets their own: nobody, including the admin, knows it.
            password_hash=self.hasher.hash(secrets.token_urlsafe(32)),
        )
        self.db.add(user)
        self.db.flush()

        raw = new_opaque_token()
        self.db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hash_opaque_token(raw),
                expires_at=utcnow() + timedelta(seconds=self.settings.invite_ttl_seconds),
                requested_ip=self.ctx.source_ip,
            )
        )
        hours = self.settings.invite_ttl_seconds // 3600
        self.db.add(
            OutboxMessage(
                recipient=email,
                subject="You've been invited to SentinelEdge",
                body=(
                    f"{principal.user.display_name} added you to SentinelEdge as "
                    f"{body.role.value}.\n\nSet your password within {hours} hours:\n"
                    f"{self.settings.canonical_origin}/reset-password#token={raw}\n"
                ),
            )
        )
        self._audit(AuditAction.USER_CREATED, principal.user, user, email=email, role=body.role)
        self.db.commit()
        return to_out(user)

    def update_user(self, principal: Principal, user_id: uuid.UUID, body: UserUpdate) -> UserOut:
        user = self.db.get(User, user_id, with_for_update=True)
        if user is None:
            raise not_found()
        changes = body.model_dump(exclude_none=True)
        if not changes:
            return to_out(user)

        is_self = user.id == principal.user.id
        demoting = "role" in changes and changes["role"] != user.role
        deactivating = changes.get("is_active") is False and user.is_active
        if is_self and (demoting or deactivating):
            raise ApiError(409, "self_lockout", "You can't remove your own administrator access.")
        if (
            user.role == Role.ADMIN
            and (demoting or deactivating)
            and self._active_admin_count() <= 1
        ):
            raise ApiError(409, "last_admin", "At least one active administrator must remain.")

        before = {k: getattr(user, k) for k in changes}
        for key, value in changes.items():
            setattr(user, key, value)
        if demoting or deactivating:
            self._revoke_sessions(user, "role_changed" if demoting else "deactivated")
        self._audit(
            AuditAction.USER_UPDATED,
            principal.user,
            user,
            before={k: str(v) for k, v in before.items()},
            after={k: str(v) for k, v in changes.items()},
        )
        self.db.commit()
        return to_out(user)

    def reset_mfa(self, principal: Principal, user_id: uuid.UUID) -> UserOut:
        """For a user who lost their authenticator and recovery codes. They must re-enroll."""
        if user_id == principal.user.id:
            raise ApiError(409, "self_mfa_reset", "Use one of your recovery codes instead.")
        user = self.db.get(User, user_id, with_for_update=True)
        if user is None:
            raise not_found()
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_pending_secret = None
        user.mfa_last_used_step = None
        self.db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
        self._revoke_sessions(user, "mfa_reset")
        self._audit(AuditAction.USER_MFA_RESET, principal.user, user)
        self.db.commit()
        return to_out(user)
