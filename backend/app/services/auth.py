"""Authentication flows (ADR-0003, spec §27).

Every flow commits its own unit of work, including on failure, because failed attempts must be
counted and audited even though the request is refused. Error messages are deliberately uniform:
an attacker learns nothing about whether an account exists, is locked, or is inactive.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.authz import Principal
from app.core.clock import utcnow
from app.core.config import Settings
from app.core.errors import ApiError
from app.models.audit import AuditResult
from app.models.outbox import OutboxMessage
from app.models.session import AuthSession, MfaRecoveryCode, PasswordResetToken, RefreshToken
from app.models.user import User
from app.security.mfa import (
    TOTP_PATTERN,
    MfaService,
    generate_recovery_codes,
    hash_recovery_code,
    normalize_recovery_code,
)
from app.security.passwords import PasswordHasher, PasswordPolicyError, check_password_policy
from app.security.tokens import (
    InvalidTokenError,
    TokenService,
    TokenType,
    hash_opaque_token,
    new_opaque_token,
)
from app.services import audit
from app.services.audit import AuditAction, RequestContext


# Factories, not shared instances: each raise gets a fresh exception (and traceback).
def invalid_credentials() -> ApiError:
    return ApiError(401, "invalid_credentials", "Invalid email or password")


def invalid_mfa() -> ApiError:
    return ApiError(401, "invalid_mfa", "Invalid or expired verification code")


def session_expired() -> ApiError:
    return ApiError(401, "session_expired", "Your session has ended. Sign in again.")


def invalid_reset() -> ApiError:
    return ApiError(400, "invalid_reset_token", "This reset link is invalid or has expired.")


RESET_RATE_LIMIT = timedelta(seconds=60)
_MAX_OPAQUE_TOKEN_LENGTH = 128


@dataclass(frozen=True)
class IssuedSession:
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_max_age: int
    user: User


@dataclass(frozen=True)
class LoginOutcome:
    session: IssuedSession | None = None
    mfa_challenge: str | None = None


def normalize_email(email: str) -> str:
    return email.strip().lower()


class AuthService:
    def __init__(
        self,
        *,
        db: Session,
        settings: Settings,
        tokens: TokenService,
        hasher: PasswordHasher,
        mfa: MfaService,
        ctx: RequestContext,
    ) -> None:
        self.db = db
        self.settings = settings
        self.tokens = tokens
        self.hasher = hasher
        self.mfa = mfa
        self.ctx = ctx

    # --- helpers --------------------------------------------------------------------------

    def _audit(
        self,
        action: AuditAction,
        result: AuditResult,
        actor: User | str | None,
        **details: object,
    ) -> None:
        audit.record(
            self.db,
            action=action,
            result=result,
            actor=actor,
            ctx=self.ctx,
            resource_type="user" if isinstance(actor, User) else None,
            resource_id=str(actor.id) if isinstance(actor, User) else None,
            details=dict(details),
        )

    def _register_failure(self, user: User, action: AuditAction, reason: str) -> None:
        """Count a failed credential check and lock the account at the threshold."""
        user.failed_login_count += 1
        if user.failed_login_count >= self.settings.max_failed_logins:
            user.locked_until = utcnow() + timedelta(seconds=self.settings.lockout_seconds)
            user.failed_login_count = 0
            self._audit(
                AuditAction.ACCOUNT_LOCKED,
                AuditResult.DENIED,
                user,
                lockout_seconds=self.settings.lockout_seconds,
            )
        self._audit(action, AuditResult.FAILURE, user, reason=reason)

    def _is_locked(self, user: User) -> bool:
        return user.locked_until is not None and user.locked_until > utcnow()

    def _start_session(self, user: User, *, mfa_verified: bool) -> IssuedSession:
        now = utcnow()
        session = AuthSession(
            user_id=user.id,
            expires_at=now + timedelta(seconds=self.settings.session_max_age_seconds),
            last_used_at=now,
            mfa_verified=mfa_verified,
            created_ip=self.ctx.source_ip,
            user_agent=self.ctx.user_agent,
        )
        self.db.add(session)
        self.db.flush()
        return self._issue_tokens(user, session)

    def _issue_tokens(self, user: User, session: AuthSession) -> IssuedSession:
        now = utcnow()
        raw = new_opaque_token()
        expires_at = min(
            now + timedelta(seconds=self.settings.refresh_token_ttl_seconds), session.expires_at
        )
        self.db.add(
            RefreshToken(
                session_id=session.id, token_hash=hash_opaque_token(raw), expires_at=expires_at
            )
        )
        self.db.flush()
        return IssuedSession(
            access_token=self.tokens.issue_access(user.id, session.id),
            expires_in=self.tokens.access_ttl_seconds,
            refresh_token=raw,
            refresh_max_age=max(int((expires_at - now).total_seconds()), 0),
            user=user,
        )

    def _revoke_sessions(self, user: User, reason: str, keep: uuid.UUID | None = None) -> None:
        query = (
            update(AuthSession)
            .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=utcnow(), revoked_reason=reason)
        )
        if keep is not None:
            query = query.where(AuthSession.id != keep)
        self.db.execute(query)

    def _set_password(self, user: User, new_password: str) -> None:
        try:
            check_password_policy(new_password, email=user.email)
        except PasswordPolicyError as exc:
            raise ApiError(400, "weak_password", str(exc)) from None
        if self.hasher.verify(user.password_hash, new_password):
            raise ApiError(400, "weak_password", "Choose a password you haven't used here.")
        user.password_hash = self.hasher.hash(new_password)
        user.password_changed_at = utcnow()
        user.must_change_password = False
        user.failed_login_count = 0
        user.locked_until = None

    # --- login ----------------------------------------------------------------------------

    def login(self, email: str, password: str) -> LoginOutcome:
        email_n = normalize_email(email)
        # FOR UPDATE: concurrent attempts against one account are counted, not lost.
        user = self.db.scalar(select(User).where(User.email == email_n).with_for_update())

        if user is None or not user.is_active or self._is_locked(user):
            # Same work and same answer whether the account is missing, inactive or locked.
            self.hasher.dummy_verify(password)
            reason = (
                "unknown_account"
                if user is None
                else ("inactive" if not user.is_active else "locked")
            )
            self._audit(
                AuditAction.LOGIN,
                AuditResult.DENIED if reason == "locked" else AuditResult.FAILURE,
                user if user is not None else email_n,
                reason=reason,
            )
            self.db.commit()
            raise invalid_credentials()

        if not self.hasher.verify(user.password_hash, password):
            self._register_failure(user, AuditAction.LOGIN, "bad_password")
            self.db.commit()
            raise invalid_credentials()

        user.failed_login_count = 0
        user.locked_until = None
        if self.hasher.needs_rehash(user.password_hash):
            user.password_hash = self.hasher.hash(password)

        if user.mfa_enabled:
            self._audit(AuditAction.LOGIN, AuditResult.SUCCESS, user, stage="password", mfa=True)
            self.db.commit()
            return LoginOutcome(mfa_challenge=self.tokens.issue_mfa_challenge(user.id))

        issued = self._start_session(user, mfa_verified=False)
        user.last_login_at = utcnow()
        self._audit(AuditAction.LOGIN, AuditResult.SUCCESS, user, stage="complete", mfa=False)
        self.db.commit()
        return LoginOutcome(session=issued)

    def verify_mfa(self, challenge_token: str, code: str) -> IssuedSession:
        try:
            claims = self.tokens.decode(challenge_token, TokenType.MFA_CHALLENGE)
        except InvalidTokenError:
            raise invalid_mfa() from None
        user = self.db.get(User, claims.subject, with_for_update=True)
        if (
            user is None
            or not user.is_active
            or not user.mfa_enabled
            or user.mfa_secret is None
            or self._is_locked(user)
        ):
            self._audit(
                AuditAction.LOGIN_MFA,
                AuditResult.DENIED,
                user if user is not None else "anonymous",
                reason="not_eligible",
            )
            self.db.commit()
            raise invalid_mfa()

        code = code.strip()
        method: str | None = None
        if TOTP_PATTERN.fullmatch(code):
            step = self.mfa.verify_totp(
                self.mfa.decrypt(user.mfa_secret), code, user.mfa_last_used_step
            )
            if step is not None:
                user.mfa_last_used_step = step
                method = "totp"
        elif (recovery := normalize_recovery_code(code)) is not None:
            row = self.db.scalar(
                select(MfaRecoveryCode)
                .where(
                    MfaRecoveryCode.user_id == user.id,
                    MfaRecoveryCode.code_hash == hash_recovery_code(recovery),
                    MfaRecoveryCode.used_at.is_(None),
                )
                .with_for_update()
            )
            if row is not None:
                row.used_at = utcnow()
                method = "recovery_code"

        if method is None:
            self._register_failure(user, AuditAction.LOGIN_MFA, "bad_code")
            self.db.commit()
            raise invalid_mfa()

        user.failed_login_count = 0
        user.last_login_at = utcnow()
        issued = self._start_session(user, mfa_verified=True)
        remaining = len(
            self.db.scalars(
                select(MfaRecoveryCode.id).where(
                    MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.used_at.is_(None)
                )
            ).all()
        )
        self._audit(
            AuditAction.LOGIN_MFA,
            AuditResult.SUCCESS,
            user,
            method=method,
            recovery_codes_remaining=remaining,
        )
        self.db.commit()
        return issued

    # --- sessions -------------------------------------------------------------------------

    def refresh(self, raw_token: str | None) -> IssuedSession:
        if not raw_token or len(raw_token) > _MAX_OPAQUE_TOKEN_LENGTH:
            raise session_expired()
        token = self.db.scalar(
            select(RefreshToken)
            .where(RefreshToken.token_hash == hash_opaque_token(raw_token))
            # Lock only the token row: two concurrent refreshes with the same token serialize,
            # and the second one sees it as already used (reuse) rather than both succeeding.
            .with_for_update(of=RefreshToken)
        )
        if token is None:
            raise session_expired()

        session = token.session
        user = session.user
        now = utcnow()
        if token.used_at is not None:
            # A rotated token came back: either it was stolen, or the legitimate client and an
            # attacker both hold it. We cannot tell which, so end the session for both.
            if session.revoked_at is None:
                session.revoked_at = now
                session.revoked_reason = "refresh_token_reuse"
            self._audit(
                AuditAction.REFRESH_TOKEN_REUSE,
                AuditResult.DENIED,
                user,
                session_id=str(session.id),
            )
            self.db.commit()
            raise session_expired()
        if (
            token.expires_at <= now
            or session.revoked_at is not None
            or session.expires_at <= now
            or not user.is_active
        ):
            raise session_expired()

        token.used_at = now
        session.last_used_at = now
        issued = self._issue_tokens(user, session)
        self.db.commit()
        return issued

    def logout(self, principal: Principal) -> None:
        principal.session.revoked_at = utcnow()
        principal.session.revoked_reason = "logout"
        self._audit(AuditAction.LOGOUT, AuditResult.SUCCESS, principal.user)
        self.db.commit()

    # --- MFA enrollment -------------------------------------------------------------------

    def start_mfa_enrollment(self, principal: Principal) -> tuple[str, str]:
        user = principal.user
        if user.mfa_enabled:
            raise ApiError(409, "mfa_already_enabled", "Two-factor authentication is already on.")
        secret = self.mfa.new_secret()
        user.mfa_pending_secret = self.mfa.encrypt(secret)
        self.db.commit()
        return secret, self.mfa.provisioning_uri(secret, user.email)

    def confirm_mfa_enrollment(self, principal: Principal, code: str) -> list[str]:
        user = self.db.get(User, principal.user.id, with_for_update=True)
        if user is None or user.mfa_pending_secret is None or user.mfa_enabled:
            raise ApiError(409, "no_pending_enrollment", "Start two-factor setup first.")
        secret = self.mfa.decrypt(user.mfa_pending_secret)
        step = self.mfa.verify_totp(secret, code.strip(), None)
        if step is None:
            self._register_failure(user, AuditAction.MFA_ENROLLED, "bad_code")
            self.db.commit()
            raise ApiError(400, "invalid_code", "That code didn't match. Try the current code.")

        user.mfa_secret = user.mfa_pending_secret
        user.mfa_pending_secret = None
        user.mfa_enabled = True
        user.mfa_last_used_step = step
        user.failed_login_count = 0
        self.db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id).delete()
        codes = generate_recovery_codes()
        self.db.add_all(
            MfaRecoveryCode(user_id=user.id, code_hash=hash_recovery_code(c)) for c in codes
        )
        principal.session.mfa_verified = True
        self._audit(AuditAction.MFA_ENROLLED, AuditResult.SUCCESS, user)
        self.db.commit()
        return codes

    # --- passwords ------------------------------------------------------------------------

    def change_password(self, principal: Principal, current: str, new: str) -> None:
        user = self.db.get(User, principal.user.id, with_for_update=True)
        if user is None:
            raise session_expired()
        if not self.hasher.verify(user.password_hash, current):
            self._register_failure(user, AuditAction.PASSWORD_CHANGED, "bad_current_password")
            self.db.commit()
            raise ApiError(400, "current_password_incorrect", "Your current password is wrong.")
        self._set_password(user, new)
        self._revoke_sessions(user, "password_changed", keep=principal.session.id)
        self._audit(AuditAction.PASSWORD_CHANGED, AuditResult.SUCCESS, user)
        self.db.commit()

    def request_password_reset(self, email: str) -> None:
        """Always succeeds from the caller's point of view (no account enumeration)."""
        email_n = normalize_email(email)
        user = self.db.scalar(select(User).where(User.email == email_n))
        if user is None or not user.is_active:
            self._audit(
                AuditAction.PASSWORD_RESET_REQUESTED,
                AuditResult.FAILURE,
                user if user is not None else email_n,
                reason="unknown_account" if user is None else "inactive",
            )
            self.db.commit()
            return

        now = utcnow()
        recent = self.db.scalar(
            select(PasswordResetToken.id).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.created_at > now - RESET_RATE_LIMIT,
            )
        )
        if recent is not None:
            self._audit(
                AuditAction.PASSWORD_RESET_REQUESTED,
                AuditResult.DENIED,
                user,
                reason="rate_limited",
            )
            self.db.commit()
            return

        raw = new_opaque_token()
        self.db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hash_opaque_token(raw),
                expires_at=now + timedelta(seconds=self.settings.password_reset_ttl_seconds),
                requested_ip=self.ctx.source_ip,
            )
        )
        minutes = self.settings.password_reset_ttl_seconds // 60
        # The token travels in the URL fragment: browsers never send fragments to servers, so it
        # stays out of access logs, proxies and Referer headers.
        link = f"{self.settings.canonical_origin}/reset-password#token={raw}"
        self.db.add(
            OutboxMessage(
                recipient=user.email,
                subject="Reset your SentinelEdge password",
                body=(
                    f"Someone asked to reset the password for {user.email}.\n\n"
                    f"Reset it here within {minutes} minutes:\n{link}\n\n"
                    "If this wasn't you, ignore this message: your password is unchanged."
                ),
            )
        )
        self._audit(AuditAction.PASSWORD_RESET_REQUESTED, AuditResult.SUCCESS, user)
        self.db.commit()

    def reset_password(self, raw_token: str, new_password: str) -> None:
        if not raw_token or len(raw_token) > _MAX_OPAQUE_TOKEN_LENGTH:
            raise invalid_reset()
        token = self.db.scalar(
            select(PasswordResetToken)
            .where(PasswordResetToken.token_hash == hash_opaque_token(raw_token))
            .with_for_update()
        )
        now = utcnow()
        if token is None or token.used_at is not None or token.expires_at <= now:
            raise invalid_reset()
        user = self.db.get(User, token.user_id, with_for_update=True)
        if user is None or not user.is_active:
            raise invalid_reset()

        self._set_password(user, new_password)
        # Every outstanding reset link for this account dies with this one.
        self.db.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
        )
        self._revoke_sessions(user, "password_reset")
        self._audit(AuditAction.PASSWORD_RESET, AuditResult.SUCCESS, user)
        self.db.commit()
