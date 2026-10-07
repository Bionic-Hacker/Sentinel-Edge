"""Authentication and authorization dependencies (ADR-0003, spec §27-28).

Every route declares exactly one of:
  * ``Depends(public_endpoint)``      — intentionally reachable without a session;
  * ``Depends(authenticated_setup)``  — any signed-in user, even mid-setup (finish-setup flows);
  * ``Depends(require_roles(...))``   — signed-in, setup complete, and one of the listed roles.
A test walks the route table and fails if any route declares none of these (M3).

The access token only *identifies* the caller. On every request the session is loaded and checked
(revocation is immediate) and the role is read from the database (role changes apply at once).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from fastapi import Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.api_policy import route_template
from app.core.clock import utcnow
from app.core.deps import token_service
from app.core.errors import ApiError
from app.core.rate_limiting import enforce_user_limit
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.audit import AuditResult
from app.models.session import AuthSession
from app.models.user import ROLES_REQUIRING_MFA, Role, User
from app.security.tokens import InvalidTokenError, TokenService, TokenType
from app.services import audit

_BEARER = re.compile(r"^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$")


class PendingStep(StrEnum):
    PASSWORD_CHANGE = "password_change"  # noqa: S105 - step name, not a secret  # nosec B105
    MFA_ENROLLMENT = "mfa_enrollment"


@dataclass(frozen=True)
class Principal:
    user: User
    session: AuthSession
    pending: frozenset[PendingStep]


def pending_steps(user: User) -> frozenset[PendingStep]:
    """Setup the account must finish before it can use anything beyond the setup endpoints."""
    pending: set[PendingStep] = set()
    if user.must_change_password:
        pending.add(PendingStep.PASSWORD_CHANGE)
    if user.role in ROLES_REQUIRING_MFA and not user.mfa_enabled:
        pending.add(PendingStep.MFA_ENROLLMENT)
    return frozenset(pending)


def unauthorized() -> ApiError:
    return ApiError(
        401, "unauthorized", "Authentication required", headers={"WWW-Authenticate": "Bearer"}
    )


def public_endpoint() -> None:
    """Marker dependency: this route is deliberately reachable without authentication."""


def authenticated_setup(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),  # noqa: B008
    tokens: TokenService = Depends(token_service),  # noqa: B008
) -> Principal:
    """Any valid session, including one that still has setup steps pending."""
    match = _BEARER.fullmatch(request.headers.get("authorization", ""))
    if not match:
        raise unauthorized()
    try:
        claims = tokens.decode(match.group(1), TokenType.ACCESS)
    except InvalidTokenError:
        raise unauthorized() from None

    session = db.get(AuthSession, claims.session_id)
    now = utcnow()
    if (
        session is None
        or session.revoked_at is not None
        or session.expires_at <= now
        or session.user_id != claims.subject
    ):
        raise unauthorized()
    user = session.user
    if not user.is_active or (user.mfa_enabled and not session.mfa_verified):
        raise unauthorized()

    # Per-account rate limit (ADR-0017): after authentication, so it follows the user.
    enforce_user_limit(request, response, user)
    return Principal(user=user, session=session, pending=pending_steps(user))


def require_roles(*roles: Role) -> Callable[..., Principal]:
    """Dependency factory: signed in, setup complete, and holding one of `roles`."""
    allowed = frozenset(roles)
    if not allowed:
        raise ValueError("require_roles needs at least one role")

    def dependency(
        request: Request,
        principal: Principal = Depends(authenticated_setup),  # noqa: B008
        db: Session = Depends(get_db),  # noqa: B008
    ) -> Principal:
        if principal.pending:
            steps = ", ".join(sorted(step.value for step in principal.pending))
            raise ApiError(403, "setup_required", f"Complete account setup first: {steps}")
        if principal.user.role not in allowed:
            audit.record(
                db,
                action=audit.AuditAction.ACCESS_DENIED,
                result=AuditResult.DENIED,
                actor=principal.user,
                ctx=request_context(request),
                resource_type="endpoint",
                # Full template ("/api/v1/users/{user_id}"), not the router-relative path.
                resource_id=f"{request.method} {route_template(request) or request.url.path}",
                details={"role": principal.user.role, "required": sorted(allowed)},
            )
            db.commit()
            raise ApiError(403, "forbidden", "You do not have permission to perform this action")
        return principal

    dependency.allowed_roles = allowed  # type: ignore[attr-defined]  # read by the route audit
    return dependency


# Convenience: every role, setup complete.
any_role = require_roles(*Role)
