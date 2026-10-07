"""Apply rate-limit policies to requests (ADR-0017).

Two checkpoints:

* `enforce_ip_limits` runs on every /api/v1 route BEFORE authentication: a global per-IP
  ceiling, plus the endpoint's own policy when that policy is keyed by IP (sign-in, refresh,
  password recovery, probes). Floods are rejected before any password hashing or token work.
* `enforce_user_limit` runs right AFTER the session is authenticated (called from
  app.core.authz.authenticated_setup) for endpoints whose policy is keyed by account, so the
  limit follows the user across IP addresses.

A denied request gets 429 with Retry-After; allowed requests carry RateLimit-* headers.
"""

from __future__ import annotations

import logging

from fastapi import Request, Response
from sqlalchemy.exc import SQLAlchemyError

from app.core.api_policy import (
    GLOBAL_IP,
    LimitScope,
    RateLimitPolicy,
    endpoint_policy,
    route_template,
)
from app.core.errors import ApiError
from app.core.request_context import request_context
from app.models.user import User
from app.security.rate_limit import Decision, RateLimiter

logger = logging.getLogger("sentineledge.ratelimit")
UNAVAILABLE_RETRY_AFTER_S = 5


def _limiter(request: Request) -> RateLimiter | None:
    limiter: RateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    return limiter if limiter is not None and limiter.enabled else None


def _endpoint_label(request: Request) -> str:
    return f"{request.method} {route_template(request) or request.url.path}"


def _apply(
    request: Request,
    response: Response,
    limiter: RateLimiter,
    policy: RateLimitPolicy,
    subject: str,
    actor: User | str,
) -> Decision | None:
    try:
        decision = limiter.check(policy, subject)
    except SQLAlchemyError:
        # Fail closed, honestly: without the limiter's state the request is refused, as 503
        # (temporarily unavailable, retry shortly) rather than a generic 500.
        logger.exception("rate_limiter_unavailable", extra={"policy": policy.name})
        raise ApiError(
            503,
            "service_unavailable",
            "The service is temporarily unavailable. Please try again shortly.",
            headers={"Retry-After": str(UNAVAILABLE_RETRY_AFTER_S)},
        ) from None
    if decision is None:
        return None
    if not decision.allowed:
        if decision.first_denial:
            limiter.record_denial(
                policy, actor=actor, ctx=request_context(request), endpoint=_endpoint_label(request)
            )
        raise ApiError(
            429,
            "rate_limited",
            "Too many requests. Please wait and try again.",
            headers=decision.headers(),
        )
    for name, value in decision.headers().items():
        response.headers[name] = value
    return decision


def enforce_ip_limits(request: Request, response: Response) -> None:
    limiter = _limiter(request)
    if limiter is None:
        return
    ip = request.client.host if request.client else "unknown"
    subject = f"ip:{ip}"
    _apply(request, response, limiter, GLOBAL_IP, subject, "anonymous")
    policy = endpoint_policy(request)
    if policy is not None and policy.rate_limit.scope is LimitScope.IP:
        _apply(request, response, limiter, policy.rate_limit, subject, "anonymous")


def enforce_user_limit(request: Request, response: Response, user: User) -> None:
    limiter = _limiter(request)
    if limiter is None:
        return
    policy = endpoint_policy(request)
    if policy is not None and policy.rate_limit.scope is LimitScope.USER:
        _apply(request, response, limiter, policy.rate_limit, f"user:{user.id}", user)
