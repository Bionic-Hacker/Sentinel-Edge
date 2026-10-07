"""Authentication endpoints (ADR-0003).

Cookie-bearing endpoints (anything that sets or reads the refresh cookie, and the public flows
around it) require a same-origin request: an allowed `Origin` header plus a custom header that
cross-site forms cannot send. The refresh cookie is `__Host-` prefixed, HttpOnly, Secure and
SameSite=Strict, so browsers never send it cross-site in the first place.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from app.core.authz import Principal, authenticated_setup, pending_steps, public_endpoint
from app.core.config import Settings
from app.core.deps import app_settings, mfa_service, password_hasher, token_service
from app.core.errors import ApiError
from app.core.request_context import request_context
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    AcceptedResponse,
    AuthenticatedResponse,
    LoginRequest,
    MfaCodeRequest,
    MfaEnrollmentStartResponse,
    MfaRequiredResponse,
    MfaVerifyRequest,
    PasswordChangeRequest,
    PasswordForgotRequest,
    PasswordResetRequest,
    RecoveryCodesResponse,
    UserProfile,
)
from app.security.mfa import MfaService
from app.security.passwords import PasswordHasher
from app.security.tokens import TokenService
from app.services.auth import AuthService, IssuedSession

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "__Host-sentinel_refresh"
CSRF_HEADER = "X-SentinelEdge-CSRF"


def get_auth_service(
    request: Request,
    db: Session = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(app_settings),  # noqa: B008
    tokens: TokenService = Depends(token_service),  # noqa: B008
    hasher: PasswordHasher = Depends(password_hasher),  # noqa: B008
    mfa: MfaService = Depends(mfa_service),  # noqa: B008
) -> AuthService:
    return AuthService(
        db=db,
        settings=settings,
        tokens=tokens,
        hasher=hasher,
        mfa=mfa,
        ctx=request_context(request),
    )


def require_same_origin(
    request: Request,
    settings: Settings = Depends(app_settings),  # noqa: B008
) -> None:
    """CSRF defense for cookie-authenticated and session-creating endpoints."""
    if (
        request.headers.get("origin") not in settings.public_origins
        or request.headers.get(CSRF_HEADER) != "1"
    ):
        raise ApiError(403, "csrf_rejected", "Request origin not allowed")


def user_profile(user: User) -> UserProfile:
    return UserProfile(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        mfa_enabled=user.mfa_enabled,
        pending_steps=sorted(pending_steps(user)),
    )


def _authenticated(response: Response, issued: IssuedSession) -> AuthenticatedResponse:
    response.set_cookie(
        REFRESH_COOKIE,
        issued.refresh_token,
        max_age=issued.refresh_max_age,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    return AuthenticatedResponse(
        access_token=issued.access_token,
        expires_in=issued.expires_in,
        user=user_profile(issued.user),
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path="/", secure=True, httponly=True, samesite="strict")


SameOrigin = [Depends(public_endpoint), Depends(require_same_origin)]


@router.post(
    "/login",
    response_model=AuthenticatedResponse | MfaRequiredResponse,
    dependencies=SameOrigin,
)
def login(
    body: LoginRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),  # noqa: B008
    settings: Settings = Depends(app_settings),  # noqa: B008
) -> AuthenticatedResponse | MfaRequiredResponse:
    outcome = service.login(body.email, body.password)
    if outcome.mfa_challenge is not None:
        return MfaRequiredResponse(
            challenge_token=outcome.mfa_challenge, expires_in=settings.mfa_challenge_ttl_seconds
        )
    if outcome.session is None:  # not `assert`: asserts vanish under python -O
        raise RuntimeError("login produced neither a session nor an MFA challenge")
    return _authenticated(response, outcome.session)


@router.post("/mfa/verify", response_model=AuthenticatedResponse, dependencies=SameOrigin)
def verify_mfa(
    body: MfaVerifyRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> AuthenticatedResponse:
    return _authenticated(response, service.verify_mfa(body.challenge_token, body.code))


@router.post("/refresh", response_model=AuthenticatedResponse, dependencies=SameOrigin)
def refresh(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> AuthenticatedResponse:
    try:
        return _authenticated(response, service.refresh(request.cookies.get(REFRESH_COOKIE)))
    except ApiError as exc:
        # A dead refresh cookie should not linger in the browser.
        exc.headers["Set-Cookie"] = (
            f"{REFRESH_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=strict"
        )
        raise


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    principal: Principal = Depends(authenticated_setup),  # noqa: B008
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> None:
    service.logout(principal)
    _clear_refresh_cookie(response)


@router.get("/me", response_model=UserProfile)
def me(principal: Principal = Depends(authenticated_setup)) -> UserProfile:  # noqa: B008
    return user_profile(principal.user)


@router.post("/mfa/enroll", response_model=MfaEnrollmentStartResponse)
def start_mfa_enrollment(
    principal: Principal = Depends(authenticated_setup),  # noqa: B008
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> MfaEnrollmentStartResponse:
    secret, uri = service.start_mfa_enrollment(principal)
    return MfaEnrollmentStartResponse(secret=secret, otpauth_uri=uri)


@router.post("/mfa/enroll/confirm", response_model=RecoveryCodesResponse)
def confirm_mfa_enrollment(
    body: MfaCodeRequest,
    principal: Principal = Depends(authenticated_setup),  # noqa: B008
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> RecoveryCodesResponse:
    return RecoveryCodesResponse(
        recovery_codes=service.confirm_mfa_enrollment(principal, body.code)
    )


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChangeRequest,
    principal: Principal = Depends(authenticated_setup),  # noqa: B008
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> None:
    service.change_password(principal, body.current_password, body.new_password)


@router.post(
    "/password/forgot",
    response_model=AcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=SameOrigin,
)
def forgot_password(
    body: PasswordForgotRequest,
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> AcceptedResponse:
    service.request_password_reset(body.email)
    return AcceptedResponse()


@router.post("/password/reset", status_code=status.HTTP_204_NO_CONTENT, dependencies=SameOrigin)
def reset_password(
    body: PasswordResetRequest,
    response: Response,
    service: AuthService = Depends(get_auth_service),  # noqa: B008
) -> None:
    service.reset_password(body.token, body.new_password)
    _clear_refresh_cookie(response)
