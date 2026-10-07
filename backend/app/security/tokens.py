"""Signed access tokens (JWT) and opaque random tokens.

JWT validation pins the algorithm and requires every claim it relies on, which closes the classic
JWT pitfalls: `alg: none`, algorithm confusion, missing expiry, and tokens minted for another
audience or purpose.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

import jwt

from app.core.clock import utcnow
from app.core.config import Settings

ALGORITHM = "HS256"
ISSUER = "sentineledge"
AUDIENCE = "sentineledge-api"
LEEWAY_SECONDS = 10


class TokenType(StrEnum):
    ACCESS = "access"
    MFA_CHALLENGE = "mfa_challenge"


class InvalidTokenError(Exception):
    """The token is malformed, forged, expired, or for another purpose."""


@dataclass(frozen=True)
class TokenClaims:
    subject: uuid.UUID
    session_id: uuid.UUID | None
    token_type: TokenType
    token_id: str
    issued_at: datetime
    expires_at: datetime


class TokenService:
    def __init__(self, settings: Settings) -> None:
        signing_key, _ = settings.require_auth_secrets()
        self._key = signing_key.get_secret_value()
        self._access_ttl = timedelta(seconds=settings.access_token_ttl_seconds)
        self._challenge_ttl = timedelta(seconds=settings.mfa_challenge_ttl_seconds)

    @property
    def access_ttl_seconds(self) -> int:
        return int(self._access_ttl.total_seconds())

    def issue_access(self, user_id: uuid.UUID, session_id: uuid.UUID) -> str:
        return self._issue(TokenType.ACCESS, user_id, self._access_ttl, {"sid": str(session_id)})

    def issue_mfa_challenge(self, user_id: uuid.UUID) -> str:
        return self._issue(TokenType.MFA_CHALLENGE, user_id, self._challenge_ttl, {})

    def _issue(
        self, token_type: TokenType, user_id: uuid.UUID, ttl: timedelta, extra: dict[str, str]
    ) -> str:
        now = utcnow()
        claims: dict[str, object] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": str(user_id),
            "typ": token_type.value,
            "jti": secrets.token_urlsafe(16),
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            **extra,
        }
        return jwt.encode(claims, self._key, algorithm=ALGORITHM)

    def decode(self, token: str, expected_type: TokenType) -> TokenClaims:
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=[ALGORITHM],
                audience=AUDIENCE,
                issuer=ISSUER,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "nbf", "sub", "aud", "iss", "typ", "jti"]},
            )
            if claims["typ"] != expected_type.value:
                raise InvalidTokenError("wrong token type")
            session = claims.get("sid")
            if expected_type is TokenType.ACCESS and not session:
                raise InvalidTokenError("access token without session")
            return TokenClaims(
                subject=uuid.UUID(claims["sub"]),
                session_id=uuid.UUID(session) if session else None,
                token_type=expected_type,
                token_id=str(claims["jti"]),
                issued_at=datetime.fromtimestamp(claims["iat"], tz=utcnow().tzinfo),
                expires_at=datetime.fromtimestamp(claims["exp"], tz=utcnow().tzinfo),
            )
        except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
            raise InvalidTokenError(str(exc)) from exc


def new_opaque_token() -> str:
    """256 bits of randomness, URL-safe."""
    return secrets.token_urlsafe(32)


def hash_opaque_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
