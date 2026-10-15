"""Signing-key rotation (Phase 12): tokens carry a key ID; the old key verifies, never signs."""

from __future__ import annotations

import uuid

import jwt
import pytest
from pydantic import SecretStr, ValidationError

from app.security.tokens import InvalidTokenError, TokenService, TokenType, key_id
from tests.conftest import make_settings

OLD = "o" * 48
NEW = "n" * 48
USER, SESSION = uuid.uuid4(), uuid.uuid4()


def service(current: str, previous: str | None = None) -> TokenService:
    return TokenService(
        make_settings(
            jwt_signing_key=SecretStr(current),
            jwt_previous_signing_key=SecretStr(previous) if previous else None,
        )
    )


def test_tokens_name_their_signing_key() -> None:
    token = service(NEW).issue_access(USER, SESSION)
    assert jwt.get_unverified_header(token)["kid"] == key_id(NEW)
    assert NEW not in key_id(NEW)  # the ID reveals nothing of the key


def test_a_rotation_keeps_tokens_signed_with_the_previous_key_valid() -> None:
    before = service(OLD).issue_access(USER, SESSION)
    rotated = service(NEW, previous=OLD)
    assert rotated.decode(before, TokenType.ACCESS).subject == USER
    # New tokens are signed with the new key only.
    after = rotated.issue_access(USER, SESSION)
    assert jwt.get_unverified_header(after)["kid"] == key_id(NEW)


def test_once_the_previous_key_is_removed_its_tokens_stop_working() -> None:
    before = service(OLD).issue_access(USER, SESSION)
    with pytest.raises(InvalidTokenError):
        service(NEW).decode(before, TokenType.ACCESS)


def test_an_unknown_key_id_is_refused_even_with_a_valid_signature() -> None:
    token = service(OLD).issue_access(USER, SESSION)
    forged = jwt.encode(
        jwt.decode(token, options={"verify_signature": False}),
        NEW,
        algorithm="HS256",
        headers={"kid": "0123456789abcdef"},
    )
    with pytest.raises(InvalidTokenError):
        service(NEW).decode(forged, TokenType.ACCESS)


def test_a_token_without_a_key_id_verifies_only_with_the_current_key() -> None:
    claims = jwt.decode(
        service(NEW).issue_access(USER, SESSION), options={"verify_signature": False}
    )
    legacy_current = jwt.encode(claims, NEW, algorithm="HS256")
    legacy_previous = jwt.encode(claims, OLD, algorithm="HS256")
    rotated = service(NEW, previous=OLD)
    assert rotated.decode(legacy_current, TokenType.ACCESS).subject == USER
    with pytest.raises(InvalidTokenError):
        rotated.decode(legacy_previous, TokenType.ACCESS)


def test_a_short_previous_key_is_refused() -> None:
    with pytest.raises(ValidationError):
        make_settings(jwt_previous_signing_key=SecretStr("short"))
