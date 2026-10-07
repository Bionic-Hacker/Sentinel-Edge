"""Password policy and hashing, JWT handling, TOTP and recovery codes."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pyotp
import pytest

from app.core.clock import utcnow
from app.security.mfa import (
    MfaService,
    generate_recovery_codes,
    hash_recovery_code,
    normalize_recovery_code,
)
from app.security.passwords import (
    MAX_LENGTH,
    MIN_LENGTH,
    PasswordHasher,
    PasswordPolicyError,
    check_password_policy,
)
from app.security.tokens import (
    InvalidTokenError,
    TokenService,
    TokenType,
    hash_opaque_token,
    new_opaque_token,
)
from tests.conftest import make_settings

# --- Password policy (NIST SP 800-63B) ------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [
        "a" * (MIN_LENGTH - 1),
        "x" * (MAX_LENGTH + 1),
        "Password1234",  # on the common list, case-insensitively
        "sentineledge123",
        "abababababababab",  # too few distinct characters
        "my-alice.smith-passphrase",  # contains the email's local part
    ],
)
def test_policy_rejects(password: str) -> None:
    with pytest.raises(PasswordPolicyError):
        check_password_policy(password, email="alice.smith@example.com")


@pytest.mark.parametrize(
    "password", ["correct horse battery staple", "Tr0ub4dor&3-but-longer", "ñandú gris 2026"]
)
def test_policy_accepts_long_varied_passphrases(password: str) -> None:
    check_password_policy(password, email="alice.smith@example.com")


def test_policy_has_no_composition_rules() -> None:
    # All lowercase, no digits or symbols: fine if long and unpredictable (NIST guidance).
    check_password_policy("quiet orchard lantern river", email="bob@example.com")


# --- Password hashing -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def hasher() -> PasswordHasher:
    return PasswordHasher(make_settings())


def test_hash_is_argon2id_and_salted(hasher: PasswordHasher) -> None:
    first, second = hasher.hash("same password here"), hasher.hash("same password here")
    assert first.startswith("$argon2id$")
    assert first != second
    assert "same password" not in first


def test_verify(hasher: PasswordHasher) -> None:
    stored = hasher.hash("right password value")
    assert hasher.verify(stored, "right password value")
    assert not hasher.verify(stored, "wrong password value")
    assert not hasher.verify("not-a-hash", "anything")


def test_rehash_needed_when_cost_increases(hasher: PasswordHasher) -> None:
    stored = hasher.hash("some password value")
    stronger = PasswordHasher(make_settings(password_hash_time_cost=2))
    assert not hasher.needs_rehash(stored)
    assert stronger.needs_rehash(stored)


# --- Tokens ---------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tokens() -> TokenService:
    return TokenService(make_settings())


def test_access_token_round_trip(tokens: TokenService) -> None:
    user, session = uuid.uuid4(), uuid.uuid4()
    claims = tokens.decode(tokens.issue_access(user, session), TokenType.ACCESS)
    assert claims.subject == user
    assert claims.session_id == session
    assert claims.expires_at > utcnow()


def test_token_types_are_not_interchangeable(tokens: TokenService) -> None:
    user = uuid.uuid4()
    with pytest.raises(InvalidTokenError):
        tokens.decode(tokens.issue_mfa_challenge(user), TokenType.ACCESS)
    with pytest.raises(InvalidTokenError):
        tokens.decode(tokens.issue_access(user, uuid.uuid4()), TokenType.MFA_CHALLENGE)


def test_tampered_token_rejected(tokens: TokenService) -> None:
    token = tokens.issue_access(uuid.uuid4(), uuid.uuid4())
    header, payload, signature = token.split(".")
    flipped = signature[:-2] + ("A" if signature[-2] != "A" else "B") + signature[-1]
    with pytest.raises(InvalidTokenError):
        tokens.decode(f"{header}.{payload}.{flipped}", TokenType.ACCESS)


def test_token_from_another_key_rejected(tokens: TokenService) -> None:
    other = TokenService(make_settings(jwt_signing_key="another-signing-key-of-adequate-length!"))
    with pytest.raises(InvalidTokenError):
        tokens.decode(other.issue_access(uuid.uuid4(), uuid.uuid4()), TokenType.ACCESS)


@pytest.mark.parametrize("garbage", ["", "a.b.c", "not even close", "e30.e30.e30"])
def test_garbage_rejected(tokens: TokenService, garbage: str) -> None:
    with pytest.raises(InvalidTokenError):
        tokens.decode(garbage, TokenType.ACCESS)


def test_opaque_tokens_are_long_unique_and_hashed() -> None:
    values = {new_opaque_token() for _ in range(100)}
    assert len(values) == 100
    assert all(len(v) >= 43 for v in values)  # 32 bytes of entropy, base64url
    token = new_opaque_token()
    assert hash_opaque_token(token) == hash_opaque_token(token)
    assert token not in hash_opaque_token(token)


# --- TOTP -----------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def mfa() -> MfaService:
    return MfaService(make_settings())


def test_secret_encryption_round_trip(mfa: MfaService) -> None:
    secret = mfa.new_secret()
    encrypted = mfa.encrypt(secret)
    assert secret.encode() not in encrypted
    assert mfa.decrypt(encrypted) == secret


def test_decrypt_with_wrong_key_fails_closed(mfa: MfaService) -> None:
    from cryptography.fernet import Fernet

    other = MfaService(make_settings(mfa_encryption_key=Fernet.generate_key().decode()))
    with pytest.raises(RuntimeError):
        other.decrypt(mfa.encrypt(mfa.new_secret()))


def test_totp_accepts_drift_of_one_step_only(mfa: MfaService) -> None:
    secret = mfa.new_secret()
    totp = pyotp.TOTP(secret)
    now = utcnow()
    for offset_steps, accepted in [(-2, False), (-1, True), (0, True), (1, True), (2, False)]:
        code = totp.at(now + timedelta(seconds=offset_steps * totp.interval))
        result = mfa.verify_totp(secret, code, None)
        assert (result is not None) is accepted, offset_steps


def test_totp_rejects_steps_at_or_before_last_used(mfa: MfaService) -> None:
    secret = mfa.new_secret()
    code = pyotp.TOTP(secret).now()
    step = mfa.verify_totp(secret, code, None)
    assert step is not None
    assert mfa.verify_totp(secret, code, step) is None


@pytest.mark.parametrize(
    "code", ["", "12345", "1234567", "abcdef", "12 456", "\u0661\u0662\u0663\u0664\u0665\u0666"]
)
def test_totp_rejects_malformed_codes(mfa: MfaService, code: str) -> None:
    assert mfa.verify_totp(mfa.new_secret(), code, None) is None


def test_provisioning_uri_names_issuer_and_account(mfa: MfaService) -> None:
    uri = mfa.provisioning_uri(mfa.new_secret(), "eng@example.com")
    assert uri.startswith("otpauth://totp/SentinelEdge:eng%40example.com?")
    assert "issuer=SentinelEdge" in uri


# --- Recovery codes -------------------------------------------------------------------------


def test_recovery_codes_are_unique_and_well_formed() -> None:
    codes = generate_recovery_codes()
    assert len(set(codes)) == 10
    assert all(normalize_recovery_code(c) == c for c in codes)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(" ABCD-EFGH-IJKL ", "abcd-efgh-ijkl"), ("abcd-efgh-ijk1", None), ("abcdefghijkl", None)],
)
def test_recovery_code_normalization(raw: str, expected: str | None) -> None:
    assert normalize_recovery_code(raw) == expected


def test_recovery_codes_stored_as_hashes() -> None:
    assert hash_recovery_code("abcd-efgh-ijkl") != "abcd-efgh-ijkl"
    assert len(hash_recovery_code("abcd-efgh-ijkl")) == 64
