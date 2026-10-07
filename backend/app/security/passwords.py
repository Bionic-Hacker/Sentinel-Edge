"""Password hashing (Argon2id) and password policy (NIST SP 800-63B).

Policy follows NIST guidance: a length floor, a length ceiling, and a check against known-bad
passwords, but no composition rules ("one symbol, one digit"), which push people toward
predictable patterns without adding real strength.
"""

from __future__ import annotations

from argon2 import PasswordHasher as _Argon2
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings

MIN_LENGTH = 12
# Bounds the work an attacker can force per request: Argon2 cost grows with input size.
MAX_LENGTH = 128

# Long-but-predictable passwords that satisfy the length rule. Short common passwords are already
# rejected by MIN_LENGTH. A breached-password lookup (k-anonymity range API) is a candidate
# hardening item for Phase 12; this list keeps the check offline and deterministic.
_COMMON = frozenset(
    {
        "password1234",
        "password12345",
        "password123456",
        "passwordpassword",
        "123456789012",
        "1234567890123",
        "12345678901234",
        "123456123456",
        "qwertyuiop123",
        "qwertyuiopasdf",
        "qwerty123456",
        "1q2w3e4r5t6y",
        "iloveyou1234",
        "letmein12345",
        "welcome12345",
        "welcome123456",
        "administrator",
        "administrator1",
        "adminadmin123",
        "changeme1234",
        "trustno1trustno1",
        "football1234",
        "baseball1234",
        "superman1234",
        "abcdefghijkl",
        "abcdefgh1234",
        "aaaaaaaaaaaa",
        "000000000000",
        "111111111111",
        "monkey123456",
        "dragon123456",
        "sunshine1234",
        "princess1234",
        "starwars1234",
        "passw0rd1234",
        "p@ssw0rd1234",
        "sentineledge",
        "sentineledge1",
        "sentineledge123",
        "securitysecurity",
    }
)


class PasswordPolicyError(ValueError):
    """Raised with a message that is safe to show the user."""


def check_password_policy(password: str, *, email: str) -> None:
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"Use at least {MIN_LENGTH} characters.")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"Use at most {MAX_LENGTH} characters.")
    lowered = password.lower()
    if lowered in _COMMON:
        raise PasswordPolicyError("This password is too common. Choose a less predictable one.")
    if len(set(password)) < 4:
        raise PasswordPolicyError("Use a wider range of characters.")
    local_part = email.split("@", 1)[0].lower()
    if len(local_part) >= 4 and local_part in lowered:
        raise PasswordPolicyError("Don't include your email address in your password.")


class PasswordHasher:
    """Argon2id with configured cost, plus a constant-work dummy verify for unknown accounts."""

    def __init__(self, settings: Settings) -> None:
        self._argon = _Argon2(
            time_cost=settings.password_hash_time_cost,
            memory_cost=settings.password_hash_memory_kib,
            parallelism=settings.password_hash_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        # Verifying against this when no account exists makes "no such user" cost the same as
        # "wrong password", so response timing does not reveal which emails are registered.
        self._dummy_hash = self._argon.hash("dummy-password-for-timing-equalisation")

    def hash(self, password: str) -> str:
        return self._argon.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self._argon.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, password_hash: str) -> bool:
        return self._argon.check_needs_rehash(password_hash)

    def dummy_verify(self, password: str) -> None:
        self.verify(self._dummy_hash, password)
