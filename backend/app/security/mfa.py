"""TOTP multi-factor authentication (RFC 6238) and recovery codes.

- Secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256) using a key held outside
  the database, so a database dump alone does not yield working second factors.
- A code is accepted for the current 30-second step or one step either side (clock drift), and
  only if its step is newer than the last one accepted, so codes cannot be replayed.
- Recovery codes are single-use, high-entropy, and stored only as hashes.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from app.core.clock import utcnow
from app.core.config import Settings

ISSUER_NAME = "SentinelEdge"
# [0-9], not \d: in Python \d also matches non-ASCII digits (e.g. Arabic-Indic), which would pass
# validation and then crash hmac.compare_digest. Found by test_totp_rejects_malformed_codes.
TOTP_PATTERN = re.compile(r"^[0-9]{6}$")
RECOVERY_PATTERN = re.compile(r"^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$")
RECOVERY_CODE_COUNT = 10
_ALLOWED_DRIFT_STEPS = 1


class MfaService:
    def __init__(self, settings: Settings) -> None:
        _, encryption_key = settings.require_auth_secrets()
        self._fernet = Fernet(encryption_key.get_secret_value().encode())

    @staticmethod
    def new_secret() -> str:
        return pyotp.random_base32()

    def encrypt(self, secret: str) -> bytes:
        return self._fernet.encrypt(secret.encode())

    def decrypt(self, token: bytes) -> str:
        try:
            return self._fernet.decrypt(token).decode()
        except InvalidToken as exc:
            # Wrong key or tampered ciphertext: never fall back to accepting the code.
            raise RuntimeError("MFA secret could not be decrypted") from exc

    @staticmethod
    def provisioning_uri(secret: str, email: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER_NAME)

    @staticmethod
    def verify_totp(secret: str, code: str, last_used_step: int | None) -> int | None:
        """Return the accepted time-step, or None. Constant-time comparison per candidate."""
        if not TOTP_PATTERN.fullmatch(code):
            return None
        totp = pyotp.TOTP(secret)
        current = totp.timecode(utcnow())
        for offset in range(-_ALLOWED_DRIFT_STEPS, _ALLOWED_DRIFT_STEPS + 1):
            step = current + offset
            if last_used_step is not None and step <= last_used_step:
                continue
            if hmac.compare_digest(totp.generate_otp(step), code):
                return step
        return None


def generate_recovery_codes() -> list[str]:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(alphabet) for _ in range(12))  # 60 bits each
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes


def normalize_recovery_code(code: str) -> str | None:
    normalized = code.strip().lower()
    return normalized if RECOVERY_PATTERN.fullmatch(normalized) else None


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()
