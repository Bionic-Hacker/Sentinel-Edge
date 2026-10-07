"""Application configuration.

All configuration comes from environment variables (prefix ``SENTINEL_``). There are no
hardcoded secrets and no insecure defaults: anything that weakens security must be
explicitly enabled, and some options are forcibly disabled outside local/test.
"""

from __future__ import annotations

import re
from enum import StrEnum
from functools import lru_cache
from typing import Annotated

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy.engine import URL


class Environment(StrEnum):
    LOCAL = "local"
    TEST = "test"
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class AIProvider(StrEnum):
    """AI provider selection. Amazon Bedrock is the selected provider (ADR-0006).

    Phase 1 ships no AI integration; the setting exists so the decision is explicit
    and validated from day one.
    """

    DISABLED = "disabled"
    OFFLINE = "offline"  # deterministic, local-only analyser for tests/demo (Phase 9)
    BEDROCK = "bedrock"  # Amazon Bedrock via ECS task role (Phase 9)


class DbSslMode(StrEnum):
    DISABLE = "disable"
    PREFER = "prefer"
    REQUIRE = "require"
    VERIFY_CA = "verify-ca"
    VERIFY_FULL = "verify-full"


class DbRole(StrEnum):
    """Which database identity a connection uses (ADR-0015)."""

    APP = "app"  # runtime API: per-table grants only
    MIGRATOR = "migrator"  # schema owner: Alembic migrations only


NON_DEPLOYED = frozenset({Environment.LOCAL, Environment.TEST})
# Deployed environments must verify the server certificate, not merely encrypt (T-DB-04).
VERIFIED_TLS = frozenset({DbSslMode.VERIFY_CA, DbSslMode.VERIFY_FULL})
_IDENTIFIER = r"^[a-z_][a-z0-9_]{0,62}$"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", extra="ignore")

    environment: Environment = Environment.LOCAL
    app_version: str = Field(default="0.2.0", pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    log_level: LogLevel = LogLevel.INFO
    enable_api_docs: bool = False
    trusted_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"]
    )
    ai_provider: AIProvider = AIProvider.DISABLED
    aws_region: str = Field(default="us-east-1", pattern=r"^[a-z]{2}-[a-z]+-[0-9]$")

    # Database. Supplied as separate fields (not a URL) so that an RDS-managed secret's
    # username/password/host/port/dbname keys map onto them directly in Phase 4, and so that
    # special characters in passwords never need URL-escaping by hand.
    db_host: str = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = Field(default="sentineledge", pattern=_IDENTIFIER)
    db_user: str = Field(default="sentinel_app", pattern=_IDENTIFIER)
    db_password: SecretStr | None = None
    db_migrator_user: str = Field(default="sentinel_migrator", pattern=_IDENTIFIER)
    db_migrator_password: SecretStr | None = None
    db_sslmode: DbSslMode = DbSslMode.PREFER
    db_sslrootcert: str | None = None

    # Authentication (ADR-0003). Keys have no defaults: the API refuses to start without them
    # (see require_auth_secrets), so a forgotten secret can never fall back to a known value.
    jwt_signing_key: SecretStr | None = None
    mfa_encryption_key: SecretStr | None = None  # Fernet key: encrypts TOTP secrets at rest
    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=8 * 3600, ge=300, le=7 * 24 * 3600)
    session_max_age_seconds: int = Field(default=24 * 3600, ge=300, le=30 * 24 * 3600)
    mfa_challenge_ttl_seconds: int = Field(default=300, ge=60, le=900)
    password_reset_ttl_seconds: int = Field(default=1800, ge=300, le=86400)
    invite_ttl_seconds: int = Field(default=72 * 3600, ge=3600, le=7 * 24 * 3600)
    max_failed_logins: int = Field(default=5, ge=3, le=20)
    lockout_seconds: int = Field(default=900, ge=60, le=86400)
    # Argon2id cost. Defaults follow RFC 9106's second recommended profile (64 MiB, t=3, p=4).
    password_hash_memory_kib: int = Field(default=65536, ge=1024)
    password_hash_time_cost: int = Field(default=3, ge=1)
    password_hash_parallelism: int = Field(default=4, ge=1, le=16)
    # Origins allowed to call cookie-authenticated endpoints (CSRF defense) and used to build
    # links in emails. The first entry is the canonical public origin.
    public_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:8080"]
    )

    @field_validator("trusted_hosts", "public_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [h.strip() for h in value.split(",") if h.strip()]
        return value

    @field_validator("trusted_hosts")
    @classmethod
    def _no_wildcard_hosts(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("trusted_hosts must not be empty")
        if any("*" in h for h in value):
            raise ValueError("wildcard trusted hosts are not permitted")
        return value

    @field_validator("public_origins")
    @classmethod
    def _valid_origins(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("public_origins must not be empty")
        for origin in value:
            if not re.fullmatch(r"https?://[a-z0-9.\-]+(:[0-9]{1,5})?", origin):
                raise ValueError(f"invalid origin {origin!r}: expected scheme://host[:port]")
        return value

    @field_validator("jwt_signing_key")
    @classmethod
    def _strong_signing_key(cls, value: SecretStr | None) -> SecretStr | None:
        # HS256 keys must carry at least 256 bits; anything shorter is brute-forceable offline.
        if value is not None and len(value.get_secret_value().encode()) < 32:
            raise ValueError("jwt_signing_key must be at least 32 bytes")
        return value

    @field_validator("mfa_encryption_key")
    @classmethod
    def _valid_fernet_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            try:
                Fernet(value.get_secret_value().encode())
            except ValueError as exc:
                raise ValueError("mfa_encryption_key must be a urlsafe-base64 32-byte key") from exc
        return value

    @model_validator(mode="after")
    def _enforce_secure_defaults(self) -> Settings:
        if self.is_deployed:
            # Interactive API docs widen the attack surface; never in a deployed environment.
            self.enable_api_docs = False
            if self.log_level == LogLevel.DEBUG:
                raise ValueError("DEBUG logging is not permitted in deployed environments")
            if self.db_sslmode not in VERIFIED_TLS:
                raise ValueError(
                    "deployed environments must verify the database certificate "
                    "(db_sslmode verify-ca or verify-full)"
                )
            if any(not o.startswith("https://") for o in self.public_origins):
                raise ValueError("deployed environments must use https public_origins")
            # OWASP password storage minimum for Argon2id: 19 MiB, t=2.
            if self.password_hash_memory_kib < 19456 or self.password_hash_time_cost < 2:
                raise ValueError("password hashing cost is below the deployed minimum")
        if self.environment == Environment.PRODUCTION and self.ai_provider == AIProvider.OFFLINE:
            raise ValueError("the offline AI analyser is a test/demo aid, not for production")
        return self

    @property
    def is_deployed(self) -> bool:
        return self.environment not in NON_DEPLOYED

    @property
    def canonical_origin(self) -> str:
        return self.public_origins[0]

    def require_auth_secrets(self) -> tuple[SecretStr, SecretStr]:
        """Fail closed at start-up if authentication secrets are missing."""
        if self.jwt_signing_key is None or self.mfa_encryption_key is None:
            raise RuntimeError(
                "SENTINEL_JWT_SIGNING_KEY and SENTINEL_MFA_ENCRYPTION_KEY must be set "
                "(run `make env` locally; Secrets Manager when deployed)"
            )
        return self.jwt_signing_key, self.mfa_encryption_key

    def database_url(self, role: DbRole = DbRole.APP) -> URL:
        """Build a SQLAlchemy URL for the given role. The password is never logged: URL's
        string form masks it, and Settings repr masks SecretStr."""
        user, secret = (
            (self.db_user, self.db_password)
            if role == DbRole.APP
            else (self.db_migrator_user, self.db_migrator_password)
        )
        query: dict[str, str] = {
            "sslmode": self.db_sslmode.value,
            "application_name": f"sentineledge-{role.value}",
            "connect_timeout": "5",
        }
        if self.db_sslrootcert:
            query["sslrootcert"] = self.db_sslrootcert
        if role == DbRole.MIGRATOR:
            # Migrations are fully schema-qualified. A neutral search_path, set at connect time,
            # stops Alembic treating `sentinel` as the default schema and reflecting our tables
            # as schema-less (which makes `alembic check` report phantom differences).
            query["options"] = "-c search_path=pg_catalog"
        return URL.create(
            drivername="postgresql+psycopg",
            username=user,
            password=secret.get_secret_value() if secret else None,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
            query=query,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
