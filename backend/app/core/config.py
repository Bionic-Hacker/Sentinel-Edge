"""Application configuration.

All configuration comes from environment variables (prefix ``SENTINEL_``). There are no
hardcoded secrets and no insecure defaults: anything that weakens security must be
explicitly enabled, and some options are forcibly disabled outside local/test.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated

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
    app_version: str = Field(default="0.1.0", pattern=r"^\d+\.\d+\.\d+$")
    log_level: LogLevel = LogLevel.INFO
    enable_api_docs: bool = False
    trusted_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"]
    )
    ai_provider: AIProvider = AIProvider.DISABLED
    aws_region: str = Field(default="us-east-1", pattern=r"^[a-z]{2}-[a-z]+-\d$")

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

    @field_validator("trusted_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, value: object) -> object:
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

    @model_validator(mode="after")
    def _enforce_secure_defaults(self) -> Settings:
        if self.is_deployed:
            # Interactive API docs widen the attack surface; never in a deployed environment.
            self.enable_api_docs = False
            if self.log_level is LogLevel.DEBUG:
                raise ValueError("DEBUG logging is not permitted in deployed environments")
            if self.db_sslmode not in VERIFIED_TLS:
                raise ValueError(
                    "deployed environments must verify the database certificate "
                    "(db_sslmode verify-ca or verify-full)"
                )
        if self.environment is Environment.PRODUCTION and self.ai_provider is AIProvider.OFFLINE:
            raise ValueError("the offline AI analyser is a test/demo aid, not for production")
        return self

    @property
    def is_deployed(self) -> bool:
        return self.environment not in NON_DEPLOYED

    def database_url(self, role: DbRole = DbRole.APP) -> URL:
        """Build a SQLAlchemy URL for the given role. The password is never logged: URL's
        string form masks it, and Settings repr masks SecretStr."""
        user, secret = (
            (self.db_user, self.db_password)
            if role is DbRole.APP
            else (self.db_migrator_user, self.db_migrator_password)
        )
        query: dict[str, str] = {
            "sslmode": self.db_sslmode.value,
            "application_name": f"sentineledge-{role.value}",
            "connect_timeout": "5",
        }
        if self.db_sslrootcert:
            query["sslrootcert"] = self.db_sslrootcert
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
