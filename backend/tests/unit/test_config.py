"""Secure-by-default configuration (spec §46)."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import AIProvider, DbRole, Environment, LogLevel, Settings
from app.main import create_app
from tests.conftest import TEST_JWT_KEY, TEST_MFA_KEY, make_settings

# The minimum a deployed environment accepts; tests prove anything weaker is refused.
DEPLOYABLE: dict[str, object] = {
    "db_sslmode": "verify-full",
    "public_origins": ["https://sentineledge.example.com"],
    "password_hash_memory_kib": 19456,
    "password_hash_time_cost": 2,
}


def test_defaults_are_secure() -> None:
    s = Settings()
    assert s.enable_api_docs is False
    assert s.ai_provider is AIProvider.DISABLED
    assert "*" not in s.trusted_hosts


@pytest.mark.parametrize("env", [Environment.DEV, Environment.STAGING, Environment.PRODUCTION])
def test_api_docs_forced_off_when_deployed(env: Environment) -> None:
    s = make_settings(environment=env, enable_api_docs=True, **DEPLOYABLE)
    assert s.enable_api_docs is False
    client = TestClient(create_app(s))
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_api_docs_available_locally_when_enabled() -> None:
    s = make_settings(environment=Environment.LOCAL, enable_api_docs=True)
    assert TestClient(create_app(s)).get("/api/openapi.json").status_code == 200


def test_debug_logging_rejected_when_deployed() -> None:
    with pytest.raises(ValidationError):
        Settings(
            environment=Environment.PRODUCTION, log_level=LogLevel.DEBUG, db_sslmode="verify-full"
        )


@pytest.mark.parametrize("mode", ["disable", "prefer", "require"])
@pytest.mark.parametrize("env", [Environment.DEV, Environment.STAGING, Environment.PRODUCTION])
def test_deployed_environments_require_verified_database_tls(env: Environment, mode: str) -> None:
    with pytest.raises(ValidationError, match="verify the database certificate"):
        Settings(environment=env, db_sslmode=mode)


def test_database_url_never_exposes_password_in_string_form() -> None:
    s = Settings(db_password="s3cr3t-value-123", db_migrator_password="m1gr8-value-456")
    for role in DbRole:
        url = s.database_url(role)
        assert "s3cr3t" not in str(url)
        assert "m1gr8" not in str(url)
        assert url.query["sslmode"] == "prefer"
    assert s.database_url(DbRole.MIGRATOR).username == "sentinel_migrator"
    assert "s3cr3t" not in repr(s)


def test_database_url_passes_ca_bundle_when_configured() -> None:
    s = Settings(db_sslmode="verify-full", db_sslrootcert="/etc/ssl/rds-ca.pem")
    assert s.database_url().query["sslrootcert"] == "/etc/ssl/rds-ca.pem"


@pytest.mark.parametrize("name", ["app; DROP TABLE x", "App", "1user", "a" * 64])
def test_database_identifiers_validated(name: str) -> None:
    with pytest.raises(ValidationError):
        Settings(db_user=name)


@pytest.mark.parametrize("hosts", ["*", "*.example.com", ""])
def test_wildcard_or_empty_trusted_hosts_rejected(
    monkeypatch: pytest.MonkeyPatch, hosts: str
) -> None:
    monkeypatch.setenv("SENTINEL_TRUSTED_HOSTS", hosts)
    with pytest.raises(ValidationError):
        Settings()


def test_trusted_hosts_parsed_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_TRUSTED_HOSTS", "localhost, api ,127.0.0.1")
    assert Settings().trusted_hosts == ["localhost", "api", "127.0.0.1"]


def test_offline_ai_rejected_in_production() -> None:
    with pytest.raises(ValidationError):
        Settings(environment=Environment.PRODUCTION, ai_provider=AIProvider.OFFLINE)


def test_bedrock_is_a_valid_provider_selection() -> None:
    assert Settings(ai_provider="bedrock").ai_provider is AIProvider.BEDROCK


def test_unknown_environment_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="prod-ish")  # type: ignore[arg-type]


# --- Authentication configuration (ADR-0003) -------------------------------------------------


def test_app_refuses_to_start_without_auth_keys() -> None:
    with pytest.raises(RuntimeError, match="SENTINEL_JWT_SIGNING_KEY"):
        create_app(Settings(trusted_hosts=["testserver"]))


def test_short_jwt_signing_key_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 32 bytes"):
        Settings(jwt_signing_key="too-short")


def test_invalid_mfa_encryption_key_rejected() -> None:
    with pytest.raises(ValidationError, match="urlsafe-base64"):
        Settings(mfa_encryption_key="not-a-fernet-key")


def test_auth_secrets_never_appear_in_repr() -> None:
    text = repr(make_settings())
    assert TEST_JWT_KEY not in text
    assert TEST_MFA_KEY not in text


@pytest.mark.parametrize("env", [Environment.DEV, Environment.STAGING, Environment.PRODUCTION])
def test_deployed_environments_require_https_origins(env: Environment) -> None:
    with pytest.raises(ValidationError, match="https public_origins"):
        Settings(environment=env, **{**DEPLOYABLE, "public_origins": ["http://example.com"]})


@pytest.mark.parametrize(
    "weak", [{"password_hash_memory_kib": 8192}, {"password_hash_time_cost": 1}]
)
def test_deployed_environments_refuse_weak_password_hashing(weak: dict[str, int]) -> None:
    with pytest.raises(ValidationError, match="password hashing cost"):
        Settings(environment=Environment.PRODUCTION, **{**DEPLOYABLE, **weak})


@pytest.mark.parametrize(
    "origin", ["localhost:8080", "https://*.example.com", "javascript:alert(1)", "https://a/b"]
)
def test_malformed_origins_rejected(origin: str) -> None:
    with pytest.raises(ValidationError):
        Settings(public_origins=[origin])


def test_origins_parsed_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_PUBLIC_ORIGINS", "http://localhost:8080, http://127.0.0.1:5173")
    s = Settings()
    assert s.public_origins == ["http://localhost:8080", "http://127.0.0.1:5173"]
    assert s.canonical_origin == "http://localhost:8080"
