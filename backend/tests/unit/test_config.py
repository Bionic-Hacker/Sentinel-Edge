"""Secure-by-default configuration (spec §46)."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import AIProvider, DbRole, Environment, LogLevel, Settings
from app.main import create_app


def test_defaults_are_secure() -> None:
    s = Settings()
    assert s.enable_api_docs is False
    assert s.ai_provider is AIProvider.DISABLED
    assert "*" not in s.trusted_hosts


@pytest.mark.parametrize("env", [Environment.DEV, Environment.STAGING, Environment.PRODUCTION])
def test_api_docs_forced_off_when_deployed(env: Environment) -> None:
    s = Settings(environment=env, enable_api_docs=True, db_sslmode="verify-full")
    assert s.enable_api_docs is False
    client = TestClient(create_app(s.model_copy(update={"trusted_hosts": ["testserver"]})))
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_api_docs_available_locally_when_enabled() -> None:
    s = Settings(environment=Environment.LOCAL, enable_api_docs=True, trusted_hosts=["testserver"])
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
