"""Secure-by-default configuration (spec §46)."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import AIProvider, Environment, LogLevel, Settings
from app.main import create_app


def test_defaults_are_secure() -> None:
    s = Settings()
    assert s.enable_api_docs is False
    assert s.ai_provider is AIProvider.DISABLED
    assert "*" not in s.trusted_hosts


@pytest.mark.parametrize("env", [Environment.DEV, Environment.STAGING, Environment.PRODUCTION])
def test_api_docs_forced_off_when_deployed(env: Environment) -> None:
    s = Settings(environment=env, enable_api_docs=True)
    assert s.enable_api_docs is False
    client = TestClient(create_app(s.model_copy(update={"trusted_hosts": ["testserver"]})))
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_api_docs_available_locally_when_enabled() -> None:
    s = Settings(environment=Environment.LOCAL, enable_api_docs=True, trusted_hosts=["testserver"])
    assert TestClient(create_app(s)).get("/api/openapi.json").status_code == 200


def test_debug_logging_rejected_when_deployed() -> None:
    with pytest.raises(ValidationError):
        Settings(environment=Environment.PRODUCTION, log_level=LogLevel.DEBUG)


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
