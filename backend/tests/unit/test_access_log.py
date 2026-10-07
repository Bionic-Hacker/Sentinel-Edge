"""Access-log levels: health probes are quiet when healthy, loud when not."""

import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.deps import app_settings


def _access_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "sentineledge.access"]


def test_successful_health_probe_logged_at_debug(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="sentineledge.access")
    client.get("/api/v1/health")
    (record,) = _access_records(caplog)
    assert record.levelno == logging.DEBUG


def test_other_requests_logged_at_info(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="sentineledge.access")
    client.get("/api/v1/does-not-exist")
    (record,) = _access_records(caplog)
    assert record.levelno == logging.INFO
    assert record.http_status == 404  # type: ignore[attr-defined]


def test_failing_health_probe_logged_at_info(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    def _unhealthy() -> None:
        raise RuntimeError("dependency down")

    # Make the health endpoint's dependency fail, so the probe returns 500.
    app.dependency_overrides[app_settings] = _unhealthy

    caplog.set_level(logging.DEBUG, logger="sentineledge.access")
    TestClient(app, raise_server_exceptions=False).get("/api/v1/health")
    (record,) = _access_records(caplog)
    assert record.levelno == logging.INFO
    assert record.http_status == 500  # type: ignore[attr-defined]
