from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Environment, Settings
from app.main import create_app


def make_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": Environment.TEST,
        "trusted_hosts": ["testserver"],
        "app_version": "0.1.0",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def app() -> FastAPI:
    return create_app(make_settings())


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    # raise_server_exceptions=False lets us assert on the response a real client would see.
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def client_factory() -> Callable[..., TestClient]:
    def _factory(**overrides: object) -> TestClient:
        return TestClient(create_app(make_settings(**overrides)), raise_server_exceptions=False)

    return _factory
