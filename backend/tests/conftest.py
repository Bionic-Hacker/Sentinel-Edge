from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.config import DbRole, Environment, Settings
from app.db.base import Base
from app.db.session import build_engine
from app.main import create_app

BACKEND_DIR = Path(__file__).resolve().parents[1]

# Database tests need a real PostgreSQL prepared by db/bootstrap-roles.sh (`make test-backend`
# provides a throwaway one; CI uses a service container). Locally, without one, they are skipped
# with a clear reason. With SENTINEL_REQUIRE_DB=1 (CI, make), a missing database is a FAILURE:
# security tests must never pass by being silently skipped.
HAS_TEST_DB = bool(os.environ.get("SENTINEL_DB_PASSWORD"))
REQUIRE_DB = os.environ.get("SENTINEL_REQUIRE_DB") == "1"


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


# --- Database fixtures ---------------------------------------------------------------------


def alembic_config() -> Config:
    return Config(str(BACKEND_DIR / "alembic.ini"))


def run_migrations(engine: Engine, revision: str = "head", *, downgrade: bool = False) -> None:
    cfg = alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        if downgrade:
            command.downgrade(cfg, revision)
        else:
            command.upgrade(cfg, revision)


@pytest.fixture(scope="session")
def migrator_engine() -> Iterator[Engine]:
    """Engine connected as the schema owner, with the schema migrated to head."""
    if not HAS_TEST_DB:
        message = "no test database configured; run `make test-backend`"
        if REQUIRE_DB:
            pytest.fail(message)
        pytest.skip(message)
    engine = build_engine(make_settings(), DbRole.MIGRATOR)
    run_migrations(engine)
    yield engine
    engine.dispose()


def _truncate_all(engine: Engine) -> None:
    tables = ", ".join(f"{t.schema}.{t.name}" for t in Base.metadata.sorted_tables)
    if tables:
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest.fixture
def db_app(migrator_engine: Engine) -> Iterator[FastAPI]:
    """An app wired to the test database (as the app role), with every table emptied after."""
    application = create_app(make_settings())
    yield application
    application.state.engine.dispose()
    _truncate_all(migrator_engine)


@pytest.fixture
def db_client(db_app: FastAPI) -> Iterator[TestClient]:
    with TestClient(db_app, raise_server_exceptions=False) as c:
        yield c
