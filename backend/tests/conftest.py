from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app.core.config import NON_DEPLOYED, DbRole, Environment, Settings
from app.db import models  # noqa: F401  (register all tables on Base.metadata)
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


# Per-run test keys: random, never written anywhere, and different on every run.
TEST_JWT_KEY = secrets.token_urlsafe(48)
TEST_MFA_KEY = Fernet.generate_key().decode()
TEST_ORIGIN = "https://testserver"


@pytest.fixture(autouse=True, scope="session")
def _no_ambient_aws(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Tests never see the developer's AWS profile, keys or config. A shell signed in with
    `aws login` (AWS_PROFILE set) made boto3 load botocore's login credential provider, which
    needs an extra dependency, and no real credential should ever reach a test anyway."""
    patch = pytest.MonkeyPatch()
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_CREDENTIAL_EXPIRATION",
    ):
        patch.delenv(name, raising=False)
    empty = tmp_path_factory.mktemp("aws")
    patch.setenv("AWS_CONFIG_FILE", str(empty / "config"))
    patch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(empty / "credentials"))
    patch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    yield
    patch.undo()


def make_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": Environment.TEST,
        "trusted_hosts": ["testserver"],
        "app_version": "0.1.0",
        "jwt_signing_key": TEST_JWT_KEY,
        "mfa_encryption_key": TEST_MFA_KEY,
        "public_origins": [TEST_ORIGIN],
        # Cheap Argon2 for speed. Config validation forbids these values when deployed.
        "password_hash_memory_kib": 1024,
        "password_hash_time_cost": 1,
        "password_hash_parallelism": 1,
    }
    base.update(overrides)
    # Rate limiting is off for the general suite (the authz sweep alone makes hundreds of calls
    # from one client); tests/integration/test_rate_limiting.py turns it on. Deployed
    # environments keep it on: config validation forbids disabling it there.
    if base["environment"] in NON_DEPLOYED:
        base.setdefault("rate_limit_enabled", False)
    # Metrics write to the database on every request; tests that need them turn them on.
    base.setdefault("api_metrics_enabled", False)
    # Attack detection records events in the database; tests that exercise it turn it on.
    if base["environment"] in NON_DEPLOYED:
        base.setdefault("http_analysis_enabled", False)
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


PLATFORM_APP_SQL = """
INSERT INTO sentinel.applications (id, slug, name, description, owner_id, environment,
    criticality, domain, status, is_platform, created_at, updated_at, version)
VALUES ('5e7e1ed6-0000-4000-8000-000000000001', 'sentineledge', 'SentinelEdge',
    'This platform: the first protected workload.', NULL, 'local', 'high', 'localhost',
    'active', true, now(), now(), 1)
"""


def _truncate_all(engine: Engine) -> None:
    """Reset between tests. The audit log's append-only trigger also blocks the table owner, so
    the owner must disable it explicitly — the same deliberate, visible step an attacker with
    owner rights would need (and which the hash chain would still expose)."""
    tables = ", ".join(f"{t.schema}.{t.name}" for t in Base.metadata.sorted_tables)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE sentinel.audit_log DISABLE TRIGGER audit_log_no_truncate"))
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
        conn.execute(text("ALTER TABLE sentinel.audit_log ENABLE TRIGGER audit_log_no_truncate"))
        # The platform application is seeded by migration 0008; restore it for the next test.
        conn.execute(text(PLATFORM_APP_SQL))


@pytest.fixture
def db_app(migrator_engine: Engine) -> Iterator[FastAPI]:
    """An app wired to the test database (as the app role), with every table emptied after."""
    application = create_app(make_settings())
    yield application
    application.state.engine.dispose()
    _truncate_all(migrator_engine)


@pytest.fixture
def db_client(db_app: FastAPI) -> Iterator[TestClient]:
    # HTTPS base URL so the Secure refresh cookie round-trips like it does in a browser, and the
    # same-origin headers the SPA sends on every auth call.
    with TestClient(
        db_app,
        base_url=TEST_ORIGIN,
        raise_server_exceptions=False,
        headers={"Origin": TEST_ORIGIN, "X-SentinelEdge-CSRF": "1"},
    ) as c:
        yield c
