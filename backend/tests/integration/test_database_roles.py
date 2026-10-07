"""ADR-0015: the runtime database role has exactly the privileges it needs, and no more.

These run against real PostgreSQL prepared by db/bootstrap-roles.sh, because privilege rules
cannot be meaningfully faked.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import ProgrammingError

from app.core.config import DbRole
from app.db.session import build_engine
from tests.conftest import make_settings, run_migrations

pytestmark = [pytest.mark.security, pytest.mark.db]

# The complete, intended privilege set of the app role, written independently of the migrations
# that implement it. Any table or privilege not listed here is a test failure (over-granting).
EXPECTED_APP_PRIVILEGES: dict[str, set[str]] = {
    # DELETE on accounts and their credentials: admin-only, audited user deletion (0003).
    "users": {"SELECT", "INSERT", "UPDATE", "DELETE"},
    "auth_sessions": {"SELECT", "INSERT", "UPDATE", "DELETE"},
    "refresh_tokens": {"SELECT", "INSERT", "UPDATE", "DELETE"},
    "mfa_recovery_codes": {"SELECT", "INSERT", "UPDATE", "DELETE"},  # regenerated as a set
    "password_reset_tokens": {"SELECT", "INSERT", "UPDATE", "DELETE"},
    "outbox_messages": {"SELECT", "INSERT"},
    "audit_log": {"SELECT", "INSERT"},  # append-only (ADR-0005)
    "rate_limit_buckets": {"SELECT", "INSERT", "UPDATE", "DELETE"},  # idle buckets pruned
    "api_endpoint_stats": {"SELECT", "INSERT", "UPDATE", "DELETE"},  # pruned after 30 days
    "security_events": {"SELECT", "INSERT"},  # evidence: append-only (0006)
}


@pytest.fixture
def app_engine(migrator_engine: Engine) -> Iterator[Engine]:
    engine = build_engine(make_settings(), DbRole.APP)
    yield engine
    engine.dispose()


def _actual_app_privileges(migrator_engine: Engine) -> dict[str, set[str]]:
    rows = (
        migrator_engine.connect()
        .execute(
            text(
                "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
                "WHERE grantee = 'sentinel_app' AND table_schema = 'sentinel'"
            )
        )
        .all()
    )
    result: dict[str, set[str]] = {}
    for table, privilege in rows:
        result.setdefault(table, set()).add(privilege)
    return result


def test_app_role_privileges_match_the_intended_matrix(migrator_engine: Engine) -> None:
    assert _actual_app_privileges(migrator_engine) == EXPECTED_APP_PRIVILEGES


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE TABLE sentinel.attacker_table (id int)",
        "CREATE TABLE public.attacker_table (id int)",
        "CREATE SCHEMA attacker",
        "CREATE ROLE attacker",
        "CREATE DATABASE attacker",
        "ALTER ROLE sentinel_app SUPERUSER",
    ],
)
def test_app_role_cannot_change_schema_or_roles(app_engine: Engine, statement: str) -> None:
    # Autocommit: CREATE DATABASE cannot run in a transaction, and we want the *permission*
    # check to be what refuses each statement.
    autocommit = app_engine.execution_options(isolation_level="AUTOCOMMIT")
    with autocommit.connect() as conn, pytest.raises(ProgrammingError) as excinfo:
        conn.execute(text(statement))
    assert (
        "permission denied" in str(excinfo.value).lower() or "must be" in str(excinfo.value).lower()
    )


def test_app_role_cannot_read_alembic_history(app_engine: Engine) -> None:
    with app_engine.connect() as conn, pytest.raises(ProgrammingError):
        conn.execute(text("SELECT * FROM sentinel.alembic_version"))


def test_roles_are_not_privileged(migrator_engine: Engine) -> None:
    rows = (
        migrator_engine.connect()
        .execute(
            text(
                "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, "
                "rolreplication FROM pg_roles WHERE rolname IN "
                "('sentinel_app', 'sentinel_migrator')"
            )
        )
        .all()
    )
    assert len(rows) == 2
    for name, *flags in rows:
        assert not any(flags), f"{name} has an elevated role attribute"


def test_app_role_has_query_timeouts(app_engine: Engine) -> None:
    with app_engine.connect() as conn:
        assert conn.execute(text("SHOW statement_timeout")).scalar() == "15s"
        assert conn.execute(text("SHOW idle_in_transaction_session_timeout")).scalar() == "30s"
        assert conn.execute(text("SHOW search_path")).scalar() == "sentinel"


def test_migrations_are_reversible(migrator_engine: Engine) -> None:
    run_migrations(migrator_engine, "base", downgrade=True)
    run_migrations(migrator_engine, "head")
    with migrator_engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM sentinel.alembic_version")).scalar()
