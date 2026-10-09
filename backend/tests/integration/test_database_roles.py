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
    "incidents": {"SELECT", "INSERT", "UPDATE"},  # closed, never deleted (0007)
    "incident_timeline": {"SELECT", "INSERT"},  # append-only (0007)
    "applications": {"SELECT", "INSERT", "UPDATE"},  # retired, never deleted (0008)
    "simulation_runs": {"SELECT", "INSERT"},  # a record of what was simulated (0008)
    "simulated_waf_rules": {"SELECT", "INSERT", "UPDATE"},  # simulated WAF modes (0008)
    "scan_runs": {"SELECT", "INSERT"},  # a record of what each scan found (0009)
    "vulnerabilities": {"SELECT", "INSERT", "UPDATE"},  # fixed or accepted, never deleted (0009)
    "risk_acceptances": {"SELECT", "INSERT"},  # the decision is never rewritten (0009)
    "sboms": {"SELECT", "INSERT"},  # what each artifact contained (0009)
    # Loaded from the reviewed catalogue; retired, never deleted (0010).
    "controls": {"SELECT", "INSERT", "UPDATE"},
    "requirements": {"SELECT", "INSERT", "UPDATE"},
    "threat_models": {"SELECT", "INSERT", "UPDATE"},  # archived, never deleted (0010)
    "model_elements": {"SELECT", "INSERT", "UPDATE"},  # retired, never deleted (0010)
    "threats": {"SELECT", "INSERT", "UPDATE"},  # retired, never deleted (0010)
    # Link tables: re-linking a threat's controls replaces its links (audited) (0010).
    "threat_controls": {"SELECT", "INSERT", "DELETE"},
    "requirement_threats": {"SELECT", "INSERT", "DELETE"},
    # Decided records are final (trigger); ended, never deleted (0011).
    "exceptions": {"SELECT", "INSERT", "UPDATE"},
    "change_requests": {"SELECT", "INSERT", "UPDATE"},
}

# Column-level grants beyond the table-level ones above: (table, column) -> privileges.
EXPECTED_APP_COLUMN_PRIVILEGES: dict[tuple[str, str], set[str]] = {
    # Linking an event to its incident; a trigger makes the link write-once (0007).
    ("security_events", "incident_id"): {"UPDATE"},
    # How an acceptance ended (revoked, expired, fixed); the decision itself is immutable (0009).
    ("risk_acceptances", "ended_at"): {"UPDATE"},
    ("risk_acceptances", "end_reason"): {"UPDATE"},
    ("risk_acceptances", "ended_by_label"): {"UPDATE"},
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


def test_app_role_column_privileges_match_the_intended_matrix(migrator_engine: Engine) -> None:
    """Column grants that are not implied by a table grant (a column-only UPDATE)."""
    with migrator_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT c.table_name, c.column_name, c.privilege_type "
                "FROM information_schema.column_privileges c "
                "WHERE c.grantee = 'sentinel_app' AND c.table_schema = 'sentinel' "
                "AND NOT EXISTS (SELECT 1 FROM information_schema.role_table_grants t "
                "  WHERE t.grantee = c.grantee AND t.table_schema = c.table_schema "
                "  AND t.table_name = c.table_name AND t.privilege_type = c.privilege_type)"
            )
        ).all()
    actual: dict[tuple[str, str], set[str]] = {}
    for table, column, privilege in rows:
        actual.setdefault((table, column), set()).add(privilege)
    assert actual == EXPECTED_APP_COLUMN_PRIVILEGES


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
