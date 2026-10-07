"""Tamper-evident audit log (ADR-0005, spec §29, T-AUD-01).

Three independent layers, each tested on its own:
1. Grants: the app role cannot UPDATE, DELETE or TRUNCATE.
2. Trigger: even the table owner cannot UPDATE, DELETE or TRUNCATE without first disabling it.
3. Hash chain: if someone does disable the trigger and edits history, verification finds it.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from app.core.config import DbRole
from app.db.session import build_engine
from app.models.audit import AuditResult
from app.services import audit
from app.services.audit import SYSTEM_CONTEXT, AuditAction, verify_chain
from tests.conftest import make_settings

pytestmark = [pytest.mark.security, pytest.mark.db]


def _write(app: FastAPI, n: int, **details: object) -> None:
    with app.state.session_factory() as db:
        for i in range(n):
            audit.record(
                db,
                action=AuditAction.USER_UPDATED,
                result=AuditResult.SUCCESS,
                actor="system:test",
                ctx=SYSTEM_CONTEXT,
                details={"i": i, **details},
            )
        db.commit()


def _verify(app: FastAPI) -> audit.ChainVerification:
    with app.state.session_factory() as db:
        return verify_chain(db)


@pytest.fixture
def app_engine(db_app: FastAPI) -> Iterator[Engine]:
    engine = build_engine(make_settings(), DbRole.APP)
    yield engine
    engine.dispose()


# --- Layer 1: grants ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE sentinel.audit_log SET actor_label = 'someone-else'",
        "DELETE FROM sentinel.audit_log",
        "TRUNCATE sentinel.audit_log",
        "ALTER TABLE sentinel.audit_log DISABLE TRIGGER audit_log_no_update_delete",
    ],
)
def test_app_role_cannot_alter_audit_history(
    db_app: FastAPI, app_engine: Engine, statement: str
) -> None:
    _write(db_app, 1)
    with app_engine.connect() as conn, pytest.raises(DBAPIError) as excinfo:
        conn.execute(text(statement))
    message = str(excinfo.value).lower()
    assert "permission denied" in message or "must be owner" in message


# --- Layer 2: trigger (applies even to the owner) ----------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE sentinel.audit_log SET actor_label = 'someone-else'",
        "DELETE FROM sentinel.audit_log",
        "TRUNCATE sentinel.audit_log",
    ],
)
def test_trigger_blocks_even_the_table_owner(
    db_app: FastAPI, migrator_engine: Engine, statement: str
) -> None:
    _write(db_app, 1)
    with migrator_engine.connect() as conn, pytest.raises(DBAPIError) as excinfo:
        conn.execute(text(statement))
    assert "append-only" in str(excinfo.value)


# --- Layer 3: hash chain --------------------------------------------------------------------


def test_chain_is_intact_after_normal_activity(db_app: FastAPI) -> None:
    _write(db_app, 25)
    result = _verify(db_app)
    assert result.intact
    assert result.records_checked == 25
    assert len(result.head_hash) == 64


def test_empty_log_verifies(db_app: FastAPI) -> None:
    result = _verify(db_app)
    assert result.intact
    assert result.records_checked == 0


def _as_owner_bypassing_trigger(
    engine: Engine, statement: str, params: dict[str, str] | None = None
) -> None:
    """Simulate an attacker with owner rights: disable the guard, edit history, re-enable."""
    with engine.begin() as conn:
        conn.execute(
            text("ALTER TABLE sentinel.audit_log DISABLE TRIGGER audit_log_no_update_delete")
        )
        conn.execute(text(statement), params or {})
        conn.execute(
            text("ALTER TABLE sentinel.audit_log ENABLE TRIGGER audit_log_no_update_delete")
        )


@pytest.mark.parametrize(
    ("statement", "problem"),
    [
        (
            "UPDATE sentinel.audit_log SET actor_label = 'innocent@example.com' WHERE seq = 4",
            "content does not match hash",
        ),
        (
            "UPDATE sentinel.audit_log SET details = '{\"i\": 99}' WHERE seq = 4",
            "content does not match hash",
        ),
        (
            "UPDATE sentinel.audit_log SET result = 'success', "
            "occurred_at = occurred_at - interval '1 hour' WHERE seq = 4",
            "content does not match hash",
        ),
        ("DELETE FROM sentinel.audit_log WHERE seq = 4", "broken link to previous"),
    ],
)
def test_tampering_is_detected_at_the_altered_record(
    db_app: FastAPI, migrator_engine: Engine, statement: str, problem: str
) -> None:
    _write(db_app, 8)
    _as_owner_bypassing_trigger(migrator_engine, statement)
    result = _verify(db_app)
    assert not result.intact
    assert result.problem == problem
    assert result.first_break_seq in {4, 5}  # the edited record, or the one after a deletion


def test_recomputing_one_hash_still_breaks_the_next_link(
    db_app: FastAPI, migrator_engine: Engine
) -> None:
    """A careful attacker who also fixes the edited record's own hash breaks the chain one later."""
    _write(db_app, 8)
    with db_app.state.session_factory() as db:
        from app.models.audit import AuditLog

        entry = db.get(AuditLog, 4)
        assert entry is not None
        entry.actor_label = "innocent@example.com"
        forged = audit.compute_record_hash(entry.prev_hash, audit.canonical_payload(entry))
        db.rollback()
    _as_owner_bypassing_trigger(
        migrator_engine,
        "UPDATE sentinel.audit_log SET actor_label = 'innocent@example.com', "
        "record_hash = :forged WHERE seq = 4",
        {"forged": forged},
    )
    result = _verify(db_app)
    assert result.first_break_seq == 5
    assert result.problem == "broken link to previous"


def test_concurrent_writers_never_fork_the_chain(db_app: FastAPI) -> None:
    """The advisory lock serializes chain extension across concurrent requests."""
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            _write(db_app, 5)
        except BaseException as exc:  # surfaced via the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    result = _verify(db_app)
    assert result.intact
    assert result.records_checked == 40


def test_audit_details_are_redacted(db_app: FastAPI) -> None:
    _write(db_app, 1, password="hunter2-secret", nested={"api_key": "abc123"}, note="x" * 1000)
    with db_app.state.session_factory() as db:
        from app.models.audit import AuditLog

        entry = db.query(AuditLog).one()
        assert entry.details["password"] == "[REDACTED]"
        assert entry.details["nested"]["api_key"] == "[REDACTED]"
        assert len(entry.details["note"]) == 256
    assert _verify(db_app).intact  # redaction happens before hashing
