"""Alembic environment: always runs as the migrator role (ADR-0015)."""

from __future__ import annotations

from alembic import context
from sqlalchemy import Connection

from app.core.config import DbRole, get_settings
from app.core.logging import configure_logging
from app.db import models  # noqa: F401  (registers every model on Base.metadata)
from app.db.base import SCHEMA, Base
from app.db.session import build_engine

target_metadata = Base.metadata


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table_schema=SCHEMA,
        include_schemas=True,
        include_name=lambda name, type_, _parent: type_ != "schema" or name == SCHEMA,
        compare_type=True,
    )


def run_migrations_online() -> None:
    # An existing connection can be supplied (tests); otherwise connect as the migrator.
    connection: Connection | None = context.config.attributes.get("connection")
    if connection is not None:
        _configure(connection)
        with context.begin_transaction():
            context.run_migrations()
        return

    settings = get_settings()
    configure_logging(settings.log_level.value)
    engine = build_engine(settings, DbRole.MIGRATOR)
    try:
        with engine.connect() as conn:
            _configure(conn)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Offline (SQL script) migrations are not supported; run against a database.")
run_migrations_online()
