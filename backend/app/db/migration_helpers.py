"""Helpers for migrations: explicit, validated grants to the app role (ADR-0015)."""

from __future__ import annotations

import re

from alembic import op

from app.core.config import get_settings
from app.db.base import SCHEMA

_ALLOWED = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def grant_to_app(table: str, *privileges: str) -> None:
    """Grant the app role exactly `privileges` on `table`. TRUNCATE, REFERENCES and TRIGGER are
    never granted; identifiers are validated because DDL cannot use bind parameters."""
    role = get_settings().db_user
    if not _IDENT.fullmatch(table) or not _IDENT.fullmatch(role):
        raise ValueError("invalid identifier")
    wanted = {p.upper() for p in privileges}
    if not wanted or not wanted <= _ALLOWED:
        raise ValueError(f"privileges must be a non-empty subset of {sorted(_ALLOWED)}")
    op.execute(f"GRANT {', '.join(sorted(wanted))} ON TABLE {SCHEMA}.{table} TO {role}")


def grant_columns_to_app(table: str, privilege: str, *columns: str) -> None:
    """Grant the app role `privilege` on specific columns only (for example, UPDATE of a single
    link column on an otherwise append-only table)."""
    role = get_settings().db_user
    wanted = privilege.upper()
    if wanted not in {"SELECT", "INSERT", "UPDATE"}:
        raise ValueError("column privileges must be SELECT, INSERT or UPDATE")
    if not columns or not all(_IDENT.fullmatch(c) for c in (table, role, *columns)):
        raise ValueError("invalid identifier")
    op.execute(f"GRANT {wanted} ({', '.join(columns)}) ON TABLE {SCHEMA}.{table} TO {role}")
