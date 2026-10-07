"""Allow administrators to permanently delete user accounts.

Phase 2 originally granted the app role no DELETE on accounts ("deactivate, never delete").
Deletion is now an explicit, admin-only, audited operation (docs/authorization.md), so the app
role may delete a user and the credentials tied to them. The audit log is unaffected: it has no
foreign key to users and stays append-only (ADR-0005).

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op

from app.core.config import get_settings
from app.db.migration_helpers import grant_to_app

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TABLES = ("users", "auth_sessions", "refresh_tokens", "password_reset_tokens")


def upgrade() -> None:
    for table in TABLES:
        grant_to_app(table, "DELETE")


def downgrade() -> None:
    role = get_settings().db_user
    for table in TABLES:
        op.execute(f"REVOKE DELETE ON TABLE {S}.{table} FROM {role}")
