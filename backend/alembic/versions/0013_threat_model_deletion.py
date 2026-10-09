"""Leads may delete threat models they built for applications (Phase 10).

Grants: DELETE added on threat_models, model_elements and threats (threat_controls already has
it). The service allows it only for application models: SentinelEdge's own model is maintained
as code and refuses (409). Every deletion is audited with a summary of what was removed, so the
hash-chained audit log keeps the record of the model after the model itself is gone.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-08
"""

from collections.abc import Sequence

from alembic import op

from app.core.config import get_settings
from app.db.migration_helpers import grant_to_app

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("threat_models", "model_elements", "threats")


def upgrade() -> None:
    for table in TABLES:
        grant_to_app(table, "DELETE")


def downgrade() -> None:
    role = get_settings().db_user
    for table in TABLES:
        # Constant table names and the validated role name; no input reaches the statement.
        op.execute(f"REVOKE DELETE ON TABLE sentinel.{table} FROM {role}")  # nosec B608
