"""Security posture snapshots (Phase 10).

Grants: posture_snapshots SELECT, INSERT (a snapshot records what the score was; never edited).

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.migration_helpers import grant_to_app

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"


def upgrade() -> None:
    op.create_table(
        "posture_snapshots",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("overall", sa.Integer(), nullable=False),
        sa.Column("built_scope", sa.Integer(), nullable=False),
        sa.Column("categories", postgresql.JSONB(), nullable=False),
        sa.Column("taken_by_label", sa.String(254), nullable=False),
        schema=S,
    )
    op.create_index(
        op.f("ix_posture_snapshots_taken_at"), "posture_snapshots", ["taken_at"], schema=S
    )
    grant_to_app("posture_snapshots", "SELECT", "INSERT")


def downgrade() -> None:
    op.drop_table("posture_snapshots", schema=S)
