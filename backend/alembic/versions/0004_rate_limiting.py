"""Token buckets for application rate limiting (ADR-0017).

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.db.migration_helpers import grant_to_app

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "rate_limit_buckets",
        sa.Column("bucket_key", sa.String(200), primary_key=True),
        sa.Column("tokens", sa.Float(), nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("last_allowed", sa.Boolean(), nullable=False),
        sa.Column("denied_since", TS),
        schema=S,
    )
    op.create_index(
        "ix_rate_limit_buckets_updated_at", "rate_limit_buckets", ["updated_at"], schema=S
    )
    # DELETE: idle buckets are pruned (they would be full anyway).
    grant_to_app("rate_limit_buckets", "SELECT", "INSERT", "UPDATE", "DELETE")


def downgrade() -> None:
    op.drop_table("rate_limit_buckets", schema=S)
