"""Hourly per-endpoint request counters for the API Security Center.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.db.migration_helpers import grant_to_app

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"


def upgrade() -> None:
    counters = [
        sa.Column(name, sa.Integer(), nullable=False)
        for name in (
            "requests",
            "client_errors",
            "server_errors",
            "unauthenticated",
            "forbidden",
            "throttled",
        )
    ]
    op.create_table(
        "api_endpoint_stats",
        sa.Column("method", sa.String(10), primary_key=True),
        sa.Column("route", sa.String(200), primary_key=True),
        sa.Column("hour", sa.DateTime(timezone=True), primary_key=True),
        *counters,
        schema=S,
    )
    # DELETE: rows older than the retention window are pruned.
    grant_to_app("api_endpoint_stats", "SELECT", "INSERT", "UPDATE", "DELETE")


def downgrade() -> None:
    op.drop_table("api_endpoint_stats", schema=S)
