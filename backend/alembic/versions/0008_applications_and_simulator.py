"""Application inventory and attack simulator (Phase 7).

Grants (each line is the complete privilege set for that table):
* applications: SELECT, INSERT, UPDATE. Retired, never deleted.
* simulation_runs: SELECT, INSERT. A run's record is evidence of what was simulated, and when.
* simulated_waf_rules: SELECT, INSERT, UPDATE. The modes of the SIMULATED WAF only.

Seeds SentinelEdge itself as the first protected application.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-07
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.migration_helpers import grant_to_app

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)
# A fixed ID, so the platform application is the same row in every environment.
PLATFORM_APP_ID = UUID("5e7e1ed6-0000-4000-8000-000000000001")


def _check(column: str, values: Sequence[str]) -> sa.CheckConstraint:
    listed = ", ".join(f"'{v}'" for v in values)
    return sa.CheckConstraint(f"{column} IN ({listed})", name=f"{column}_valid")


def upgrade() -> None:
    applications = op.create_table(
        "applications",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("owner_id", sa.Uuid(), sa.ForeignKey(f"{S}.users.id", ondelete="SET NULL")),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("criticality", sa.String(16), nullable=False),
        sa.Column("domain", sa.String(253)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("is_platform", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("slug"),
        _check("environment", ("local", "dev", "staging", "production")),
        _check("criticality", ("low", "medium", "high", "critical")),
        _check("status", ("active", "retired")),
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'", name="slug_format"),
        schema=S,
    )
    op.create_index(op.f("ix_applications_owner_id"), "applications", ["owner_id"], schema=S)

    op.create_table(
        "simulation_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column("scenario", sa.String(48), nullable=False),
        sa.Column("started_by_id", sa.Uuid()),
        sa.Column("started_by_label", sa.String(254), nullable=False),
        sa.Column("started_at", TS, nullable=False),
        sa.Column("completed_at", TS, nullable=False),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("summary", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("number"),
        schema=S,
    )

    op.create_table(
        "simulated_waf_rules",
        sa.Column("rule_id", sa.String(32), primary_key=True),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("updated_by_label", sa.String(254), nullable=False),
        _check("mode", ("block", "count", "off")),
        schema=S,
    )

    now = datetime.now(UTC)
    op.bulk_insert(
        applications,
        [
            {
                "id": PLATFORM_APP_ID,
                "slug": "sentineledge",
                "name": "SentinelEdge",
                "description": (
                    "This platform: the first protected workload. Every control it reports on "
                    "also protects it."
                ),
                "owner_id": None,
                "environment": "local",
                "criticality": "high",
                "domain": "localhost",
                "status": "active",
                "is_platform": True,
                "created_at": now,
                "updated_at": now,
                "version": 1,
            }
        ],
    )

    grant_to_app("applications", "SELECT", "INSERT", "UPDATE")
    grant_to_app("simulation_runs", "SELECT", "INSERT")
    grant_to_app("simulated_waf_rules", "SELECT", "INSERT", "UPDATE")


def downgrade() -> None:
    op.drop_table("simulated_waf_rules", schema=S)
    op.drop_table("simulation_runs", schema=S)
    op.drop_table("applications", schema=S)
