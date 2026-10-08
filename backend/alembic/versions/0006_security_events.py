"""Security events: the telemetry security operations works from (Phase 7).

Append-only for the application: SELECT and INSERT only. Migration 0007 adds the incident link
and grants UPDATE on that one column.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.migration_helpers import grant_to_app

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)

# Values as of this migration (enums can grow later only through a new migration).
PROVENANCE = (
    "REAL_AWS",
    "LOCAL",
    "SIMULATED",
    "DEMO",
)
SOURCES = (
    "auth",
    "authz",
    "rate_limit",
    "http_analysis",
    "audit",
    "correlation",
    "waf",
    "certificate",
    "dependency",
)
CATEGORIES = (
    "sql_injection",
    "xss",
    "path_traversal",
    "command_injection",
    "ssrf",
    "scanner",
    "recon",
    "bot",
    "auth_failure",
    "brute_force",
    "credential_stuffing",
    "token_theft",
    "bola",
    "bfla",
    "privilege_change",
    "rate_limit",
    "api_abuse",
    "audit_tampering",
    "certificate",
    "vulnerable_dependency",
)
SEVERITIES = (
    "info",
    "low",
    "medium",
    "high",
    "critical",
)
OUTCOMES = (
    "allowed",
    "rejected",
    "throttled",
    "blocked",
    "detected",
)


def _check(column: str, values: Sequence[str]) -> sa.CheckConstraint:
    listed = ", ".join(f"'{v}'" for v in values)
    return sa.CheckConstraint(f"{column} IN ({listed})", name=f"{column}_valid")


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", TS, nullable=False),
        sa.Column("provenance", sa.String(16), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("rule_id", sa.String(32)),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("user_agent", sa.String(256)),
        sa.Column("method", sa.String(10)),
        sa.Column("endpoint", sa.String(200)),
        sa.Column("status_code", sa.SmallInteger()),
        sa.Column("actor_id", sa.Uuid()),
        sa.Column("actor_label", sa.String(254)),
        sa.Column("correlation_id", sa.String(64)),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("id"),
        _check("provenance", PROVENANCE),
        _check("source", SOURCES),
        _check("category", CATEGORIES),
        _check("severity", SEVERITIES),
        _check("outcome", OUTCOMES),
        schema=S,
    )
    op.create_index("ix_security_events_occurred_at", "security_events", ["occurred_at"], schema=S)
    op.create_index(
        "ix_security_events_source_ip_occurred",
        "security_events",
        ["source_ip", "occurred_at"],
        schema=S,
    )
    op.create_index(
        "ix_security_events_category_occurred",
        "security_events",
        ["category", "occurred_at"],
        schema=S,
    )
    # Evidence: the app may add events and read them, never change or remove them.
    grant_to_app("security_events", "SELECT", "INSERT")


def downgrade() -> None:
    op.drop_table("security_events", schema=S)
