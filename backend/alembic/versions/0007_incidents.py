"""Incidents (Phase 7): the DETECTED -> CLOSED workflow, its append-only timeline, and the link
from a security event to the incident it is evidence for.

Grants (each line is the complete privilege set for that table):
* incidents: SELECT, INSERT, UPDATE. Never DELETE: an incident is closed, not erased.
* incident_timeline: SELECT, INSERT. Append-only, like the audit log.
* security_events: UPDATE of the incident_id column only. A trigger makes that link write-once,
  so evidence can be attached to an incident but never moved to another or detached.

Also adds the `suspicious_auth` event category and an index for looking up the audit records
of one resource (incident evidence is verified against them).

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.core.config import get_settings
from app.db.migration_helpers import grant_columns_to_app, grant_to_app

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)

PROVENANCE = ("REAL_AWS", "LOCAL", "SIMULATED", "DEMO")
SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = (
    "DETECTED",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT",
    "REMEDIATION",
    "VALIDATION",
    "CLOSED",
)
RESOLUTIONS = ("resolved", "accepted_risk", "false_positive", "duplicate")
TIMELINE_KINDS = (
    "created",
    "status_changed",
    "note",
    "assigned",
    "updated",
    "severity_raised",
    "events_linked",
)
CATEGORIES_0006 = (
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
CATEGORIES = (*CATEGORIES_0006, "suspicious_auth")


def _listed(values: Sequence[str]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _check(column: str, values: Sequence[str]) -> sa.CheckConstraint:
    return sa.CheckConstraint(f"{column} IN ({_listed(values)})", name=f"{column}_valid")


def _replace_category_check(values: Sequence[str]) -> None:
    op.drop_constraint(
        op.f("ck_security_events_category_valid"), "security_events", schema=S, type_="check"
    )
    op.create_check_constraint(
        op.f("ck_security_events_category_valid"),
        "security_events",
        f"category IN ({_listed(values)})",
        schema=S,
    )


def upgrade() -> None:
    _replace_category_check(CATEGORIES)

    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("summary", sa.String(2000), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("category", sa.String(32)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("resolution", sa.String(16)),
        sa.Column("provenance", sa.String(16), nullable=False),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("detection_rule", sa.String(32)),
        sa.Column("trigger_event_id", sa.Uuid()),
        sa.Column("dedupe_key", sa.String(300)),
        sa.Column(
            "owner_id",
            sa.Uuid(),
            sa.ForeignKey(f"{S}.users.id", ondelete="SET NULL"),
        ),
        sa.Column("created_by_label", sa.String(254), nullable=False),
        sa.Column("remediation", sa.String(4000)),
        sa.Column("detected_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("closed_at", TS),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("number"),
        _check("status", STATUSES),
        _check("severity", SEVERITIES),
        _check("category", CATEGORIES),
        _check("resolution", RESOLUTIONS),
        _check("provenance", PROVENANCE),
        sa.CheckConstraint(
            "(status = 'CLOSED') = (resolution IS NOT NULL AND closed_at IS NOT NULL)",
            name="closed_has_resolution",
        ),
        schema=S,
    )
    op.create_index(
        "ix_incidents_dedupe_key_status", "incidents", ["dedupe_key", "status"], schema=S
    )
    op.create_index("ix_incidents_status_number", "incidents", ["status", "number"], schema=S)
    op.create_index(op.f("ix_incidents_owner_id"), "incidents", ["owner_id"], schema=S)

    op.create_table(
        "incident_timeline",
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey(f"{S}.incidents.id"), nullable=False),
        sa.Column("at", TS, nullable=False),
        sa.Column("actor_id", sa.Uuid()),
        sa.Column("actor_label", sa.String(254), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("from_status", sa.String(16)),
        sa.Column("to_status", sa.String(16)),
        sa.Column("body", sa.String(4000)),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("id"),
        _check("kind", TIMELINE_KINDS),
        _check("from_status", STATUSES),
        _check("to_status", STATUSES),
        schema=S,
    )
    op.create_index(
        op.f("ix_incident_timeline_incident_id"), "incident_timeline", ["incident_id"], schema=S
    )

    op.add_column(
        "security_events",
        sa.Column("incident_id", sa.Uuid(), sa.ForeignKey(f"{S}.incidents.id")),
        schema=S,
    )
    op.create_index(
        op.f("ix_security_events_incident_id"), "security_events", ["incident_id"], schema=S
    )
    op.create_index(
        "ix_security_events_actor_occurred",
        "security_events",
        ["actor_label", "occurred_at"],
        schema=S,
    )
    op.create_index(
        "ix_security_events_rule_occurred",
        "security_events",
        ["rule_id", "occurred_at"],
        schema=S,
    )
    op.create_index(
        "ix_audit_log_resource", "audit_log", ["resource_type", "resource_id"], schema=S
    )

    # Evidence links are write-once, for every role (grants alone cannot express "only from
    # NULL"). The function pins its search_path so it cannot be hijacked.
    op.execute(
        f"""
        CREATE FUNCTION {S}.security_event_link_once() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
          IF OLD.incident_id IS NOT NULL AND NEW.incident_id IS DISTINCT FROM OLD.incident_id THEN
            RAISE EXCEPTION 'security event % is already evidence for an incident', OLD.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        f"CREATE TRIGGER security_events_link_once BEFORE UPDATE OF incident_id "
        f"ON {S}.security_events FOR EACH ROW EXECUTE FUNCTION {S}.security_event_link_once()"
    )

    grant_to_app("incidents", "SELECT", "INSERT", "UPDATE")
    grant_to_app("incident_timeline", "SELECT", "INSERT")
    grant_columns_to_app("security_events", "UPDATE", "incident_id")


def downgrade() -> None:
    role = get_settings().db_user
    op.execute(f"REVOKE UPDATE (incident_id) ON TABLE {S}.security_events FROM {role}")
    op.execute(f"DROP TRIGGER security_events_link_once ON {S}.security_events")
    op.execute(f"DROP FUNCTION {S}.security_event_link_once()")
    op.drop_index("ix_audit_log_resource", "audit_log", schema=S)
    op.drop_index("ix_security_events_rule_occurred", "security_events", schema=S)
    op.drop_index("ix_security_events_actor_occurred", "security_events", schema=S)
    op.drop_index(op.f("ix_security_events_incident_id"), "security_events", schema=S)
    op.drop_column("security_events", "incident_id", schema=S)
    op.drop_table("incident_timeline", schema=S)
    op.drop_table("incidents", schema=S)
    # Rows with the new category would violate the old constraint: there can be none to keep
    # once incidents are gone in development, so remove them explicitly before narrowing.
    op.execute(f"DELETE FROM {S}.security_events WHERE category = 'suspicious_auth'")  # noqa: S608  # nosec B608 - constant identifiers, no input
    _replace_category_check(CATEGORIES_0006)
