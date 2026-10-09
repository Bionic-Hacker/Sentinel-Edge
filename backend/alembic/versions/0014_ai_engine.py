"""AI security engine: analyses and proposals (Phase 9; ADR-0024).

Grants:
* ai_analyses SELECT, INSERT: a record of what the AI was asked and what it said, never edited.
* ai_proposals SELECT, INSERT, UPDATE: a proposal is decided once; a trigger then refuses any
  change, for every role including the table owner. Nothing is deletable by the app role.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.migration_helpers import grant_to_app

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)


def _in(column: str, values: Sequence[str]) -> sa.CheckConstraint:
    listed = ", ".join(f"'{v}'" for v in values)
    return sa.CheckConstraint(f"{column} IN ({listed})", name=f"{column}_valid")


def upgrade() -> None:
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False, unique=True),
        sa.Column("subject_type", sa.String(16), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("subject_ref", sa.String(64), nullable=False),
        sa.Column("application_id", sa.Uuid(), sa.ForeignKey(f"{S}.applications.id")),
        sa.Column("provenance", sa.String(16), nullable=False),
        sa.Column("requested_by_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_label", sa.String(254), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("failure", sa.String(500)),
        sa.Column("prompt_risk", sa.SmallInteger(), nullable=False),
        sa.Column("risk_signals", postgresql.JSONB(), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("input_chars", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("output", postgresql.JSONB()),
        sa.Column("created_at", TS, nullable=False),
        _in("subject_type", ["security_event", "incident", "vulnerability", "threat_model"]),
        _in("status", ["completed", "rejected", "failed"]),
        _in("provenance", ["REAL_AWS", "LOCAL", "SIMULATED", "DEMO"]),
        sa.CheckConstraint("prompt_risk BETWEEN 0 AND 100", name="prompt_risk_range"),
        sa.CheckConstraint(
            "(status = 'completed') = (output IS NOT NULL)", name="output_only_when_completed"
        ),
        schema=S,
    )
    op.create_index(
        "ix_ai_analyses_subject", "ai_analyses", ["subject_type", "subject_id"], schema=S
    )
    op.create_index(
        "ix_ai_analyses_requested", "ai_analyses", ["requested_by_id", "created_at"], schema=S
    )
    op.create_index("ix_ai_analyses_created_at", "ai_analyses", ["created_at"], schema=S)

    op.create_table(
        "ai_proposals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False, unique=True),
        sa.Column("analysis_id", sa.Uuid(), sa.ForeignKey(f"{S}.ai_analyses.id"), nullable=False),
        sa.Column("action_type", sa.String(24), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("decided_by_id", sa.Uuid()),
        sa.Column("decided_by_label", sa.String(254)),
        sa.Column("decided_at", TS),
        sa.Column("decision_note", sa.String(2000)),
        sa.Column("result_ref", sa.String(64)),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        _in("action_type", ["open_incident", "raise_change_request", "add_threat"]),
        _in("status", ["proposed", "approved", "rejected"]),
        sa.CheckConstraint(
            "(status = 'proposed') = (decided_at IS NULL)", name="decided_has_decision"
        ),
        sa.CheckConstraint(
            "status <> 'approved' OR result_ref IS NOT NULL", name="approved_has_result"
        ),
        schema=S,
    )
    op.create_index(op.f("ix_ai_proposals_analysis_id"), "ai_proposals", ["analysis_id"], schema=S)
    op.create_index("ix_ai_proposals_status", "ai_proposals", ["status"], schema=S)

    # A decision is permanent. The function pins its search_path; constant identifiers only.
    op.execute(
        f"""
        CREATE FUNCTION {S}.ai_proposal_decision_final() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
          IF OLD.status <> 'proposed' THEN
            RAISE EXCEPTION 'AI proposal % has been decided and cannot be changed', OLD.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          IF NEW.action_type IS DISTINCT FROM OLD.action_type
             OR NEW.payload IS DISTINCT FROM OLD.payload
             OR NEW.rationale IS DISTINCT FROM OLD.rationale
             OR NEW.analysis_id IS DISTINCT FROM OLD.analysis_id
          THEN
            RAISE EXCEPTION 'AI proposal % cannot be rewritten', OLD.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        f"CREATE TRIGGER ai_proposals_decision_final BEFORE UPDATE ON {S}.ai_proposals "
        f"FOR EACH ROW EXECUTE FUNCTION {S}.ai_proposal_decision_final()"
    )
    grant_to_app("ai_analyses", "SELECT", "INSERT")
    grant_to_app("ai_proposals", "SELECT", "INSERT", "UPDATE")


def downgrade() -> None:
    op.drop_table("ai_proposals", schema=S)
    op.execute(f"DROP FUNCTION {S}.ai_proposal_decision_final()")
    op.drop_table("ai_analyses", schema=S)
