"""Threat modeling and the control catalogue (Phase 10).

Grants (each line is the complete privilege set for that table):
* controls, requirements: SELECT, INSERT, UPDATE. Loaded from the reviewed catalogue
  (app/governance/catalogue.json); a control dropped from the documents is retired, never
  deleted.
* threat_models, model_elements, threats: SELECT, INSERT, UPDATE. Retired or archived, never
  deleted.
* threat_controls, requirement_threats: SELECT, INSERT, DELETE. Link tables: changing a
  threat's controls replaces its links (audited).

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.migration_helpers import grant_to_app

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)
STRIDE_PATTERN = r"^([STRIDE](/[STRIDE]){0,5}|LLM\d{2})$"


def _check(column: str, values: Sequence[str]) -> sa.CheckConstraint:
    listed = ", ".join(f"'{v}'" for v in values)
    return sa.CheckConstraint(f"{column} IN ({listed})", name=f"{column}_valid")


def upgrade() -> None:
    op.create_table(
        "controls",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("ref", sa.String(16), nullable=False),
        sa.Column("family", sa.String(8), nullable=False),
        sa.Column("layer", sa.String(60)),
        sa.Column("title", sa.String(400), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("phase", sa.Integer(), nullable=False),
        sa.Column("implementation", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_text", sa.Text(), nullable=False),
        sa.Column("extensions", postgresql.JSONB(), nullable=False),
        sa.Column("retired", sa.Boolean(), nullable=False),
        sa.Column("synced_at", TS, nullable=False),
        sa.UniqueConstraint("ref"),
        _check("status", ("implemented", "planned")),
        sa.CheckConstraint("ref ~ '^C-[A-Z]+-[0-9]{2}$'", name="ref_format"),
        schema=S,
    )
    op.create_table(
        "threat_models",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "application_id", sa.Uuid(), sa.ForeignKey(f"{S}.applications.id"), nullable=False
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("origin", sa.String(12), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("version_label", sa.String(32), nullable=False),
        sa.Column("pasta", postgresql.JSONB(), nullable=False),
        sa.Column("catalogue_digest", sa.String(64)),
        sa.Column("created_by_label", sa.String(254), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("number"),
        _check("method", ("stride", "pasta")),
        _check("origin", ("catalogue", "app")),
        _check("status", ("draft", "active", "archived")),
        sa.CheckConstraint(
            "(origin = 'catalogue') = (catalogue_digest IS NOT NULL)", name="catalogue_has_digest"
        ),
        schema=S,
    )
    op.create_index(
        op.f("ix_threat_models_application_id"), "threat_models", ["application_id"], schema=S
    )
    op.create_index(
        "uq_threat_models_catalogue",
        "threat_models",
        ["application_id"],
        unique=True,
        schema=S,
        postgresql_where=sa.text("origin = 'catalogue'"),
    )
    op.create_table(
        "model_elements",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("model_id", sa.Uuid(), sa.ForeignKey(f"{S}.threat_models.id"), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("ref", sa.String(16), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("attributes", postgresql.JSONB(), nullable=False),
        sa.Column("retired", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.UniqueConstraint("model_id", "kind", "ref", name="uq_model_elements_ref"),
        _check("kind", ("asset", "boundary", "flow", "attack_path", "residual_risk")),
        schema=S,
    )
    op.create_index(op.f("ix_model_elements_model_id"), "model_elements", ["model_id"], schema=S)
    op.create_table(
        "threats",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("model_id", sa.Uuid(), sa.ForeignKey(f"{S}.threat_models.id"), nullable=False),
        sa.Column("ref", sa.String(16), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("stride", sa.String(16), nullable=False),
        sa.Column("owasp", sa.String(64), nullable=False),
        sa.Column("group_name", sa.String(200), nullable=False),
        sa.Column("boundaries", postgresql.JSONB(), nullable=False),
        sa.Column("likelihood", sa.Integer(), nullable=False),
        sa.Column("impact", sa.Integer(), nullable=False),
        sa.Column("mitigation", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("status_text", sa.Text(), nullable=False),
        sa.Column("phases", postgresql.JSONB(), nullable=False),
        sa.Column("retired", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("model_id", "ref", name="uq_threats_ref"),
        _check(
            "status",
            (
                "open",
                "planned",
                "partly_mitigated",
                "mitigated",
                "accepted",
                "not_exposed",
                "closed",
            ),
        ),
        sa.CheckConstraint("likelihood BETWEEN 1 AND 3", name="likelihood_range"),
        sa.CheckConstraint("impact BETWEEN 1 AND 3", name="impact_range"),
        sa.CheckConstraint(f"stride ~ '{STRIDE_PATTERN}'", name="stride_format"),
        schema=S,
    )
    op.create_index(op.f("ix_threats_model_id"), "threats", ["model_id"], schema=S)
    op.create_table(
        "threat_controls",
        sa.Column("threat_id", sa.Uuid(), sa.ForeignKey(f"{S}.threats.id"), primary_key=True),
        sa.Column("control_id", sa.Uuid(), sa.ForeignKey(f"{S}.controls.id"), primary_key=True),
        schema=S,
    )
    op.create_index(
        op.f("ix_threat_controls_control_id"), "threat_controls", ["control_id"], schema=S
    )
    op.create_table(
        "requirements",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("ref", sa.String(8), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("control_text", sa.Text(), nullable=False),
        sa.Column("implementation", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_text", sa.Text(), nullable=False),
        sa.Column("phase_text", sa.String(100), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("retired", sa.Boolean(), nullable=False),
        sa.UniqueConstraint("ref"),
        sa.CheckConstraint("ref ~ '^REQ-[0-9]{2,3}$'", name="ref_format"),
        schema=S,
    )
    op.create_table(
        "requirement_threats",
        sa.Column(
            "requirement_id",
            sa.Uuid(),
            sa.ForeignKey(f"{S}.requirements.id"),
            primary_key=True,
        ),
        sa.Column("threat_id", sa.Uuid(), sa.ForeignKey(f"{S}.threats.id"), primary_key=True),
        schema=S,
    )
    op.create_index(
        op.f("ix_requirement_threats_threat_id"), "requirement_threats", ["threat_id"], schema=S
    )

    grant_to_app("controls", "SELECT", "INSERT", "UPDATE")
    grant_to_app("requirements", "SELECT", "INSERT", "UPDATE")
    grant_to_app("threat_models", "SELECT", "INSERT", "UPDATE")
    grant_to_app("model_elements", "SELECT", "INSERT", "UPDATE")
    grant_to_app("threats", "SELECT", "INSERT", "UPDATE")
    grant_to_app("threat_controls", "SELECT", "INSERT", "DELETE")
    grant_to_app("requirement_threats", "SELECT", "INSERT", "DELETE")


def downgrade() -> None:
    op.drop_table("requirement_threats", schema=S)
    op.drop_table("requirements", schema=S)
    op.drop_table("threat_controls", schema=S)
    op.drop_table("threats", schema=S)
    op.drop_table("model_elements", schema=S)
    op.drop_table("threat_models", schema=S)
    op.drop_table("controls", schema=S)
