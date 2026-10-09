"""Security exceptions and change management (Phase 10).

Grants (each line is the complete privilege set for that table):
* exceptions, change_requests: SELECT, INSERT, UPDATE. Withdrawn, expired, closed, rejected or
  rolled back, never deleted.

Two triggers make a decision permanent: once an exception or a change request has been decided,
the request (what, why, risk, controls, expiry or plan) and the decision (who approved it, when,
with what note) can no longer change, for any role. Only the outcome can still be recorded: an
exception's end, a change's implementation (once) and its validation or rollback.

EXC-0001 and EXC-0002 are migrated from docs/governance/exceptions.md, marked as imported:
they were approved by the project owner before separation of duties was enforced.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-08
"""

from collections.abc import Sequence
from datetime import UTC, date, datetime
from uuid import UUID

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.migration_helpers import grant_to_app

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)
PLATFORM_APP_ID = UUID("5e7e1ed6-0000-4000-8000-000000000001")
RISK = ("low", "medium", "high", "critical")
SOD = "approver_id IS NULL OR requester_id IS NULL OR approver_id <> requester_id"


def _check(column: str, values: Sequence[str]) -> sa.CheckConstraint:
    listed = ", ".join(f"'{v}'" for v in values)
    return sa.CheckConstraint(f"{column} IN ({listed})", name=f"{column}_valid")


def _people() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column("requester_id", sa.Uuid()),
        sa.Column("requester_label", sa.String(254), nullable=False),
        sa.Column("approver_id", sa.Uuid()),
        sa.Column("approver_label", sa.String(254)),
        sa.Column("decided_at", TS),
        sa.Column("decision_note", sa.Text()),
    ]


EXCEPTION_DECISION = (
    "application_id, title, scope, scope_ref, gate_match, risk_level, risk, justification, "
    "compensating_control, control_refs, implementation, exit_criteria, expires_on, "
    "requester_id, requester_label, approver_id, approver_label, decided_at, decision_note"
)
CHANGE_DECISION = (
    "application_id, title, change_type, description, risk_level, impact, rollback_plan, "
    "validation_plan, target, requester_id, requester_label, approver_id, approver_label, "
    "decided_at, decision_note"
)
SEED_COLUMNS = (
    "id",
    "application_id",
    "title",
    "scope",
    "scope_ref",
    "risk_level",
    "risk",
    "justification",
    "compensating_control",
    "implementation",
    "exit_criteria",
    "expires_on",
    "status",
    "requester_label",
    "approver_label",
    "decided_at",
    "decision_note",
    "imported",
    "created_at",
    "updated_at",
    "version",
)
CHANGE_IMPLEMENTATION = "previous_state, implemented_at, implemented_by_label, implementation_ref"


def _row(columns: str, alias: str) -> str:
    return "(" + ", ".join(f"{alias}.{c.strip()}" for c in columns.split(",")) + ")"


def upgrade() -> None:
    op.create_table(
        "exceptions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "application_id", sa.Uuid(), sa.ForeignKey(f"{S}.applications.id"), nullable=False
        ),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("scope_ref", sa.String(200), nullable=False),
        sa.Column("gate_match", postgresql.JSONB()),
        sa.Column("risk_level", sa.String(8), nullable=False),
        sa.Column("risk", sa.Text(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("compensating_control", sa.Text(), nullable=False),
        sa.Column("control_refs", postgresql.JSONB(), nullable=False),
        sa.Column("implementation", sa.Text(), nullable=False),
        sa.Column("exit_criteria", sa.Text(), nullable=False),
        sa.Column("expires_on", sa.Date(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        *_people(),
        sa.Column("ended_at", TS),
        sa.Column("end_note", sa.Text()),
        sa.Column("imported", sa.Boolean(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("number"),
        _check("scope", ("dependency", "scan_finding", "control", "configuration", "other")),
        _check("risk_level", RISK),
        _check("status", ("requested", "approved", "rejected", "withdrawn", "expired", "closed")),
        sa.CheckConstraint(SOD, name="approver_is_not_requester"),
        sa.CheckConstraint(
            "status IN ('requested', 'withdrawn') OR approver_label IS NOT NULL",
            name="decided_has_approver",
        ),
        sa.CheckConstraint(
            "(scope = 'scan_finding') = (gate_match IS NOT NULL)", name="gate_match"
        ),
        schema=S,
    )
    op.create_index(
        op.f("ix_exceptions_application_id"), "exceptions", ["application_id"], schema=S
    )
    op.create_index("ix_exceptions_status", "exceptions", ["status"], schema=S)

    op.create_table(
        "change_requests",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("number", sa.Integer(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "application_id", sa.Uuid(), sa.ForeignKey(f"{S}.applications.id"), nullable=False
        ),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("change_type", sa.String(16), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.String(8), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("rollback_plan", sa.Text(), nullable=False),
        sa.Column("validation_plan", sa.Text(), nullable=False),
        sa.Column("target", postgresql.JSONB()),
        sa.Column("previous_state", postgresql.JSONB()),
        sa.Column("status", sa.String(12), nullable=False),
        *_people(),
        sa.Column("implemented_at", TS),
        sa.Column("implemented_by_label", sa.String(254)),
        sa.Column("implementation_ref", sa.String(300)),
        sa.Column("closed_at", TS),
        sa.Column("closing_note", sa.Text()),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("number"),
        _check("change_type", ("waf_rule", "configuration", "access", "deployment", "other")),
        _check("risk_level", RISK),
        _check(
            "status",
            (
                "submitted",
                "approved",
                "rejected",
                "cancelled",
                "implemented",
                "validated",
                "rolled_back",
            ),
        ),
        sa.CheckConstraint(SOD, name="approver_is_not_requester"),
        sa.CheckConstraint(
            "status IN ('submitted', 'cancelled') OR approver_label IS NOT NULL",
            name="decided_has_approver",
        ),
        sa.CheckConstraint("(change_type = 'waf_rule') = (target IS NOT NULL)", name="waf_target"),
        schema=S,
    )
    op.create_index(
        op.f("ix_change_requests_application_id"), "change_requests", ["application_id"], schema=S
    )
    op.create_index("ix_change_requests_status", "change_requests", ["status"], schema=S)

    # A decision is permanent, for every role, including the table owner. The functions pin
    # their search_path so they cannot be hijacked. Constant identifiers only.
    op.execute(
        f"""
        CREATE FUNCTION {S}.exception_decision_final() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
          IF OLD.status <> 'requested'
             AND {_row(EXCEPTION_DECISION, "NEW")}
                 IS DISTINCT FROM {_row(EXCEPTION_DECISION, "OLD")}
          THEN
            RAISE EXCEPTION 'exception % has been decided and cannot be rewritten', OLD.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        f"CREATE TRIGGER exceptions_decision_final BEFORE UPDATE ON {S}.exceptions "
        f"FOR EACH ROW EXECUTE FUNCTION {S}.exception_decision_final()"
    )
    op.execute(
        f"""
        CREATE FUNCTION {S}.change_decision_final() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
          IF OLD.status <> 'submitted'
             AND {_row(CHANGE_DECISION, "NEW")} IS DISTINCT FROM {_row(CHANGE_DECISION, "OLD")}
          THEN
            RAISE EXCEPTION 'change request % has been decided and cannot be rewritten', OLD.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          IF OLD.implemented_at IS NOT NULL
             AND {_row(CHANGE_IMPLEMENTATION, "NEW")}
                 IS DISTINCT FROM {_row(CHANGE_IMPLEMENTATION, "OLD")}
          THEN
            RAISE EXCEPTION 'change request % was implemented; that record is final', OLD.id
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        f"CREATE TRIGGER change_requests_decision_final BEFORE UPDATE ON {S}.change_requests "
        f"FOR EACH ROW EXECUTE FUNCTION {S}.change_decision_final()"
    )

    exceptions = sa.table(
        "exceptions",
        *(sa.column(c) for c in SEED_COLUMNS),
        sa.column("control_refs", postgresql.JSONB()),
        schema=S,
    )
    raised = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)
    common = {
        "application_id": PLATFORM_APP_ID,
        "scope": "dependency",
        "risk_level": "low",
        "expires_on": date(2027, 1, 7),
        "status": "approved",
        "requester_label": "Bionic-Hacker (project owner)",
        "approver_label": "Bionic-Hacker",
        "decided_at": raised,
        "decision_note": (
            "Imported from docs/governance/exceptions.md; approved before separation of duties "
            "was enforced in the application."
        ),
        "imported": True,
        "created_at": raised,
        "updated_at": raised,
        "version": 1,
    }
    op.bulk_insert(
        exceptions,
        [
            {
                **common,
                "id": UUID("5e7e1ed6-0000-4000-8000-0000000e0001"),
                "title": "ESLint held on major version 9",
                "scope_ref": "frontend dev tooling: eslint, @eslint/js",
                "risk": (
                    "ESLint 9 no longer receives upstream support. ESLint is a development-time "
                    "tool never shipped to users; the residual risk is missing future lint-rule "
                    "improvements and fixes in the linter itself."
                ),
                "justification": (
                    "The accessibility rule set (eslint-plugin-jsx-a11y, whose latest release "
                    "supports ESLint 9 at most) is a required quality control for the UI. "
                    "Upgrading would mean removing it or forcing an unsupported install, which "
                    "defeats lockfile integrity."
                ),
                "compensating_control": (
                    "npm audit gates every CI run; all security lint rules still run on every "
                    "commit; Dependabot still proposes ESLint 9.x minor and patch updates."
                ),
                "control_refs": ["C-CICD-02", "C-WEB-03"],
                "implementation": (
                    ".github/dependabot.yml ignores semver-major updates of eslint and "
                    "@eslint/js (comment EXC-0001)."
                ),
                "exit_criteria": (
                    "eslint-plugin-jsx-a11y publishes a release supporting ESLint 10; then "
                    "upgrade and close."
                ),
            },
            {
                **common,
                "id": UUID("5e7e1ed6-0000-4000-8000-0000000e0002"),
                "title": "TypeScript held below major version 7",
                "scope_ref": "frontend dev tooling: typescript",
                "risk": (
                    "TypeScript is a build-time tool; its output is plain JavaScript, scanned by "
                    "npm audit like any other dependency."
                ),
                "justification": (
                    "Type-aware lint rules from typescript-eslint (which supports TypeScript "
                    "below 6.1) are part of the frontend quality gate."
                ),
                "compensating_control": (
                    "tsc strict mode and all lint rules continue to gate every commit; minor and "
                    "patch updates still flow."
                ),
                "control_refs": ["C-CICD-02", "C-WEB-03"],
                "implementation": (
                    ".github/dependabot.yml ignores semver-major updates of typescript "
                    "(comment EXC-0002)."
                ),
                "exit_criteria": "typescript-eslint supports TypeScript 7; then upgrade and close.",
            },
        ],
    )

    grant_to_app("exceptions", "SELECT", "INSERT", "UPDATE")
    grant_to_app("change_requests", "SELECT", "INSERT", "UPDATE")


def downgrade() -> None:
    op.execute(f"DROP TRIGGER change_requests_decision_final ON {S}.change_requests")
    op.execute(f"DROP FUNCTION {S}.change_decision_final()")
    op.execute(f"DROP TRIGGER exceptions_decision_final ON {S}.exceptions")
    op.execute(f"DROP FUNCTION {S}.exception_decision_final()")
    op.drop_table("change_requests", schema=S)
    op.drop_table("exceptions", schema=S)
