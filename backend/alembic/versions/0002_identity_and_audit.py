"""Identity, sessions, local outbox and the tamper-evident audit log.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db.migration_helpers import grant_to_app

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)
ROLES = ("ADMIN", "SECURITY_ENGINEER", "DEVELOPER", "ANALYST", "VIEWER")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("mfa_secret", sa.LargeBinary()),
        sa.Column("mfa_pending_secret", sa.LargeBinary()),
        sa.Column("mfa_last_used_step", sa.BigInteger()),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", TS),
        sa.Column("password_changed_at", TS, nullable=False),
        sa.Column("last_login_at", TS),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("updated_at", TS, nullable=False),
        sa.CheckConstraint(
            "role IN (" + ", ".join(f"'{r}'" for r in ROLES) + ")", name="role_valid"
        ),
        sa.CheckConstraint("email = lower(email)", name="email_lowercase"),
        sa.CheckConstraint("failed_login_count >= 0", name="failed_count_nonnegative"),
        sa.UniqueConstraint("email"),
        schema=S,
    )
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey(f"{S}.users.id"), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("last_used_at", TS),
        sa.Column("revoked_at", TS),
        sa.Column("revoked_reason", sa.String(64)),
        sa.Column("mfa_verified", sa.Boolean(), nullable=False),
        sa.Column("created_ip", sa.String(45)),
        sa.Column("user_agent", sa.String(256)),
        schema=S,
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"], schema=S)
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), sa.ForeignKey(f"{S}.auth_sessions.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("issued_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS),
        sa.UniqueConstraint("token_hash"),
        schema=S,
    )
    op.create_index("ix_refresh_tokens_session_id", "refresh_tokens", ["session_id"], schema=S)
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey(f"{S}.users.id"), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("used_at", TS),
        schema=S,
    )
    op.create_index("ix_mfa_recovery_codes_user_id", "mfa_recovery_codes", ["user_id"], schema=S)
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey(f"{S}.users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS),
        sa.Column("requested_ip", sa.String(45)),
        sa.UniqueConstraint("token_hash"),
        schema=S,
    )
    op.create_index(
        "ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"], schema=S
    )
    op.create_table(
        "outbox_messages",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("recipient", sa.String(254), nullable=False),
        sa.Column("subject", sa.String(200), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", TS, nullable=False),
        schema=S,
    )
    op.create_table(
        "audit_log",
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("occurred_at", TS, nullable=False),
        sa.Column("actor_id", sa.Uuid()),
        sa.Column("actor_label", sa.String(254), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(64)),
        sa.Column("resource_id", sa.String(128)),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("source_ip", sa.String(45)),
        sa.Column("correlation_id", sa.String(64)),
        sa.Column("details", postgresql.JSONB(), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("result IN ('success', 'failure', 'denied')", name="result_valid"),
        sa.CheckConstraint("record_hash ~ '^[0-9a-f]{64}$'", name="record_hash_format"),
        sa.CheckConstraint("prev_hash ~ '^[0-9a-f]{64}$'", name="prev_hash_format"),
        sa.UniqueConstraint("id"),
        sa.UniqueConstraint("record_hash"),
        schema=S,
    )
    op.create_index("ix_audit_log_actor_id", "audit_log", ["actor_id"], schema=S)
    op.create_index("ix_audit_log_action", "audit_log", ["action"], schema=S)

    # Append-only enforcement that does not depend on grants (ADR-0005). The function pins its
    # search_path so it cannot be hijacked by objects in another schema.
    op.execute(
        f"""
        CREATE FUNCTION {S}.audit_log_append_only() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
          RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP
            USING ERRCODE = 'insufficient_privilege';
        END
        $$
        """
    )
    op.execute(
        f"CREATE TRIGGER audit_log_no_update_delete BEFORE UPDATE OR DELETE ON {S}.audit_log "
        f"FOR EACH ROW EXECUTE FUNCTION {S}.audit_log_append_only()"
    )
    op.execute(
        f"CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON {S}.audit_log "
        f"FOR EACH STATEMENT EXECUTE FUNCTION {S}.audit_log_append_only()"
    )

    # Least-privilege grants: each line is the complete privilege set for that table.
    grant_to_app("users", "SELECT", "INSERT", "UPDATE")  # deactivate, never delete
    grant_to_app("auth_sessions", "SELECT", "INSERT", "UPDATE")
    grant_to_app("refresh_tokens", "SELECT", "INSERT", "UPDATE")
    grant_to_app("mfa_recovery_codes", "SELECT", "INSERT", "UPDATE", "DELETE")
    grant_to_app("password_reset_tokens", "SELECT", "INSERT", "UPDATE")
    grant_to_app("outbox_messages", "SELECT", "INSERT")
    grant_to_app("audit_log", "SELECT", "INSERT")


def downgrade() -> None:
    # Dropping the audit log destroys evidence. Migrations only go backwards in development;
    # the downgrade exists so the migration history stays testable (test_migrations_are_reversible).
    op.drop_table("audit_log", schema=S)
    op.execute(f"DROP FUNCTION {S}.audit_log_append_only()")
    op.drop_table("outbox_messages", schema=S)
    op.drop_table("password_reset_tokens", schema=S)
    op.drop_table("mfa_recovery_codes", schema=S)
    op.drop_table("refresh_tokens", schema=S)
    op.drop_table("auth_sessions", schema=S)
    op.drop_table("users", schema=S)
