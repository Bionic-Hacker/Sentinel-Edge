"""Administrators issue temporary passwords; no email path (ADR-0028).

New users and forgotten passwords no longer go through a link in a local outbox that only the
operator could read: an administrator creates the account (or resets its password) and is shown
a generated temporary password once. The user must replace it at first sign-in, and it stops
working after a set time if unused (users.temporary_password_expires_at).

The outbox and the reset-link tokens are dropped. Neither held anything worth keeping: messages
carried only links, and the tokens only hashes of them. The audit log keeps every past invitation
and reset.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.db.migration_helpers import grant_to_app

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("users", sa.Column("temporary_password_expires_at", TS), schema=S)
    op.drop_table("outbox_messages", schema=S)
    op.drop_index("ix_password_reset_tokens_user_id", "password_reset_tokens", schema=S)
    op.drop_table("password_reset_tokens", schema=S)


def downgrade() -> None:
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
    grant_to_app("password_reset_tokens", "SELECT", "INSERT", "UPDATE", "DELETE")
    grant_to_app("outbox_messages", "SELECT", "INSERT")
    op.drop_column("users", "temporary_password_expires_at", schema=S)
