"""Baseline: establishes the migration history in the sentinel schema.

The schema itself and both roles are created by db/bootstrap-roles.sh (ADR-0015). Tables arrive
in later revisions, each granting the app role only the privileges it needs.

Revision ID: 0001
Revises:
Create Date: 2026-10-07
"""

from collections.abc import Sequence

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
