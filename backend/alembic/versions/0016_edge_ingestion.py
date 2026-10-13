"""Real AWS WAF blocks and certificate checks become security events (Phase 5, ADR-0029).

Events the API reads from outside, WAF log records and certificate checks, carry
`evidence.dedupe_key`; a partial unique index on it means a record pulled twice, by an
overlapping sync or a second API task, is stored once. No new grants: the app role already
inserts security events.

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-13
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "CREATE UNIQUE INDEX ux_security_events_dedupe_key ON sentinel.security_events "
        "((evidence ->> 'dedupe_key')) WHERE evidence ? 'dedupe_key'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX sentinel.ux_security_events_dedupe_key")
