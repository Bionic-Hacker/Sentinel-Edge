"""Each user's colour theme, light or dark, saved with their account.

The web app offers a light theme (the default) and the original dark theme, switched from the
page header. The choice is stored on the user rather than in the browser: web storage stays
banned for the SPA (ADR-0003), and the setting follows the user to any device.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

S = "sentinel"


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("theme", sa.String(8), nullable=False, server_default="light"),
        schema=S,
    )
    op.create_check_constraint(
        "ck_users_theme_valid", "users", "theme IN ('light', 'dark')", schema=S
    )


def downgrade() -> None:
    op.drop_constraint("ck_users_theme_valid", "users", type_="check", schema=S)
    op.drop_column("users", "theme", schema=S)
