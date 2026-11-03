"""backup space

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-03 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "backups",
        sa.Column("space", sa.String(length=32), nullable=False, server_default="personal"),
    )


def downgrade() -> None:
    op.drop_column("backups", "space")
