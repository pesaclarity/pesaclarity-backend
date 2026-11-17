"""app notices

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-17 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_notices",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=80), nullable=False),
        sa.Column("body", sa.String(length=500), nullable=False),
        sa.Column("latest_version", sa.String(length=64), nullable=True),
        sa.Column("min_version", sa.String(length=64), nullable=True),
        sa.Column("required_reason", sa.String(length=32), nullable=True),
        sa.Column("builds", sa.JSON(), nullable=False),
        sa.Column("reread_from", sa.Date(), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_notices")),
    )


def downgrade() -> None:
    op.drop_table("app_notices")
