"""policy copies

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-04 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policy_copies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["account_id"], ["accounts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_policy_copies_account_id", "policy_copies", ["account_id"])
    op.create_index("ix_policy_copies_sent_at", "policy_copies", ["sent_at"])


def downgrade() -> None:
    op.drop_index("ix_policy_copies_sent_at", table_name="policy_copies")
    op.drop_index("ix_policy_copies_account_id", table_name="policy_copies")
    op.drop_table("policy_copies")
