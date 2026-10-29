"""app attest keys and challenges

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-29 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "app_attest_keys",
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["accounts.id"],
            name=op.f("fk_app_attest_keys_account_id_accounts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("key_id", name=op.f("pk_app_attest_keys")),
    )
    op.create_index(
        op.f("ix_app_attest_keys_account_id"), "app_attest_keys", ["account_id"], unique=False
    )
    op.create_table(
        "app_attest_challenges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("challenge_sha256", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["accounts.id"],
            name=op.f("fk_app_attest_challenges_account_id_accounts"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_attest_challenges")),
        sa.UniqueConstraint(
            "challenge_sha256", name=op.f("uq_app_attest_challenges_challenge_sha256")
        ),
    )
    op.create_index(
        op.f("ix_app_attest_challenges_account_id"),
        "app_attest_challenges",
        ["account_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_app_attest_challenges_expires_at"),
        "app_attest_challenges",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_app_attest_challenges_expires_at"), table_name="app_attest_challenges")
    op.drop_index(op.f("ix_app_attest_challenges_account_id"), table_name="app_attest_challenges")
    op.drop_table("app_attest_challenges")
    op.drop_index(op.f("ix_app_attest_keys_account_id"), table_name="app_attest_keys")
    op.drop_table("app_attest_keys")
