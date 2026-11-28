"""group sync for shared spaces, served by this backend (decision 0035)

Five tables for the relay: spaces, members, the batch index, seen nonces and the note a push
leaves before it writes an object. None holds an account id or has a foreign key to the
account tables; batch bytes go to the blob store.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-28 15:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sync_nonces",
        sa.Column("space_id", sa.String(length=64), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("space_id", "nonce", name=op.f("pk_sync_nonces")),
    )
    op.create_index(op.f("ix_sync_nonces_expires_at"), "sync_nonces", ["expires_at"], unique=False)
    op.create_table(
        "sync_pending_blobs",
        sa.Column("object_key", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("object_key", name=op.f("pk_sync_pending_blobs")),
    )
    op.create_index(
        op.f("ix_sync_pending_blobs_created_at"),
        "sync_pending_blobs",
        ["created_at"],
        unique=False,
    )
    op.create_table(
        "sync_spaces",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("owner_key", sa.String(length=43), nullable=False),
        sa.Column("valid_until", sa.BigInteger(), nullable=False),
        sa.Column("last_cursor", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sync_spaces")),
    )
    op.create_table(
        "sync_batches",
        sa.Column("space_id", sa.String(length=64), nullable=False),
        sa.Column("cursor", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("batch_id", sa.String(length=64), nullable=False),
        sa.Column("author", sa.String(length=43), nullable=False),
        sa.Column("recipient", sa.String(length=43), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("hash", sa.String(length=43), nullable=False),
        sa.Column("at", sa.BigInteger(), nullable=False),
        sa.Column("object_key", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(
            ["space_id"],
            ["sync_spaces.id"],
            name=op.f("fk_sync_batches_space_id_sync_spaces"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("space_id", "cursor", name=op.f("pk_sync_batches")),
        sa.UniqueConstraint("object_key", name=op.f("uq_sync_batches_object_key")),
        sa.UniqueConstraint("space_id", "batch_id", name="uq_sync_batches_batch"),
    )
    op.create_index(op.f("ix_sync_batches_at"), "sync_batches", ["at"], unique=False)
    op.create_table(
        "sync_members",
        sa.Column("space_id", sa.String(length=64), nullable=False),
        sa.Column("key", sa.String(length=43), nullable=False),
        sa.Column("added_at", sa.BigInteger(), nullable=False),
        sa.Column("acked", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["space_id"],
            ["sync_spaces.id"],
            name=op.f("fk_sync_members_space_id_sync_spaces"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("space_id", "key", name=op.f("pk_sync_members")),
    )


def downgrade() -> None:
    op.drop_table("sync_members")
    op.drop_index(op.f("ix_sync_batches_at"), table_name="sync_batches")
    op.drop_table("sync_batches")
    op.drop_table("sync_spaces")
    op.drop_index(op.f("ix_sync_pending_blobs_created_at"), table_name="sync_pending_blobs")
    op.drop_table("sync_pending_blobs")
    op.drop_index(op.f("ix_sync_nonces_expires_at"), table_name="sync_nonces")
    op.drop_table("sync_nonces")
