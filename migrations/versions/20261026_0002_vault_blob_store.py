"""move backup ciphertext behind a blob store

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-26 12:00:00.000000
"""

import secrets
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vault_blobs",
        sa.Column("object_key", sa.String(length=128), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("object_key", name=op.f("pk_vault_blobs")),
    )
    op.create_table(
        "vault_blob_deletions",
        sa.Column("object_key", sa.String(length=128), nullable=False),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("object_key", name=op.f("pk_vault_blob_deletions")),
    )
    op.create_index(
        op.f("ix_vault_blob_deletions_queued_at"),
        "vault_blob_deletions",
        ["queued_at"],
        unique=False,
    )

    with op.batch_alter_table("backups") as batch:
        batch.add_column(sa.Column("object_key", sa.String(length=128), nullable=True))

    # Existing ciphertext moves into the Postgres blob store under fresh random keys.
    bind = op.get_bind()
    backups = sa.table(
        "backups",
        sa.column("id", sa.Uuid()),
        sa.column("object_key", sa.String()),
        sa.column("ciphertext", sa.LargeBinary()),
    )
    blobs = sa.table(
        "vault_blobs", sa.column("object_key", sa.String()), sa.column("data", sa.LargeBinary())
    )
    for (backup_id,) in bind.execute(sa.select(backups.c.id)).all():
        key = f"backups/{secrets.token_hex(16)}"
        bind.execute(backups.update().where(backups.c.id == backup_id).values(object_key=key))
    bind.execute(
        blobs.insert().from_select(
            ["object_key", "data"], sa.select(backups.c.object_key, backups.c.ciphertext)
        )
    )

    with op.batch_alter_table("backups") as batch:
        batch.alter_column("object_key", existing_type=sa.String(length=128), nullable=False)
        batch.create_unique_constraint(op.f("uq_backups_object_key"), ["object_key"])
        batch.drop_column("ciphertext")


def downgrade() -> None:
    with op.batch_alter_table("backups") as batch:
        batch.add_column(sa.Column("ciphertext", sa.LargeBinary(), nullable=True))

    bind = op.get_bind()
    backups = sa.table(
        "backups", sa.column("object_key", sa.String()), sa.column("ciphertext", sa.LargeBinary())
    )
    blobs = sa.table(
        "vault_blobs", sa.column("object_key", sa.String()), sa.column("data", sa.LargeBinary())
    )
    bind.execute(
        backups.update().values(
            ciphertext=sa.select(blobs.c.data)
            .where(blobs.c.object_key == backups.c.object_key)
            .scalar_subquery()
        )
    )
    # Backups held in object storage cannot be brought back into this table.
    bind.execute(backups.delete().where(backups.c.ciphertext.is_(None)))

    with op.batch_alter_table("backups") as batch:
        batch.alter_column("ciphertext", existing_type=sa.LargeBinary(), nullable=False)
        batch.drop_constraint(op.f("uq_backups_object_key"), type_="unique")
        batch.drop_column("object_key")

    op.drop_index(op.f("ix_vault_blob_deletions_queued_at"), table_name="vault_blob_deletions")
    op.drop_table("vault_blob_deletions")
    op.drop_table("vault_blobs")
