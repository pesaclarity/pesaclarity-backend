"""Vault tables: backup metadata, the Postgres blob store and the object deletion queue."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime

OBJECT_KEY_LENGTH = 128


class Backup(Base):
    """Metadata for one backup. The ciphertext itself lives in the blob store under
    ``object_key``."""

    __tablename__ = "backups"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    object_key: Mapped[str] = mapped_column(String(OBJECT_KEY_LENGTH), unique=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class StoredBlob(Base):
    """Ciphertext for the ``postgres`` blob store. Unused when backups go to object storage."""

    __tablename__ = "vault_blobs"

    object_key: Mapped[str] = mapped_column(String(OBJECT_KEY_LENGTH), primary_key=True)
    data: Mapped[bytes] = mapped_column(LargeBinary)


class BlobDeletion(Base):
    """An object whose metadata is gone but which may still be in the blob store.

    Rows are written in the same transaction that removes the metadata and cleared once the
    store confirms the delete, so a failed delete is retried rather than forgotten.
    """

    __tablename__ = "vault_blob_deletions"

    object_key: Mapped[str] = mapped_column(String(OBJECT_KEY_LENGTH), primary_key=True)
    queued_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
