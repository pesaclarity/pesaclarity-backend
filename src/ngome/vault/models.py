"""Vault table: opaque ciphertext plus the minimum metadata needed to list and verify it."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime


class Backup(Base):
    __tablename__ = "backups"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # TODO(storage): move blobs to object storage once backups outgrow Postgres.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
