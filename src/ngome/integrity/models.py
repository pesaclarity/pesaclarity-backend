"""App Attest keys and the one-time challenges they are registered with."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime


class AppAttestKey(Base):
    """A key an iPhone install generated and Apple attested. ``key_id`` is the hex SHA-256 of
    its public key, as Apple defines it."""

    __tablename__ = "app_attest_keys"

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AppAttestChallenge(Base):
    """A challenge sent to an account for one attestation. Only its SHA-256 is kept."""

    __tablename__ = "app_attest_challenges"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    challenge_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
