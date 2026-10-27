"""Auth tables. Nothing here is financial; contacts are stored only as keyed hashes."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime


class ContactKind(enum.StrEnum):
    EMAIL = "email"
    GOOGLE = "google"


class AuthEventKind(enum.StrEnum):
    SIGN_UP = "sign_up"
    SIGN_IN = "sign_in"
    SIGN_OUT = "sign_out"
    DEVICE_REVOKED = "device_revoked"
    REFRESH_REUSE = "refresh_reuse"


def _values(kind: type[enum.StrEnum]) -> list[str]:
    return [member.value for member in kind]


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (UniqueConstraint("contact_kind", "contact_hash", name="uq_accounts_contact"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    contact_kind: Mapped[ContactKind] = mapped_column(
        Enum(
            ContactKind, name="contact_kind", native_enum=False, length=16, values_callable=_values
        )
    )
    contact_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Device(Base):
    """One signed-in install. Revoking it ends its refresh chain and its access tokens."""

    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    contact_hash: Mapped[str] = mapped_column(String(64), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class AuthEvent(Base):
    __tablename__ = "auth_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("accounts.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, default=None)
    kind: Mapped[AuthEventKind] = mapped_column(
        Enum(
            AuthEventKind,
            name="auth_event_kind",
            native_enum=False,
            length=32,
            values_callable=_values,
        )
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
