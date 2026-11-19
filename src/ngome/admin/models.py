"""Admin passkeys, sessions and the short-lived rows of the passkey ceremonies.

Sessions, enrolment links and challenges are stored as SHA-256 digests of their random ids,
so a copy of the database cannot be used to sign in.
"""

import uuid
from datetime import datetime

from sqlalchemy import Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime


class AdminPasskey(Base):
    """A passkey on the allow-list. Only these credentials can sign in."""

    __tablename__ = "admin_passkeys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(1023), unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(2048))
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    label: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AdminSession(Base):
    """A signed-in browser, for ``admin_session_hours``. Sign-out deletes it."""

    __tablename__ = "admin_sessions"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    passkey_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class AdminEnrolment(Base):
    """A single-use link to register a passkey, minted with the admin token."""

    __tablename__ = "admin_enrolments"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    label: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AdminChallenge(Base):
    """A WebAuthn challenge, used once. ``purpose`` is ``register`` or ``sign_in``."""

    __tablename__ = "admin_challenges"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(16))
    challenge: Mapped[bytes] = mapped_column(LargeBinary(64))
    enrolment_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
