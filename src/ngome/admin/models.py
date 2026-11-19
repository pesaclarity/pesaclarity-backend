"""The admin user, its second factors, sessions, limits and audit log (ADR 0025).

Session, sign-in and challenge ids, email codes and recovery codes are stored only as
digests; the password as an Argon2id hash; the authenticator secret encrypted with
``NGOME_ADMIN_SECRET_KEY``. Client addresses are never stored: limits and the audit log
hold a keyed hash of them. A copy of the database cannot be used to sign in.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ngome.core.security import utcnow
from ngome.db.base import Base, UTCDateTime


class AdminUser(Base):
    """The one admin user. Made (or reset) with the admin token's starter command."""

    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # A starter password: works for one sign-in, until ``temporary_until``.
    password_temporary: Mapped[bool] = mapped_column(Boolean, default=True)
    temporary_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # The authenticator: AES-256-GCM ciphertext of the TOTP secret, its nonce, and the last
    # time step accepted (codes for that step or earlier are refused: each works once).
    totp_secret: Mapped[bytes | None] = mapped_column(LargeBinary(64), nullable=True)
    totp_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12), nullable=True)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    totp_added_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    totp_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # A new secret being set up, kept until a code from it verifies.
    totp_pending: Mapped[bytes | None] = mapped_column(LargeBinary(64), nullable=True)
    totp_pending_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12), nullable=True)
    recovery_made_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AdminRecoveryCode(Base):
    """One recovery code's keyed hash. Each works once."""

    __tablename__ = "admin_recovery_codes"

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AdminPasskey(Base):
    """A passkey: an optional second factor, after the password."""

    __tablename__ = "admin_passkeys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(1023), unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(2048))
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    label: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AdminPending(Base):
    """A sign-in between the password and the second factor (``admin_pending_minutes``).

    ``starter`` marks the first sign-in with a temporary password, whose second step is the
    email check.
    """

    __tablename__ = "admin_pending"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    starter: Mapped[bool] = mapped_column(Boolean, default=False)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    email_sends: Mapped[int] = mapped_column(Integer, default=0)
    last_send_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class AdminEmailCode(Base):
    """An emailed code, bound to a sign-in in progress or to a session's step-up."""

    __tablename__ = "admin_email_codes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_hash: Mapped[str] = mapped_column(String(64), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class AdminSession(Base):
    """A signed-in browser: 8 hours at most, ending after 30 minutes idle.

    ``stage`` is ``full`` once sign-in is complete. A first sign-in's session moves through
    ``password``, ``authenticator`` and ``recovery_codes`` first and opens nothing else.
    """

    __tablename__ = "admin_sessions"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    stage: Mapped[str] = mapped_column(String(16))
    factor: Mapped[str] = mapped_column(String(16))
    device_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    browser: Mapped[str] = mapped_column(String(48), default="")
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    # A fresh second factor: until when, and which (``email`` opens CSVs only).
    reauth_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    reauth_factor: Mapped[str | None] = mapped_column(String(16), nullable=True)


class AdminDevice(Base):
    """A browser that has completed a sign-in (the device cookie's digest)."""

    __tablename__ = "admin_devices"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class AdminChallenge(Base):
    """A WebAuthn challenge, used once. ``purpose`` is ``register``, ``sign_in`` or
    ``reauth``; ``owner_hash`` binds it to the sign-in or session that asked for it."""

    __tablename__ = "admin_challenges"

    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(16))
    challenge: Mapped[bytes] = mapped_column(LargeBinary(64))
    owner_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class AdminThrottle(Base):
    """A failure counter shared by every instance. ``bucket`` is a keyed hash of what is
    counted (a username, an address, a sign-in), never the value itself."""

    __tablename__ = "admin_throttle"

    bucket: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    window_start: Mapped[datetime] = mapped_column(UTCDateTime)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    lockouts: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class AdminEvent(Base):
    """One audit entry. No password, code, secret, submitted username or address."""

    __tablename__ = "admin_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32))
    ok: Mapped[bool] = mapped_column(Boolean)
    factor: Mapped[str | None] = mapped_column(String(16), nullable=True)
    address_hash: Mapped[str | None] = mapped_column(String(16), nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    browser: Mapped[str] = mapped_column(String(48), default="")
    known_browser: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(String(64), default="")
