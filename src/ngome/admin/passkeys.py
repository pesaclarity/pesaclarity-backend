"""Passkey enrolment and sign-in (WebAuthn, with py_webauthn), and admin sessions."""

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ngome.admin.models import AdminChallenge, AdminEnrolment, AdminPasskey, AdminSession
from ngome.core.config import Settings
from ngome.core.security import utcnow

RP_NAME = "Pesa Clarity admin"
CHALLENGE_SECONDS = 300
# Unauthenticated callers can open ceremonies, so the number open at once is capped.
MAX_OPEN_CHALLENGES = 200
# One user handle for the owner: passkeys name no person.
_USER_ID = b"pesaclarity-owner"
_USER_NAME = "owner"


class PasskeyError(Exception):
    """The ceremony failed: an unknown, used or expired link or challenge, a passkey not on
    the allow-list, or a response that does not verify."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def rp_id(origin: str) -> str:
    """The relying party id for one of the dashboard's origins: its host. The router passes
    only origins from ``Settings.admin_origins``."""
    host = urlsplit(origin).hostname
    if not host:
        raise PasskeyError
    return host


@dataclass(frozen=True, slots=True)
class Ceremony:
    challenge_id: str
    options: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Enrolment:
    token: str
    expires_at: datetime


async def mint_enrolment(session: AsyncSession, settings: Settings, label: str) -> Enrolment:
    """A single-use link token, valid for ``admin_enrolment_minutes``."""
    token = secrets.token_urlsafe(32)
    expires = utcnow() + timedelta(minutes=settings.admin_enrolment_minutes)
    session.add(AdminEnrolment(token_hash=_digest(token), label=label, expires_at=expires))
    await session.commit()
    return Enrolment(token=token, expires_at=expires)


async def _open_enrolment(session: AsyncSession, token: str, now: datetime) -> AdminEnrolment:
    enrolment = await session.get(AdminEnrolment, _digest(token))
    if enrolment is None or enrolment.used_at is not None or enrolment.expires_at <= now:
        raise PasskeyError
    return enrolment


async def enrolment_is_open(session: AsyncSession, token: str) -> bool:
    try:
        await _open_enrolment(session, token, utcnow())
    except PasskeyError:
        return False
    return True


async def _new_challenge(
    session: AsyncSession, purpose: str, challenge: bytes, enrolment_hash: str | None
) -> str:
    now = utcnow()
    await session.execute(delete(AdminChallenge).where(AdminChallenge.expires_at <= now))
    open_now = await session.scalar(select(func.count()).select_from(AdminChallenge))
    if (open_now or 0) >= MAX_OPEN_CHALLENGES:
        await session.commit()
        raise PasskeyError
    challenge_id = secrets.token_urlsafe(24)
    session.add(
        AdminChallenge(
            id_hash=_digest(challenge_id),
            purpose=purpose,
            challenge=challenge,
            enrolment_hash=enrolment_hash,
            expires_at=now + timedelta(seconds=CHALLENGE_SECONDS),
        )
    )
    await session.commit()
    return challenge_id


async def _take_challenge(
    session: AsyncSession, challenge_id: str, purpose: str, now: datetime
) -> AdminChallenge:
    row = await session.get(AdminChallenge, _digest(challenge_id))
    if row is None:
        raise PasskeyError
    await session.delete(row)
    await session.flush()
    if row.purpose != purpose or row.expires_at <= now:
        await session.commit()
        raise PasskeyError
    return row


async def registration_options(session: AsyncSession, origin: str, token: str) -> Ceremony:
    enrolment = await _open_enrolment(session, token, utcnow())
    existing = await session.scalars(select(AdminPasskey.credential_id))
    options = generate_registration_options(
        rp_id=rp_id(origin),
        rp_name=RP_NAME,
        user_id=_USER_ID,
        user_name=_USER_NAME,
        user_display_name="Pesa Clarity owner",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c) for c in existing],
    )
    challenge_id = await _new_challenge(
        session, "register", options.challenge, enrolment.token_hash
    )
    return Ceremony(challenge_id, json.loads(options_to_json(options)))


async def register(
    session: AsyncSession,
    origin: str,
    *,
    token: str,
    challenge_id: str,
    credential: dict[str, Any],
) -> AdminPasskey:
    """Verify the new passkey, put it on the allow-list and use up the link."""
    now = utcnow()
    row = await _take_challenge(session, challenge_id, "register", now)
    enrolment = await _open_enrolment(session, token, now)
    if row.enrolment_hash != enrolment.token_hash:
        await session.commit()
        raise PasskeyError
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=row.challenge,
            expected_rp_id=rp_id(origin),
            expected_origin=origin,
            require_user_verification=True,
        )
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError):
        await session.commit()
        raise PasskeyError from None
    passkey = AdminPasskey(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        label=enrolment.label,
        last_used_at=now,
    )
    enrolment.used_at = now
    session.add(passkey)
    await session.commit()
    return passkey


async def sign_in_options(session: AsyncSession, origin: str) -> Ceremony:
    # No allow_credentials: the passkeys are discoverable, so the page need not list ids.
    options = generate_authentication_options(
        rp_id=rp_id(origin), user_verification=UserVerificationRequirement.REQUIRED
    )
    challenge_id = await _new_challenge(session, "sign_in", options.challenge, None)
    return Ceremony(challenge_id, json.loads(options_to_json(options)))


def _credential_id(credential: dict[str, Any]) -> bytes:
    raw = credential.get("rawId") or credential.get("id")
    if not isinstance(raw, str):
        raise PasskeyError
    try:
        return base64url_to_bytes(raw)
    except ValueError:
        raise PasskeyError from None


async def sign_in(
    session: AsyncSession, origin: str, *, challenge_id: str, credential: dict[str, Any]
) -> AdminPasskey:
    """Verify an assertion from a passkey on the allow-list."""
    now = utcnow()
    row = await _take_challenge(session, challenge_id, "sign_in", now)
    passkey = (
        await session.scalars(
            select(AdminPasskey).where(AdminPasskey.credential_id == _credential_id(credential))
        )
    ).one_or_none()
    if passkey is None:
        await session.commit()
        raise PasskeyError
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=row.challenge,
            expected_rp_id=rp_id(origin),
            expected_origin=origin,
            credential_public_key=passkey.public_key,
            credential_current_sign_count=passkey.sign_count,
            require_user_verification=True,
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError):
        await session.commit()
        raise PasskeyError from None
    passkey.sign_count = verified.new_sign_count
    passkey.last_used_at = now
    await session.commit()
    return passkey


async def start_session(
    session: AsyncSession, settings: Settings, passkey: AdminPasskey
) -> tuple[str, datetime]:
    """A new session id for the cookie, and when it expires."""
    session_id = secrets.token_urlsafe(32)
    now = utcnow()
    expires = now + timedelta(hours=settings.admin_session_hours)
    session.add(
        AdminSession(
            id_hash=_digest(session_id), passkey_id=passkey.id, created_at=now, expires_at=expires
        )
    )
    await session.commit()
    return session_id, expires


async def session_is_valid(session: AsyncSession, session_id: str | None) -> bool:
    if not session_id:
        return False
    row = await session.get(AdminSession, _digest(session_id))
    if row is None:
        return False
    if row.expires_at <= utcnow():
        await session.delete(row)
        await session.commit()
        return False
    # A removed passkey's sessions end with it.
    return await session.get(AdminPasskey, row.passkey_id) is not None


async def end_session(session: AsyncSession, session_id: str | None) -> None:
    if session_id:
        await session.execute(
            delete(AdminSession).where(AdminSession.id_hash == _digest(session_id))
        )
        await session.commit()


async def list_passkeys(session: AsyncSession) -> list[AdminPasskey]:
    return list(await session.scalars(select(AdminPasskey).order_by(AdminPasskey.created_at)))


async def remove_passkey(session: AsyncSession, passkey_id: uuid.UUID) -> bool:
    passkey = await session.get(AdminPasskey, passkey_id)
    if passkey is None:
        return False
    await session.execute(delete(AdminSession).where(AdminSession.passkey_id == passkey_id))
    await session.delete(passkey)
    await session.commit()
    return True


async def purge_admin(session: AsyncSession, *, now: datetime) -> int:
    """Expired sessions, enrolment links and challenges."""
    total = 0
    for model, column in (
        (AdminSession, AdminSession.expires_at),
        (AdminEnrolment, AdminEnrolment.expires_at),
        (AdminChallenge, AdminChallenge.expires_at),
    ):
        result = await session.execute(delete(model).where(column <= now))
        total += getattr(result, "rowcount", 0) or 0
    await session.commit()
    return total
