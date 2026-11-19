"""Passkeys (WebAuthn, with py_webauthn): an optional second factor after the password, and
for a fresh check before sign-in changes (ADR 0025 §3).

Each ceremony's challenge is bound to the sign-in in progress or the session that asked for
it, and used once. Passkeys are added from Security by a signed-in session, never by the
admin token alone.
"""

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

from ngome.admin.models import AdminChallenge, AdminPasskey
from ngome.core.security import utcnow

RP_NAME = "Pesa Clarity admin"
CHALLENGE_SECONDS = 300
# Ceremonies are opened only after a password or by a session, but stay capped anyway.
MAX_OPEN_CHALLENGES = 200
_USER_ID = b"pesaclarity-owner"


class PasskeyError(Exception):
    """The ceremony failed: an unknown, used or expired challenge, a passkey not on the
    allow-list, or a response that does not verify."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def rp_id(origin: str) -> str:
    """The relying party id for one of the dashboard's origins: its host. Routes pass only
    origins from ``Settings.admin_origins``."""
    host = urlsplit(origin).hostname
    if not host:
        raise PasskeyError
    return host


@dataclass(frozen=True, slots=True)
class Ceremony:
    challenge_id: str
    options: dict[str, Any]


async def _new_challenge(
    session: AsyncSession, purpose: str, challenge: bytes, owner_hash: str
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
            owner_hash=owner_hash,
            expires_at=now + timedelta(seconds=CHALLENGE_SECONDS),
        )
    )
    await session.commit()
    return challenge_id


async def _take_challenge(
    session: AsyncSession, challenge_id: str, purpose: str, owner_hash: str, now: datetime
) -> AdminChallenge:
    row = await session.get(AdminChallenge, _digest(challenge_id))
    if row is None:
        raise PasskeyError
    await session.delete(row)
    await session.flush()
    if row.purpose != purpose or row.expires_at <= now or row.owner_hash != owner_hash:
        await session.commit()
        raise PasskeyError
    return row


async def list_passkeys(session: AsyncSession) -> list[AdminPasskey]:
    return list(await session.scalars(select(AdminPasskey).order_by(AdminPasskey.created_at)))


async def registration_options(
    session: AsyncSession, origin: str, *, owner_hash: str, username: str
) -> Ceremony:
    existing = await session.scalars(select(AdminPasskey.credential_id))
    options = generate_registration_options(
        rp_id=rp_id(origin),
        rp_name=RP_NAME,
        user_id=_USER_ID,
        user_name=username,
        user_display_name="Pesa Clarity owner",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c) for c in existing],
    )
    challenge_id = await _new_challenge(session, "register", options.challenge, owner_hash)
    return Ceremony(challenge_id, json.loads(options_to_json(options)))


async def register(
    session: AsyncSession,
    origin: str,
    *,
    owner_hash: str,
    challenge_id: str,
    credential: dict[str, Any],
    label: str,
) -> AdminPasskey:
    now = utcnow()
    row = await _take_challenge(session, challenge_id, "register", owner_hash, now)
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
        label=label,
        last_used_at=None,
    )
    session.add(passkey)
    await session.commit()
    return passkey


async def assertion_options(
    session: AsyncSession, origin: str, *, purpose: str, owner_hash: str
) -> Ceremony:
    """Options naming the enrolled passkeys, for a second factor or a fresh check."""
    credentials = list(await session.scalars(select(AdminPasskey.credential_id)))
    if not credentials:
        raise PasskeyError
    options = generate_authentication_options(
        rp_id=rp_id(origin),
        allow_credentials=[PublicKeyCredentialDescriptor(id=c) for c in credentials],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_id = await _new_challenge(session, purpose, options.challenge, owner_hash)
    return Ceremony(challenge_id, json.loads(options_to_json(options)))


def _credential_id(credential: dict[str, Any]) -> bytes:
    raw = credential.get("rawId") or credential.get("id")
    if not isinstance(raw, str):
        raise PasskeyError
    try:
        return base64url_to_bytes(raw)
    except ValueError:
        raise PasskeyError from None


async def verify_assertion(
    session: AsyncSession,
    origin: str,
    *,
    purpose: str,
    owner_hash: str,
    challenge_id: str,
    credential: dict[str, Any],
) -> AdminPasskey:
    now = utcnow()
    row = await _take_challenge(session, challenge_id, purpose, owner_hash, now)
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


async def remove_passkey(session: AsyncSession, passkey_id: uuid.UUID) -> bool:
    passkey = await session.get(AdminPasskey, passkey_id)
    if passkey is None:
        return False
    await session.delete(passkey)
    await session.commit()
    return True
