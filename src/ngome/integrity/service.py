"""App Attest state: challenges, registered keys and assertion counters."""

import base64
import binascii
import hashlib
import secrets
import uuid
from datetime import timedelta

from cryptography import x509
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.core.logging import get_logger
from ngome.core.security import utcnow
from ngome.integrity.apple import (
    HEADER_SCHEME,
    AppAttestPolicy,
    AttestedKey,
    verify_assertion,
    verify_attestation,
)
from ngome.integrity.models import AppAttestChallenge, AppAttestKey
from ngome.integrity.play import IntegrityFailedError

log = get_logger(__name__)


def _b64(value: str, reason: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise IntegrityFailedError(reason) from None


async def issue_challenge(session: AsyncSession, account_id: uuid.UUID, ttl_seconds: int) -> str:
    """A fresh challenge for this account, base64; it works once, for ``ttl_seconds``."""
    now = utcnow()
    await session.execute(delete(AppAttestChallenge).where(AppAttestChallenge.expires_at < now))
    challenge = secrets.token_bytes(32)
    session.add(
        AppAttestChallenge(
            account_id=account_id,
            challenge_sha256=hashlib.sha256(challenge).hexdigest(),
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
    )
    await session.commit()
    return base64.b64encode(challenge).decode()


async def register_key(
    session: AsyncSession,
    account_id: uuid.UUID,
    *,
    key_id: str,
    attestation: str,
    challenge: str,
    policy: AppAttestPolicy,
    root: x509.Certificate,
) -> None:
    """Check the attestation and keep the key for this account. The challenge is used up
    whether or not the attestation passes."""
    challenge_bytes = _b64(challenge, "challenge")
    row = await session.scalar(
        select(AppAttestChallenge).where(
            AppAttestChallenge.challenge_sha256 == hashlib.sha256(challenge_bytes).hexdigest(),
            AppAttestChallenge.account_id == account_id,
        )
    )
    if row is None:
        raise IntegrityFailedError("challenge")
    await session.delete(row)
    await session.commit()
    if row.expires_at < utcnow():
        raise IntegrityFailedError("challenge")

    key_bytes = _b64(key_id, "key")
    attested = verify_attestation(
        _b64(attestation, "attestation"), challenge_bytes, key_bytes, policy, root, utcnow()
    )
    existing = await session.get(AppAttestKey, key_bytes.hex())
    if existing is not None and existing.account_id != account_id:
        raise IntegrityFailedError("key")
    if existing is None:
        session.add(
            AppAttestKey(
                key_id=key_bytes.hex(),
                account_id=account_id,
                public_key=attested.public_key_der,
                sign_count=attested.sign_count,
            )
        )
    await session.commit()
    log.info("app_attest.registered")


def parse_header(value: str) -> tuple[bytes, bytes] | None:
    """The key id and assertion in an ``appattest <key id> <assertion>`` header, or None when
    the header holds something else, such as a Play Integrity token."""
    parts = value.split(" ")
    if len(parts) != 3 or parts[0] != HEADER_SCHEME:
        return None
    return _b64(parts[1], "key"), _b64(parts[2], "assertion")


async def check_assertion(
    session: AsyncSession,
    account_id: uuid.UUID,
    key_id: bytes,
    assertion: bytes,
    request_hash: str,
    policy: AppAttestPolicy,
) -> None:
    """Check an assertion over ``request_hash`` by a key this account registered, and move its
    counter on so the assertion cannot be used again."""
    row = await session.scalar(
        select(AppAttestKey).where(AppAttestKey.key_id == key_id.hex()).with_for_update()
    )
    if row is None or row.account_id != account_id:
        raise IntegrityFailedError("key")
    counter = verify_assertion(
        assertion,
        request_hash.encode(),
        AttestedKey(key_id=key_id, public_key_der=row.public_key, sign_count=row.sign_count),
        policy,
    )
    row.sign_count = counter
    row.last_used_at = utcnow()
    await session.commit()


async def delete_account_keys(session: AsyncSession, account_id: uuid.UUID) -> None:
    await session.execute(delete(AppAttestKey).where(AppAttestKey.account_id == account_id))
    await session.execute(
        delete(AppAttestChallenge).where(AppAttestChallenge.account_id == account_id)
    )
