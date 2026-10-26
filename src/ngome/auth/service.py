"""Sign-up, sign-in, token rotation and device management."""

import uuid
from dataclasses import dataclass
from datetime import timedelta

import phonenumbers
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.auth.models import (
    Account,
    AuthEvent,
    AuthEventKind,
    ContactKind,
    Device,
    OtpChallenge,
    RefreshToken,
)
from ngome.auth.providers import SmsSender
from ngome.core.config import Settings
from ngome.core.logging import get_logger
from ngome.core.security import (
    constant_time_equals,
    create_access_token,
    generate_otp,
    hash_contact,
    hash_otp,
    hash_refresh_token,
    new_refresh_token,
    utcnow,
)
from ngome.vault import service as vault_service

log = get_logger(__name__)


class InvalidPhoneError(Exception):
    pass


class RateLimitedError(Exception):
    pass


class InvalidCodeError(Exception):
    pass


class InvalidRefreshTokenError(Exception):
    pass


class DeviceNotFoundError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    account_id: uuid.UUID
    device_id: uuid.UUID


def normalise_phone(raw: str, region: str) -> str:
    try:
        parsed = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException as exc:
        raise InvalidPhoneError from exc
    if not phonenumbers.is_valid_number(parsed):
        raise InvalidPhoneError
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


async def start_phone_sign_in(
    session: AsyncSession, settings: Settings, sms: SmsSender, raw_phone: str
) -> OtpChallenge:
    """Create and send a one-time code. Behaves the same whether or not an account exists."""
    phone = normalise_phone(raw_phone, settings.default_phone_region)
    contact_hash = hash_contact(settings, ContactKind.PHONE, phone)
    now = utcnow()

    recent = await session.scalar(
        select(func.count())
        .select_from(OtpChallenge)
        .where(
            OtpChallenge.contact_hash == contact_hash,
            OtpChallenge.created_at > now - timedelta(hours=1),
        )
    )
    if (recent or 0) >= settings.otp_max_per_hour:
        raise RateLimitedError

    challenge_id = uuid.uuid4()
    code = generate_otp(settings.otp_length)
    challenge = OtpChallenge(
        id=challenge_id,
        contact_hash=contact_hash,
        code_hash=hash_otp(settings, challenge_id, code),
        created_at=now,
        expires_at=now + timedelta(seconds=settings.otp_ttl_seconds),
    )
    session.add(challenge)
    await session.commit()

    await sms.send(phone, f"Your Pesa Clarity code is {code}. Do not share it with anyone.")
    log.info("otp.issued", challenge_id=str(challenge_id))
    return challenge


async def verify_phone_sign_in(
    session: AsyncSession,
    settings: Settings,
    challenge_id: uuid.UUID,
    code: str,
    device_name: str,
) -> IssuedTokens:
    now = utcnow()
    challenge = await session.get(OtpChallenge, challenge_id, with_for_update=True)
    if (
        challenge is None
        or challenge.consumed_at is not None
        or challenge.expires_at <= now
        or challenge.attempts >= settings.otp_max_attempts
    ):
        raise InvalidCodeError

    challenge.attempts += 1
    if not constant_time_equals(challenge.code_hash, hash_otp(settings, challenge_id, code)):
        await session.commit()
        raise InvalidCodeError

    challenge.consumed_at = now
    return await _sign_in(session, settings, ContactKind.PHONE, challenge.contact_hash, device_name)


async def google_sign_in(
    session: AsyncSession, settings: Settings, subject: str, device_name: str
) -> IssuedTokens:
    contact_hash = hash_contact(settings, ContactKind.GOOGLE, subject)
    return await _sign_in(session, settings, ContactKind.GOOGLE, contact_hash, device_name)


async def _sign_in(
    session: AsyncSession,
    settings: Settings,
    kind: ContactKind,
    contact_hash: str,
    device_name: str,
) -> IssuedTokens:
    account = await session.scalar(
        select(Account).where(Account.contact_kind == kind, Account.contact_hash == contact_hash)
    )
    event_kind = AuthEventKind.SIGN_IN
    if account is None:
        account = Account(contact_kind=kind, contact_hash=contact_hash)
        session.add(account)
        await session.flush()
        event_kind = AuthEventKind.SIGN_UP

    device = Device(account_id=account.id, name=device_name)
    session.add(device)
    await session.flush()
    session.add(AuthEvent(account_id=account.id, device_id=device.id, kind=event_kind))

    tokens = _issue_tokens(session, settings, account.id, device.id)
    await session.commit()
    log.info("auth.signed_in", kind=event_kind.value, account_id=str(account.id))
    return tokens


def _issue_tokens(
    session: AsyncSession, settings: Settings, account_id: uuid.UUID, device_id: uuid.UUID
) -> IssuedTokens:
    now = utcnow()
    refresh = new_refresh_token()
    session.add(
        RefreshToken(
            device_id=device_id,
            token_hash=hash_refresh_token(refresh),
            created_at=now,
            expires_at=now + timedelta(days=settings.refresh_token_ttl_days),
        )
    )
    return IssuedTokens(
        access_token=create_access_token(settings, account_id, device_id, now=now),
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
        account_id=account_id,
        device_id=device_id,
    )


async def refresh_tokens(session: AsyncSession, settings: Settings, token: str) -> IssuedTokens:
    """Rotate a refresh token. A reused token means theft, so the whole device is revoked."""
    now = utcnow()
    stored = await session.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_refresh_token(token))
        .with_for_update()
    )
    if stored is None:
        raise InvalidRefreshTokenError
    device = await session.get(Device, stored.device_id)
    if device is None or device.revoked_at is not None:
        raise InvalidRefreshTokenError

    if stored.used_at is not None:
        device.revoked_at = now
        session.add(
            AuthEvent(
                account_id=device.account_id, device_id=device.id, kind=AuthEventKind.REFRESH_REUSE
            )
        )
        await session.commit()
        log.warning("auth.refresh_reuse", device_id=str(device.id))
        raise InvalidRefreshTokenError
    if stored.expires_at <= now:
        raise InvalidRefreshTokenError

    stored.used_at = now
    device.last_seen_at = now
    tokens = _issue_tokens(session, settings, device.account_id, device.id)
    await session.commit()
    return tokens


async def list_devices(session: AsyncSession, account_id: uuid.UUID) -> list[Device]:
    result = await session.scalars(
        select(Device)
        .where(Device.account_id == account_id, Device.revoked_at.is_(None))
        .order_by(Device.created_at)
    )
    return list(result)


async def revoke_device(
    session: AsyncSession,
    account_id: uuid.UUID,
    device_id: uuid.UUID,
    *,
    kind: AuthEventKind = AuthEventKind.DEVICE_REVOKED,
) -> None:
    device = await session.get(Device, device_id)
    if device is None or device.account_id != account_id or device.revoked_at is not None:
        raise DeviceNotFoundError
    device.revoked_at = utcnow()
    session.add(AuthEvent(account_id=account_id, device_id=device_id, kind=kind))
    await session.commit()


async def delete_account(session: AsyncSession, account_id: uuid.UUID) -> None:
    """Erase the account and everything tied to it, immediately and in one transaction."""
    account = await session.get(Account, account_id)
    if account is None:
        return
    device_ids = select(Device.id).where(Device.account_id == account_id)
    await session.execute(delete(RefreshToken).where(RefreshToken.device_id.in_(device_ids)))
    await vault_service.queue_account_deletions(session, account_id)
    await session.execute(delete(AuthEvent).where(AuthEvent.account_id == account_id))
    await session.execute(delete(Device).where(Device.account_id == account_id))
    await session.execute(
        delete(OtpChallenge).where(OtpChallenge.contact_hash == account.contact_hash)
    )
    await session.execute(delete(Account).where(Account.id == account_id))
    await session.commit()
    log.info("account.deleted")
