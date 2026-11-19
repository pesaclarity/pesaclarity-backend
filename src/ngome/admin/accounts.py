"""The admin user: the starter command, password sign-in, second factors, sessions and
step-up (ADR 0025).

One admin user exists at most. Every sign-in is a password, then a second factor: the
authenticator app (required), a passkey (optional), an emailed code (a fallback that cannot
change sign-in settings) or a recovery code. The first sign-in uses a starter password made
with the admin token, then an emailed code, then forces a new password, the authenticator
and the recovery codes before the dashboard opens.
"""

import base64
import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.admin import audit, passwords, throttle, totp
from ngome.admin.audit import Caller
from ngome.admin.models import (
    AdminChallenge,
    AdminDevice,
    AdminEmailCode,
    AdminPending,
    AdminRecoveryCode,
    AdminSession,
    AdminUser,
)
from ngome.auth.providers import EmailSender
from ngome.core.config import Settings
from ngome.core.security import constant_time_equals, generate_otp, utcnow

USERNAME = re.compile(r"^[a-z0-9._-]{3,32}$")
RESERVED = frozenset({"admin", "administrator", "root", "pesaclarity", "owner-admin", "test"})
RECOVERY_CODES = 10
# Crockford base32: no I, L, O or U, so codes read back without mistakes.
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CODE_LENGTH = 6
_CODE_MINUTES = 5
_SENDS_PER_SIGN_IN = 3
_SEND_GAP = timedelta(seconds=60)
_LAST_SEEN_EVERY = timedelta(minutes=1)
_STAGED_SESSION = timedelta(minutes=30)
_ALERT_AT = 3


class Stage(StrEnum):
    PASSWORD = "password"  # noqa: S105 - a stage name, not a password
    AUTHENTICATOR = "authenticator"
    RECOVERY_CODES = "recovery_codes"
    FULL = "full"


class Factor(StrEnum):
    TOTP = "totp"
    PASSKEY = "passkey"
    EMAIL = "email"
    RECOVERY = "recovery"


FACTOR_NAMES = {
    "totp": "authenticator",
    "passkey": "passkey",
    "email": "email code",
    "recovery": "recovery code",
}


class AdminError(Exception):
    """A request the admin user's rules refuse; ``str(exc)`` is safe to show."""


class Paused(Exception):  # noqa: N818 - reads as "raise Paused(until)"
    def __init__(self, until: datetime) -> None:
        super().__init__(until.isoformat())
        self.until = until


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _keyed(settings: Settings, *parts: str) -> str:
    key = settings.contact_pepper.get_secret_value().encode()
    return hmac.new(key, "\x1f".join(parts).encode(), hashlib.sha256).hexdigest()


def _secret_key(settings: Settings) -> bytes:
    if settings.admin_secret_key is None:
        raise AdminError("The dashboard is not configured")
    return base64.b64decode(settings.admin_secret_key.get_secret_value())


def host(settings: Settings) -> str:
    return (settings.admin_origin or "").split("://")[-1]


def mask_email(address: str | None) -> str:
    if not address or "@" not in address:
        return "the owner\u2019s address"
    name, domain = address.rsplit("@", 1)
    head, _, tld = domain.rpartition(".")
    return f"{name[:1]}•••@{(head or domain)[:1]}•••.{tld or ''}".rstrip(".")


async def the_user(session: AsyncSession) -> AdminUser | None:
    return (await session.scalars(select(AdminUser).limit(1))).one_or_none()


# The starter command.


@dataclass(frozen=True, slots=True)
class Starter:
    username: str
    password: str
    expires_at: datetime
    reset: bool


async def make_starter(
    session: AsyncSession, settings: Settings, *, username: str, reset: bool
) -> Starter:
    """Make the admin user with a random temporary password, or replace a temporary one.
    Once a real password exists, only ``reset`` replaces it, wiping the authenticator, the
    recovery codes and every session (passkeys stay)."""
    name = username.strip().lower()
    if not USERNAME.fullmatch(name) or name in RESERVED:
        raise AdminError(
            "Choose a username of 3 to 32 characters (a-z, 0-9, '.', '_', '-'), not a "
            "well-known one such as admin or root"
        )
    now = utcnow()
    user = await the_user(session)
    was_reset = False
    if user is not None and not user.password_temporary:
        if not reset:
            raise AdminError('A password is already set. Send "reset": true to replace it')
        was_reset = True
    password = secrets.token_urlsafe(18)
    expires = now + timedelta(hours=settings.admin_starter_hours)
    hashed = await passwords.hash_password(password)
    if user is None:
        user = AdminUser(username=name, password_hash=hashed)
        session.add(user)
        await session.flush()
    user.username = name
    user.password_hash = hashed
    user.password_temporary = True
    user.temporary_until = expires
    if was_reset or user.totp_secret is None:
        user.totp_secret = user.totp_nonce = user.totp_pending = user.totp_pending_nonce = None
        user.totp_last_step = 0
        user.totp_added_at = user.totp_used_at = None
        await session.execute(delete(AdminRecoveryCode))
        user.recovery_made_at = None
    await session.execute(delete(AdminSession))
    await session.execute(delete(AdminPending))
    await session.execute(delete(AdminEmailCode))
    return Starter(name, password, expires, was_reset)


# Step one: the password.


@dataclass(frozen=True, slots=True)
class PasswordOk:
    user: AdminUser
    starter: bool


def _rule(settings: Settings, max_failures: int, window: timedelta) -> throttle.Rule:
    return throttle.Rule(max_failures, window, timedelta(minutes=settings.admin_pause_minutes))


async def check_password(
    session: AsyncSession,
    settings: Settings,
    mail: EmailSender,
    caller: Caller,
    *,
    username: str,
    password: str,
) -> PasswordOk | None:
    """The user when the username and password match; ``None`` otherwise. Raises
    :class:`Paused` while a limit holds, before any password is checked."""
    now = utcnow()
    name = username.strip().lower()[:64]
    if caller.known_browser and caller.device_hash:
        user_bucket = throttle.bucket(settings, "pw-known", name, caller.device_hash)
        user_rule = _rule(settings, settings.admin_password_known_max_failures, timedelta(hours=1))
    else:
        user_bucket = throttle.bucket(settings, "pw-user", name)
        user_rule = _rule(settings, settings.admin_password_max_failures, timedelta(hours=1))
    address_bucket = throttle.bucket(settings, "pw-address", caller.address_key)
    address_rule = throttle.Rule(
        settings.admin_address_max_failures, timedelta(hours=1), timedelta(hours=1)
    )
    for name_ in (user_bucket, address_bucket):
        until = await throttle.paused_until(session, name_, now)
        if until is not None:
            raise Paused(until)

    user = await the_user(session)
    stored = user.password_hash if user is not None and user.username == name else None
    ok = await passwords.verify_password(stored, password)
    starter = False
    if ok and user is not None and user.password_temporary:
        starter = True
        ok = user.temporary_until is not None and user.temporary_until > now
    if ok and user is not None:
        await throttle.clear(session, user_bucket)
        await audit.record(session, caller, "password", ok=True, note="starter" if starter else "")
        if not starter and passwords.needs_rehash(user.password_hash):
            user.password_hash = await passwords.hash_password(password)
        await session.commit()
        return PasswordOk(user, starter)

    await audit.record(session, caller, "password", ok=False)
    paused = await throttle.fail(session, user_bucket, user_rule, now)
    paused = await throttle.fail(session, address_bucket, address_rule, now) or paused
    flood = await throttle.fail(
        session,
        throttle.bucket(settings, "pw-all"),
        throttle.Rule(
            settings.admin_alert_failures_per_hour, timedelta(hours=1), timedelta(hours=1)
        ),
        now,
    )
    if paused is not None:
        await audit.record(session, caller, "paused", ok=False, note="password")
    await session.commit()
    if paused is not None:
        await audit.alert(session, settings, mail, "paused", detail=_where(caller), now=now)
    if flood is not None:
        await audit.alert(session, settings, mail, "failures", detail="", now=now)
    if paused is not None:
        raise Paused(paused)
    return None


def _where(caller: Caller | None) -> str:
    if caller is None:
        return ""
    known = "a browser seen before" if caller.known_browser else "a browser not seen before"
    return f"From: {caller.browser}, {caller.country or 'unknown country'}, {known}."


# The sign-in between the password and the second factor.


async def start_pending(
    session: AsyncSession, settings: Settings, user: AdminUser, *, starter: bool
) -> str:
    pending_id = secrets.token_urlsafe(32)
    now = utcnow()
    await session.execute(delete(AdminPending).where(AdminPending.expires_at <= now))
    session.add(
        AdminPending(
            id_hash=digest(pending_id),
            user_id=user.id,
            starter=starter,
            created_at=now,
            expires_at=now + timedelta(minutes=settings.admin_pending_minutes),
        )
    )
    await session.commit()
    return pending_id


async def get_pending(session: AsyncSession, pending_id: str | None) -> AdminPending | None:
    if not pending_id:
        return None
    row = await session.get(AdminPending, digest(pending_id))
    if row is None or row.expires_at <= utcnow():
        return None
    return row


# Emailed codes.


@dataclass(frozen=True, slots=True)
class Sent:
    ok: bool
    wait_seconds: int = 0


async def send_email_code(
    session: AsyncSession,
    settings: Settings,
    mail: EmailSender,
    caller: Caller | None,
    *,
    owner_hash: str,
    pending: AdminPending | None = None,
) -> Sent:
    """Email a 6-digit code bound to ``owner_hash`` (a sign-in in progress or a session).
    One a minute, three per sign-in, ``otp_max_per_hour`` an hour and
    ``admin_email_codes_per_day`` a day."""
    if settings.admin_email is None:
        return Sent(False)
    now = utcnow()
    last = await session.scalar(
        select(func.max(AdminEmailCode.created_at)).where(AdminEmailCode.owner_hash == owner_hash)
    )
    if last is not None and now - last < _SEND_GAP:
        return Sent(False, int((_SEND_GAP - (now - last)).total_seconds()) + 1)
    if pending is not None and pending.email_sends >= _SENDS_PER_SIGN_IN:
        return Sent(False)
    hour = await session.scalar(
        select(func.count())
        .select_from(AdminEmailCode)
        .where(AdminEmailCode.created_at > now - timedelta(hours=1))
    )
    day = await session.scalar(
        select(func.count())
        .select_from(AdminEmailCode)
        .where(AdminEmailCode.created_at > now - timedelta(days=1))
    )
    if (hour or 0) >= settings.otp_max_per_hour or (day or 0) >= settings.admin_email_codes_per_day:
        return Sent(False)
    code_id = uuid.uuid4()
    code = generate_otp(_CODE_LENGTH)
    await session.execute(
        update(AdminEmailCode)
        .where(AdminEmailCode.owner_hash == owner_hash, AdminEmailCode.consumed_at.is_(None))
        .values(consumed_at=now)
    )
    session.add(
        AdminEmailCode(
            id=code_id,
            owner_hash=owner_hash,
            code_hash=_keyed(settings, "admin-email-code", str(code_id), code),
            created_at=now,
            expires_at=now + timedelta(minutes=_CODE_MINUTES),
        )
    )
    if pending is not None:
        pending.email_sends += 1
        pending.last_send_at = now
    await audit.record(session, caller, "email_code_sent", ok=True, factor="email")
    await session.commit()
    where = host(settings)
    await mail.send(
        settings.admin_email,
        f"Pesa Clarity admin code: {code}",
        f"Your code for the Pesa Clarity admin dashboard is {code}. It works for "
        f"{_CODE_MINUTES} minutes.\n\nType it only on {where}. We never email a sign-in "
        "link.\n\nIf you didn\u2019t just sign in, someone knows the admin password: change it.",
    )
    return Sent(True)


async def _check_email_code(
    session: AsyncSession, settings: Settings, owner_hash: str, code: str
) -> bool:
    now = utcnow()
    row = (
        await session.scalars(
            select(AdminEmailCode)
            .where(
                AdminEmailCode.owner_hash == owner_hash,
                AdminEmailCode.consumed_at.is_(None),
                AdminEmailCode.expires_at > now,
            )
            .order_by(AdminEmailCode.created_at.desc())
            .limit(1)
            .with_for_update()
        )
    ).one_or_none()
    if row is None or row.attempts >= settings.otp_max_attempts:
        return False
    row.attempts += 1
    clean = totp.clean(code)
    if constant_time_equals(
        row.code_hash, _keyed(settings, "admin-email-code", str(row.id), clean)
    ):
        row.consumed_at = now
        return True
    return False


# Second factors.


def _recovery_hash(settings: Settings, code: str) -> str:
    return _keyed(settings, "admin-recovery", normalise_recovery(code))


def normalise_recovery(code: str) -> str:
    text = code.upper().replace("-", "").replace(" ", "")
    return text.translate(str.maketrans("OILU", "011V"))


async def _check_totp(
    session: AsyncSession, settings: Settings, user: AdminUser, code: str
) -> bool:
    if user.totp_secret is None or user.totp_nonce is None:
        return False
    secret = totp.unseal(_secret_key(settings), user.totp_secret, user.totp_nonce, user.id.bytes)
    step = totp.matching_step(secret, code, now=utcnow(), after=user.totp_last_step)
    if step is None:
        return False
    # Each code works once: no step at or before this one is accepted again.
    result = await session.execute(
        update(AdminUser)
        .where(AdminUser.id == user.id, AdminUser.totp_last_step < step)
        .values(totp_last_step=step, totp_used_at=utcnow())
    )
    return (getattr(result, "rowcount", 0) or 0) == 1


async def _check_recovery(session: AsyncSession, settings: Settings, code: str) -> bool:
    result = await session.execute(
        update(AdminRecoveryCode)
        .where(
            AdminRecoveryCode.code_hash == _recovery_hash(settings, code),
            AdminRecoveryCode.used_at.is_(None),
        )
        .values(used_at=utcnow())
    )
    return (getattr(result, "rowcount", 0) or 0) == 1


async def recovery_left(session: AsyncSession) -> tuple[int, int]:
    total = await session.scalar(select(func.count()).select_from(AdminRecoveryCode)) or 0
    left = (
        await session.scalar(
            select(func.count())
            .select_from(AdminRecoveryCode)
            .where(AdminRecoveryCode.used_at.is_(None))
        )
        or 0
    )
    return left, total


async def check_code(
    session: AsyncSession,
    settings: Settings,
    mail: EmailSender,
    caller: Caller | None,
    *,
    user: AdminUser,
    factor: Factor,
    code: str,
    owner_hash: str,
    pending: AdminPending | None = None,
) -> bool:
    """Check a second-factor code. Wrong codes count against the sign-in (5 end it) and the
    user (10 in 24 hours pause the second step). Raises :class:`Paused` while paused."""
    now = utcnow()
    user_bucket = throttle.bucket(settings, "code-user", str(user.id))
    until = await throttle.paused_until(session, user_bucket, now)
    if until is not None:
        raise Paused(until)
    if factor is Factor.TOTP:
        ok = await _check_totp(session, settings, user, code)
    elif factor is Factor.EMAIL:
        ok = await _check_email_code(session, settings, owner_hash, code)
    else:
        ok = await _check_recovery(session, settings, code)
    await audit.record(session, caller, "second_factor", ok=ok, factor=factor.value)
    if ok:
        await throttle.clear(session, user_bucket)
        if pending is not None:
            await session.delete(pending)
        await session.commit()
        if factor is Factor.RECOVERY:
            left, _ = await recovery_left(session)
            await audit.alert(
                session,
                settings,
                mail,
                "recovery_used",
                detail=f"{left} recovery codes are left. {_where(caller)}",
                now=now,
            )
        return True
    paused = await throttle.fail(
        session,
        user_bucket,
        throttle.Rule(
            settings.admin_user_code_max_failures, timedelta(hours=24), timedelta(hours=1)
        ),
        now,
    )
    count = await throttle.failures(session, user_bucket)
    if pending is not None:
        pending.failures += 1
        if pending.failures >= settings.admin_code_max_failures:
            await session.delete(pending)
    if paused is not None:
        await audit.record(session, caller, "paused", ok=False, note="second factor")
    await session.commit()
    if count == _ALERT_AT or paused is not None:
        await audit.alert(session, settings, mail, "second_factor", detail=_where(caller), now=now)
    if paused is not None:
        raise Paused(paused)
    return False


# Sessions.


async def known_device(session: AsyncSession, device_cookie: str | None) -> str | None:
    """The device cookie's digest when this browser has signed in before."""
    if not device_cookie:
        return None
    hashed = digest(device_cookie)
    return hashed if await session.get(AdminDevice, hashed) is not None else None


async def remember_device(
    session: AsyncSession,
    settings: Settings,
    mail: EmailSender,
    caller: Caller,
    row: AdminSession,
) -> str | None:
    """Tie a completed sign-in to this browser. Returns a new device cookie (and emails the
    owner) when the browser has not signed in before."""
    now = utcnow()
    if caller.device_hash is not None:
        row.device_hash = caller.device_hash
        await session.execute(
            update(AdminDevice)
            .where(AdminDevice.id_hash == caller.device_hash)
            .values(last_seen_at=now)
        )
        await session.commit()
        return None
    cookie = secrets.token_urlsafe(32)
    row.device_hash = digest(cookie)
    session.add(AdminDevice(id_hash=row.device_hash, first_seen_at=now, last_seen_at=now))
    await session.commit()
    await audit.alert(session, settings, mail, "new_browser", detail=_where(caller), now=now)
    return cookie


async def start_session(
    session: AsyncSession,
    settings: Settings,
    mail: EmailSender,
    caller: Caller,
    *,
    user: AdminUser,
    stage: Stage,
    factor: str,
) -> tuple[str, datetime, str | None]:
    """A new session id, when it ends, and (for a completed sign-in on a browser not seen
    before) a new device cookie to set."""
    now = utcnow()
    session_id = secrets.token_urlsafe(32)
    hours = timedelta(hours=settings.admin_session_hours)
    expires = now + (hours if stage is Stage.FULL else min(hours, _STAGED_SESSION))
    row = AdminSession(
        id_hash=digest(session_id),
        user_id=user.id,
        stage=stage.value,
        factor=factor,
        device_hash=None,
        browser=caller.browser[:48],
        country=caller.country,
        created_at=now,
        last_seen_at=now,
        expires_at=expires,
        reauth_until=now + timedelta(minutes=settings.admin_reauth_minutes),
        reauth_factor=factor,
    )
    session.add(row)
    await session.commit()
    device = None
    if stage is Stage.FULL:
        device = await remember_device(session, settings, mail, caller, row)
    return session_id, expires, device


async def load_session(
    session: AsyncSession, settings: Settings, session_id: str | None
) -> AdminSession | None:
    """The live session for this cookie: not past 8 hours, not idle for 30 minutes."""
    if not session_id:
        return None
    row = await session.get(AdminSession, digest(session_id))
    if row is None:
        return None
    now = utcnow()
    idle = timedelta(minutes=settings.admin_idle_minutes)
    if row.expires_at <= now or now - row.last_seen_at > idle:
        await session.delete(row)
        await session.commit()
        return None
    if now - row.last_seen_at > _LAST_SEEN_EVERY:
        row.last_seen_at = now
        await session.commit()
    return row


async def advance(
    session: AsyncSession, settings: Settings, row: AdminSession, stage: Stage
) -> tuple[str, datetime, AdminSession]:
    """Move a first sign-in's session to its next stage, under a new id."""
    now = utcnow()
    session_id = secrets.token_urlsafe(32)
    expires = row.created_at + (
        timedelta(hours=settings.admin_session_hours) if stage is Stage.FULL else _STAGED_SESSION
    )
    expires = max(expires, now + timedelta(minutes=1))
    replacement = AdminSession(
        id_hash=digest(session_id),
        user_id=row.user_id,
        stage=stage.value,
        factor=row.factor,
        device_hash=row.device_hash,
        browser=row.browser,
        country=row.country,
        created_at=row.created_at,
        last_seen_at=now,
        expires_at=expires,
        reauth_until=row.reauth_until,
        reauth_factor=row.reauth_factor,
    )
    await session.delete(row)
    session.add(replacement)
    await session.commit()
    return session_id, expires, replacement


async def end_session(session: AsyncSession, session_id: str | None) -> None:
    if session_id:
        await session.execute(
            delete(AdminSession).where(AdminSession.id_hash == digest(session_id))
        )
        await session.commit()


async def end_other_sessions(session: AsyncSession, keep: AdminSession) -> int:
    result = await session.execute(delete(AdminSession).where(AdminSession.id_hash != keep.id_hash))
    return getattr(result, "rowcount", 0) or 0


def is_fresh(row: AdminSession, *, strong: bool) -> bool:
    if row.reauth_until is None or row.reauth_until <= utcnow():
        return False
    return not (strong and row.reauth_factor == Factor.EMAIL.value)


async def mark_fresh(
    session: AsyncSession, settings: Settings, row: AdminSession, factor: str
) -> None:
    row.reauth_until = utcnow() + timedelta(minutes=settings.admin_reauth_minutes)
    row.reauth_factor = factor
    await session.commit()


async def sessions(session: AsyncSession) -> list[AdminSession]:
    return list(
        await session.scalars(
            select(AdminSession)
            .where(AdminSession.stage == Stage.FULL.value)
            .order_by(AdminSession.last_seen_at.desc())
        )
    )


# Changing sign-in settings.


async def set_password(
    session: AsyncSession, settings: Settings, user: AdminUser, new_password: str
) -> str | None:
    """Set a new password, or say why it can't be used."""
    why = passwords.problem(new_password, username=user.username, host=host(settings))
    if why is not None:
        return why
    if await passwords.verify_password(user.password_hash, new_password):
        return "Choose a password you haven\u2019t used here."
    user.password_hash = await passwords.hash_password(new_password)
    user.password_temporary = False
    user.temporary_until = None
    user.password_changed_at = utcnow()
    return None


async def totp_setup(session: AsyncSession, settings: Settings, user: AdminUser) -> bytes:
    """The secret being set up (made once, so a reload shows the same QR code)."""
    key = _secret_key(settings)
    if user.totp_pending is not None and user.totp_pending_nonce is not None:
        return totp.unseal(key, user.totp_pending, user.totp_pending_nonce, user.id.bytes)
    secret = totp.new_secret()
    user.totp_pending, user.totp_pending_nonce = totp.seal(key, secret, user.id.bytes)
    await session.commit()
    return secret


async def totp_confirm(
    session: AsyncSession, settings: Settings, user: AdminUser, code: str
) -> bool:
    """Make the secret being set up the authenticator, if ``code`` comes from it."""
    if user.totp_pending is None or user.totp_pending_nonce is None:
        return False
    key = _secret_key(settings)
    secret = totp.unseal(key, user.totp_pending, user.totp_pending_nonce, user.id.bytes)
    step = totp.matching_step(secret, code, now=utcnow(), after=0)
    if step is None:
        return False
    user.totp_secret, user.totp_nonce = totp.seal(key, secret, user.id.bytes)
    user.totp_pending = user.totp_pending_nonce = None
    user.totp_last_step = step
    user.totp_added_at = utcnow()
    return True


def _recovery_code() -> str:
    text = "".join(secrets.choice(_CROCKFORD) for _ in range(10))
    return f"{text[:5]}-{text[5:]}"


async def new_recovery_codes(
    session: AsyncSession, settings: Settings, user: AdminUser
) -> list[str]:
    """Ten new codes, replacing any before. Shown once: only keyed hashes are kept."""
    codes = [_recovery_code() for _ in range(RECOVERY_CODES)]
    await session.execute(delete(AdminRecoveryCode))
    for code in codes:
        session.add(AdminRecoveryCode(code_hash=_recovery_hash(settings, code), user_id=user.id))
    user.recovery_made_at = utcnow()
    return codes


async def purge(session: AsyncSession, settings: Settings, *, now: datetime) -> int:
    """Expired sessions, sign-ins, codes and challenges, idle limits and old audit entries."""
    total = 0
    for statement in (
        delete(AdminSession).where(AdminSession.expires_at <= now),
        delete(AdminPending).where(AdminPending.expires_at <= now),
        delete(AdminEmailCode).where(AdminEmailCode.expires_at <= now - timedelta(days=1)),
        delete(AdminChallenge).where(AdminChallenge.expires_at <= now),
        delete(AdminDevice).where(AdminDevice.last_seen_at <= now - timedelta(days=400)),
    ):
        result = await session.execute(statement)
        total += getattr(result, "rowcount", 0) or 0
    total += await throttle.purge(session, now)
    total += await audit.purge(session, settings, now)
    await session.commit()
    return total
