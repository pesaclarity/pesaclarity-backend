"""Who is asking (as little as needed), the audit log and the owner's alert emails
(ADR 0025 §4).

The audit log keeps the kind of event, its outcome, which factor, a short keyed hash of the
client address, its country and the browser's family. Never a password, code, secret,
submitted username, full address or cookie. Entries go after 90 days.
"""

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.admin import throttle
from ngome.admin.models import AdminEvent
from ngome.auth.providers import EmailSender
from ngome.core.config import Settings
from ngome.core.logging import get_logger

log = get_logger(__name__)

ALERT_EVERY = timedelta(hours=1)
ALWAYS = frozenset({"starter"})


@dataclass(frozen=True, slots=True)
class Caller:
    """The request's caller, reduced to what limits and the audit log need."""

    address_key: str  # keyed hash of the address, for limit buckets
    address_hash: str | None  # its first 16 hex characters, for the audit log
    country: str | None
    browser: str
    device_hash: str | None  # the device cookie's digest, when the browser is known
    known_browser: bool


def address_key(settings: Settings, address: str | None) -> str:
    key = settings.contact_pepper.get_secret_value().encode()
    return hmac.new(key, f"admin-ip\x1f{address or '-'}".encode(), hashlib.sha256).hexdigest()


def browser_of(user_agent: str) -> str:
    """ "Firefox on Linux": a browser family and a system, nothing finer."""
    ua = user_agent or ""
    name = next(
        (
            label
            for token, label in (
                ("Edg/", "Edge"),
                ("OPR/", "Opera"),
                ("Firefox/", "Firefox"),
                ("FxiOS/", "Firefox"),
                ("CriOS/", "Chrome"),
                ("Chrome/", "Chrome"),
                ("Safari/", "Safari"),
            )
            if token in ua
        ),
        "A browser",
    )
    system = next(
        (
            label
            for token, label in (
                ("iPhone", "iPhone"),
                ("iPad", "iPad"),
                ("Android", "Android"),
                ("Windows", "Windows"),
                ("Mac OS X", "macOS"),
                ("CrOS", "ChromeOS"),
                ("Linux", "Linux"),
            )
            if token in ua
        ),
        None,
    )
    return f"{name} on {system}" if system else name


async def record(
    session: AsyncSession,
    caller: Caller | None,
    kind: str,
    *,
    ok: bool,
    factor: str | None = None,
    note: str = "",
) -> None:
    session.add(
        AdminEvent(
            kind=kind,
            ok=ok,
            factor=factor,
            address_hash=caller.address_hash if caller else None,
            country=caller.country if caller else None,
            browser=caller.browser if caller else "",
            known_browser=caller.known_browser if caller else False,
            note=note[:64],
        )
    )
    log.info("admin.event", kind=kind, ok=ok, factor=factor)


async def recent(session: AsyncSession, limit: int = 12) -> list[AdminEvent]:
    return list(
        await session.scalars(select(AdminEvent).order_by(AdminEvent.at.desc()).limit(limit))
    )


ALERTS = {
    "paused": "Sign-in to the Pesa Clarity admin dashboard was paused after too many wrong tries.",
    "second_factor": "Someone entered the right admin password, then wrong second-step codes. "
    "If it wasn't you, change the password now.",
    "new_browser": "The admin dashboard was signed in to from a browser not seen before.",
    "changed": "A sign-in setting of the admin dashboard changed.",
    "recovery_used": "A recovery code was used to sign in to the admin dashboard.",
    "starter": "The admin starter command was run with the admin token.",
    "failures": "Many wrong admin passwords were tried in the last hour.",
}


async def alert(
    session: AsyncSession,
    settings: Settings,
    mail: EmailSender,
    kind: str,
    *,
    detail: str,
    now: datetime,
) -> None:
    """Email the owner, at most once an hour per kind (the starter command, which needs the
    admin token, every time). A failed send never fails the request."""
    if settings.admin_email is None:
        return
    if kind not in ALWAYS and not await throttle.once_per(
        session, throttle.bucket(settings, "alert", kind), ALERT_EVERY, now
    ):
        return
    await session.commit()
    host = (settings.admin_origin or "").split("://")[-1]
    spacing = "" if kind in ALWAYS else " At most one email of each kind an hour."
    text = (
        f"{ALERTS[kind]}\n\n{detail}\nTime: {now:%Y-%m-%d %H:%M} UTC\n\n"
        f"Check Security on {host}. We never send sign-in links.{spacing}"
    )
    try:
        await mail.send(settings.admin_email, "Pesa Clarity admin: security alert", text)
    except Exception:
        log.warning("admin.alert_failed", kind=kind)


async def purge(session: AsyncSession, settings: Settings, now: datetime) -> int:
    result = await session.execute(
        delete(AdminEvent).where(
            AdminEvent.at <= now - timedelta(days=settings.retention_auth_event_days)
        )
    )
    return getattr(result, "rowcount", 0) or 0
