"""Failure limits shared by every instance, kept in Postgres (ADR 0025 §4).

A bucket counts failures in a window. Reaching the limit pauses the bucket; each later pause
within 24 hours doubles, up to a day. The row is locked while it is read and changed, so two
instances cannot both slip past a limit. Callers commit.
"""

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.admin.models import AdminThrottle
from ngome.core.config import Settings
from ngome.db.upsert import insert_for

MAX_PAUSE = timedelta(hours=24)
_LOCKOUT_MEMORY = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class Rule:
    max_failures: int
    window: timedelta
    pause: timedelta


def bucket(settings: Settings, *parts: str) -> str:
    """A keyed hash naming what is counted, so the table never holds the value itself."""
    key = settings.contact_pepper.get_secret_value().encode()
    return hmac.new(
        key, "\x1f".join(("admin-throttle", *parts)).encode(), hashlib.sha256
    ).hexdigest()


async def paused_until(session: AsyncSession, name: str, now: datetime) -> datetime | None:
    row = await session.get(AdminThrottle, name)
    if row is not None and row.locked_until is not None and row.locked_until > now:
        return row.locked_until
    return None


async def _row(session: AsyncSession, name: str, now: datetime) -> AdminThrottle:
    insert = insert_for(session)
    await session.execute(
        insert(AdminThrottle)
        .values(bucket=name, failures=0, window_start=now, lockouts=0, updated_at=now)
        .on_conflict_do_nothing(index_elements=["bucket"])
    )
    row = (
        await session.scalars(
            select(AdminThrottle)
            .where(AdminThrottle.bucket == name)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).one()
    return row


async def fail(session: AsyncSession, name: str, rule: Rule, now: datetime) -> datetime | None:
    """Count one failure. Returns when the pause ends if this failure started one."""
    row = await _row(session, name, now)
    if now - row.updated_at > _LOCKOUT_MEMORY:
        row.lockouts = 0
    if now - row.window_start > rule.window:
        row.failures, row.window_start = 0, now
    row.failures += 1
    row.updated_at = now
    if row.failures < rule.max_failures:
        return None
    row.lockouts += 1
    pause = min(rule.pause * 2 ** (row.lockouts - 1), MAX_PAUSE)
    row.locked_until = now + pause
    row.failures, row.window_start = 0, now
    return row.locked_until


async def failures(session: AsyncSession, name: str) -> int:
    row = await session.get(AdminThrottle, name)
    return row.failures if row is not None else 0


async def clear(session: AsyncSession, name: str) -> None:
    """Forget the failures, but not the pauses (they still double within 24 hours)."""
    row = await session.get(AdminThrottle, name)
    if row is not None:
        row.failures = 0


async def once_per(session: AsyncSession, name: str, every: timedelta, now: datetime) -> bool:
    """True at most once per ``every`` for ``name`` (used to space alert emails)."""
    row = await _row(session, name, now)
    if row.locked_until is not None and row.locked_until > now:
        return False
    row.locked_until = now + every
    row.updated_at = now
    return True


async def purge(session: AsyncSession, now: datetime) -> int:
    result = await session.execute(
        delete(AdminThrottle).where(
            AdminThrottle.updated_at <= now - timedelta(hours=48),
            (AdminThrottle.locked_until.is_(None)) | (AdminThrottle.locked_until <= now),
        )
    )
    return getattr(result, "rowcount", 0) or 0
