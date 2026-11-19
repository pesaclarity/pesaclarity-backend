"""Deleting digests and keys when their period closes, and old daily figures."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, and_, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.core.config import Settings
from ngome.counting.models import DAY, MONTH, CountFlood, CountKey, CountSeen, CountTotal
from ngome.counting.models import NoticeReach as NoticeReachRow
from ngome.counting.service import month_of


@dataclass(frozen=True, slots=True)
class CountingPurge:
    digests: int
    keys: int
    daily_rows: int


def _rows(result: object) -> int:
    return cast(CursorResult[Any], result).rowcount


async def purge_counting(
    session: AsyncSession, settings: Settings, *, now: datetime
) -> CountingPurge:
    """A day's set and key go once the day after it is over (only today's and yesterday's
    are kept); a month's on the 2nd of the next month (a day's grace for phone clocks).
    Daily totals, notice reach and flood marks go after ``retention_daily_count_days``.
    Monthly totals are kept."""
    today = now.date()
    oldest_day = today - timedelta(days=1)
    oldest_month = month_of(today - timedelta(days=1))
    closed = or_(
        and_(CountSeen.kind == DAY, CountSeen.period < oldest_day),
        and_(CountSeen.kind == MONTH, CountSeen.period < oldest_month),
    )
    digests = _rows(await session.execute(delete(CountSeen).where(closed)))
    keys = _rows(
        await session.execute(
            delete(CountKey).where(
                or_(
                    and_(CountKey.kind == DAY, CountKey.period < oldest_day),
                    and_(CountKey.kind == MONTH, CountKey.period < oldest_month),
                )
            )
        )
    )
    cutoff = today - timedelta(days=settings.retention_daily_count_days)
    daily = _rows(
        await session.execute(
            delete(CountTotal).where(CountTotal.kind == DAY, CountTotal.period < cutoff)
        )
    )
    daily += _rows(await session.execute(delete(NoticeReachRow).where(NoticeReachRow.day < cutoff)))
    daily += _rows(
        await session.execute(
            delete(CountFlood).where(
                CountFlood.hour < datetime.combine(cutoff, datetime.min.time(), tzinfo=now.tzinfo)
            )
        )
    )
    await session.commit()
    return CountingPurge(digests=digests, keys=keys, daily_rows=daily)
