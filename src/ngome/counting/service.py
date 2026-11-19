"""Counting a check-in: one keyed digest per period, and totals that name no one."""

import hashlib
import hmac
import re
import secrets
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.core.config import Settings
from ngome.counting.models import DAY, MONTH, CountFlood, CountKey, CountSeen, CountTotal
from ngome.counting.models import NoticeReach as NoticeReachRow
from ngome.db.upsert import insert_for

# 128 random bits from the phone, base64url without padding.
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22}$")
KEY_BYTES = 32
DIGEST_BYTES = 16
ALL = "all"


class Outcome(StrEnum):
    COUNTED = "counted"  # new in at least one period
    SEEN = "seen"  # already counted today and this month
    IGNORED = "ignored"  # no token, a malformed one, or counting off
    FLOOD = "flood"  # over the hourly ceiling
    FULL = "full"  # a period is at its row cap


def month_of(day: date) -> date:
    return day.replace(day=1)


def _hour(now: datetime) -> datetime:
    return now.replace(minute=0, second=0, microsecond=0)


@dataclass
class FloodGate:
    """The ceiling on new tokens per hour, for this instance.

    Kept in memory: a per-instance ceiling needs no shared state, and Cloud Run's maximum
    instances bounds the total.
    """

    ceiling: int
    _hour: datetime | None = field(default=None, init=False)
    _new: int = field(default=0, init=False)

    def _roll(self, now: datetime) -> None:
        hour = _hour(now)
        if hour != self._hour:
            self._hour, self._new = hour, 0

    def allows(self, now: datetime) -> bool:
        self._roll(now)
        return self._new < self.ceiling

    def note_new(self, now: datetime) -> None:
        self._roll(now)
        self._new += 1


def is_valid_token(token: str | None) -> bool:
    return token is not None and TOKEN_PATTERN.fullmatch(token) is not None


def digest(key: bytes, token: str) -> bytes:
    return hmac.new(key, token.encode("ascii"), hashlib.sha256).digest()[:DIGEST_BYTES]


async def _period_key(session: AsyncSession, kind: str, period: date) -> bytes:
    insert = insert_for(session)
    await session.execute(
        insert(CountKey)
        .values(kind=kind, period=period, key=secrets.token_bytes(KEY_BYTES))
        .on_conflict_do_nothing()
    )
    key = await session.scalar(
        select(CountKey.key).where(CountKey.kind == kind, CountKey.period == period)
    )
    if key is None:  # inserted just above
        raise RuntimeError("count key missing")
    return key


async def _add_one(
    session: AsyncSession, kind: str, period: date, cells: Iterable[tuple[str, str]]
) -> None:
    insert = insert_for(session)
    for dimension, value in cells:
        stmt = insert(CountTotal).values(
            kind=kind, period=period, dimension=dimension, value=value, n=1
        )
        await session.execute(
            stmt.on_conflict_do_update(
                index_elements=["kind", "period", "dimension", "value"],
                set_={"n": CountTotal.n + 1},
            )
        )


async def _period_total(session: AsyncSession, kind: str, period: date) -> int:
    n = await session.scalar(
        select(CountTotal.n).where(
            CountTotal.kind == kind,
            CountTotal.period == period,
            CountTotal.dimension == ALL,
            CountTotal.value == ALL,
        )
    )
    return n or 0


async def _mark_flood(session: AsyncSession, now: datetime) -> None:
    insert = insert_for(session)
    await session.execute(
        insert(CountFlood)
        .values(hour=_hour(now), dropped=1)
        .on_conflict_do_update(index_elements=["hour"], set_={"dropped": CountFlood.dropped + 1})
    )


async def record_check_in(
    session: AsyncSession,
    settings: Settings,
    gate: FloodGate,
    *,
    token: str | None,
    build: str,
    version: str,
    country: str | None,
    now: datetime,
) -> Outcome:
    """Count ``token`` once today and once this month, then commit.

    Totals go up only when a digest is new in its period, so each period counts a token
    once, under the version it had when first seen. ``country`` is ``None`` while country
    lookup is off; it is only ever added to the month's totals.
    """
    if not settings.counting_enabled or token is None or not is_valid_token(token):
        return Outcome.IGNORED
    if not gate.allows(now):
        await _mark_flood(session, now)
        await session.commit()
        return Outcome.FLOOD

    today = now.date()
    insert = insert_for(session)
    counted = full = False
    for kind, period in ((DAY, today), (MONTH, month_of(today))):
        if await _period_total(session, kind, period) >= settings.counting_max_per_period:
            full = True
            continue
        key = await _period_key(session, kind, period)
        new = await session.scalar(
            insert(CountSeen)
            .values(kind=kind, period=period, digest=digest(key, token))
            .on_conflict_do_nothing()
            .returning(CountSeen.digest)
        )
        if new is None:
            continue
        cells = [(ALL, ALL), ("build", build), ("version", version)]
        if kind == MONTH and country is not None:
            cells.append(("country", country))
        await _add_one(session, kind, period, cells)
        counted = True
    await session.commit()
    if counted:
        gate.note_new(now)
        return Outcome.COUNTED
    return Outcome.FULL if full else Outcome.SEEN


async def record_reach(session: AsyncSession, notice_ids: Iterable[uuid.UUID], day: date) -> None:
    """Add one check-in to each notice's reach for ``day``, then commit."""
    insert = insert_for(session)
    for notice_id in notice_ids:
        await session.execute(
            insert(NoticeReachRow)
            .values(notice_id=notice_id, day=day, n=1)
            .on_conflict_do_update(
                index_elements=["notice_id", "day"], set_={"n": NoticeReachRow.n + 1}
            )
        )
    await session.commit()
