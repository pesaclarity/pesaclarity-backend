"""Retention: delete sign-in data once it is past the period we promise to keep it.

Run daily from cron or a scheduled job with ``ngome-purge``.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.auth.models import AuthEvent, OtpChallenge
from ngome.core.config import Settings, get_settings
from ngome.core.logging import configure_logging, get_logger
from ngome.core.security import utcnow
from ngome.db.session import create_engine, create_sessionmaker

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class PurgeResult:
    otp_challenges: int
    auth_events: int


async def purge_expired(
    session: AsyncSession, settings: Settings, *, now: datetime | None = None
) -> PurgeResult:
    """Delete one-time codes and sign-in events older than their retention periods."""
    now = now or utcnow()
    otp_cutoff = now - timedelta(hours=settings.retention_otp_challenge_hours)
    event_cutoff = now - timedelta(days=settings.retention_auth_event_days)

    otp = await session.execute(delete(OtpChallenge).where(OtpChallenge.expires_at < otp_cutoff))
    events = await session.execute(delete(AuthEvent).where(AuthEvent.created_at < event_cutoff))
    await session.commit()
    result = PurgeResult(
        otp_challenges=cast(CursorResult[Any], otp).rowcount,
        auth_events=cast(CursorResult[Any], events).rowcount,
    )
    log.info(
        "retention.purged", otp_challenges=result.otp_challenges, auth_events=result.auth_events
    )
    return result


async def run(settings: Settings) -> PurgeResult:
    engine = create_engine(settings.database_url)
    try:
        async with create_sessionmaker(engine)() as session:
            return await purge_expired(session, settings)
    finally:
        await engine.dispose()


def main() -> None:
    """Entry point for ``ngome-purge``. Exits non-zero if the purge fails."""
    settings = get_settings()
    configure_logging(settings.log_level, json=settings.log_json)
    asyncio.run(run(settings))
