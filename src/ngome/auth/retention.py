"""Retention: delete sign-in data once it is past the period we promise to keep it.

Run daily from cron, a systemd timer or a Kubernetes CronJob with ``ngome-purge`` (see the
README). The same run retries backup objects still queued for deletion.
"""

import asyncio
import dataclasses
import sys
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
from ngome.vault.service import SWEEP_BATCH, sweep_deletions
from ngome.vault.storage import BlobStore, build_blob_store

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class PurgeResult:
    otp_challenges: int
    auth_events: int
    blobs_deleted: int = 0
    blobs_failed: int = 0


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


async def sweep_all_deletions(
    session: AsyncSession, store: BlobStore, *, max_batches: int = 100
) -> tuple[int, int]:
    """Work through the blob deletion queue in batches. Returns ``(deleted, failed)``.

    Stops at the first batch with a failure: failed keys stay at the head of the queue, so
    another batch would only retry them.
    """
    deleted = failed = 0
    for _ in range(max_batches):
        done, failures = await sweep_deletions(session, store, limit=SWEEP_BATCH)
        deleted += done
        failed += failures
        if failures or done < SWEEP_BATCH:
            break
    return deleted, failed


async def run(settings: Settings) -> PurgeResult:
    engine = create_engine(settings.database_url)
    sessionmaker = create_sessionmaker(engine)
    store = build_blob_store(settings, sessionmaker)
    try:
        async with sessionmaker() as session:
            result = await purge_expired(session, settings)
            deleted, failed = await sweep_all_deletions(session, store)
        return dataclasses.replace(result, blobs_deleted=deleted, blobs_failed=failed)
    finally:
        await store.aclose()
        await engine.dispose()


def main() -> None:
    """Entry point for ``ngome-purge``. Exits non-zero if the purge fails or a queued backup
    object could not be deleted (it stays queued for the next run)."""
    settings = get_settings()
    configure_logging(settings.log_level, json=settings.log_json)
    result = asyncio.run(run(settings))
    if result.blobs_failed:
        sys.exit(1)
