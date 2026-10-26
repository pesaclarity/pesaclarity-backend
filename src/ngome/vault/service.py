"""Store, list, fetch and delete encrypted backups. The server never interprets the bytes."""

import hashlib
import uuid
from collections.abc import AsyncIterable, AsyncIterator
from typing import Any

from sqlalchemy import ColumnElement, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.core.logging import get_logger
from ngome.vault.models import Backup, BlobDeletion
from ngome.vault.storage import BlobStore, new_object_key

log = get_logger(__name__)

# AES-256-GCM output is at least a 12-byte nonce plus a 16-byte tag.
MIN_CIPHERTEXT_BYTES = 28
SWEEP_BATCH = 100


class BackupTooLargeError(Exception):
    pass


class BackupTooSmallError(Exception):
    pass


class ChecksumMismatchError(Exception):
    pass


class _Meter:
    """Passes chunks through while counting and hashing them, stopping at ``max_bytes``."""

    def __init__(self, chunks: AsyncIterable[bytes], max_bytes: int) -> None:
        self._chunks = chunks
        self._max_bytes = max_bytes
        self._hash = hashlib.sha256()
        self.size = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._chunks:
            if not chunk:
                continue
            self.size += len(chunk)
            if self.size > self._max_bytes:
                raise BackupTooLargeError
            self._hash.update(chunk)
            yield chunk

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


async def store_backup(
    session: AsyncSession,
    store: BlobStore,
    account_id: uuid.UUID,
    chunks: AsyncIterable[bytes],
    *,
    max_bytes: int,
    expected_sha256: str | None,
    keep: int,
) -> Backup:
    """Stream a backup into the blob store, record it, and prune the oldest beyond ``keep``.

    The object is written before its metadata, so a backup is never listed without its bytes.
    """
    key = new_object_key()
    meter = _Meter(chunks, max_bytes)
    await store.put(key, meter)

    digest = meter.hexdigest()
    rejection: Exception | None = None
    if meter.size < MIN_CIPHERTEXT_BYTES:
        rejection = BackupTooSmallError()
    elif expected_sha256 is not None and expected_sha256.lower() != digest:
        rejection = ChecksumMismatchError()
    if rejection is not None:
        await _discard(session, store, key)
        raise rejection

    try:
        backup = Backup(account_id=account_id, object_key=key, size_bytes=meter.size, sha256=digest)
        session.add(backup)
        await session.flush()
        stale_ids = list(
            await session.scalars(
                select(Backup.id)
                .where(Backup.account_id == account_id)
                .order_by(Backup.created_at.desc(), Backup.id.desc())
                .offset(keep)
            )
        )
        if stale_ids:
            await _queue_deletions(session, Backup.id.in_(stale_ids))
        await session.commit()
    except BaseException:
        await session.rollback()
        await _discard(session, store, key)
        raise
    log.info(
        "vault.stored",
        backup_id=str(backup.id),
        size_bytes=backup.size_bytes,
        pruned=len(stale_ids),
    )
    if stale_ids:
        await sweep_deletions(session, store)
    return backup


async def list_backups(session: AsyncSession, account_id: uuid.UUID) -> list[Backup]:
    result = await session.scalars(
        select(Backup)
        .where(Backup.account_id == account_id)
        .order_by(Backup.created_at.desc(), Backup.id.desc())
    )
    return list(result)


async def get_backup(
    session: AsyncSession, account_id: uuid.UUID, backup_id: uuid.UUID
) -> Backup | None:
    return await session.scalar(
        select(Backup).where(Backup.id == backup_id, Backup.account_id == account_id)
    )


async def delete_backup(
    session: AsyncSession, store: BlobStore, account_id: uuid.UUID, backup_id: uuid.UUID
) -> bool:
    queued = await _queue_deletions(
        session, (Backup.id == backup_id) & (Backup.account_id == account_id)
    )
    await session.commit()
    if queued:
        await sweep_deletions(session, store)
    return queued > 0


async def queue_account_deletions(session: AsyncSession, account_id: uuid.UUID) -> int:
    """Remove every backup's metadata for an account and queue its objects for deletion.

    Does not commit: account deletion runs it inside its own transaction, then calls
    :func:`sweep_deletions` once that has committed.
    """
    return await _queue_deletions(session, Backup.account_id == account_id)


async def sweep_deletions(
    session: AsyncSession, store: BlobStore, *, limit: int = SWEEP_BATCH
) -> tuple[int, int]:
    """Delete queued objects from the store, oldest first. Returns ``(deleted, failed)``.

    Failed keys stay queued with their attempt count raised and are retried on the next sweep.
    Safe to run concurrently: store deletes are idempotent and queue updates are set-based.
    """
    keys = list(
        await session.scalars(
            select(BlobDeletion.object_key).order_by(BlobDeletion.queued_at).limit(limit)
        )
    )
    done: list[str] = []
    failed: list[str] = []
    for key in keys:
        try:
            await store.delete(key)
        except Exception:
            failed.append(key)
        else:
            done.append(key)
    if done:
        await session.execute(delete(BlobDeletion).where(BlobDeletion.object_key.in_(done)))
    if failed:
        await session.execute(
            update(BlobDeletion)
            .where(BlobDeletion.object_key.in_(failed))
            .values(attempts=BlobDeletion.attempts + 1)
        )
    await session.commit()
    if failed:
        log.warning("vault.blob_delete_failed", deleted=len(done), failed=len(failed))
    elif done:
        log.info("vault.blobs_deleted", deleted=len(done))
    return len(done), len(failed)


async def _queue_deletions(session: AsyncSession, condition: ColumnElement[Any]) -> int:
    keys = list(await session.scalars(select(Backup.object_key).where(condition)))
    if not keys:
        return 0
    session.add_all(BlobDeletion(object_key=key) for key in keys)
    await session.execute(delete(Backup).where(Backup.object_key.in_(keys)))
    return len(keys)


async def _discard(session: AsyncSession, store: BlobStore, key: str) -> None:
    """Remove an object that never got metadata, queueing it if the store refuses."""
    try:
        await store.delete(key)
    except Exception:
        try:
            session.add(BlobDeletion(object_key=key))
            await session.commit()
        except Exception:
            await session.rollback()
            log.exception("vault.blob_orphaned", orphaned=1)
        else:
            log.warning("vault.blob_delete_failed", deleted=0, failed=1)
