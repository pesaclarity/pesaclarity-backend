"""Store, list, fetch and delete encrypted backups. The server never interprets the bytes."""

import hashlib
import uuid
from collections.abc import AsyncIterator

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import undefer

from ngome.core.logging import get_logger
from ngome.vault.models import Backup

log = get_logger(__name__)

# AES-256-GCM output is at least a 12-byte nonce plus a 16-byte tag.
MIN_CIPHERTEXT_BYTES = 28


class BackupTooLargeError(Exception):
    pass


class BackupTooSmallError(Exception):
    pass


class ChecksumMismatchError(Exception):
    pass


async def read_capped(chunks: AsyncIterator[bytes], max_bytes: int) -> bytes:
    buffer = bytearray()
    async for chunk in chunks:
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            raise BackupTooLargeError
    return bytes(buffer)


async def store_backup(
    session: AsyncSession,
    account_id: uuid.UUID,
    ciphertext: bytes,
    *,
    expected_sha256: str | None,
    keep: int,
) -> Backup:
    """Save a backup and prune the oldest ones beyond ``keep``."""
    if len(ciphertext) < MIN_CIPHERTEXT_BYTES:
        raise BackupTooSmallError
    digest = hashlib.sha256(ciphertext).hexdigest()
    if expected_sha256 is not None and expected_sha256.lower() != digest:
        raise ChecksumMismatchError

    backup = Backup(
        account_id=account_id, size_bytes=len(ciphertext), sha256=digest, ciphertext=ciphertext
    )
    session.add(backup)
    await session.flush()

    stale = (
        select(Backup.id)
        .where(Backup.account_id == account_id)
        .order_by(Backup.created_at.desc(), Backup.id.desc())
        .offset(keep)
    )
    stale_ids = list(await session.scalars(stale))
    if stale_ids:
        await session.execute(delete(Backup).where(Backup.id.in_(stale_ids)))
    await session.commit()
    log.info(
        "vault.stored",
        backup_id=str(backup.id),
        size_bytes=backup.size_bytes,
        pruned=len(stale_ids),
    )
    return backup


async def list_backups(session: AsyncSession, account_id: uuid.UUID) -> list[Backup]:
    result = await session.scalars(
        select(Backup)
        .where(Backup.account_id == account_id)
        .order_by(Backup.created_at.desc(), Backup.id.desc())
    )
    return list(result)


async def get_backup(
    session: AsyncSession, account_id: uuid.UUID, backup_id: uuid.UUID, *, with_data: bool = False
) -> Backup | None:
    query = select(Backup).where(Backup.id == backup_id, Backup.account_id == account_id)
    if with_data:
        query = query.options(undefer(Backup.ciphertext))
    return await session.scalar(query)


async def delete_backup(session: AsyncSession, account_id: uuid.UUID, backup_id: uuid.UUID) -> bool:
    result = await session.execute(
        delete(Backup).where(Backup.id == backup_id, Backup.account_id == account_id)
    )
    await session.commit()
    return bool(getattr(result, "rowcount", 0))
