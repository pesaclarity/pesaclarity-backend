import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.auth import retention
from ngome.auth.models import Account, AuthEvent, AuthEventKind, ContactKind, OtpChallenge
from ngome.core.config import Settings, get_settings
from ngome.db.models import Base
from ngome.db.session import create_engine, create_sessionmaker
from ngome.vault.models import BlobDeletion
from ngome.vault.service import SWEEP_BATCH
from ngome.vault.storage import FilesystemBlobStore, new_object_key
from tests.conftest import MemoryBlobStore, make_settings

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _otp(expires_at: datetime) -> OtpChallenge:
    return OtpChallenge(
        id=uuid.uuid4(),
        contact_hash="c" * 64,
        code_hash="h" * 64,
        created_at=expires_at - timedelta(minutes=5),
        expires_at=expires_at,
    )


async def _seed(settings: Settings) -> None:
    engine = create_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with create_sessionmaker(engine)() as session:
        account = Account(contact_kind=ContactKind.EMAIL, contact_hash="a" * 64)
        session.add(account)
        await session.flush()
        session.add_all(
            [
                _otp(NOW - timedelta(hours=25)),
                _otp(NOW - timedelta(hours=23)),
                _otp(NOW + timedelta(minutes=4)),
                AuthEvent(
                    account_id=account.id,
                    kind=AuthEventKind.SIGN_UP,
                    created_at=NOW - timedelta(days=91),
                ),
                AuthEvent(
                    account_id=account.id,
                    kind=AuthEventKind.SIGN_IN,
                    created_at=NOW - timedelta(days=89),
                ),
            ]
        )
        await session.commit()
    await engine.dispose()


async def _remaining(settings: Settings) -> tuple[list[datetime], list[AuthEventKind]]:
    engine = create_engine(settings.database_url)
    async with create_sessionmaker(engine)() as session:
        otps = list(await session.scalars(select(OtpChallenge.expires_at)))
        events = list(await session.scalars(select(AuthEvent.kind)))
    await engine.dispose()
    return otps, events


async def _purge(settings: Settings) -> retention.PurgeResult:
    engine = create_engine(settings.database_url)
    try:
        session: AsyncSession
        async with create_sessionmaker(engine)() as session:
            return await retention.purge_expired(session, settings, now=NOW)
    finally:
        await engine.dispose()


async def test_purge_deletes_only_data_past_retention(settings: Settings) -> None:
    await _seed(settings)

    result = await _purge(settings)

    assert result == retention.PurgeResult(otp_challenges=1, auth_events=1)
    otps, events = await _remaining(settings)
    assert len(otps) == 2
    assert events == [AuthEventKind.SIGN_IN]


async def test_purge_is_idempotent(settings: Settings) -> None:
    await _seed(settings)
    await _purge(settings)
    assert await _purge(settings) == retention.PurgeResult(otp_challenges=0, auth_events=0)


async def test_retention_periods_are_configurable(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path, retention_otp_challenge_hours=1, retention_auth_event_days=30
    )
    await _seed(settings)

    assert await _purge(settings) == retention.PurgeResult(otp_challenges=2, auth_events=2)


def test_otp_retention_cannot_undercut_the_rate_limit_window(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="retention_otp_challenge_hours"):
        make_settings(tmp_path, retention_otp_challenge_hours=0)


def test_cli_entry_point_purges(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    asyncio.run(_seed(settings))
    for name in ("database_url", "jwt_secret", "contact_pepper"):
        value = getattr(settings, name)
        raw = value.get_secret_value() if hasattr(value, "get_secret_value") else value
        monkeypatch.setenv(f"NGOME_{name.upper()}", raw)
    monkeypatch.setenv("NGOME_ENVIRONMENT", "test")
    monkeypatch.setenv("NGOME_LOG_JSON", "false")
    get_settings.cache_clear()
    try:
        retention.main()
    finally:
        get_settings.cache_clear()

    otps, events = asyncio.run(_remaining(settings))
    # main() uses the real clock, so everything seeded in the past is gone.
    assert len(otps) == 0
    assert events == []


async def _queue(settings: Settings, keys: list[str]) -> None:
    engine = create_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with create_sessionmaker(engine)() as session:
        session.add_all(BlobDeletion(object_key=key) for key in keys)
        await session.commit()
    await engine.dispose()


async def _sweep(settings: Settings, store: MemoryBlobStore) -> tuple[int, int, int]:
    engine = create_engine(settings.database_url)
    try:
        async with create_sessionmaker(engine)() as session:
            deleted, failed = await retention.sweep_all_deletions(session, store)
            left = len(list(await session.scalars(select(BlobDeletion.object_key))))
        return deleted, failed, left
    finally:
        await engine.dispose()


async def test_sweep_works_through_the_whole_deletion_queue(settings: Settings) -> None:
    keys = [new_object_key() for _ in range(SWEEP_BATCH * 2 + 5)]
    await _queue(settings, keys)
    store = MemoryBlobStore()
    store.objects = dict.fromkeys(keys, b"x")

    assert await _sweep(settings, store) == (len(keys), 0, 0)
    assert store.objects == {}
    assert await _sweep(settings, store) == (0, 0, 0)


async def test_sweep_stops_and_keeps_keys_queued_when_the_store_fails(settings: Settings) -> None:
    await _queue(settings, [new_object_key() for _ in range(SWEEP_BATCH * 2)])
    store = MemoryBlobStore()
    store.fail_deletes = True

    assert await _sweep(settings, store) == (0, SWEEP_BATCH, SWEEP_BATCH * 2)
    assert store.delete_calls == SWEEP_BATCH


async def test_run_purges_and_deletes_queued_objects(tmp_path: Path) -> None:
    settings = make_settings(
        tmp_path, vault_blob_store="filesystem", vault_fs_root=tmp_path / "blobs"
    )
    await _seed(settings)
    key = new_object_key()
    await FilesystemBlobStore(tmp_path / "blobs").put(key, _one_chunk(b"ciphertext"))
    await _queue(settings, [key])

    result = await retention.run(settings)

    assert result.blobs_deleted == 1
    assert result.blobs_failed == 0
    assert not (tmp_path / "blobs" / key).exists()
    assert result.auth_events >= 1


async def _one_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data
