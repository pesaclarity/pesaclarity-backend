"""Blob store implementations. The S3 tests need a reachable S3-compatible endpoint such as the
MinIO in docker-compose; set ``NGOME_TEST_S3_ENDPOINT_URL`` (and the other ``NGOME_TEST_S3_*``
variables if they differ from the compose defaults) to run them."""

import os
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from ngome.api.app import create_app
from ngome.core.config import Settings
from ngome.db.models import Base
from ngome.vault.storage import (
    MIN_PART_BYTES,
    BlobNotFoundError,
    BlobStore,
    FilesystemBlobStore,
    PostgresBlobStore,
    S3BlobStore,
    new_object_key,
)
from tests.conftest import FakeSms, bearer, make_settings, sign_in


async def chunks_of(data: bytes, size: int = 1000) -> AsyncIterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


async def read_all(store: BlobStore, key: str) -> bytes:
    return b"".join([chunk async for chunk in await store.open(key)])


class UploadInterruptedError(Exception):
    pass


async def interrupted_after(data: bytes) -> AsyncIterator[bytes]:
    yield data
    raise UploadInterruptedError


async def check_contract(store: BlobStore, large: bytes) -> None:
    small_key, large_key, broken_key = new_object_key(), new_object_key(), new_object_key()
    await store.put(small_key, chunks_of(b"\x01" * 100))
    assert await read_all(store, small_key) == b"\x01" * 100

    await store.put(large_key, chunks_of(large, 64 * 1024))
    assert await read_all(store, large_key) == large

    with pytest.raises(UploadInterruptedError):
        await store.put(broken_key, interrupted_after(large))
    with pytest.raises(BlobNotFoundError):
        await store.open(broken_key)

    await store.delete(small_key)
    await store.delete(small_key)
    with pytest.raises(BlobNotFoundError):
        await store.open(small_key)
    await store.delete(large_key)


@pytest.mark.parametrize("blob_store_kind", ["postgres"])
async def test_postgres_store(app: FastAPI, blob_store: BlobStore) -> None:
    assert isinstance(blob_store, PostgresBlobStore)
    await check_contract(blob_store, os.urandom(300 * 1024))


async def test_filesystem_store(tmp_path: Path) -> None:
    store = FilesystemBlobStore(tmp_path / "blobs")
    await check_contract(store, os.urandom(300 * 1024))
    # The interrupted upload left no partial file behind.
    leftovers = [p for p in (tmp_path / "blobs").rglob("*") if p.is_file()]
    assert leftovers == []


@pytest.mark.parametrize("key", ["../escape", "/etc/passwd", "backups/../../x", "a//b", ""])
async def test_filesystem_store_refuses_unsafe_keys(tmp_path: Path, key: str) -> None:
    store = FilesystemBlobStore(tmp_path / "blobs")
    with pytest.raises(ValueError, match="invalid object key"):
        await store.put(key, chunks_of(b"x"))
    with pytest.raises(ValueError, match="invalid object key"):
        await store.open(key)
    with pytest.raises(ValueError, match="invalid object key"):
        await store.delete(key)


def test_filesystem_settings_need_a_root(settings: Settings) -> None:
    with pytest.raises(ValueError, match="vault_fs_root"):
        Settings(**{**settings.model_dump(), "vault_blob_store": "filesystem"})


def test_filesystem_store_is_built_from_settings(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, vault_blob_store="filesystem", vault_fs_root=tmp_path / "b")
    assert isinstance(create_app(settings).state.blob_store, FilesystemBlobStore)


def test_s3_settings_need_a_bucket(settings: Settings) -> None:
    with pytest.raises(ValueError, match="vault_s3_bucket"):
        Settings(**{**settings.model_dump(), "vault_blob_store": "s3"})


def test_s3_part_size_floor() -> None:
    with pytest.raises(ValueError, match="part_bytes"):
        S3BlobStore(bucket="b", part_bytes=MIN_PART_BYTES - 1)


S3_ENDPOINT = os.environ.get("NGOME_TEST_S3_ENDPOINT_URL")
S3_BUCKET = os.environ.get("NGOME_TEST_S3_BUCKET", "ngome-test")
S3_ACCESS_KEY = os.environ.get("NGOME_TEST_S3_ACCESS_KEY_ID", "ngome-dev")
S3_SECRET_KEY = os.environ.get("NGOME_TEST_S3_SECRET_ACCESS_KEY", "ngome-dev-only-secret")

object_storage = pytest.mark.skipif(
    S3_ENDPOINT is None, reason="set NGOME_TEST_S3_ENDPOINT_URL to test against MinIO or S3"
)


@pytest.fixture
async def s3_store() -> AsyncIterator[S3BlobStore]:
    store = S3BlobStore(
        bucket=S3_BUCKET,
        endpoint_url=S3_ENDPOINT,
        region="us-east-1",
        access_key_id=S3_ACCESS_KEY,
        secret_access_key=S3_SECRET_KEY,
        addressing_style="path",
        part_bytes=MIN_PART_BYTES,
    )
    s3 = await store._s3()
    existing = {b["Name"] for b in (await s3.list_buckets()).get("Buckets", [])}
    if S3_BUCKET not in existing:
        await s3.create_bucket(Bucket=S3_BUCKET)
    yield store
    await store.aclose()


@pytest.mark.object_storage
@object_storage
async def test_s3_store(s3_store: S3BlobStore) -> None:
    # Over two parts, so the multipart path and its abort both run.
    await check_contract(s3_store, os.urandom(MIN_PART_BYTES * 2 + 1234))
    s3 = await s3_store._s3()
    uploads = await s3.list_multipart_uploads(Bucket=S3_BUCKET)
    assert uploads.get("Uploads", []) == []


@pytest.mark.object_storage
@object_storage
async def test_vault_api_on_s3(s3_store: S3BlobStore, tmp_path: Path, sms: FakeSms) -> None:
    settings = make_settings(
        tmp_path,
        vault_blob_store="s3",
        vault_s3_bucket=S3_BUCKET,
        vault_s3_endpoint_url=S3_ENDPOINT,
        vault_s3_region="us-east-1",
        vault_s3_access_key_id=S3_ACCESS_KEY,
        vault_s3_secret_access_key=S3_SECRET_KEY,
        vault_s3_addressing_style="path",
        vault_max_backup_bytes=MIN_PART_BYTES * 3,
    )
    app = create_app(settings)
    app.state.sms_sender = sms
    async with app.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    blob = os.urandom(MIN_PART_BYTES + 10)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            auth = bearer(await sign_in(client, sms))
            created = await client.post(
                "/v1/vault/backups",
                content=chunks_of(blob, 256 * 1024),
                headers={**auth, "Content-Type": "application/octet-stream"},
            )
            assert created.status_code == 201, created.text
            backup_id = created.json()["id"]
            downloaded = await client.get(f"/v1/vault/backups/{backup_id}", headers=auth)
            assert downloaded.content == blob
            assert (await client.delete("/v1/account", headers=auth)).status_code == 204
    finally:
        await app.state.blob_store.aclose()
        await app.state.engine.dispose()
