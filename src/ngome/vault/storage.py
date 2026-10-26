"""Where backup ciphertext lives. Metadata always stays in Postgres; only the bytes move.

Object keys are random and carry no account or user identifier, so a bucket listing on its own
says nothing about who a backup belongs to.
"""

import asyncio
import secrets
from collections.abc import AsyncIterable, AsyncIterator
from contextlib import AsyncExitStack, suppress
from typing import TYPE_CHECKING, Protocol

from aiobotocore.config import AioConfig
from aiobotocore.session import get_session
from botocore.exceptions import ClientError
from pydantic import SecretStr
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.core.config import Settings
from ngome.vault.models import StoredBlob

if TYPE_CHECKING:
    from types_aiobotocore_s3 import S3Client
    from types_aiobotocore_s3.type_defs import CompletedPartTypeDef

DOWNLOAD_CHUNK_BYTES = 64 * 1024
# S3 needs every part but the last to be at least 5 MiB; R2 also wants them all the same size.
MIN_PART_BYTES = 5 * 1024 * 1024
DEFAULT_PART_BYTES = 8 * 1024 * 1024


class BlobNotFoundError(Exception):
    """No object is stored under the requested key."""


def new_object_key() -> str:
    """A fresh, unguessable key that reveals nothing about the account it belongs to."""
    return f"backups/{secrets.token_hex(16)}"


class BlobStore(Protocol):
    """Opaque byte storage keyed by object key."""

    async def put(self, key: str, chunks: AsyncIterable[bytes]) -> None:
        """Store everything ``chunks`` yields under ``key``.

        All or nothing: if ``chunks`` raises, nothing is left behind and the error propagates.
        """
        ...

    async def open(self, key: str) -> AsyncIterator[bytes]:
        """Start reading ``key``, raising :class:`BlobNotFoundError` before any bytes flow."""
        ...

    async def delete(self, key: str) -> None:
        """Remove ``key``. Deleting a missing key succeeds, so retries are safe."""
        ...

    async def aclose(self) -> None:
        """Release connections."""
        ...


class PostgresBlobStore:
    """Keeps ciphertext in the ``vault_blobs`` table. Fine for development, tests and small
    deployments; each blob is held in memory while it is written or read."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def put(self, key: str, chunks: AsyncIterable[bytes]) -> None:
        buffer = bytearray()
        async for chunk in chunks:
            buffer.extend(chunk)
        async with self._sessionmaker() as session:
            session.add(StoredBlob(object_key=key, data=bytes(buffer)))
            await session.commit()

    async def open(self, key: str) -> AsyncIterator[bytes]:
        async with self._sessionmaker() as session:
            data = await session.scalar(select(StoredBlob.data).where(StoredBlob.object_key == key))
        if data is None:
            raise BlobNotFoundError(key)
        return _chunked(data)

    async def delete(self, key: str) -> None:
        async with self._sessionmaker() as session:
            await session.execute(delete(StoredBlob).where(StoredBlob.object_key == key))
            await session.commit()

    async def aclose(self) -> None:
        return None


async def _chunked(data: bytes) -> AsyncIterator[bytes]:
    view = memoryview(data)
    for start in range(0, len(view), DOWNLOAD_CHUNK_BYTES):
        yield bytes(view[start : start + DOWNLOAD_CHUNK_BYTES])


class S3BlobStore:
    """S3-compatible object storage: AWS S3, Cloudflare R2, MinIO.

    Uploads stream through in fixed-size multipart parts, so memory use stays at one part
    whatever the backup size. Credentials come from settings (that is, the environment) or,
    when those are unset, from botocore's usual chain such as an instance role.
    """

    def __init__(
        self,
        *,
        bucket: str,
        endpoint_url: str | None = None,
        region: str | None = None,
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        addressing_style: str = "auto",
        part_bytes: int = DEFAULT_PART_BYTES,
    ) -> None:
        if part_bytes < MIN_PART_BYTES:
            raise ValueError(f"part_bytes must be at least {MIN_PART_BYTES}")
        self._bucket = bucket
        self._part_bytes = part_bytes
        self._endpoint_url = endpoint_url
        self._region = region
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._config = AioConfig(
            s3={"addressing_style": addressing_style},
            retries={"mode": "standard", "max_attempts": 3},
        )
        self._stack = AsyncExitStack()
        self._client: S3Client | None = None
        self._lock = asyncio.Lock()

    async def _s3(self) -> "S3Client":
        async with self._lock:
            if self._client is None:
                creator = get_session().create_client(
                    "s3",
                    endpoint_url=self._endpoint_url,
                    region_name=self._region,
                    aws_access_key_id=self._access_key_id,
                    aws_secret_access_key=self._secret_access_key,
                    config=self._config,
                )
                self._client = await self._stack.enter_async_context(creator)
            return self._client

    async def put(self, key: str, chunks: AsyncIterable[bytes]) -> None:
        s3 = await self._s3()
        buffer = bytearray()
        upload_id: str | None = None
        parts: list[CompletedPartTypeDef] = []

        async def send_part(upload_id: str, body: bytes) -> None:
            number = len(parts) + 1
            result = await s3.upload_part(
                Bucket=self._bucket, Key=key, UploadId=upload_id, PartNumber=number, Body=body
            )
            parts.append({"ETag": result["ETag"], "PartNumber": number})

        try:
            async for chunk in chunks:
                buffer.extend(chunk)
                while len(buffer) >= self._part_bytes:
                    if upload_id is None:
                        created = await s3.create_multipart_upload(
                            Bucket=self._bucket, Key=key, ContentType="application/octet-stream"
                        )
                        upload_id = created["UploadId"]
                    await send_part(upload_id, bytes(buffer[: self._part_bytes]))
                    del buffer[: self._part_bytes]
            if upload_id is None:
                await s3.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=bytes(buffer),
                    ContentType="application/octet-stream",
                )
                return
            if buffer:
                await send_part(upload_id, bytes(buffer))
            await s3.complete_multipart_upload(
                Bucket=self._bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except BaseException:
            if upload_id is not None:
                # Unfinished parts are billed until aborted.
                with suppress(Exception):
                    await asyncio.shield(
                        s3.abort_multipart_upload(Bucket=self._bucket, Key=key, UploadId=upload_id)
                    )
            raise

    async def open(self, key: str) -> AsyncIterator[bytes]:
        s3 = await self._s3()
        try:
            response = await s3.get_object(Bucket=self._bucket, Key=key)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
                raise BlobNotFoundError(key) from None
            raise

        async def stream() -> AsyncIterator[bytes]:
            async with response["Body"] as body:
                async for chunk in body.iter_chunks(DOWNLOAD_CHUNK_BYTES):
                    yield chunk

        return stream()

    async def delete(self, key: str) -> None:
        s3 = await self._s3()
        await s3.delete_object(Bucket=self._bucket, Key=key)

    async def aclose(self) -> None:
        self._client = None
        await self._stack.aclose()


def build_blob_store(
    settings: Settings, sessionmaker: async_sessionmaker[AsyncSession]
) -> BlobStore:
    match settings.vault_blob_store:
        case "postgres":
            return PostgresBlobStore(sessionmaker)
        case "s3":
            if not settings.vault_s3_bucket:
                raise ValueError("vault_s3_bucket is required for the s3 blob store")
            return S3BlobStore(
                bucket=settings.vault_s3_bucket,
                endpoint_url=settings.vault_s3_endpoint_url,
                region=settings.vault_s3_region,
                access_key_id=_secret(settings.vault_s3_access_key_id),
                secret_access_key=_secret(settings.vault_s3_secret_access_key),
                addressing_style=settings.vault_s3_addressing_style,
                part_bytes=settings.vault_s3_part_bytes,
            )


def _secret(value: SecretStr | None) -> str | None:
    return None if value is None else value.get_secret_value()
