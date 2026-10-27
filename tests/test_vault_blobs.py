import hashlib
import re
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from ngome.vault import service
from ngome.vault.models import Backup, BlobDeletion
from tests.conftest import OTHER_EMAIL, FakeMail, MemoryBlobStore, bearer, sign_in
from tests.test_vault import OCTET, ciphertext


@pytest.fixture
def memory_store(app: FastAPI) -> MemoryBlobStore:
    store: MemoryBlobStore = app.state.blob_store
    return store


async def upload(client: httpx.AsyncClient, auth: dict[str, str], blob: bytes) -> str:
    created = await client.post("/v1/vault/backups", content=blob, headers={**auth, **OCTET})
    assert created.status_code == 201, created.text
    backup_id: str = created.json()["id"]
    return backup_id


async def queued(app: FastAPI) -> list[BlobDeletion]:
    async with app.state.sessionmaker() as session:
        return list(await session.scalars(select(BlobDeletion)))


async def test_object_keys_are_random_and_carry_no_identifiers(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    tokens = await sign_in(client, mail)
    blob = ciphertext()
    backup_id = await upload(client, bearer(tokens), blob)

    [(key, stored)] = memory_store.objects.items()
    assert stored == blob
    assert re.fullmatch(r"backups/[0-9a-f]{32}", key)
    account_hex = tokens["account_id"].replace("-", "")
    for identifier in (tokens["account_id"], account_hex, backup_id, backup_id.replace("-", "")):
        assert identifier not in key
    async with app.state.sessionmaker() as session:
        assert await session.scalar(select(Backup.object_key)) == key


async def test_delete_removes_the_object(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    auth = bearer(await sign_in(client, mail))
    backup_id = await upload(client, auth, ciphertext())
    assert (await client.delete(f"/v1/vault/backups/{backup_id}", headers=auth)).status_code == 204
    assert memory_store.objects == {}
    assert await queued(app) == []


async def test_pruning_removes_old_objects(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    auth = bearer(await sign_in(client, mail))
    blobs = [ciphertext() for _ in range(5)]
    for blob in blobs:
        await upload(client, auth, blob)
    assert sorted(memory_store.objects.values()) == sorted(blobs[-3:])
    assert await queued(app) == []


async def test_rejected_uploads_leave_no_object(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    auth = bearer(await sign_in(client, mail))
    mismatch = await client.post(
        "/v1/vault/backups",
        content=ciphertext(),
        headers={**auth, **OCTET, "X-Content-SHA256": "0" * 64},
    )
    assert mismatch.status_code == 422
    too_small = await client.post(
        "/v1/vault/backups", content=ciphertext(8), headers={**auth, **OCTET}
    )
    assert too_small.status_code == 422

    async def oversized() -> AsyncIterator[bytes]:
        # No Content-Length, so only the streaming cap can stop it.
        for _ in range(5):
            yield ciphertext(1000)

    too_big = await client.post("/v1/vault/backups", content=oversized(), headers={**auth, **OCTET})
    assert too_big.status_code == 413
    assert memory_store.objects == {}
    assert await queued(app) == []


async def test_account_deletion_removes_its_objects_only(
    client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    mine = bearer(await sign_in(client, mail))
    theirs = bearer(await sign_in(client, mail, email=OTHER_EMAIL))
    await upload(client, mine, ciphertext())
    await upload(client, mine, ciphertext())
    kept = ciphertext()
    await upload(client, theirs, kept)

    assert (await client.delete("/v1/account", headers=mine)).status_code == 204
    assert list(memory_store.objects.values()) == [kept]


async def test_failed_object_deletes_are_queued_and_retried(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    auth = bearer(await sign_in(client, mail))
    backup_id = await upload(client, auth, ciphertext())
    memory_store.fail_deletes = True

    assert (await client.delete(f"/v1/vault/backups/{backup_id}", headers=auth)).status_code == 204
    assert (await client.get("/v1/vault/backups", headers=auth)).json() == []
    [pending] = await queued(app)
    assert pending.attempts == 1
    assert pending.object_key in memory_store.objects

    async with app.state.sessionmaker() as session:
        assert await service.sweep_deletions(session, memory_store) == (0, 1)
    assert (await queued(app))[0].attempts == 2

    memory_store.fail_deletes = False
    async with app.state.sessionmaker() as session:
        assert await service.sweep_deletions(session, memory_store) == (1, 0)
        assert await service.sweep_deletions(session, memory_store) == (0, 0)
    assert memory_store.objects == {}
    assert await queued(app) == []


async def test_failed_discard_is_queued(
    app: FastAPI, client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    auth = bearer(await sign_in(client, mail))
    memory_store.fail_deletes = True
    response = await client.post(
        "/v1/vault/backups",
        content=ciphertext(),
        headers={**auth, **OCTET, "X-Content-SHA256": "0" * 64},
    )
    assert response.status_code == 422
    [pending] = await queued(app)
    assert pending.object_key in memory_store.objects
    async with app.state.sessionmaker() as session:
        assert await session.scalar(select(func.count()).select_from(Backup)) == 0


async def test_missing_object_reads_as_not_found(
    client: httpx.AsyncClient, mail: FakeMail, memory_store: MemoryBlobStore
) -> None:
    auth = bearer(await sign_in(client, mail))
    blob = ciphertext()
    backup_id = await upload(client, auth, blob)
    memory_store.objects.clear()
    assert (await client.get(f"/v1/vault/backups/{backup_id}", headers=auth)).status_code == 404
    listed = (await client.get("/v1/vault/backups", headers=auth)).json()
    assert listed[0]["sha256"] == hashlib.sha256(blob).hexdigest()
