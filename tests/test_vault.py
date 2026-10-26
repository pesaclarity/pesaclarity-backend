import hashlib
import os

import httpx

from tests.conftest import OTHER_PHONE, FakeSms, bearer, sign_in

OCTET = {"Content-Type": "application/octet-stream"}


def ciphertext(size: int = 256) -> bytes:
    # Random bytes stand in for AES-256-GCM output; the server must treat them as opaque.
    return os.urandom(size)


async def test_upload_list_download_delete(client: httpx.AsyncClient, sms: FakeSms) -> None:
    auth = bearer(await sign_in(client, sms))
    blob = ciphertext()
    digest = hashlib.sha256(blob).hexdigest()

    created = await client.post(
        "/v1/vault/backups", content=blob, headers={**auth, **OCTET, "X-Content-SHA256": digest}
    )
    assert created.status_code == 201, created.text
    meta = created.json()
    assert meta["size_bytes"] == len(blob)
    assert meta["sha256"] == digest
    assert set(meta) == {"id", "size_bytes", "sha256", "created_at"}

    listed = await client.get("/v1/vault/backups", headers=auth)
    assert [b["id"] for b in listed.json()] == [meta["id"]]

    downloaded = await client.get(f"/v1/vault/backups/{meta['id']}", headers=auth)
    assert downloaded.status_code == 200
    assert downloaded.content == blob
    assert downloaded.headers["x-content-sha256"] == digest
    assert downloaded.headers["cache-control"] == "no-store"

    assert (await client.delete(f"/v1/vault/backups/{meta['id']}", headers=auth)).status_code == 204
    assert (await client.get(f"/v1/vault/backups/{meta['id']}", headers=auth)).status_code == 404
    assert (await client.delete(f"/v1/vault/backups/{meta['id']}", headers=auth)).status_code == 404


async def test_requires_sign_in(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/vault/backups")).status_code == 401
    upload = await client.post("/v1/vault/backups", content=ciphertext(), headers=OCTET)
    assert upload.status_code == 401


async def test_checksum_mismatch_is_rejected(client: httpx.AsyncClient, sms: FakeSms) -> None:
    auth = bearer(await sign_in(client, sms))
    response = await client.post(
        "/v1/vault/backups",
        content=ciphertext(),
        headers={**auth, **OCTET, "X-Content-SHA256": "0" * 64},
    )
    assert response.status_code == 422
    assert (await client.get("/v1/vault/backups", headers=auth)).json() == []


async def test_size_limits(client: httpx.AsyncClient, sms: FakeSms) -> None:
    auth = bearer(await sign_in(client, sms))
    too_big = await client.post(
        "/v1/vault/backups", content=ciphertext(4097), headers={**auth, **OCTET}
    )
    assert too_big.status_code == 413
    too_small = await client.post(
        "/v1/vault/backups", content=ciphertext(8), headers={**auth, **OCTET}
    )
    assert too_small.status_code == 422


async def test_only_accepts_octet_stream(client: httpx.AsyncClient, sms: FakeSms) -> None:
    auth = bearer(await sign_in(client, sms))
    response = await client.post("/v1/vault/backups", json={"balance": 100}, headers=auth)
    assert response.status_code == 415


async def test_backups_are_private_to_the_account(client: httpx.AsyncClient, sms: FakeSms) -> None:
    mine = bearer(await sign_in(client, sms))
    theirs = bearer(await sign_in(client, sms, phone=OTHER_PHONE))
    created = await client.post(
        "/v1/vault/backups", content=ciphertext(), headers={**mine, **OCTET}
    )
    backup_id = created.json()["id"]

    assert (await client.get(f"/v1/vault/backups/{backup_id}", headers=theirs)).status_code == 404
    assert (
        await client.delete(f"/v1/vault/backups/{backup_id}", headers=theirs)
    ).status_code == 404
    assert (await client.get("/v1/vault/backups", headers=theirs)).json() == []


async def test_keeps_only_the_newest_backups(client: httpx.AsyncClient, sms: FakeSms) -> None:
    auth = bearer(await sign_in(client, sms))
    ids = []
    for _ in range(5):
        created = await client.post(
            "/v1/vault/backups", content=ciphertext(), headers={**auth, **OCTET}
        )
        ids.append(created.json()["id"])

    listed = await client.get("/v1/vault/backups", headers=auth)
    assert [b["id"] for b in listed.json()] == list(reversed(ids[-3:]))
