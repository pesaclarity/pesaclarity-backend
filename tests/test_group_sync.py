"""Group sync served by the backend (decision 0035): the scenarios of the Worker's tests
(``sync/test/unit.test.ts`` and ``e2e.test.ts``), plus what several instances add.

Each end-to-end test runs on SQLite with the in-memory blob store. With
``NGOME_TEST_DATABASE_URL`` set to an empty Postgres database it runs on Postgres as well
(marked ``postgres``, which is what ``tool/check`` selects): there the schema comes from the
migrations and batches go to the Postgres blob store, or to MinIO when
``NGOME_TEST_S3_ENDPOINT_URL`` is set too. The tests of several instances at once need
Postgres. Every key, licence and batch here is made up.
"""

import asyncio
import base64
import json
import os
import secrets
import stat
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy import delete, func, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.api.app import create_app
from ngome.auth import retention
from ngome.core.config import Settings
from ngome.core.ed25519 import is_small_order
from ngome.db.migrate import upgrade_to_head
from ngome.db.models import Base
from ngome.db.session import create_engine, create_sessionmaker
from ngome.groupsync import licence as licences
from ngome.groupsync import service
from ngome.groupsync.licence import Ed25519LicenceVerifier, LicenceResult
from ngome.groupsync.models import SyncBatch, SyncMember, SyncNonce, SyncPendingBlob, SyncSpace
from ngome.groupsync.protocol import (
    CLOCK_WINDOW_MS,
    MAX_BATCH_BYTES,
    MAX_MEMBERS,
    PULL_MAX_BATCHES,
    SIZE_STEPS,
    SignedParts,
    b64url,
    check_signature,
    from_b64url,
    is_key,
    is_padded_size,
    padded_size,
    verify_ed25519,
)
from ngome.groupsync.ratelimit import RateLimiter
from ngome.groupsync.retention import MIN_KEEP_MS, BatchRow, expired_batches
from ngome.vault.models import BlobDeletion
from ngome.vault.storage import BlobNotFoundError, BlobStore
from tests.conftest import MemoryBlobStore, make_settings
from tests.sync_client import (
    DAY_MS,
    Member,
    Result,
    call,
    licence,
    new_licence_seed,
    new_member,
    padded,
    random_id,
    sign,
)

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"
POSTGRES_URL = os.environ.get("NGOME_TEST_DATABASE_URL")
S3_ENDPOINT = os.environ.get("NGOME_TEST_S3_ENDPOINT_URL")
S3_SETTINGS: dict[str, object] = {
    "vault_blob_store": "s3",
    "vault_s3_bucket": os.environ.get("NGOME_TEST_S3_BUCKET", "ngome-test"),
    "vault_s3_endpoint_url": S3_ENDPOINT,
    "vault_s3_region": "us-east-1",
    "vault_s3_access_key_id": os.environ.get("NGOME_TEST_S3_ACCESS_KEY_ID", "ngome-dev"),
    "vault_s3_secret_access_key": os.environ.get(
        "NGOME_TEST_S3_SECRET_ACCESS_KEY", "ngome-dev-only-secret"
    ),
    "vault_s3_addressing_style": "path",
}

needs_postgres = pytest.mark.skipif(
    POSTGRES_URL is None, reason="set NGOME_TEST_DATABASE_URL to an empty Postgres database"
)
needs_s3 = pytest.mark.skipif(
    S3_ENDPOINT is None, reason="set NGOME_TEST_S3_ENDPOINT_URL to test against MinIO or S3"
)
ON_POSTGRES = pytest.param("postgres", marks=[pytest.mark.postgres, needs_postgres])
# Every end-to-end test runs on SQLite, and on Postgres too when there is one.
BACKENDS = ["sqlite", ON_POSTGRES] if POSTGRES_URL else ["sqlite"]
# For what only row locks can show: several instances changing one space at once.
postgres_only = pytest.mark.parametrize("make_sync", [ON_POSTGRES], indirect=True)


# ---------------------------------------------------------------- unit (unit.test.ts)


def test_base64url_round_trip() -> None:
    data = os.urandom(33)
    assert from_b64url(b64url(data)) == data
    assert "=" not in b64url(data)
    for bad in ("a", "ab=d", "ab+d", "ab/d", "a b"):
        with pytest.raises(ValueError, match="base64url"):
            from_b64url(bad)


def test_size_steps() -> None:
    assert list(SIZE_STEPS) == [1024 * 2**i for i in range(11)]
    assert padded_size(1) == 1024
    assert padded_size(1025) == 2048
    assert padded_size(1024 * 1024) == 1024 * 1024
    assert padded_size(1024 * 1024 + 1) is None
    assert is_padded_size(4096)
    assert not is_padded_size(4097)
    assert not is_padded_size(0)


def _parts(signed: dict[str, str], **changes: str) -> SignedParts:
    values = {
        "key": signed["x-pc-key"],
        "time": signed["x-pc-time"],
        "nonce": signed["x-pc-nonce"],
        "sig": signed["x-pc-sig"],
        **changes,
    }
    return SignedParts(**values)


def test_signature_good_forged_changed_body_old_clock() -> None:
    member, other = new_member(), new_member()
    body = b"{}"
    now = service.wall_clock_ms()
    signed = sign(member, "POST", "/v1/spaces/x", body, now)
    parts = _parts(signed)
    assert check_signature(parts, "POST", "/v1/spaces/x", body, now) is None
    assert check_signature(parts, "post", "/v1/spaces/x", body, now) is None
    forged = _parts(signed, key=other.key)
    assert check_signature(forged, "POST", "/v1/spaces/x", body, now) == "signature"
    assert check_signature(parts, "POST", "/v1/spaces/y", body, now) == "signature"
    assert check_signature(parts, "PUT", "/v1/spaces/x", body, now) == "signature"
    assert check_signature(parts, "POST", "/v1/spaces/x", b"\x01", now) == "signature"
    assert check_signature(parts, "POST", "/v1/spaces/x", body, now + 6 * 60_000) == "clock"
    assert check_signature(parts, "POST", "/v1/spaces/x", body, now - 6 * 60_000) == "clock"
    # Inside the window, to the millisecond.
    assert check_signature(parts, "POST", "/v1/spaces/x", body, now + CLOCK_WINDOW_MS) is None
    for broken in (
        _parts(signed, key="short"),
        _parts(signed, time="soon"),
        _parts(signed, time="1" * 17),
        _parts(signed, nonce="tiny"),
        _parts(signed, sig=""),
    ):
        assert check_signature(broken, "POST", "/v1/spaces/x", body, now) == "malformed"
    assert check_signature(_parts(signed, sig="!!"), "POST", "/v1/spaces/x", body, now) == (
        "signature"
    )


def test_licence_verifier() -> None:
    seed = new_licence_seed()
    verifier = Ed25519LicenceVerifier(licences.public_key_of(seed))
    now = service.wall_clock_ms()
    good = licence(seed, now_ms=now, expires_ms=now + 1000)
    assert verifier.verify(good, now) == LicenceResult(valid_until=now + 1000)
    assert verifier.verify(good, now + 2000) == LicenceResult(why="expired")
    business = licence(seed, now_ms=now, expires_ms=now + 1000, features=("business",))
    assert verifier.verify(business, now) == LicenceResult(why="feature")
    forged = good[:-4] + ("BBBB" if good.endswith("AAAA") else "AAAA")
    assert verifier.verify(forged, now) == LicenceResult(why="signature")
    other = licence(new_licence_seed(), now_ms=now, expires_ms=now + 1000)
    assert verifier.verify(other, now) == LicenceResult(why="signature")
    # No key configured: every licence is refused.
    assert Ed25519LicenceVerifier("").verify(good, now) == LicenceResult(why="no_key")
    assert Ed25519LicenceVerifier(None).verify(good, now) == LicenceResult(why="no_key")
    for nonsense in ("nonsense", "", None, 5, "pclic.2.a.b", "a.b.c.d", good + "." + "x" * 4096):
        assert verifier.verify(nonsense, now) == LicenceResult(why="malformed")


def test_licence_payload_must_be_what_is_planned() -> None:
    seed = new_licence_seed()
    verifier = Ed25519LicenceVerifier(licences.public_key_of(seed))
    now = service.wall_clock_ms()

    def signed(payload: bytes) -> str:
        text = f"pclic.1.{b64url(payload)}"
        return f"{text}.{b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(text.encode()))}"

    for payload in (
        b"not json",
        b"[]",
        b'{"v":2,"exp":9999999999999,"features":["group-sync"]}',
        b'{"v":1,"exp":"9999999999999","features":["group-sync"]}',
        b'{"v":1,"exp":true,"features":["group-sync"]}',
        b'{"v":1,"exp":NaN,"features":["group-sync"]}',
        b'{"v":1,"exp":1.5,"features":["group-sync"]}',
    ):
        assert verifier.verify(signed(payload), now) == LicenceResult(why="malformed"), payload
    no_feature = b'{"v":1,"exp":9999999999999,"features":"group-sync"}'
    assert verifier.verify(signed(no_feature), now) == LicenceResult(why="feature")


def test_retention_keeps_batches_until_read_by_everyone_and_90_days_old() -> None:
    now = 1_000 * MIN_KEEP_MS
    old = now - MIN_KEEP_MS - 1
    batches = [
        BatchRow(cursor=1, id="a", author="A", recipient=None, at=old),
        BatchRow(cursor=2, id="b", author="A", recipient="B", at=old),
        BatchRow(cursor=3, id="c", author="A", recipient="C", at=old),
        BatchRow(cursor=4, id="d", author="A", recipient=None, at=now - 1000),
        BatchRow(cursor=5, id="e", author="B", recipient="Gone", at=old),
    ]
    acked = {"A": 0, "B": 4, "C": 1}
    gone = [b.id for b in expired_batches(batches, acked, now)]
    # a: B and C pulled past 1; b: B pulled past; c: C has not; d: too new; e: recipient removed
    assert gone == ["a", "b", "e"]


def test_rate_limiter_refills_over_time() -> None:
    limiter = RateLimiter(2, 60)
    assert limiter.take("k", 0)
    assert limiter.take("k", 0)
    assert not limiter.take("k", 0)
    assert limiter.take("k", 1000)
    assert limiter.take("other", 0)


def test_rate_limiter_forgets_the_quietest_key_when_full() -> None:
    limiter = RateLimiter(1, 1, max_keys=2)
    assert limiter.take("a", 0)
    assert limiter.take("b", 0)
    assert not limiter.take("b", 0)
    assert limiter.take("c", 0)  # "a" goes, "b" keeps its empty bucket
    assert len(limiter) == 2
    assert not limiter.take("b", 0)


# ---------------------------------------------------------------- the harness


class Clock:
    """The server's clock, which a test can move."""

    def __init__(self) -> None:
        self.ms = service.wall_clock_ms()

    def __call__(self) -> int:
        return self.ms


@dataclass
class Sync:
    """One server instance and a client for it."""

    app: FastAPI
    client: httpx.AsyncClient
    clock: Clock
    seed: bytes

    @property
    def maker(self) -> async_sessionmaker[AsyncSession]:
        maker: async_sessionmaker[AsyncSession] = self.app.state.sessionmaker
        return maker

    @property
    def store(self) -> BlobStore:
        store: BlobStore = self.app.state.blob_store
        return store

    async def call(self, member: Member, method: str, path: str, **options: Any) -> Result:
        options.setdefault("time_ms", self.clock.ms)
        return await call(self.client, member, method, path, **options)

    def licence(self, lasts_ms: int = 365 * DAY_MS, **options: Any) -> str:
        return licence(
            self.seed, now_ms=self.clock.ms, expires_ms=self.clock.ms + lasts_ms, **options
        )

    async def new_space(self, owner: Member, lasts_ms: int = 365 * DAY_MS) -> str:
        space = random_id()
        made = await self.call(
            owner, "POST", f"/v1/spaces/{space}", body={"licence": self.licence(lasts_ms)}
        )
        assert made.status == 201, made.data
        return space

    async def add(self, owner: Member, space: str, member: Member) -> Result:
        return await self.call(owner, "PUT", f"/v1/spaces/{space}/members/{member.key}")

    async def push(
        self,
        member: Member,
        space: str,
        body: bytes,
        batch_id: str | None = None,
        to: str | None = None,
        **options: Any,
    ) -> Result:
        headers = {"x-pc-batch": batch_id or random_id(), **({"x-pc-to": to} if to else {})}
        return await self.call(
            member, "POST", f"/v1/spaces/{space}/batches", body=body, headers=headers, **options
        )

    async def pull(self, member: Member, space: str, since: int = 0) -> Result:
        return await self.call(member, "GET", f"/v1/spaces/{space}/batches?since={since}")

    async def count(self, table: type[Base], *where: Any) -> int:
        async with self.maker() as session:
            total = await session.scalar(select(func.count()).select_from(table).where(*where))
        return total or 0

    async def rows(self, space: str) -> dict[str, int]:
        """How many rows each sync table holds for ``space``."""
        return {
            "spaces": await self.count(SyncSpace, SyncSpace.id == space),
            "members": await self.count(SyncMember, SyncMember.space_id == space),
            "batches": await self.count(SyncBatch, SyncBatch.space_id == space),
        }

    async def named(self, space: str) -> list[str]:
        """The sync tables with a row that names ``space`` anywhere in it."""
        found = []
        async with self.maker() as session:
            for table in Base.metadata.sorted_tables:
                if table.name.startswith("sync_"):
                    for row in await session.execute(select(table)):
                        if any(isinstance(value, str) and space in value for value in row):
                            found.append(table.name)
                            break
        return found

    async def object_keys(self, space: str) -> list[str]:
        """Where each of the space's batches is stored, in cursor order."""
        async with self.maker() as session:
            return list(
                await session.scalars(
                    select(SyncBatch.object_key)
                    .where(SyncBatch.space_id == space)
                    .order_by(SyncBatch.cursor)
                )
            )

    async def stored(self, object_key: str) -> bytes | None:
        try:
            return b"".join([chunk async for chunk in await self.store.open(object_key)])
        except BlobNotFoundError:
            return None


MakeSync = Callable[..., Awaitable[Sync]]


async def _wipe(app: FastAPI) -> None:
    """Leave a shared Postgres (and MinIO) as it was found: no sync rows, no sync objects."""
    store: BlobStore = app.state.blob_store
    async with app.state.sessionmaker() as session:
        keys = [
            *await session.scalars(select(SyncBatch.object_key)),
            *await session.scalars(select(SyncPendingBlob.object_key)),
            *await session.scalars(
                select(BlobDeletion.object_key).where(BlobDeletion.object_key.like("sync/%"))
            ),
        ]
        for key in keys:
            await store.delete(key)
        for table in (SyncBatch, SyncMember, SyncSpace, SyncNonce, SyncPendingBlob):
            await session.execute(delete(table))
        await session.execute(delete(BlobDeletion).where(BlobDeletion.object_key.like("sync/%")))
        await session.commit()


@pytest.fixture(params=BACKENDS)
async def make_sync(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[MakeSync]:
    """Makes server instances on the backend under test. Instances made in one test share
    the database, the blob store, the licence key and the clock, as Cloud Run instances do."""
    backend: str = request.param
    seed = new_licence_seed()
    clock = Clock()
    shared_store = MemoryBlobStore()
    made: list[Sync] = []

    async def make(**overrides: object) -> Sync:
        values: dict[str, object] = {"licence_public_key": licences.public_key_of(seed)}
        if backend == "postgres":
            values["database_url"] = POSTGRES_URL
            if S3_ENDPOINT is not None:
                values.update(S3_SETTINGS)
        settings = make_settings(tmp_path, **{**values, **overrides})
        app = create_app(settings)
        if backend == "postgres":
            if not made:
                await upgrade_to_head(app.state.engine, ALEMBIC_INI)
                if S3_ENDPOINT is not None:
                    await _ensure_bucket(app.state.blob_store)
                await _wipe(app)
        else:
            app.state.blob_store = shared_store
            if not made:
                async with app.state.engine.begin() as connection:
                    await connection.run_sync(Base.metadata.create_all)
        app.state.group_sync.clock = clock
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
        made.append(Sync(app=app, client=client, clock=clock, seed=seed))
        return made[-1]

    yield make
    for instance in made:
        await instance.client.aclose()
    if made and backend == "postgres":
        await _wipe(made[0].app)
    for instance in made:
        await instance.app.state.blob_store.aclose()
        await instance.app.state.engine.dispose()


async def _ensure_bucket(store: Any) -> None:
    s3 = await store._s3()
    bucket = S3_SETTINGS["vault_s3_bucket"]
    if bucket not in {b["Name"] for b in (await s3.list_buckets()).get("Buckets", [])}:
        await s3.create_bucket(Bucket=bucket)


@pytest.fixture
async def sync(make_sync: MakeSync) -> Sync:
    return await make_sync()


# ---------------------------------------------------------------- end to end (e2e.test.ts)


async def test_two_members_push_and_pull(sync: Sync) -> None:
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    added = await sync.add(owner, space, jane)
    assert (added.status, added.data) == (201, {"added": True, "cursor": 0})

    batch_id = random_id()
    first = await sync.push(owner, space, padded(2048, 1), batch_id, jane.key)
    assert (first.status, first.data) == (201, {"cursor": 1, "duplicate": False})

    # Same id and bytes again: the same cursor, not a second batch.
    again = await sync.push(owner, space, padded(2048, 1), batch_id, jane.key)
    assert (again.status, again.data) == (200, {"cursor": 1, "duplicate": True})
    # Same id, other bytes: refused. So is the same id from someone else.
    taken = await sync.push(owner, space, padded(2048, 2), batch_id, jane.key)
    assert (taken.status, taken.error) == (409, "batch_id_taken")
    assert (await sync.push(jane, space, padded(2048, 1), batch_id)).error == "batch_id_taken"
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 1

    assert (await sync.push(jane, space, padded(1024, 3))).status == 201

    janes = await sync.pull(jane, space)
    assert janes.status == 200
    assert len(janes.data["batches"]) == 1
    got = janes.data["batches"][0]
    assert got["id"] == batch_id
    assert got["from"] == owner.key
    assert got["cursor"] == 1
    assert got["at"] == sync.clock.ms
    assert from_b64url(got["data"]) == padded(2048, 1)
    assert (janes.data["next"], janes.data["more"], janes.data["readOnly"]) == (2, False, False)

    owners = await sync.pull(owner, space)
    assert [b["from"] for b in owners.data["batches"]] == [jane.key]
    assert from_b64url(owners.data["batches"][0]["data"]) == padded(1024, 3)
    # Nothing new after the cursor.
    after = await sync.pull(owner, space, owners.data["next"])
    assert (after.data["batches"], after.data["next"]) == ([], 2)

    # Unpadded sizes are refused.
    unpadded = await sync.push(jane, space, bytes(1000))
    assert (unpadded.status, unpadded.error) == (400, "not_padded")

    status = await sync.call(jane, "GET", f"/v1/spaces/{space}")
    assert status.data == {
        "owner": owner.key,
        "members": [owner.key, jane.key],
        "validUntil": sync.clock.ms + 365 * DAY_MS,
        "readOnly": False,
        "cursor": 2,
    }


async def test_a_batch_goes_to_the_one_member_it_is_for_or_to_everyone(sync: Sync) -> None:
    owner, jane, otieno, stranger = new_member(), new_member(), new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)
    await sync.add(owner, space, otieno)

    assert (await sync.push(owner, space, padded(1024, 1), to=jane.key)).data["cursor"] == 1
    assert (await sync.push(owner, space, padded(1024, 2))).data["cursor"] == 2
    for bad in (stranger.key, "not-a-key"):
        refused = await sync.push(owner, space, padded(1024), to=bad)
        assert (refused.status, refused.error) == (400, "bad_recipient")
    for bad_id in ("short", "has space in it....", "x" * 65):
        refused = await sync.push(owner, space, padded(1024), batch_id=bad_id)
        assert (refused.status, refused.error) == (400, "bad_batch_id")

    assert [b["cursor"] for b in (await sync.pull(jane, space)).data["batches"]] == [1, 2]
    assert [b["cursor"] for b in (await sync.pull(otieno, space)).data["batches"]] == [2]
    # The sender is not handed their own batches back; the cursor still moves past them.
    mine = await sync.pull(owner, space)
    assert (mine.data["batches"], mine.data["next"]) == ([], 2)

    for bad_since in ("-1", "abc", "1.5", "9" * 17):
        path = f"/v1/spaces/{space}/batches?since={bad_since}"
        refused = await sync.call(jane, "GET", path)
        assert (refused.status, refused.error) == (400, "bad_cursor")
    # No cursor at all starts from the beginning.
    start = await sync.call(jane, "GET", f"/v1/spaces/{space}/batches")
    assert len(start.data["batches"]) == 2


async def test_forged_replayed_and_stale_requests_are_refused(sync: Sync) -> None:
    owner, mallory = new_member(), new_member()
    space = await sync.new_space(owner)
    pull_path = f"/v1/spaces/{space}/batches?since=0"

    # Mallory signs with her own key but claims the owner's.
    def claim_owner(signed: dict[str, str]) -> None:
        signed["x-pc-key"] = owner.key

    forged = await sync.call(mallory, "GET", pull_path, tamper=claim_owner)
    assert (forged.status, forged.error) == (401, "unauthorized")
    # No signature at all, or one made for another path or body.
    bare = await sync.client.get(pull_path)
    assert (bare.status_code, bare.json()) == (401, {"error": "unauthorized"})
    elsewhere = sign(owner, "GET", f"/v1/spaces/{space}/batches?since=1", b"", sync.clock.ms)
    moved = await sync.client.get(pull_path, headers=elsewhere)
    assert moved.json() == {"error": "unauthorized"}
    swapped = sign(owner, "POST", f"/v1/spaces/{space}/batches", padded(1024, 1), sync.clock.ms)
    changed = await sync.client.post(
        f"/v1/spaces/{space}/batches",
        content=padded(1024, 2),
        headers={**swapped, "x-pc-batch": random_id()},
    )
    assert changed.json() == {"error": "unauthorized"}

    # A non-member with a good signature.
    outsider = await sync.pull(mallory, space)
    assert (outsider.status, outsider.error) == (403, "not_member")

    # The same signed request twice.
    once = await sync.pull(owner, space)
    assert once.status == 200
    replay = await sync.call(owner, "GET", pull_path, reuse=once.signed)
    assert (replay.status, replay.error) == (401, "replay")
    # A nonce the space has seen is refused from another member too.
    jane = new_member()
    await sync.add(owner, space, jane)
    borrowed = await sync.call(jane, "GET", pull_path, nonce=once.signed["x-pc-nonce"])
    assert borrowed.error == "replay"

    # Ten minutes old, and ten minutes ahead.
    for skew in (-600_000, 600_000):
        stale = await sync.call(owner, "GET", pull_path, time_ms=sync.clock.ms + skew)
        assert (stale.status, stale.error) == (401, "clock")

    # Only the owner changes members.
    member = new_member()
    assert (await sync.add(owner, space, member)).status == 201
    not_owner = await sync.add(member, space, mallory)
    assert (not_owner.status, not_owner.error) == (403, "not_owner")
    assert (await sync.call(member, "DELETE", f"/v1/spaces/{space}")).error == "not_owner"

    # A space needs a licence signed with our key.
    fake = licence(new_licence_seed(), now_ms=sync.clock.ms, expires_ms=sync.clock.ms + DAY_MS)
    bad = await sync.call(owner, "POST", f"/v1/spaces/{random_id()}", body={"licence": fake})
    assert (bad.status, bad.error) == (402, "licence_signature")


async def test_a_copy_of_a_push_or_of_a_create_is_refused(sync: Sync) -> None:
    owner = new_member()
    space = random_id()
    licence_body = {"licence": sync.licence()}
    made = await sync.call(owner, "POST", f"/v1/spaces/{space}", body=licence_body)
    assert made.status == 201
    # A copy of the create (same body, same signature). While the space is there it is
    # refused because the space exists; once the space is gone, because it is a copy.
    path = f"/v1/spaces/{space}"
    again = await sync.call(owner, "POST", path, body=licence_body, reuse=made.signed)
    assert (again.status, again.error) == (409, "exists")
    assert (await sync.call(owner, "DELETE", path)).status == 200
    again = await sync.call(owner, "POST", path, body=licence_body, reuse=made.signed)
    assert (again.status, again.error) == (401, "replay")
    assert (await sync.call(owner, "POST", path, body=licence_body)).status == 201

    batch = padded(1024, 5)
    headers = {**sign(owner, "POST", f"/v1/spaces/{space}/batches", batch, sync.clock.ms)}
    headers["x-pc-batch"] = random_id()
    first = await sync.client.post(f"/v1/spaces/{space}/batches", content=batch, headers=headers)
    assert first.status_code == 201
    second = await sync.client.post(f"/v1/spaces/{space}/batches", content=batch, headers=headers)
    assert (second.status_code, second.json()) == (401, {"error": "replay"})
    # The same signed bytes under a new batch id would be a second batch: refused too.
    headers["x-pc-batch"] = random_id()
    third = await sync.client.post(f"/v1/spaces/{space}/batches", content=batch, headers=headers)
    assert third.json() == {"error": "replay"}
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 1
    assert await sync.count(SyncPendingBlob) == 0


async def test_a_removed_member_is_refused(sync: Sync) -> None:
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)
    assert (await sync.push(jane, space, padded(1024))).status == 201
    removed = await sync.call(owner, "DELETE", f"/v1/spaces/{space}/members/{jane.key}")
    assert (removed.status, removed.data) == (200, {"removed": True})
    for refused in (await sync.push(jane, space, padded(1024)), await sync.pull(jane, space)):
        assert (refused.status, refused.error) == (403, "not_member")
    # The owner cannot be removed.
    stays = await sync.call(owner, "DELETE", f"/v1/spaces/{space}/members/{owner.key}")
    assert (stays.status, stays.error) == (409, "owner_stays")
    # Removing someone who is not there changes nothing.
    assert (await sync.call(owner, "DELETE", f"/v1/spaces/{space}/members/{jane.key}")).data == {
        "removed": True
    }
    status = await sync.call(owner, "GET", f"/v1/spaces/{space}")
    assert status.data["members"] == [owner.key]


async def test_an_expired_licence_makes_the_space_read_only_and_renewal_opens_it(
    sync: Sync,
) -> None:
    owner, jane, late = new_member(), new_member(), new_member()
    space = await sync.new_space(owner, lasts_ms=3000)
    await sync.add(owner, space, jane)
    assert (await sync.push(owner, space, padded(1024))).status == 201
    sync.clock.ms += 3500

    refused = await sync.push(owner, space, padded(1024))
    assert (refused.status, refused.error) == (403, "read_only")
    pulled = await sync.pull(jane, space)
    assert pulled.status == 200
    assert len(pulled.data["batches"]) == 1
    assert pulled.data["readOnly"] is True
    assert (await sync.call(jane, "GET", f"/v1/spaces/{space}")).data["readOnly"] is True

    # No new members while read-only. A member who is already there changes nothing, so the
    # owner's phone, which sends its member list on every sync, still gets through.
    new_one = await sync.add(owner, space, late)
    assert (new_one.status, new_one.error) == (403, "read_only")
    known = await sync.add(owner, space, jane)
    assert (known.status, known.data) == (200, {"added": False})
    # The owner can always take someone out.
    gone = await sync.call(owner, "DELETE", f"/v1/spaces/{space}/members/{jane.key}")
    assert (gone.status, gone.data) == (200, {"removed": True})

    # An expired licence is not accepted as a renewal.
    still_old = await sync.call(
        owner, "PUT", f"/v1/spaces/{space}/licence", body={"licence": sync.licence(lasts_ms=-1)}
    )
    assert (still_old.status, still_old.error) == (402, "licence_expired")
    # Only the owner renews.
    assert (await sync.add(owner, space, late)).error == "read_only"
    renewed = await sync.call(
        owner, "PUT", f"/v1/spaces/{space}/licence", body={"licence": sync.licence(DAY_MS)}
    )
    assert (renewed.status, renewed.data) == (200, {"validUntil": sync.clock.ms + DAY_MS})
    assert (await sync.push(owner, space, padded(1024))).status == 201
    assert (await sync.add(owner, space, late)).status == 201
    not_owner = await sync.call(
        late, "PUT", f"/v1/spaces/{space}/licence", body={"licence": sync.licence(DAY_MS)}
    )
    assert (not_owner.status, not_owner.error) == (403, "not_owner")
    # A shorter licence never shortens what the space has.
    shorter = await sync.call(
        owner, "PUT", f"/v1/spaces/{space}/licence", body={"licence": sync.licence(DAY_MS // 2)}
    )
    assert shorter.data == {"validUntil": sync.clock.ms + DAY_MS}


async def test_deleting_a_space_removes_its_rows_and_its_objects(sync: Sync) -> None:
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)
    await sync.push(owner, space, padded(1024))
    await sync.push(owner, space, padded(4096))
    await sync.pull(jane, space)

    keys = await sync.object_keys(space)
    assert len(keys) == 2
    assert [len(await sync.stored(key) or b"") for key in keys] == [1024, 4096]
    assert await sync.named(space) == ["sync_spaces", "sync_batches", "sync_members"]

    not_owner = await sync.call(jane, "DELETE", f"/v1/spaces/{space}")
    assert (not_owner.status, not_owner.error) == (403, "not_owner")
    deleted = await sync.call(owner, "DELETE", f"/v1/spaces/{space}")
    assert (deleted.status, deleted.data) == (200, {"deleted": True})

    assert [await sync.stored(key) for key in keys] == [None, None]
    assert await sync.count(BlobDeletion, BlobDeletion.object_key.in_(keys)) == 0
    assert await sync.rows(space) == {"spaces": 0, "members": 0, "batches": 0}
    assert await sync.count(SyncPendingBlob) == 0
    # The nonces its requests used stay until they run out (a copy of an old request must
    # still be refused if the space is made again), but as digests: no row names the space.
    assert await sync.count(SyncNonce) == 6
    assert await sync.named(space) == []
    for member in (jane, owner):
        missing = await sync.pull(member, space)
        assert (missing.status, missing.error) == (404, "not_found")

    # The id can be used again from scratch: nothing of the old space is left to it.
    again = await sync.call(
        owner, "POST", f"/v1/spaces/{space}", body={"licence": sync.licence(DAY_MS)}
    )
    assert again.status == 201
    fresh = await sync.call(owner, "GET", f"/v1/spaces/{space}")
    assert fresh.data["members"] == [owner.key]
    assert fresh.data["cursor"] == 0


@pytest.mark.parametrize("make_sync", ["sqlite"], indirect=True)
async def test_objects_the_store_would_not_delete_stay_queued_for_the_purge(
    make_sync: MakeSync,
) -> None:
    sync = await make_sync()
    assert isinstance(sync.store, MemoryBlobStore)  # the fake, which can be told to fail
    owner = new_member()
    space = await sync.new_space(owner)
    await sync.push(owner, space, padded(1024))
    keys = await sync.object_keys(space)

    sync.store.fail_deletes = True
    deleted = await sync.call(owner, "DELETE", f"/v1/spaces/{space}")
    assert (deleted.status, deleted.data) == (200, {"deleted": True})
    # The rows are gone at once; the object waits in the deletion queue.
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 0
    assert await sync.count(BlobDeletion, BlobDeletion.object_key.in_(keys)) == 1

    sync.store.fail_deletes = False
    async with sync.maker() as session:
        assert await retention.sweep_all_deletions(session, sync.store) == (1, 0)
    assert await sync.stored(keys[0]) is None


async def test_pushes_are_rate_limited(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    statuses = [(await sync.push(owner, space, padded(1024))).status for _ in range(31)]
    assert statuses == [201] * 30 + [429]
    limited = await sync.push(owner, space, padded(1024))
    assert (limited.status, limited.error) == (429, "rate_limited")
    # Pulls are not pushes; and a minute later pushes go through again.
    assert (await sync.pull(owner, space)).status == 200
    sync.clock.ms += 60_000
    assert (await sync.push(owner, space, padded(1024))).status == 201


async def test_requests_are_rate_limited_per_member_key(make_sync: MakeSync) -> None:
    sync = await make_sync(group_sync_key_requests_per_minute=5)
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)  # the owner's first request
    await sync.add(owner, space, jane)  # the second
    assert [(await sync.pull(owner, space)).status for _ in range(4)] == [200, 200, 200, 429]
    # Another member of the same space has their own allowance.
    assert (await sync.pull(jane, space)).status == 200
    # It refills as time passes: one request every twelve seconds at five a minute.
    sync.clock.ms += 12_000
    assert [(await sync.pull(owner, space)).status for _ in range(2)] == [200, 429]


async def test_requests_are_rate_limited_per_address(make_sync: MakeSync) -> None:
    sync = await make_sync(group_sync_address_requests_per_minute=6)
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)
    statuses = [(await sync.pull(owner, space)).status for _ in range(5)]
    assert statuses == [200] * 4 + [429]
    # Everyone at that address waits, signed or not, before anything is read.
    flooded = await sync.client.get(f"/v1/spaces/{space}")
    assert (flooded.status_code, flooded.json()) == (429, {"error": "rate_limited"})
    assert (await sync.pull(jane, space)).error == "rate_limited"
    # Another address is not held back. The address is the entry Cloud Run appends.
    path = f"/v1/spaces/{space}"
    elsewhere = await sync.call(jane, "GET", path, headers={"x-forwarded-for": "198.51.100.23"})
    assert elsewhere.status == 200
    # It is a key in memory only: no table has a column for it (see the schema test below).


async def test_only_padded_sizes_up_to_one_mebibyte_are_taken(make_sync: MakeSync) -> None:
    sync = await make_sync(group_sync_key_pushes_per_minute=100)
    owner = new_member()
    space = await sync.new_space(owner)
    for size in SIZE_STEPS:
        assert (await sync.push(owner, space, padded(size))).status == 201, size
    for size in (0, 1, 1000, 1023, 1025, 3072, MAX_BATCH_BYTES - 1, MAX_BATCH_BYTES + 1):
        refused = await sync.push(owner, space, padded(size))
        assert (refused.status, refused.error) == (400, "not_padded"), size
    too_large = await sync.push(owner, space, padded(2 * MAX_BATCH_BYTES))
    assert (too_large.status, too_large.error) == (413, "too_large")
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == len(SIZE_STEPS)


async def test_a_pull_comes_in_pages(make_sync: MakeSync) -> None:
    sync = await make_sync(
        group_sync_key_pushes_per_minute=500,
        group_sync_key_requests_per_minute=500,
        group_sync_address_requests_per_minute=1000,
    )
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)

    # By size: five batches of 1 MiB come four at a time.
    for fill in range(5):
        assert (await sync.push(owner, space, padded(MAX_BATCH_BYTES, fill))).status == 201
    first = await sync.pull(jane, space)
    assert [b["cursor"] for b in first.data["batches"]] == [1, 2, 3, 4]
    assert (first.data["next"], first.data["more"]) == (4, True)
    rest = await sync.pull(jane, space, first.data["next"])
    assert [b["cursor"] for b in rest.data["batches"]] == [5]
    assert (rest.data["next"], rest.data["more"]) == (5, False)

    # By count: at most 100 a pull.
    for _ in range(PULL_MAX_BATCHES + 1):
        assert (await sync.push(owner, space, padded(1024))).status == 201
    page = await sync.pull(jane, space, 5)
    assert len(page.data["batches"]) == PULL_MAX_BATCHES
    assert (page.data["next"], page.data["more"]) == (5 + PULL_MAX_BATCHES, True)
    last = await sync.pull(jane, space, page.data["next"])
    assert [b["cursor"] for b in last.data["batches"]] == [5 + PULL_MAX_BATCHES + 1]
    assert last.data["more"] is False


async def test_a_space_holds_thirty_members_listed_in_the_order_added(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    members = [new_member() for _ in range(MAX_MEMBERS - 1)]
    for member in members:
        assert (await sync.add(owner, space, member)).status == 201
    full = await sync.add(owner, space, new_member())
    assert (full.status, full.error) == (409, "space_full")
    assert await sync.count(SyncMember, SyncMember.space_id == space) == MAX_MEMBERS
    # The owner first, then each as added, even when the clock has not moved between them.
    status = await sync.call(owner, "GET", f"/v1/spaces/{space}")
    assert status.data["members"] == [owner.key, *(member.key for member in members)]


async def test_making_a_space_needs_a_good_licence(make_sync: MakeSync) -> None:
    sync = await make_sync()
    owner = new_member()
    space = random_id()
    path = f"/v1/spaces/{space}"
    for body, status, error in (
        (b"not json", 400, "bad_request"),
        (b"[]", 400, "bad_request"),
        ({}, 402, "licence_malformed"),
        ({"licence": "dev"}, 402, "licence_malformed"),
        ({"licence": sync.licence(lasts_ms=-1)}, 402, "licence_expired"),
        ({"licence": sync.licence(features=("business",))}, 402, "licence_feature"),
    ):
        refused = await sync.call(owner, "POST", path, body=body)
        assert (refused.status, refused.error) == (status, error), body
    assert await sync.count(SyncSpace, SyncSpace.id == space) == 0

    assert (await sync.call(owner, "POST", path, body={"licence": sync.licence()})).status == 201
    exists = await sync.call(new_member(), "POST", path, body={"licence": sync.licence()})
    assert (exists.status, exists.error) == (409, "exists")

    # No licence key configured: every licence is refused.
    unset = await make_sync(licence_public_key=None)
    no_key = await unset.call(
        owner, "POST", f"/v1/spaces/{random_id()}", body={"licence": sync.licence()}
    )
    assert (no_key.status, no_key.error) == (402, "licence_no_key")


async def test_paths_that_are_not_routes_are_refused_in_the_same_shape(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    for method, path in (
        ("GET", "/v1/spaces"),
        ("GET", "/v1/spaces/"),
        ("GET", "/v1/spaces/short"),
        ("GET", f"/v1/spaces/{random_id()}"),
        ("GET", f"/v1/spaces/{space}/"),
        ("GET", f"/v1/spaces/{space}/nothing"),
        ("PATCH", f"/v1/spaces/{space}"),
        ("POST", f"/v1/spaces/{space}/licence"),
        ("PUT", f"/v1/spaces/{space}/members/not-a-key"),
        ("DELETE", f"/v1/spaces/{space}/batches"),
    ):
        refused = await sync.call(owner, method, path)
        assert (refused.status, refused.data) == (404, {"error": "not_found"}), (method, path)


async def test_the_websocket_for_live_notices_is_not_served(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    plain = await sync.call(owner, "GET", f"/v1/spaces/{space}/ws")
    assert (plain.status, plain.data) == (404, {"error": "ws_not_available"})


@pytest.mark.parametrize("can_deny", [True, False])
async def test_a_websocket_handshake_is_refused(tmp_path: Path, can_deny: bool) -> None:
    """A phone that tries to upgrade gets the same 404, or a plain refusal from a server
    that cannot answer a handshake with a response."""
    app = create_app(make_settings(tmp_path))
    path = f"/v1/spaces/{random_id()}/ws"
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"key=k&t=1&n=n&sig=s",
        "root_path": "",
        "headers": [],
        "client": ("203.0.113.77", 51234),
        "server": ("test", 80),
        "subprotocols": [],
        "state": {},
        "extensions": {"websocket.http.response": {}} if can_deny else {},
    }
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "websocket.connect"}

    async def send(message: Any) -> None:
        sent.append(dict(message))

    await app(scope, receive, send)
    assert not any(message["type"] == "websocket.accept" for message in sent)
    if can_deny:
        start = next(m for m in sent if m["type"] == "websocket.http.response.start")
        assert start["status"] == 404
        body = b"".join(
            m.get("body", b"") for m in sent if m["type"] == "websocket.http.response.body"
        )
        assert json.loads(body) == {"error": "ws_not_available"}
    else:
        assert [m["type"] for m in sent] == ["websocket.close"]


# ---------------------------------------------------------------- privacy


def test_sync_tables_link_to_no_account() -> None:
    """These tables hold what the relay needs and nothing that names a person."""
    columns = {
        table.name: {column.name for column in table.columns}
        for table in Base.metadata.sorted_tables
        if table.name.startswith("sync_")
    }
    assert columns == {
        "sync_spaces": {"id", "owner_key", "valid_until", "last_cursor"},
        "sync_members": {"space_id", "key", "added_at", "acked", "served"},
        "sync_batches": {
            "space_id",
            "cursor",
            "batch_id",
            "author",
            "recipient",
            "size",
            "hash",
            "at",
            "object_key",
        },
        "sync_nonces": {"digest", "expires_at"},
        "sync_pending_blobs": {"object_key", "created_at"},
    }
    for name in columns:
        for key in Base.metadata.tables[name].foreign_keys:
            assert key.column.table.name == "sync_spaces"
    for table in Base.metadata.sorted_tables:
        if not table.name.startswith("sync_"):
            assert not any(k.column.table.name.startswith("sync_") for k in table.foreign_keys)


async def test_sign_in_plays_no_part_and_only_valid_until_is_kept_of_the_licence(
    sync: Sync,
) -> None:
    owner = new_member()
    space = random_id()
    token = sync.licence()
    before = await _other_rows(sync)
    # An account's bearer token is neither needed nor looked at.
    made = await sync.call(
        owner,
        "POST",
        f"/v1/spaces/{space}",
        body={"licence": token},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert (made.status, made.data) == (
        201,
        {"space": space, "validUntil": sync.clock.ms + 365 * DAY_MS},
    )
    unsigned = await sync.client.get(
        f"/v1/spaces/{space}", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert unsigned.status_code == 401

    async with sync.maker() as session:
        row = (await session.execute(select(SyncSpace).where(SyncSpace.id == space))).scalar_one()
    assert (row.owner_key, row.valid_until, row.last_cursor) == (
        owner.key,
        sync.clock.ms + 365 * DAY_MS,
        0,
    )
    # Nothing was written outside the sync tables.
    assert await _other_rows(sync) == before


async def _other_rows(sync: Sync) -> dict[str, int]:
    counts: dict[str, int] = {}
    async with sync.maker() as session:
        for table in Base.metadata.sorted_tables:
            if not table.name.startswith("sync_"):
                counts[table.name] = (
                    await session.scalar(select(func.count()).select_from(table)) or 0
                )
    return counts


async def test_someone_who_may_not_do_a_thing_adds_no_rows(sync: Sync) -> None:
    owner, mallory = new_member(), new_member()
    space = await sync.new_space(owner)
    before = {table: await sync.count(table) for table in (SyncNonce, SyncSpace, SyncMember)}
    for refused in (
        await sync.pull(mallory, space),
        await sync.push(mallory, space, padded(1024)),
        await sync.pull(mallory, random_id()),
        await sync.call(mallory, "DELETE", f"/v1/spaces/{space}"),
        await sync.call(mallory, "POST", f"/v1/spaces/{random_id()}", body={"licence": "dev"}),
        await sync.push(owner, space, bytes(100)),
    ):
        assert refused.status in (400, 402, 403, 404), refused.data
    assert before == {
        table: await sync.count(table) for table in (SyncNonce, SyncSpace, SyncMember)
    }
    assert await sync.count(SyncPendingBlob) == 0


async def test_logs_carry_no_ids_keys_addresses_or_bodies(
    make_sync: MakeSync, capsys: pytest.CaptureFixture[str]
) -> None:
    sync = await make_sync()
    owner, jane = new_member(), new_member()
    capsys.readouterr()
    space = random_id()
    token = sync.licence()
    address = {"x-forwarded-for": "198.51.100.23"}
    await sync.call(owner, "POST", f"/v1/spaces/{space}", body={"licence": token}, headers=address)
    await sync.call(owner, "PUT", f"/v1/spaces/{space}/members/{jane.key}", headers=address)
    batch_id = random_id()
    batch = os.urandom(1024)
    pushed = await sync.push(owner, space, batch, batch_id, jane.key)
    pulled = await sync.pull(jane, space)
    await sync.pull(new_member(), space)
    await sync.call(owner, "DELETE", f"/v1/spaces/{space}", headers=address)

    logged = capsys.readouterr().out
    for line in ("sync.space_created", "sync.pushed", "sync.pulled", "sync.refused"):
        assert line in logged
    assert "/v1/spaces/{space}/batches" in logged  # the route's template, not its path
    for private in (
        space,
        owner.key,
        jane.key,
        batch_id,
        token,
        token.split(".")[2],
        b64url(batch),
        base64.b64encode(batch).decode(),
        pushed.signed["x-pc-nonce"],
        pulled.signed["x-pc-sig"],
        "198.51.100.23",
        "127.0.0.1",
    ):
        assert private not in logged


async def test_an_unexpected_error_is_answered_and_logged_without_details(
    make_sync: MakeSync, capsys: pytest.CaptureFixture[str]
) -> None:
    sync = await make_sync()
    owner = new_member()
    space = await sync.new_space(owner)

    class Broken(MemoryBlobStore):
        async def put(self, key: str, chunks: Any) -> None:
            raise OSError(f"could not write {key}")

    working = sync.app.state.blob_store
    sync.app.state.blob_store = Broken()
    capsys.readouterr()
    try:
        failed = await sync.push(owner, space, padded(1024))
    finally:
        sync.app.state.blob_store = working
    assert (failed.status, failed.data) == (500, {"error": "server_error"})
    logged = capsys.readouterr().out
    assert "sync.error" in logged
    assert "OSError" in logged
    assert "could not write" not in logged
    assert space not in logged
    # Nothing is left behind: no row, and no note of an object.
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 0
    assert await sync.count(SyncPendingBlob) == 0


# ---------------------------------------------------------------- retention


async def _purge(sync: Sync, *, days: int = 0) -> retention.PurgeResult:
    """Run the daily purge as ``ngome-purge`` does, ``days`` after the test's clock."""
    now = datetime.fromtimestamp(sync.clock.ms / 1000, UTC) + timedelta(days=days)
    settings: Settings = sync.app.state.settings
    async with sync.maker() as session:
        result = await retention.purge_expired(session, settings, now=now)
        await retention.sweep_all_deletions(session, sync.store)
    return result


async def test_the_purge_deletes_batches_everyone_has_pulled_once_they_are_old(
    sync: Sync,
) -> None:
    owner, jane, otieno = new_member(), new_member(), new_member()
    space = await sync.new_space(owner, lasts_ms=400 * DAY_MS)
    await sync.add(owner, space, jane)
    await sync.add(owner, space, otieno)
    for fill, to in ((1, None), (2, jane.key), (3, otieno.key)):
        assert (await sync.push(owner, space, padded(1024, fill), to=to)).status == 201
    keys = await sync.object_keys(space)
    assert len(keys) == 3

    # Jane has pulled everything. Otieno has only pulled past the first batch.
    seen = await sync.pull(jane, space)
    await sync.pull(jane, space, seen.data["next"])
    await sync.pull(otieno, space)
    await sync.pull(otieno, space, 1)

    # Read, but not yet 90 days old: nothing goes.
    assert (await _purge(sync, days=89)).sync_batches == 0
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 3

    # 91 days on: the one for everyone and the one for Jane go; Otieno's waits for him.
    result = await _purge(sync, days=91)
    assert result.sync_batches == 2
    async with sync.maker() as session:
        left = list(
            await session.scalars(select(SyncBatch.cursor).where(SyncBatch.space_id == space))
        )
    assert left == [3]
    # The objects went with their rows.
    async with sync.maker() as session:
        kept = await session.scalar(
            select(SyncBatch.object_key).where(SyncBatch.space_id == space, SyncBatch.cursor == 3)
        )
    assert kept is not None
    assert await sync.stored(kept) == padded(1024, 3)
    gone = [key for key in keys if key != kept]
    assert len(gone) == 2
    assert [await sync.stored(key) for key in gone] == [None, None]
    assert await sync.count(BlobDeletion, BlobDeletion.object_key.in_(gone)) == 0

    # Otieno still gets his batch, and cursors are never reused.
    assert [b["cursor"] for b in (await sync.pull(otieno, space, 1)).data["batches"]] == [3]
    assert (await sync.push(owner, space, padded(1024))).data["cursor"] == 4
    # Once he is removed, nobody is left to read it.
    await sync.call(owner, "DELETE", f"/v1/spaces/{space}/members/{otieno.key}")
    assert (await _purge(sync, days=91)).sync_batches == 1


async def test_the_purge_clears_old_nonces_and_objects_left_by_dead_pushes(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    await sync.pull(owner, space)
    assert await sync.count(SyncNonce) == 2

    # A push that died after writing its object: the note is there, the row is not.
    async def one_chunk() -> AsyncIterator[bytes]:
        yield padded(1024)

    dead = f"sync/{secrets.token_hex(16)}"
    await sync.store.put(dead, one_chunk())
    async with sync.maker() as session:
        session.add(SyncPendingBlob(object_key=dead, created_at=sync.clock.ms))
        await session.commit()

    # Too soon for either: the requests could still be replayed, the push could be running.
    early = await _purge(sync)
    assert (early.sync_nonces, early.sync_orphans) == (0, 0)
    assert await sync.stored(dead) is not None

    late = await _purge(sync, days=1)
    assert (late.sync_nonces, late.sync_orphans) == (2, 1)
    assert await sync.count(SyncNonce) == 0
    assert await sync.count(SyncPendingBlob) == 0
    assert await sync.stored(dead) is None


async def test_an_instance_sweeps_nonces_a_minute_after_they_run_out(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    for _ in range(3):
        await sync.pull(owner, space)
    assert await sync.count(SyncNonce) == 4
    # Half a minute after those four ran out they are still kept: a copy of one of the
    # requests, opened in time, could still be on its way through.
    sync.clock.ms += CLOCK_WINDOW_MS + 30_000
    assert (await sync.pull(owner, space)).status == 200
    assert await sync.count(SyncNonce) == 5
    # Past the minute, the next sweep takes them. The two newer ones stay.
    sync.clock.ms += 61_000
    assert (await sync.pull(owner, space)).status == 200
    assert await sync.count(SyncNonce) == 2


async def test_the_purge_keeps_the_same_margin_for_nonces(sync: Sync) -> None:
    owner = new_member()
    await sync.new_space(owner)
    half_a_minute_past = sync.clock.ms + CLOCK_WINDOW_MS + 30_000
    async with sync.maker() as session:
        assert await service.purge_nonces(session, half_a_minute_past) == 0
        assert await service.purge_nonces(session, half_a_minute_past + 31_000) == 1


# ---------------------------------------------------------------- several instances


@postgres_only
async def test_concurrent_pushes_get_distinct_cursors(make_sync: MakeSync) -> None:
    """Two instances, two members, twenty pushes at once: every batch gets its own cursor,
    with none skipped."""
    one = await make_sync()
    two = await make_sync()
    owner, jane = new_member(), new_member()
    space = await one.new_space(owner)
    await one.add(owner, space, jane)

    pushes = [
        (one if n % 2 else two).push(owner if n % 4 < 2 else jane, space, padded(1024, n))
        for n in range(20)
    ]
    results = await asyncio.gather(*pushes)
    assert [r.status for r in results] == [201] * 20, [r.data for r in results]
    assert sorted(r.data["cursor"] for r in results) == list(range(1, 21))

    status = await two.call(owner, "GET", f"/v1/spaces/{space}")
    assert status.data["cursor"] == 20
    # Each member gets the other's ten, in cursor order, with the bytes that were pushed.
    for member in (owner, jane):
        pulled = (await one.pull(member, space)).data
        cursors = [b["cursor"] for b in pulled["batches"]]
        assert len(cursors) == 10
        assert cursors == sorted(cursors)
        assert pulled["next"] == 20
        for batch in pulled["batches"]:
            assert len(set(from_b64url(batch["data"]))) == 1
    assert await one.count(SyncPendingBlob) == 0


@postgres_only
async def test_the_same_push_sent_to_two_instances_at_once_is_one_batch(
    make_sync: MakeSync,
) -> None:
    one = await make_sync()
    two = await make_sync()
    owner = new_member()
    space = await one.new_space(owner)
    for attempt in range(5):
        batch_id = random_id()
        first, second = await asyncio.gather(
            one.push(owner, space, padded(2048, attempt), batch_id),
            two.push(owner, space, padded(2048, attempt), batch_id),
        )
        assert sorted([first.status, second.status]) == [200, 201]
        assert first.data["cursor"] == second.data["cursor"] == attempt + 1
        assert {first.data["duplicate"], second.data["duplicate"]} == {True, False}
    assert await one.count(SyncBatch, SyncBatch.space_id == space) == 5
    assert await one.count(SyncPendingBlob) == 0
    keys = await one.object_keys(space)
    assert [len(await one.stored(key) or b"") for key in keys] == [2048] * 5


@postgres_only
async def test_one_signed_request_sent_to_two_instances_at_once_is_accepted_once(
    make_sync: MakeSync,
) -> None:
    one = await make_sync()
    two = await make_sync()
    owner = new_member()
    space = await one.new_space(owner)
    path = f"/v1/spaces/{space}/batches"
    for attempt in range(5):
        batch = padded(1024, attempt)
        headers = {**sign(owner, "POST", path, batch, one.clock.ms), "x-pc-batch": random_id()}
        answers = await asyncio.gather(
            one.client.post(path, content=batch, headers=headers),
            two.client.post(path, content=batch, headers=headers),
        )
        assert sorted(a.status_code for a in answers) == [201, 401], [a.json() for a in answers]
        assert {"error": "replay"} in [a.json() for a in answers]

        signed = sign(owner, "GET", f"{path}?since=0", b"", one.clock.ms)
        pulls = await asyncio.gather(
            one.client.get(f"{path}?since=0", headers=signed),
            two.client.get(f"{path}?since=0", headers=signed),
        )
        assert sorted(p.status_code for p in pulls) == [200, 401]
    assert await one.count(SyncBatch, SyncBatch.space_id == space) == 5
    assert await one.count(SyncPendingBlob) == 0


@postgres_only
async def test_two_owners_making_the_same_space_at_once_make_it_once(make_sync: MakeSync) -> None:
    one = await make_sync()
    two = await make_sync()
    space = random_id()
    first, second = new_member(), new_member()
    made = await asyncio.gather(
        one.call(first, "POST", f"/v1/spaces/{space}", body={"licence": one.licence()}),
        two.call(second, "POST", f"/v1/spaces/{space}", body={"licence": one.licence()}),
    )
    assert sorted(m.status for m in made) == [201, 409]
    assert await one.count(SyncSpace, SyncSpace.id == space) == 1
    assert await one.count(SyncMember, SyncMember.space_id == space) == 1


@postgres_only
async def test_one_delete_sent_to_two_instances_at_once_deletes_once(make_sync: MakeSync) -> None:
    one = await make_sync()
    two = await make_sync()
    owner = new_member()
    space = await one.new_space(owner)
    await one.push(owner, space, padded(1024))
    path = f"/v1/spaces/{space}"
    signed = sign(owner, "DELETE", path, b"", one.clock.ms)
    answers = await asyncio.gather(
        one.client.delete(path, headers=signed), two.client.delete(path, headers=signed)
    )
    assert sorted(a.status_code for a in answers) == [200, 404]
    assert await one.rows(space) == {"spaces": 0, "members": 0, "batches": 0}
    # The owner makes the space again: the copy of the delete does not take it away.
    assert (await one.call(owner, "POST", path, body={"licence": one.licence()})).status == 201
    copy = await two.client.delete(path, headers=signed)
    assert (copy.status_code, copy.json()) == (401, {"error": "replay"})


@postgres_only
async def test_a_member_following_next_misses_nothing_while_others_push(
    make_sync: MakeSync,
) -> None:
    limits = {
        "group_sync_key_pushes_per_minute": 10_000,
        "group_sync_key_requests_per_minute": 10_000,
        "group_sync_address_requests_per_minute": 100_000,
    }
    one = await make_sync(**limits)
    two = await make_sync(**limits)
    owner, jane, otieno = new_member(), new_member(), new_member()
    space = await one.new_space(owner)
    await one.add(owner, space, jane)
    await one.add(owner, space, otieno)
    total = 96
    done = asyncio.Event()

    async def push_all() -> list[int]:
        async def one_push(n: int) -> int:
            sender = owner if n % 3 else otieno
            pushed = await (one if n % 2 else two).push(
                sender, space, padded(1024, n % 250), to=jane.key if n % 2 else None
            )
            assert pushed.status == 201, pushed.data
            cursor: int = pushed.data["cursor"]
            return cursor

        cursors: list[int] = []
        for start in range(0, total, 12):
            cursors += await asyncio.gather(*(one_push(n) for n in range(start, start + 12)))
        done.set()
        return cursors

    async def pull_all() -> list[int]:
        got: list[int] = []
        cursor = 0
        while True:
            finished = done.is_set()
            pulled = await two.pull(jane, space, cursor)
            assert pulled.status == 200, pulled.data
            got += [b["cursor"] for b in pulled.data["batches"]]
            assert pulled.data["next"] >= cursor
            cursor = pulled.data["next"]
            if finished and not pulled.data["more"]:
                return got

    cursors, got = await asyncio.gather(push_all(), pull_all())
    assert sorted(cursors) == list(range(1, total + 1))
    assert got == list(range(1, total + 1))  # every batch here is one Jane reads


# ---------------------------------------------------------------- object storage


@pytest.mark.object_storage
@needs_s3
async def test_batches_go_to_object_storage_and_leave_it_with_the_space(tmp_path: Path) -> None:
    seed = new_licence_seed()
    settings = make_settings(
        tmp_path, licence_public_key=licences.public_key_of(seed), **S3_SETTINGS
    )
    app = create_app(settings)
    await _ensure_bucket(app.state.blob_store)
    async with app.state.engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    clock = Clock()
    app.state.group_sync.clock = clock
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            sync = Sync(app=app, client=client, clock=clock, seed=seed)
            owner, jane = new_member(), new_member()
            space = await sync.new_space(owner)
            await sync.add(owner, space, jane)
            batch = os.urandom(MAX_BATCH_BYTES)
            assert (await sync.push(owner, space, batch, to=jane.key)).status == 201
            assert (await sync.push(owner, space, padded(1024))).status == 201
            keys = await sync.object_keys(space)
            assert all(key.startswith("sync/") and space not in key for key in keys)
            assert await sync.stored(keys[0]) == batch
            pulled = await sync.pull(jane, space)
            assert from_b64url(pulled.data["batches"][0]["data"]) == batch
            assert (await sync.call(owner, "DELETE", f"/v1/spaces/{space}")).status == 200
            assert [await sync.stored(key) for key in keys] == [None, None]
            s3 = await app.state.blob_store._s3()
            listed = await s3.list_objects_v2(
                Bucket=str(S3_SETTINGS["vault_s3_bucket"]), Prefix="sync/"
            )
            assert not {item["Key"] for item in listed.get("Contents", [])} & set(keys)
    finally:
        await app.state.blob_store.aclose()
        await app.state.engine.dispose()


# ---------------------------------------------------------------- settings and the command


def test_the_licence_public_key_setting_is_checked(tmp_path: Path) -> None:
    public = licences.public_key_of(new_licence_seed())
    assert make_settings(tmp_path, licence_public_key=public).licence_public_key == public
    # Standard base64, as the app status key is written, is taken too.
    standard = base64.b64encode(from_b64url(public)).decode()
    assert make_settings(tmp_path, licence_public_key=standard).licence_public_key == public
    for unset in (None, "", "  "):
        assert make_settings(tmp_path, licence_public_key=unset).licence_public_key is None
    for bad in ("not a key", public[:-2], b64url(os.urandom(31)), b64url(os.urandom(33))):
        with pytest.raises(ValidationError, match="licence_public_key"):
            make_settings(tmp_path, licence_public_key=bad)


def test_the_licence_command_makes_a_pair_and_mints_without_showing_the_private_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "licence.key"
    licences.main(["new", str(key_file)])
    made = capsys.readouterr()
    private = key_file.read_text().strip()
    assert len(base64.b64decode(private)) == 32
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    public = next(
        line.removeprefix("NGOME_LICENCE_PUBLIC_KEY=")
        for line in made.out.splitlines()
        if line.startswith("NGOME_LICENCE_PUBLIC_KEY=")
    )
    assert private not in made.out + made.err
    assert make_settings(tmp_path, licence_public_key=public).licence_public_key == public

    # It never writes over a key that is there.
    with pytest.raises(SystemExit, match="already exists"):
        licences.main(["new", str(key_file)])
    assert key_file.read_text().strip() == private

    licences.main(["public", "--key-file", str(key_file)])
    assert capsys.readouterr().out.strip() == public

    now = service.wall_clock_ms()
    verifier = Ed25519LicenceVerifier(public)
    licences.main(["mint", "--key-file", str(key_file), "--days", "30"])
    minted = capsys.readouterr()
    assert private not in minted.out + minted.err
    result = verifier.verify(minted.out.strip(), now)
    assert result.valid_until is not None
    assert abs(result.valid_until - (now + 30 * DAY_MS)) < 60_000

    licences.main(["mint", "--key-file", str(key_file), "--minutes", "10"])
    short = verifier.verify(capsys.readouterr().out.strip(), now)
    assert short.valid_until is not None
    assert abs(short.valid_until - (now + 600_000)) < 60_000

    # The private key can come from the environment instead of a file.
    monkeypatch.setenv(licences.SEED_ENV, private)
    licences.main(["mint", "--feature", "business"])
    other = capsys.readouterr().out.strip()
    assert verifier.verify(other, now) == LicenceResult(why="feature")

    # A key it cannot use is refused without being shown.
    monkeypatch.setenv(licences.SEED_ENV, "bm90IGEga2V5IGF0IGFsbA==")
    with pytest.raises(SystemExit) as refused:
        licences.main(["mint"])
    assert "bm90IGEga2V5" not in str(refused.value)
    monkeypatch.delenv(licences.SEED_ENV)
    with pytest.raises(SystemExit, match="--key-file"):
        licences.main(["mint"])


# ---------------------------------------------------------------- replays, timing and care
# From the review of the pull request: each of these failed before its fix.


async def _raw_http(
    app: FastAPI,
    method: str,
    path: str,
    headers: dict[str, str],
    messages: list[dict[str, Any]],
) -> tuple[int | None, bytes]:
    """Drive the app as an HTTP server would, with full say over headers and body events."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
        "client": ("203.0.113.9", 1),
        "server": ("test", 80),
        "state": {},
    }
    waiting = list(messages)
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return waiting.pop(0) if waiting else {"type": "http.disconnect"}

    async def send(message: Any) -> None:
        sent.append(dict(message))

    await app(scope, receive, send)
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


async def test_a_request_is_timed_when_its_body_has_arrived_not_when_it_starts(
    sync: Sync,
) -> None:
    """A copy of a request, opened inside the clock window with its body held back until
    the nonce has been swept, must not get in."""
    owner = new_member()
    space = await sync.new_space(owner)
    path = f"/v1/spaces/{space}/batches"
    batch = padded(1024, 9)
    start = sync.clock.ms
    captured = sign(owner, "POST", path, batch, start)

    async def send(body: Any) -> httpx.Response:
        headers = {**captured, "x-pc-batch": random_id()}
        return await sync.client.post(path, content=body, headers=headers)

    assert (await send(batch)).status_code == 201
    assert (await send(batch)).json() == {"error": "replay"}

    release = asyncio.Event()

    async def held_body() -> AsyncIterator[bytes]:
        await release.wait()
        yield batch

    # Opened a second before the window closes.
    sync.clock.ms = start + CLOCK_WINDOW_MS - 1000
    held = asyncio.create_task(send(held_body()))
    await asyncio.sleep(0.3)
    assert not held.done()
    # Two minutes on. Any signed request makes the instance sweep old nonces.
    sync.clock.ms = start + CLOCK_WINDOW_MS + 121_000
    assert (await sync.pull(new_member(), random_id())).status == 404
    release.set()
    answer = await held
    assert (answer.status_code, answer.json()) == (401, {"error": "clock"})
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 1


async def test_a_request_without_a_body_held_open_is_timed_when_it_ends(sync: Sync) -> None:
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    assert (await sync.add(owner, space, jane)).status == 201
    start = sync.clock.ms
    removed = await sync.call(owner, "DELETE", f"/v1/spaces/{space}/members/{jane.key}")
    assert removed.status == 200
    # The owner changes their mind and adds Jane back.
    assert (await sync.add(owner, space, jane)).status == 201

    release = asyncio.Event()

    async def empty_but_late() -> AsyncIterator[bytes]:
        await release.wait()
        return
        yield b""  # pragma: no cover

    sync.clock.ms = start + CLOCK_WINDOW_MS - 1000
    held = asyncio.create_task(
        sync.client.request(
            "DELETE",
            f"/v1/spaces/{space}/members/{jane.key}",
            content=empty_but_late(),
            headers=removed.signed,
        )
    )
    await asyncio.sleep(0.3)
    sync.clock.ms = start + CLOCK_WINDOW_MS + 121_000
    assert (await sync.pull(new_member(), random_id())).status == 404
    release.set()
    answer = await held
    assert (answer.status_code, answer.json()) == (401, {"error": "clock"})
    assert (await sync.pull(jane, space)).status == 200


async def test_a_body_that_does_not_arrive_in_time_is_refused(sync: Sync) -> None:
    sync.app.state.group_sync.body_seconds = 0.2
    owner = new_member()
    space = await sync.new_space(owner)
    path = f"/v1/spaces/{space}/batches"
    never = asyncio.Event()

    async def stalled() -> AsyncIterator[bytes]:
        yield padded(512)
        await never.wait()
        yield padded(512)

    signed = sign(owner, "POST", path, padded(1024), sync.clock.ms)
    answer = await asyncio.wait_for(
        sync.client.post(path, content=stalled(), headers={**signed, "x-pc-batch": random_id()}),
        timeout=5,
    )
    assert (answer.status_code, answer.json()) == (408, {"error": "too_slow"})
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 0
    never.set()


async def test_a_request_that_cannot_pass_is_refused_without_waiting_for_its_body(
    sync: Sync,
) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    path = f"/v1/spaces/{space}/batches"
    never = asyncio.Event()

    async def held() -> AsyncIterator[bytes]:
        yield padded(512)
        await never.wait()
        yield padded(512)

    # No signature at all, and one made ten minutes ago: neither needs the body to refuse.
    stale = sign(owner, "POST", path, padded(1024), sync.clock.ms - 600_000)
    for headers, error in (({}, "unauthorized"), (stale, "clock")):
        answer = await asyncio.wait_for(
            sync.client.post(path, content=held(), headers=headers), timeout=5
        )
        assert (answer.status_code, answer.json()) == (401, {"error": error})
    never.set()


async def test_a_push_that_leaves_its_window_while_it_is_stored_is_refused(sync: Sync) -> None:
    """The window is looked at again when the nonce is written, however long the work took."""
    owner = new_member()
    space = await sync.new_space(owner)
    working = sync.app.state.blob_store
    clock = sync.clock
    stored: list[str] = []

    class Slow:
        async def put(self, key: str, chunks: Any) -> None:
            await working.put(key, chunks)
            stored.append(key)
            clock.ms += CLOCK_WINDOW_MS + 1000  # six minutes go by while the object is written

        def __getattr__(self, name: str) -> Any:
            return getattr(working, name)

    sync.app.state.blob_store = Slow()
    try:
        late = await sync.push(owner, space, padded(1024))
    finally:
        sync.app.state.blob_store = working
    assert (late.status, late.error) == (401, "clock")
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 0
    assert await sync.count(SyncPendingBlob) == 0
    assert [await sync.stored(key) for key in stored] == [None]


async def test_a_captured_request_stays_refused_after_the_space_is_deleted_and_made_again(
    sync: Sync,
) -> None:
    owner, jane, mallory = new_member(), new_member(), new_member()
    space = random_id()
    path = f"/v1/spaces/{space}"
    licence_body = {"licence": sync.licence()}
    made = await sync.call(owner, "POST", path, body=licence_body)
    assert made.status == 201
    add_mallory = await sync.add(owner, space, mallory)
    assert add_mallory.status == 201
    kicked = await sync.call(owner, "DELETE", f"{path}/members/{mallory.key}")
    assert kicked.status == 200
    deleted = await sync.call(owner, "DELETE", path)
    assert deleted.status == 200

    # A copy of the owner's own create would make the deleted space again.
    remade = await sync.call(owner, "POST", path, body=licence_body, reuse=made.signed)
    assert (remade.status, remade.error) == (401, "replay")
    assert await sync.count(SyncSpace, SyncSpace.id == space) == 0

    # The owner turns sync on again a minute later; the app uses the same space id.
    sync.clock.ms += 60_000
    assert (await sync.call(owner, "POST", path, body=licence_body)).status == 201
    assert (await sync.add(owner, space, jane)).status == 201
    assert (await sync.push(owner, space, padded(1024), to=jane.key)).status == 201

    # Copies of requests from before the delete, all still inside their five minutes.
    back = await sync.call(owner, "PUT", f"{path}/members/{mallory.key}", reuse=add_mallory.signed)
    assert (back.status, back.error) == (401, "replay")
    assert (await sync.pull(mallory, space)).error == "not_member"
    again = await sync.call(owner, "DELETE", path, reuse=deleted.signed)
    assert (again.status, again.error) == (401, "replay")
    assert await sync.count(SyncSpace, SyncSpace.id == space) == 1
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 1


async def test_a_replay_does_not_spend_the_members_allowance(make_sync: MakeSync) -> None:
    sync = await make_sync(group_sync_key_requests_per_minute=5, group_sync_key_pushes_per_minute=3)
    owner = new_member()
    space = await sync.new_space(owner)  # the owner's first request
    once = await sync.pull(owner, space)  # the second
    assert once.status == 200
    elsewhere = {"x-forwarded-for": "198.51.100.23"}  # whoever copied it, from their address
    pull_path = f"/v1/spaces/{space}/batches?since=0"
    replies = [
        (await sync.call(owner, "GET", pull_path, reuse=once.signed, headers=elsewhere)).error
        for _ in range(6)
    ]
    assert replies == ["replay"] * 6
    # The member is not held back by them.
    assert (await sync.pull(owner, space)).status == 200

    path = f"/v1/spaces/{space}/batches"
    batch = padded(1024)
    captured = sign(owner, "POST", path, batch, sync.clock.ms)
    for expected in (201, 401, 401, 401, 401):
        headers = {**captured, "x-pc-batch": random_id()}
        copy = await sync.client.post(path, content=batch, headers=headers)
        assert copy.status_code == expected
    # One push of three is used; the copies took none.
    assert (await sync.push(owner, space, padded(1024))).status == 201


async def test_a_replay_learns_nothing_from_the_headers_that_are_not_signed(sync: Sync) -> None:
    owner, jane, stranger = new_member(), new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)
    janes_batch = random_id()
    assert (await sync.push(jane, space, padded(1024, 3), batch_id=janes_batch)).status == 201

    path = f"/v1/spaces/{space}/batches"
    batch = padded(1024, 1)
    captured = sign(owner, "POST", path, batch, sync.clock.ms)
    first = await sync.client.post(
        path, content=batch, headers={**captured, "x-pc-batch": random_id()}
    )
    assert first.status_code == 201

    # X-PC-To and X-PC-Batch are outside the signature. A copy of the push must get the same
    # answer whatever they say: not who is a member, nor which batch ids are taken.
    for extra in (
        {"x-pc-batch": random_id(), "x-pc-to": jane.key},
        {"x-pc-batch": random_id(), "x-pc-to": stranger.key},
        {"x-pc-batch": janes_batch},
        {"x-pc-batch": "short"},
        {"x-pc-batch": random_id()},
    ):
        copy = await sync.client.post(path, content=batch, headers={**captured, **extra})
        assert (copy.status_code, copy.json()) == (401, {"error": "replay"}), extra


async def test_a_cursor_from_before_the_space_was_deleted_and_made_again_starts_over(
    sync: Sync,
) -> None:
    owner, jane = new_member(), new_member()
    space = random_id()
    path = f"/v1/spaces/{space}"
    licence_body = {"licence": sync.licence()}

    async def remake(batches: int) -> None:
        assert (await sync.call(owner, "DELETE", path)).status == 200
        assert (await sync.call(owner, "POST", path, body=licence_body)).status == 201
        assert (await sync.add(owner, space, jane)).status == 201
        for n in range(batches):
            pushed = await sync.push(owner, space, padded(1024, 50 + n), to=jane.key)
            assert pushed.data["cursor"] == n + 1

    assert (await sync.call(owner, "POST", path, body=licence_body)).status == 201
    await sync.add(owner, space, jane)
    for n in range(3):
        assert (await sync.push(owner, space, padded(1024, n), to=jane.key)).status == 201
    assert (await sync.pull(jane, space)).data["next"] == 3  # Jane's phone keeps 3

    # The owner turns sync off and on again; Jane's phone did not sync in between. Its old
    # cursor is past anything the new space has given out: she gets everything, and the
    # cursor her phone keeps next is the new space's.
    await remake(batches=2)
    pulled = await sync.pull(jane, space, since=3)
    assert [b["cursor"] for b in pulled.data["batches"]] == [1, 2]
    assert (pulled.data["next"], pulled.data["more"]) == (2, False)
    assert (await sync.pull(jane, space, since=2)).data["batches"] == []

    # The same when the new space has already passed her old cursor: it is still one this
    # space never gave her.
    await remake(batches=5)
    pulled = await sync.pull(jane, space, since=2)
    assert [b["cursor"] for b in pulled.data["batches"]] == [1, 2, 3, 4, 5]
    assert pulled.data["next"] == 5
    # A made-up cursor marks nothing as pulled, so retention keeps what she has not had.
    await remake(batches=2)
    await sync.pull(jane, space, since=1_000_000)
    async with sync.maker() as session:
        acked = await session.scalar(
            select(SyncMember.acked).where(SyncMember.space_id == space, SyncMember.key == jane.key)
        )
    assert acked == 0


async def test_a_batch_whose_object_is_missing_is_not_skipped(sync: Sync) -> None:
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)
    for n in range(3):
        assert (await sync.push(owner, space, padded(1024, n), to=jane.key)).status == 201
    keys = await sync.object_keys(space)
    lost = await sync.stored(keys[1])
    assert lost is not None
    await sync.store.delete(keys[1])  # the store lost it, or the server reads another store

    # What comes before the gap is delivered; the gap itself is an error, not a skip.
    pulled = await sync.pull(jane, space)
    assert [b["cursor"] for b in pulled.data["batches"]] == [1]
    assert (pulled.data["next"], pulled.data["more"]) == (1, True)
    stuck = await sync.pull(jane, space, since=1)
    assert (stuck.status, stuck.data) == (500, {"error": "server_error"})
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 3

    async def one_chunk() -> AsyncIterator[bytes]:
        yield lost

    await sync.store.put(keys[1], one_chunk())  # the object is back
    rest = await sync.pull(jane, space, since=1)
    assert [b["cursor"] for b in rest.data["batches"]] == [2, 3]
    assert (rest.data["next"], rest.data["more"]) == (3, False)


async def test_a_batch_deleted_while_a_pull_reads_it_is_passed_over(sync: Sync) -> None:
    """Retention can take a batch between a pull's query and its read: row and object."""
    owner, jane = new_member(), new_member()
    space = await sync.new_space(owner)
    await sync.add(owner, space, jane)
    for n in range(3):
        assert (await sync.push(owner, space, padded(1024, n), to=jane.key)).status == 201
    keys = await sync.object_keys(space)
    working = sync.app.state.blob_store
    maker = sync.maker

    class Racing:
        async def open(self, key: str) -> Any:
            if key == keys[1]:
                async with maker() as session:
                    await session.execute(delete(SyncBatch).where(SyncBatch.object_key == key))
                    await session.commit()
                await working.delete(key)
            return await working.open(key)

        def __getattr__(self, name: str) -> Any:
            return getattr(working, name)

    sync.app.state.blob_store = Racing()
    try:
        pulled = await sync.pull(jane, space)
    finally:
        sync.app.state.blob_store = working
    assert pulled.status == 200
    assert [b["cursor"] for b in pulled.data["batches"]] == [1, 3]
    assert (pulled.data["next"], pulled.data["more"]) == (3, False)


def _downgrade(connection: Any, revision: str) -> None:
    config = Config(str(ALEMBIC_INI))
    config.attributes["configure_logger"] = False
    config.attributes["connection"] = connection
    command.downgrade(config, revision)


@pytest.mark.parametrize("backend", BACKENDS)
async def test_undoing_the_migration_queues_every_object_for_deletion(
    backend: str, tmp_path: Path
) -> None:
    url = POSTGRES_URL if backend == "postgres" else f"sqlite+aiosqlite:///{tmp_path / 'm.db'}"
    assert url is not None
    engine = create_engine(url)
    key = "k" * 43
    stored, noted, both = (f"sync/{secrets.token_hex(16)}" for _ in range(3))
    try:
        await upgrade_to_head(engine, ALEMBIC_INI)
        async with create_sessionmaker(engine)() as session:
            space = random_id()
            session.add(SyncSpace(id=space, owner_key=key, valid_until=1, last_cursor=1))
            await session.flush()
            session.add(
                SyncBatch(
                    space_id=space,
                    cursor=1,
                    batch_id=random_id(),
                    author=key,
                    recipient=None,
                    size=1024,
                    hash="h" * 43,
                    at=1,
                    object_key=stored,
                )
            )
            session.add_all(SyncPendingBlob(object_key=k, created_at=1) for k in (noted, both))
            session.add(BlobDeletion(object_key=both))  # queued already: not queued twice
            await session.commit()

        async with engine.begin() as connection:
            await connection.run_sync(_downgrade, "0008")

        async with engine.connect() as connection:
            tables = await connection.run_sync(lambda c: inspect(c).get_table_names())
            queued = set(
                await connection.scalars(
                    select(BlobDeletion.object_key).where(
                        BlobDeletion.object_key.in_([stored, noted, both])
                    )
                )
            )
        assert not [name for name in tables if name.startswith("sync_")]
        assert queued == {stored, noted, both}
    finally:
        async with create_sessionmaker(engine)() as session:
            await session.execute(
                delete(BlobDeletion).where(BlobDeletion.object_key.in_([stored, noted, both]))
            )
            await session.commit()
        await upgrade_to_head(engine, ALEMBIC_INI)
        await engine.dispose()


# The eight points of small order on Ed25519, worked out from the curve rather than copied.
_P = 2**255 - 19
_D = (-121665 * pow(121666, -1, _P)) % _P


def _point(raw: bytes) -> tuple[int, int] | None:
    """Decode as a lenient verifier does: any y below 2^255, either sign."""
    y = (int.from_bytes(raw, "little") & ((1 << 255) - 1)) % _P
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x = (u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P)) % _P
    if (v * x * x - u) % _P != 0:
        if (v * x * x + u) % _P != 0:
            return None
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
    return (x if x % 2 == raw[31] >> 7 else (_P - x) % _P, y)


def _times_eight(point: tuple[int, int]) -> tuple[int, int]:
    x, y = point
    for _ in range(3):
        t = _D * x * x * y * y % _P
        x, y = (2 * x * y) * pow(1 + t, -1, _P) % _P, (y * y + x * x) * pow(1 - t, -1, _P) % _P
    return x, y


def _small_order_encodings() -> list[bytes]:
    order_eight = int.from_bytes(
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"
    )
    encodings = []
    for y in (0, 1, _P - 1, order_eight, _P - order_eight):
        for spelt in (y, y + _P):  # the second is the same y, not reduced
            if spelt < 2**255:
                for sign in (0, 1):
                    encodings.append((spelt | sign << 255).to_bytes(32, "little"))
    return encodings


def test_keys_of_small_order_are_refused(tmp_path: Path) -> None:
    """Such a key "signs" anything: with the identity as the key, the identity and zero are
    a valid signature over every message."""
    encodings = _small_order_encodings()
    assert len(encodings) == 14
    for raw in encodings:
        point = _point(raw)
        assert point is not None
        assert _times_eight(point) == (0, 1)
        assert is_small_order(raw)
        assert not is_key(b64url(raw))
        with pytest.raises(ValidationError, match="licence_public_key"):
            make_settings(tmp_path, licence_public_key=b64url(raw))
        with pytest.raises(ValidationError, match="licence_public_key"):
            make_settings(tmp_path, licence_public_key=base64.b64encode(raw).decode())

    identity = bytes([1]) + bytes(31)
    forged = b64url(identity + bytes(32))
    assert not verify_ed25519(b64url(identity), b"anything at all", forged)
    now = service.wall_clock_ms()
    parts = SignedParts(key=b64url(identity), time=str(now), nonce=random_id(), sig=forged)
    assert check_signature(parts, "GET", "/v1/spaces/x", b"", now) == "malformed"
    licence_text = "pclic.1." + b64url(b'{"v":1,"exp":9999999999999,"features":["group-sync"]}')
    forged_licence = f"{licence_text}.{forged}"
    assert Ed25519LicenceVerifier(b64url(identity)).verify(forged_licence, now) == LicenceResult(
        why="signature"
    )

    # Real keys are untouched.
    member = new_member()
    assert is_key(member.key)
    assert not is_small_order(from_b64url(member.key))


async def test_a_key_of_small_order_cannot_sign_a_request_or_be_made_a_member(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    identity = b64url(bytes([1]) + bytes(31))
    forged = {
        "x-pc-key": identity,
        "x-pc-time": str(sync.clock.ms),
        "x-pc-nonce": random_id(),
        "x-pc-sig": b64url(bytes([1]) + bytes(63)),
    }
    refused = await sync.client.post(
        f"/v1/spaces/{random_id()}", content=b'{"licence": "x"}', headers=forged
    )
    assert (refused.status_code, refused.json()) == (401, {"error": "unauthorized"})
    added = await sync.call(owner, "PUT", f"/v1/spaces/{space}/members/{identity}")
    assert (added.status, added.error) == (404, "not_found")
    to = await sync.push(owner, space, padded(1024), to=identity)
    assert (to.status, to.error) == (400, "bad_recipient")


def test_a_key_has_one_spelling() -> None:
    """Base64 leaves two bits spare in 43 characters, so four texts decode to one key. Only
    the one the app writes is a key here, so a member has one name."""
    member = new_member()
    raw = from_b64url(member.key)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(member.key[-1])
    spellings = [member.key[:-1] + alphabet[(last & ~3) | n] for n in range(4)]
    assert all(from_b64url(spelling) == raw for spelling in spellings)
    assert [spelling for spelling in spellings if is_key(spelling)] == [member.key]


async def test_a_content_length_that_is_not_plain_digits_is_not_a_server_error(
    sync: Sync,
) -> None:
    """An HTTP server would refuse such a header itself; the app must not fall over if one
    lets it through."""
    status, body = await _raw_http(
        sync.app,
        "GET",
        f"/v1/spaces/{random_id()}",
        {"content-length": "²"},
        [{"type": "http.request", "body": b"", "more_body": False}],
    )
    assert (status, json.loads(body)) == (401, {"error": "unauthorized"})


async def test_a_caller_who_goes_away_mid_body_is_not_logged_as_an_error(
    make_sync: MakeSync, capsys: pytest.CaptureFixture[str]
) -> None:
    sync = await make_sync()
    owner = new_member()
    space = await sync.new_space(owner)
    path = f"/v1/spaces/{space}/batches"
    signed = sign(owner, "POST", path, padded(1024), sync.clock.ms)
    capsys.readouterr()
    status, _ = await _raw_http(
        sync.app,
        "POST",
        path,
        {**signed, "x-pc-batch": random_id()},
        [{"type": "http.request", "body": padded(512), "more_body": True}],  # then gone
    )
    logged = capsys.readouterr().out
    assert status != 500
    assert "sync.error" not in logged
    assert "Traceback" not in logged
    assert await sync.count(SyncBatch, SyncBatch.space_id == space) == 0


async def test_the_size_cap_holds_for_a_body_sent_in_chunks(sync: Sync) -> None:
    owner = new_member()
    space = await sync.new_space(owner)
    path = f"/v1/spaces/{space}/batches"
    sent = 0

    async def endless() -> AsyncIterator[bytes]:
        nonlocal sent
        while True:  # no Content-Length, and no end
            sent += 64 * 1024
            yield bytes(64 * 1024)

    signed = sign(owner, "POST", path, b"", sync.clock.ms)
    refused = await asyncio.wait_for(
        sync.client.post(path, content=endless(), headers={**signed, "x-pc-batch": random_id()}),
        timeout=10,
    )
    assert (refused.status_code, refused.json()) == (413, {"error": "too_large"})
    assert sent <= MAX_BATCH_BYTES + 128 * 1024  # stopped reading just past the cap
