"""What the group sync routes do: spaces, members, pushes, pulls, retention.

The Worker this replaces ran one single-threaded cell per space. Here several Cloud Run
instances share Postgres, so:

- everything that changes a space first locks its row (``SELECT ... FOR UPDATE``), which
  puts changes to one space in a line. A new batch takes the next cursor under that lock,
  so cursors are never shared or reused and a lower one is always committed first;
- a push is idempotent by batch id, checked under the lock and backed by a unique
  constraint;
- every request's nonce is written in the same transaction as what the request does, with
  the primary key refusing a second copy, so of two copies of one signed request sent to two
  instances exactly one is accepted.

A request is checked in this order: the signature and the clock, once its body has arrived;
whether the space exists and the signer may do this; whether its nonce has been seen (a
read, so a copy of an old request is refused before it can use up the member's allowance or
learn anything from headers the signature does not cover); the per-key limits and the rest;
and last the nonce is written, with the clock looked at once more. So only a request that is
otherwise allowed writes anything, and someone who is not a member of a space cannot add
rows to the database.

Nonces are kept as digests and outlive their space, so a copy of a request made before a
space was deleted is still refused if the space is made again. They are swept a minute after
they run out, never sooner, so a sweep cannot let a copy in while it is being served.

Batch bytes go to the blob store before their row, so a row never points at a missing
object. The object key is noted first (``sync_pending_blobs``), so an object whose push died
half way is found and deleted by the purge.
"""

import hashlib
import json
import secrets
import time
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.core.config import Settings
from ngome.core.logging import get_logger
from ngome.core.security import utcnow
from ngome.db.upsert import insert_for
from ngome.groupsync.licence import Ed25519LicenceVerifier, LicenceVerifier
from ngome.groupsync.models import SyncBatch, SyncMember, SyncNonce, SyncPendingBlob, SyncSpace
from ngome.groupsync.protocol import (
    BODY_SECONDS,
    CLOCK_WINDOW_MS,
    MAX_MEMBERS,
    MAX_SAFE_INTEGER,
    PULL_MAX_BATCHES,
    PULL_MAX_BYTES,
    SignedParts,
    b64url,
    is_id,
    is_key,
    is_padded_size,
    sha256_b64url,
)
from ngome.groupsync.ratelimit import RateLimiter
from ngome.groupsync.retention import BatchRow, expired_batches
from ngome.vault.models import BlobDeletion
from ngome.vault.storage import BlobNotFoundError, BlobStore

log = get_logger(__name__)

# An object noted this long ago with no batch row belongs to a push that died.
PENDING_BLOB_GRACE_MS = 60 * 60_000
# Old nonces are swept this often by each instance, and by the daily purge.
NONCE_SWEEP_EVERY_MS = 60_000
# A nonce is swept only once it ran out this long ago. A request is inside its clock window
# when its nonce is written, so no sweep can clear the way for a copy that is still being
# served, nor can an instance whose clock is a little ahead.
NONCE_SWEEP_MARGIN_MS = 60_000
# How long deleting a space spends removing objects before leaving the rest, already queued,
# to the purge.
DELETE_NOW_SECONDS = 8.0
_DELETE_CHUNK = 100
_PURGE_CHUNK = 500


class RefusedError(Exception):
    """The request is refused with this status and error code."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class ObjectMissingError(Exception):
    """A batch's row is there and its object is not. Never expected: the store lost it, or
    the server is reading another store than the one it was written to."""


def wall_clock_ms() -> int:
    return time.time_ns() // 1_000_000


@dataclass
class GroupSync:
    """What the routes share on one instance: the licence check, the in-memory limits and
    the clock."""

    licences: LicenceVerifier
    # Per member key, in each space: requests in general, and pushes.
    requests: RateLimiter
    pushes: RateLimiter
    # Per caller's address: a backstop against floods. The address is only ever a key in
    # this instance's memory.
    addresses: RateLimiter
    clock: Callable[[], int] = wall_clock_ms
    # How long a request's body may take to arrive, before the allowance for its size.
    body_seconds: float = BODY_SECONDS
    _next_nonce_sweep: int = field(default=0, init=False)

    @classmethod
    def from_settings(cls, settings: Settings) -> "GroupSync":
        per_key = settings.group_sync_key_requests_per_minute
        pushes = settings.group_sync_key_pushes_per_minute
        per_address = settings.group_sync_address_requests_per_minute
        return cls(
            licences=Ed25519LicenceVerifier(settings.licence_public_key),
            requests=RateLimiter(per_key, per_key),
            pushes=RateLimiter(pushes, pushes),
            addresses=RateLimiter(per_address, per_address),
        )

    def nonce_sweep_due(self, now_ms: int) -> bool:
        """True about once a minute, when this instance should clear old nonces (with
        :func:`purge_nonces`, which leaves the margin)."""
        if now_ms < self._next_nonce_sweep:
            return False
        self._next_nonce_sweep = now_ms + NONCE_SWEEP_EVERY_MS
        return True


@dataclass(frozen=True, slots=True)
class Call:
    """One request whose signature and clock have been checked."""

    space: str
    signer: str
    parts: SignedParts
    body: bytes
    now: int


@dataclass(frozen=True, slots=True)
class Answer:
    status: int
    body: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Space:
    owner: str
    valid_until: int
    last_cursor: int


@dataclass(frozen=True, slots=True)
class _Member:
    acked: int
    served: int


# ------------------------------------------------------------ shared checks


async def _space(session: AsyncSession, space_id: str, *, lock: bool = False) -> _Space | None:
    query = select(SyncSpace.owner_key, SyncSpace.valid_until, SyncSpace.last_cursor).where(
        SyncSpace.id == space_id
    )
    if lock:
        query = query.with_for_update()
    row = (await session.execute(query)).first()
    return None if row is None else _Space(row.owner_key, row.valid_until, row.last_cursor)


async def _is_member(session: AsyncSession, space_id: str, key: str) -> bool:
    found = await session.scalar(
        select(SyncMember.key).where(SyncMember.space_id == space_id, SyncMember.key == key)
    )
    return found is not None


async def _member_space(
    session: AsyncSession, call: Call, *, lock: bool = False
) -> tuple[_Space, _Member]:
    """The space and the signer's place in it, or the refusal.

    Without the lock both are read in one statement, so a space being deleted is either
    there with its members or gone: never there with its members missing. With the lock the
    space's row is taken first and the member read after it; every change to members holds
    that lock, so the member is as it stands.
    """
    if lock:
        space = await _space(session, call.space, lock=True)
        row = None
        if space is not None:
            row = (
                await session.execute(
                    select(SyncMember.acked, SyncMember.served).where(
                        SyncMember.space_id == call.space, SyncMember.key == call.signer
                    )
                )
            ).first()
        member = None if row is None else _Member(row.acked, row.served)
    else:
        both = (
            await session.execute(
                select(
                    SyncSpace.owner_key,
                    SyncSpace.valid_until,
                    SyncSpace.last_cursor,
                    SyncMember.key,
                    SyncMember.acked,
                    SyncMember.served,
                )
                .select_from(SyncSpace)
                .outerjoin(
                    SyncMember,
                    (SyncMember.space_id == SyncSpace.id) & (SyncMember.key == call.signer),
                )
                .where(SyncSpace.id == call.space)
            )
        ).first()
        space = None if both is None else _Space(*both[:3])
        member = None if both is None or both.key is None else _Member(both.acked, both.served)
    if space is None:
        raise RefusedError(404, "not_found")
    if member is None:
        raise RefusedError(403, "not_member")
    return space, member


async def _owner_space(session: AsyncSession, call: Call, *, lock: bool = False) -> _Space:
    space = await _space(session, call.space, lock=lock)
    if space is None:
        raise RefusedError(404, "not_found")
    if space.owner != call.signer:
        raise RefusedError(403, "not_owner")
    return space


def _limit(limiter: RateLimiter, call: Call) -> None:
    if not limiter.take(f"{call.space}/{call.signer}", call.now):
        raise RefusedError(429, "rate_limited")


def _nonce_digest(space_id: str, nonce: str) -> bytes:
    """What is kept of a nonce: neither the space id nor the nonce can hold a newline."""
    return hashlib.sha256(f"{space_id}\n{nonce}".encode()).digest()


async def _refuse_replay(session: AsyncSession, call: Call) -> None:
    """Refuse a request whose nonce this space has seen, before it is looked at any further.

    A read only. The nonce is written by :func:`_use_nonce` when the request is accepted,
    which is also what settles two copies racing each other.
    """
    expires = await session.scalar(
        select(SyncNonce.expires_at).where(
            SyncNonce.digest == _nonce_digest(call.space, call.parts.nonce)
        )
    )
    if expires is not None and expires >= call.now:
        raise RefusedError(401, "replay")


async def _use_nonce(session: AsyncSession, state: GroupSync, call: Call) -> None:
    """Record the request's nonce, refusing one this space has seen within the clock window.

    One statement, so two copies of a request racing on two instances cannot both pass: the
    second waits for the first's transaction and then finds the row. The clock is read again
    first: however long the request took to get here (a slow object store, a wait for a
    lock), its nonce is only written while it is still inside its window, and nonces are
    swept a minute after they run out, so a sweep never clears the way for a copy.
    """
    now = state.clock()
    if abs(now - int(call.parts.time)) > CLOCK_WINDOW_MS:
        raise RefusedError(401, "clock")
    insert = insert_for(session)
    statement = insert(SyncNonce).values(
        digest=_nonce_digest(call.space, call.parts.nonce),
        expires_at=int(call.parts.time) + CLOCK_WINDOW_MS + 1,
    )
    written = await session.execute(
        statement.on_conflict_do_update(
            index_elements=[SyncNonce.digest],
            set_={"expires_at": statement.excluded.expires_at},
            # Only over a row that has run out and not been swept yet.
            where=SyncNonce.expires_at < now,
        ).returning(SyncNonce.digest)
    )
    if written.first() is None:
        raise RefusedError(401, "replay")


def _json_object(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        raise RefusedError(400, "bad_request") from None
    if not isinstance(value, dict):
        raise RefusedError(400, "bad_request")
    return value


def _check_licence(state: GroupSync, call: Call) -> int:
    result = state.licences.verify(_json_object(call.body).get("licence"), call.now)
    if result.valid_until is None:
        raise RefusedError(402, f"licence_{result.why}")
    return result.valid_until


# ------------------------------------------------------------ spaces and members


async def create(session: AsyncSession, state: GroupSync, call: Call) -> Answer:
    """The owner makes the space with their licence; they are its first member."""
    if await _space(session, call.space) is not None:
        raise RefusedError(409, "exists")
    await _refuse_replay(session, call)
    valid_until = _check_licence(state, call)
    _limit(state.requests, call)
    await _use_nonce(session, state, call)
    insert = insert_for(session)
    made = await session.execute(
        insert(SyncSpace)
        .values(id=call.space, owner_key=call.signer, valid_until=valid_until, last_cursor=0)
        .on_conflict_do_nothing(index_elements=[SyncSpace.id])
        .returning(SyncSpace.id)
    )
    if made.first() is None:
        # Someone made it between the check above and here.
        await session.rollback()
        raise RefusedError(409, "exists")
    await session.execute(
        insert(SyncMember).values(
            space_id=call.space, key=call.signer, added_at=call.now, acked=0, served=0
        )
    )
    await session.commit()
    log.info("sync.space_created")
    return Answer(201, {"space": call.space, "validUntil": valid_until})


async def status(session: AsyncSession, state: GroupSync, call: Call) -> Answer:
    space, _ = await _member_space(session, call)
    await _refuse_replay(session, call)
    _limit(state.requests, call)
    await _use_nonce(session, state, call)
    members = list(
        await session.scalars(
            select(SyncMember.key)
            .where(SyncMember.space_id == call.space)
            .order_by(SyncMember.added_at, SyncMember.key)
        )
    )
    await session.commit()
    return Answer(
        200,
        {
            "owner": space.owner,
            "members": members,
            "validUntil": space.valid_until,
            "readOnly": space.valid_until <= call.now,
            "cursor": space.last_cursor,
        },
    )


async def renew(session: AsyncSession, state: GroupSync, call: Call) -> Answer:
    """The owner sends a new licence. "Valid until" only ever moves forward."""
    await _owner_space(session, call)
    await _refuse_replay(session, call)
    valid_until = _check_licence(state, call)
    _limit(state.requests, call)
    space = await _owner_space(session, call, lock=True)
    await _use_nonce(session, state, call)
    if valid_until > space.valid_until:
        await session.execute(
            update(SyncSpace).where(SyncSpace.id == call.space).values(valid_until=valid_until)
        )
    await session.commit()
    log.info("sync.licence_renewed", extended=valid_until > space.valid_until)
    return Answer(200, {"validUntil": max(valid_until, space.valid_until)})


async def add_member(session: AsyncSession, state: GroupSync, call: Call, key: str) -> Answer:
    await _owner_space(session, call)
    await _refuse_replay(session, call)
    _limit(state.requests, call)
    space = await _owner_space(session, call, lock=True)
    if await _is_member(session, call.space, key):
        # Nothing to add, read-only or not: the owner's phone sends its whole member list
        # on every sync, and must still get through to pull once the licence has run out.
        await _use_nonce(session, state, call)
        await session.commit()
        return Answer(200, {"added": False})
    if space.valid_until <= call.now:
        raise RefusedError(403, "read_only")
    count, newest = (
        await session.execute(
            select(func.count(), func.max(SyncMember.added_at)).where(
                SyncMember.space_id == call.space
            )
        )
    ).one()
    if count >= MAX_MEMBERS:
        raise RefusedError(409, "space_full")
    await _use_nonce(session, state, call)
    # A new member starts at the latest cursor: older batches were sealed to the others, and
    # the owner's phone sends them what they need. Members are listed in the order they were
    # added, so two added in the same millisecond still get different times.
    await session.execute(
        insert_for(session)(SyncMember).values(
            space_id=call.space,
            key=key,
            added_at=max(call.now, (newest or 0) + 1),
            acked=space.last_cursor,
            served=space.last_cursor,
        )
    )
    await session.commit()
    log.info("sync.member_added", members=count + 1)
    return Answer(201, {"added": True, "cursor": space.last_cursor})


async def remove_member(session: AsyncSession, state: GroupSync, call: Call, key: str) -> Answer:
    """Allowed even when read-only: the owner can always take someone out."""
    await _owner_space(session, call)
    await _refuse_replay(session, call)
    if key == call.signer:
        raise RefusedError(409, "owner_stays")
    _limit(state.requests, call)
    await _owner_space(session, call, lock=True)
    await _use_nonce(session, state, call)
    await session.execute(
        delete(SyncMember).where(SyncMember.space_id == call.space, SyncMember.key == key)
    )
    await session.commit()
    log.info("sync.member_removed")
    return Answer(200, {"removed": True})


async def remove(session: AsyncSession, store: BlobStore, state: GroupSync, call: Call) -> Answer:
    """The owner deletes the space: every row that names it, and every object.

    The objects are queued for deletion in the transaction that removes the rows, then
    deleted straight away. Any the store does not delete now stays queued and is retried by
    ``ngome-purge``, as for backups.

    The nonces the space's requests used stay until they run out, this request's among them.
    They are digests, so they do not name the space; they are what refuses a copy of this
    delete, or of anything sent before it, if the owner makes the space again.
    """
    await _owner_space(session, call)
    await _refuse_replay(session, call)
    _limit(state.requests, call)
    await _owner_space(session, call, lock=True)
    await _use_nonce(session, state, call)
    keys = list(
        await session.scalars(select(SyncBatch.object_key).where(SyncBatch.space_id == call.space))
    )
    await _queue_objects(session, keys)
    await session.execute(delete(SyncBatch).where(SyncBatch.space_id == call.space))
    await session.execute(delete(SyncMember).where(SyncMember.space_id == call.space))
    await session.execute(delete(SyncSpace).where(SyncSpace.id == call.space))
    await session.commit()
    deleted, left = await _delete_objects(session, store, keys, seconds=DELETE_NOW_SECONDS)
    log.info("sync.space_deleted", batches=len(keys), objects_deleted=deleted, objects_left=left)
    return Answer(200, {"deleted": True})


# ------------------------------------------------------------ push and pull


async def _one_chunk(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _batch_by_id(
    session: AsyncSession, space_id: str, batch_id: str
) -> tuple[int, str, str] | None:
    row = (
        await session.execute(
            select(SyncBatch.cursor, SyncBatch.author, SyncBatch.hash).where(
                SyncBatch.space_id == space_id, SyncBatch.batch_id == batch_id
            )
        )
    ).first()
    return None if row is None else (row.cursor, row.author, row.hash)


async def _same_batch(
    session: AsyncSession,
    state: GroupSync,
    call: Call,
    existing: tuple[int, str, str],
    digest: str,
) -> Answer:
    """The batch id is already there: the same sender and bytes get the same cursor again."""
    cursor, author, stored_digest = existing
    if author != call.signer or stored_digest != digest:
        raise RefusedError(409, "batch_id_taken")
    await _use_nonce(session, state, call)
    await session.commit()
    return Answer(200, {"cursor": cursor, "duplicate": True})


async def push(
    session: AsyncSession,
    store: BlobStore,
    state: GroupSync,
    call: Call,
    *,
    batch_id: str | None,
    to: str | None,
) -> Answer:
    """Store one batch. The body is the padded file from the phone; it is never opened."""
    space, _ = await _member_space(session, call)
    # Before the limits and before the headers the signature does not cover are looked at.
    await _refuse_replay(session, call)
    _limit(state.requests, call)
    if space.valid_until <= call.now:
        raise RefusedError(403, "read_only")
    _limit(state.pushes, call)
    if batch_id is None or not is_id(batch_id):
        raise RefusedError(400, "bad_batch_id")
    if to is not None and (not is_key(to) or not await _is_member(session, call.space, to)):
        raise RefusedError(400, "bad_recipient")
    if not is_padded_size(len(call.body)):
        raise RefusedError(400, "not_padded")
    digest = sha256_b64url(call.body)

    existing = await _batch_by_id(session, call.space, batch_id)
    if existing is not None:
        answer = await _same_batch(session, state, call, existing, digest)
        log.info("sync.pushed", size_bytes=len(call.body), duplicate=True)
        return answer

    # Note the object, then write it, with no transaction held open meanwhile.
    object_key = f"sync/{secrets.token_hex(16)}"
    await session.execute(
        insert_for(session)(SyncPendingBlob).values(object_key=object_key, created_at=call.now)
    )
    await session.commit()
    try:
        await store.put(object_key, _one_chunk(call.body))
        answer = await _record_push(session, state, call, batch_id, to, digest, object_key)
    except BaseException:
        await session.rollback()
        await _discard(session, store, object_key)
        raise
    if answer.status != 201:
        # Another copy of this push got there first; this object is not needed.
        await _discard(session, store, object_key)
    log.info("sync.pushed", size_bytes=len(call.body), duplicate=answer.status != 201)
    return answer


async def _record_push(
    session: AsyncSession,
    state: GroupSync,
    call: Call,
    batch_id: str,
    to: str | None,
    digest: str,
    object_key: str,
) -> Answer:
    """With the space locked: check again, take the next cursor and add the batch's row."""
    space, _ = await _member_space(session, call, lock=True)
    if space.valid_until <= call.now:
        raise RefusedError(403, "read_only")
    if to is not None and not await _is_member(session, call.space, to):
        raise RefusedError(400, "bad_recipient")
    existing = await _batch_by_id(session, call.space, batch_id)
    if existing is not None:
        return await _same_batch(session, state, call, existing, digest)
    await _use_nonce(session, state, call)
    cleared = await session.execute(
        delete(SyncPendingBlob)
        .where(SyncPendingBlob.object_key == object_key)
        .returning(SyncPendingBlob.object_key)
    )
    if cleared.first() is None:
        # The purge took the object for dead (the push sat for an hour) and will delete it.
        # Answered as a server error, so the phone sends the batch again.
        raise RuntimeError("the object's note is gone")
    cursor = space.last_cursor + 1
    await session.execute(
        update(SyncSpace).where(SyncSpace.id == call.space).values(last_cursor=cursor)
    )
    await session.execute(
        insert_for(session)(SyncBatch).values(
            space_id=call.space,
            cursor=cursor,
            batch_id=batch_id,
            author=call.signer,
            recipient=to,
            size=len(call.body),
            hash=digest,
            at=call.now,
            object_key=object_key,
        )
    )
    await session.commit()
    return Answer(201, {"cursor": cursor, "duplicate": False})


async def _discard(session: AsyncSession, store: BlobStore, object_key: str) -> None:
    """Remove an object that got no batch row. If the store refuses, its note stays and the
    purge deletes it later."""
    try:
        await store.delete(object_key)
        await session.execute(
            delete(SyncPendingBlob).where(SyncPendingBlob.object_key == object_key)
        )
        await session.commit()
    except Exception:
        await session.rollback()
        log.warning("sync.blob_delete_failed", deleted=0, failed=1)


def parse_since(raw: str | None) -> int:
    """The ``since`` cursor of a pull: a whole number, 0 when left out."""
    if raw is None or raw == "":
        return 0
    if not raw.isascii() or not raw.isdigit() or len(raw) > 16 or int(raw) > MAX_SAFE_INTEGER:
        raise RefusedError(400, "bad_cursor")
    return int(raw)


async def _batch_is_there(session: AsyncSession, space_id: str, cursor: int) -> bool:
    found = await session.scalar(
        select(SyncBatch.cursor).where(SyncBatch.space_id == space_id, SyncBatch.cursor == cursor)
    )
    await session.commit()  # only a read: nothing is held open while objects are fetched
    return found is not None


async def pull(
    session: AsyncSession, store: BlobStore, state: GroupSync, call: Call, since_text: str | None
) -> Answer:
    """Everything for the signer after ``since``. Asking from ``since`` also says the member
    holds everything up to it, which retention counts on."""
    space, member = await _member_space(session, call)
    await _refuse_replay(session, call)
    since = parse_since(since_text)
    _limit(state.requests, call)
    await _use_nonce(session, state, call)
    if since > member.served:
        # No pull has ever answered this member with a cursor that high, so it is not from
        # this space as it is now: the owner deleted the space and made it again, and the
        # phone kept its old cursor. Start over, and take nothing as pulled on its word.
        since = 0
    if since > member.acked:
        await session.execute(
            update(SyncMember)
            .where(
                SyncMember.space_id == call.space,
                SyncMember.key == call.signer,
                SyncMember.acked < since,
            )
            .values(acked=since)
        )
    if space.last_cursor > member.served:
        await session.execute(
            update(SyncMember)
            .where(
                SyncMember.space_id == call.space,
                SyncMember.key == call.signer,
                SyncMember.served < space.last_cursor,
            )
            .values(served=space.last_cursor)
        )
    # Up to the cursor read with the space: a batch pushed after that is not skipped by the
    # jump to ``next`` below, it comes with the next pull.
    rows = (
        await session.execute(
            select(
                SyncBatch.cursor,
                SyncBatch.batch_id,
                SyncBatch.author,
                SyncBatch.size,
                SyncBatch.at,
                SyncBatch.object_key,
            )
            .where(
                SyncBatch.space_id == call.space,
                SyncBatch.cursor > since,
                SyncBatch.cursor <= space.last_cursor,
                SyncBatch.author != call.signer,
                (SyncBatch.recipient.is_(None)) | (SyncBatch.recipient == call.signer),
            )
            .order_by(SyncBatch.cursor)
            .limit(PULL_MAX_BATCHES + 1)
        )
    ).all()
    await session.commit()

    out: list[dict[str, Any]] = []
    size = 0
    reached = since
    gap = False
    for row in rows[:PULL_MAX_BATCHES]:
        if out and size + row.size > PULL_MAX_BYTES:
            break
        try:
            data = b"".join([chunk async for chunk in await store.open(row.object_key)])
        except BlobNotFoundError:
            if not await _batch_is_there(session, call.space, row.cursor):
                # Deleted since the query above, row and object: retention, or the space.
                reached = row.cursor
                continue
            if reached == since:
                # Nothing to hand over before it. Not a skip: the phone would never get it.
                raise ObjectMissingError from None
            gap = True  # hand over what came before; the next pull meets the gap
            break
        reached = row.cursor
        size += row.size
        out.append(
            {
                "cursor": row.cursor,
                "id": row.batch_id,
                "from": row.author,
                "at": row.at,
                "data": b64url(data),
            }
        )
    more = gap or (bool(rows) and reached < rows[-1].cursor)
    log.info("sync.pulled", batches=len(out), more=more)
    return Answer(
        200,
        {
            "batches": out,
            # With nothing left for this member, the cursor jumps past others' batches.
            "next": reached if more else max(since, space.last_cursor),
            "more": more,
            "readOnly": space.valid_until <= call.now,
        },
    )


# ------------------------------------------------------------ deleting objects


async def _queue_objects(session: AsyncSession, keys: Sequence[str]) -> None:
    """Queue objects for deletion (the vault's queue), in the caller's transaction."""
    queued_at = utcnow()
    for start in range(0, len(keys), _PURGE_CHUNK):
        await session.execute(
            insert_for(session)(BlobDeletion),
            [
                {"object_key": key, "queued_at": queued_at, "attempts": 0}
                for key in keys[start : start + _PURGE_CHUNK]
            ],
        )


async def _delete_objects(
    session: AsyncSession, store: BlobStore, keys: Sequence[str], *, seconds: float
) -> tuple[int, int]:
    """Delete queued objects now, for at most ``seconds``. Returns ``(deleted, left)``; what
    is left stays queued."""
    deadline = time.monotonic() + seconds
    deleted = failed = 0
    for start in range(0, len(keys), _DELETE_CHUNK):
        if time.monotonic() >= deadline:
            break
        done: list[str] = []
        missed: list[str] = []
        for key in keys[start : start + _DELETE_CHUNK]:
            try:
                await store.delete(key)
            except Exception:
                missed.append(key)
            else:
                done.append(key)
        if done:
            await session.execute(delete(BlobDeletion).where(BlobDeletion.object_key.in_(done)))
        if missed:
            await session.execute(
                update(BlobDeletion)
                .where(BlobDeletion.object_key.in_(missed))
                .values(attempts=BlobDeletion.attempts + 1)
            )
        await session.commit()
        deleted += len(done)
        failed += len(missed)
    if failed:
        log.warning("sync.blob_delete_failed", deleted=deleted, failed=failed)
    return deleted, len(keys) - deleted


# ------------------------------------------------------------ retention


@dataclass(frozen=True, slots=True)
class SyncPurge:
    batches: int = 0
    nonces: int = 0
    orphans: int = 0


async def purge_nonces(session: AsyncSession, now_ms: int) -> int:
    """Delete nonces that ran out at least a minute ago (``NONCE_SWEEP_MARGIN_MS``). Commits."""
    gone = await session.execute(
        delete(SyncNonce).where(SyncNonce.expires_at < now_ms - NONCE_SWEEP_MARGIN_MS)
    )
    await session.commit()
    return cast(CursorResult[Any], gone).rowcount


async def purge(session: AsyncSession, *, now_ms: int, min_keep_ms: int) -> SyncPurge:
    """The daily job (``ngome-purge``): old nonces, batches every reader has pulled past and
    that are old enough, and objects left by pushes that died.

    Rows go here and their objects are queued in the same transaction; the purge's sweep of
    the deletion queue, which runs next, removes the objects.
    """
    nonces = await purge_nonces(session, now_ms)

    cutoff = now_ms - min_keep_ms
    spaces = list(
        await session.scalars(select(SyncBatch.space_id).where(SyncBatch.at <= cutoff).distinct())
    )
    batches = 0
    for space_id in spaces:
        batches += await _purge_space(session, space_id, now_ms, min_keep_ms)

    # A push notes its object before writing it and clears the note with the batch's row.
    # Claiming a note here is what lets a very slow push find it gone and give up.
    stale = (
        await session.execute(
            delete(SyncPendingBlob)
            .where(SyncPendingBlob.created_at < now_ms - PENDING_BLOB_GRACE_MS)
            .returning(SyncPendingBlob.object_key)
        )
    ).all()
    orphans = [row.object_key for row in stale]
    await _queue_objects(session, orphans)
    await session.commit()

    return SyncPurge(batches=batches, nonces=nonces, orphans=len(orphans))


async def _purge_space(session: AsyncSession, space_id: str, now_ms: int, min_keep_ms: int) -> int:
    if await _space(session, space_id, lock=True) is None:
        await session.rollback()
        return 0
    acked = {
        row.key: row.acked
        for row in await session.execute(
            select(SyncMember.key, SyncMember.acked).where(SyncMember.space_id == space_id)
        )
    }
    rows = (
        await session.execute(
            select(
                SyncBatch.cursor,
                SyncBatch.batch_id,
                SyncBatch.author,
                SyncBatch.recipient,
                SyncBatch.at,
                SyncBatch.object_key,
            )
            .where(SyncBatch.space_id == space_id, SyncBatch.at <= now_ms - min_keep_ms)
            .order_by(SyncBatch.cursor)
        )
    ).all()
    object_keys = {row.cursor: row.object_key for row in rows}
    gone = expired_batches(
        (BatchRow(r.cursor, r.batch_id, r.author, r.recipient, r.at) for r in rows),
        acked,
        now_ms,
        min_keep_ms,
    )
    for start in range(0, len(gone), _PURGE_CHUNK):
        chunk = gone[start : start + _PURGE_CHUNK]
        await _queue_objects(session, [object_keys[b.cursor] for b in chunk])
        await session.execute(
            delete(SyncBatch).where(
                SyncBatch.space_id == space_id, SyncBatch.cursor.in_([b.cursor for b in chunk])
            )
        )
    await session.commit()
    return len(gone)
