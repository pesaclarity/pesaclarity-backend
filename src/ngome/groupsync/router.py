"""Group sync routes: ``/v1/spaces/{space}`` and below (decisions 0033 and 0035).

The same wire protocol as the Worker this replaces (``sync/``), so the app's
``GroupSyncClient`` needs no change. These routes take no account sign-in: each request is
signed with the member's Ed25519 space key (``X-PC-Key``, ``X-PC-Time``, ``X-PC-Nonce``,
``X-PC-Sig``), and nothing here reads or stores an account id.

Answers are JSON. A refusal is ``{"error": "<code>"}``. Bodies are never parsed (a batch is
the phone's sealed file, passed on as it came) and never logged; log lines carry outcomes,
counts and sizes only, with no space id, member key or address. The caller's address is used
once, as a key in this instance's memory for the flood limit, and is not stored.

Live notices over a WebSocket (``/ws``) are not served here; phones pull.
"""

import asyncio
import traceback
from collections.abc import Awaitable, Callable
from typing import cast

from fastapi import APIRouter, Request, WebSocket
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import ClientDisconnect

from ngome.core.client import client_address
from ngome.core.config import Settings
from ngome.core.logging import get_logger
from ngome.groupsync import service
from ngome.groupsync.protocol import (
    BODY_MIN_BYTES_PER_SECOND,
    HEADER_BATCH,
    HEADER_KEY,
    HEADER_NONCE,
    HEADER_SIG,
    HEADER_TIME,
    HEADER_TO,
    MAX_BODY_BYTES,
    SignedParts,
    check_headers,
    check_signature,
    is_id,
    is_key,
)
from ngome.groupsync.service import Answer, Call, GroupSync, RefusedError
from ngome.vault.storage import BlobStore

router = APIRouter(prefix="/v1/spaces", tags=["group sync"])
log = get_logger(__name__)

# What ``/ws`` answers, with 404: this server has no live notices.
WS_NOT_AVAILABLE = "ws_not_available"
_ANY_METHOD = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

Operation = Callable[[AsyncSession, BlobStore, GroupSync, Call], Awaitable[Answer]]


def _json(status: int, body: dict[str, object]) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


def _state(request: Request) -> GroupSync:
    return cast(GroupSync, request.app.state.group_sync)


def _signed_path(request: Request) -> str:
    """The path and query exactly as the caller sent and signed them."""
    raw = request.scope.get("raw_path")
    path = raw.decode("latin-1") if raw else request.url.path
    query = request.scope.get("query_string") or b""
    return f"{path}?{query.decode('latin-1')}" if query else path


def _check_address(request: Request, state: GroupSync, now: int) -> None:
    settings = cast(Settings, request.app.state.settings)
    address = client_address(request, settings.proxy_hops) or "?"
    if not state.addresses.take(address, now):
        raise RefusedError(429, "rate_limited")


def _declared_length(request: Request) -> int | None:
    """The Content-Length, when it is there and is plain digits."""
    declared = request.headers.get("content-length")
    if declared is None or not (declared.isascii() and declared.isdigit()):
        return None
    return int(declared)


async def _read_body(request: Request, state: GroupSync) -> bytes:
    """The whole body, up to the cap, within its deadline: a base time plus what its
    declared length takes at the slowest rate allowed."""
    declared = min(_declared_length(request) or 0, MAX_BODY_BYTES)
    body = bytearray()
    try:
        async with asyncio.timeout(state.body_seconds + declared / BODY_MIN_BYTES_PER_SECOND):
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > MAX_BODY_BYTES:
                    raise RefusedError(413, "too_large")
    except TimeoutError:
        raise RefusedError(408, "too_slow") from None
    return bytes(body)


def _refuse(problem: str | None) -> None:
    if problem is not None:
        raise RefusedError(401, "clock" if problem == "clock" else "unauthorized")


async def _open(request: Request, space: str, state: GroupSync) -> Call:
    """Everything checked before the database is touched: the space id's shape, the flood
    limit, the body's size, the clock and the signature.

    The clock is read when the body has arrived, and that reading is the request's time from
    then on. A body held back, to slip a copy of an old request past the clock check, gains
    nothing. What the headers alone decide is refused before the body is read at all.
    """
    if not is_id(space):
        raise RefusedError(404, "not_found")
    _check_address(request, state, state.clock())
    headers = request.headers
    parts = SignedParts(
        key=headers.get(HEADER_KEY, ""),
        time=headers.get(HEADER_TIME, ""),
        nonce=headers.get(HEADER_NONCE, ""),
        sig=headers.get(HEADER_SIG, ""),
    )
    if (_declared_length(request) or 0) > MAX_BODY_BYTES:
        raise RefusedError(413, "too_large")
    _refuse(check_headers(parts, state.clock()))
    body = await _read_body(request, state)
    now = state.clock()
    _refuse(check_signature(parts, request.method, _signed_path(request), body, now))
    return Call(space=space, signer=parts.key, parts=parts, body=body, now=now)


def _where(error: BaseException) -> str:
    """Where in our code an unexpected error came from: a file and line, never a value."""
    frames = [f for f in traceback.extract_tb(error.__traceback__) if "ngome" in f.filename]
    if not frames:
        return "unknown"
    last = frames[-1]
    return f"{last.filename.rsplit('/', 1)[-1]}:{last.lineno} {last.name}"


async def _serve(request: Request, space: str, operation: Operation) -> JSONResponse:
    state = _state(request)
    try:
        call = await _open(request, space, state)
        maker = cast(async_sessionmaker[AsyncSession], request.app.state.sessionmaker)
        store = cast(BlobStore, request.app.state.blob_store)
        async with maker() as session:
            if state.nonce_sweep_due(call.now):
                await service.purge_nonces(session, call.now)
            answer = await operation(session, store, state, call)
    except RefusedError as refusal:
        log.info("sync.refused", reason=refusal.code)
        return _json(refusal.status, {"error": refusal.code})
    except ClientDisconnect:
        # The caller went away while sending. Nobody is left to answer and nothing is wrong.
        log.info("sync.refused", reason="client_gone")
        return _json(400, {"error": "bad_request"})
    except Exception as error:
        # Database errors can quote the statement and its values, so no traceback is logged:
        # only the kind of error and where it was raised.
        log.error("sync.error", kind=type(error).__name__, at=_where(error))
        return _json(500, {"error": "server_error"})
    return _json(answer.status, answer.body)


@router.post("/{space}")
async def create_space(request: Request, space: str) -> JSONResponse:
    """Owner: make the space. Body ``{"licence": "pclic.1...."}``; the signer becomes its
    owner and first member. Only "valid until" is kept from the licence."""

    async def run(session: AsyncSession, _: BlobStore, state: GroupSync, call: Call) -> Answer:
        return await service.create(session, state, call)

    return await _serve(request, space, run)


@router.get("/{space}")
async def space_status(request: Request, space: str) -> JSONResponse:
    """Member: the owner, the members, ``validUntil``, ``readOnly`` and the latest cursor."""

    async def run(session: AsyncSession, _: BlobStore, state: GroupSync, call: Call) -> Answer:
        return await service.status(session, state, call)

    return await _serve(request, space, run)


@router.delete("/{space}")
async def delete_space(request: Request, space: str) -> JSONResponse:
    """Owner: delete the space, every row of it and every stored batch."""
    return await _serve(request, space, service.remove)


@router.put("/{space}/licence")
async def renew_licence(request: Request, space: str) -> JSONResponse:
    """Owner: a new licence after renewal. Body ``{"licence": "pclic.1...."}``."""

    async def run(session: AsyncSession, _: BlobStore, state: GroupSync, call: Call) -> Answer:
        return await service.renew(session, state, call)

    return await _serve(request, space, run)


@router.put("/{space}/members/{key}")
async def add_member(request: Request, space: str, key: str) -> JSONResponse:
    """Owner: let the member with this signing key sync. RefusedError for a new member while the
    space is read-only."""

    async def run(session: AsyncSession, _: BlobStore, state: GroupSync, call: Call) -> Answer:
        if not is_key(key):
            raise RefusedError(404, "not_found")
        return await service.add_member(session, state, call, key)

    return await _serve(request, space, run)


@router.delete("/{space}/members/{key}")
async def remove_member(request: Request, space: str, key: str) -> JSONResponse:
    """Owner: stop a member syncing. Always allowed, read-only or not."""

    async def run(session: AsyncSession, _: BlobStore, state: GroupSync, call: Call) -> Answer:
        if not is_key(key):
            raise RefusedError(404, "not_found")
        return await service.remove_member(session, state, call, key)

    return await _serve(request, space, run)


@router.post("/{space}/batches")
async def push_batch(request: Request, space: str) -> JSONResponse:
    """Member: push one batch. The body is the padded file (1, 2, 4 ... 1024 KiB).
    ``X-PC-Batch`` is the batch id, which makes the call idempotent; ``X-PC-To`` names the
    one member it is for."""
    batch_id = request.headers.get(HEADER_BATCH)
    to = request.headers.get(HEADER_TO)

    async def run(session: AsyncSession, store: BlobStore, state: GroupSync, call: Call) -> Answer:
        return await service.push(session, store, state, call, batch_id=batch_id, to=to)

    return await _serve(request, space, run)


@router.get("/{space}/batches")
async def pull_batches(request: Request, space: str) -> JSONResponse:
    """Member: the batches for the signer after cursor ``since``, with ``next`` and ``more``."""
    given = request.query_params.getlist("since")
    since = given[0] if given else None

    async def run(session: AsyncSession, store: BlobStore, state: GroupSync, call: Call) -> Answer:
        return await service.pull(session, store, state, call, since)

    return await _serve(request, space, run)


@router.get("/{space}/ws", include_in_schema=False)
async def live_notices(request: Request, space: str) -> JSONResponse:
    """The Worker's WebSocket for live notices is not served here."""
    try:
        _check_address(request, _state(request), _state(request).clock())
    except RefusedError as refusal:
        return _json(refusal.status, {"error": refusal.code})
    return _json(404, {"error": WS_NOT_AVAILABLE})


@router.websocket("/{space}/ws")
async def live_notices_socket(websocket: WebSocket, space: str) -> None:
    """A WebSocket handshake gets the same 404 instead of an upgrade."""
    try:
        await websocket.send_denial_response(_json(404, {"error": WS_NOT_AVAILABLE}))
    except RuntimeError:
        # A server without the denial extension: close before accepting, which refuses it.
        await websocket.close(code=1008)


@router.api_route("", methods=_ANY_METHOD, include_in_schema=False)
@router.api_route("/", methods=_ANY_METHOD, include_in_schema=False)
@router.api_route("/{space}", methods=_ANY_METHOD, include_in_schema=False)
@router.api_route("/{space}/{rest:path}", methods=_ANY_METHOD, include_in_schema=False)
async def not_found(request: Request) -> JSONResponse:
    """Anything else under ``/v1/spaces`` is refused in the same JSON shape."""
    try:
        _check_address(request, _state(request), _state(request).clock())
    except RefusedError as refusal:
        return _json(refusal.status, {"error": refusal.code})
    return _json(404, {"error": "not_found"})
