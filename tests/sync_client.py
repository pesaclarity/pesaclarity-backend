"""A small signing client for the group sync tests, signing requests as the phone does
(``GroupSyncClient`` in the app). Every key is made up for the test run."""

import json
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ngome.groupsync import licence as licences
from ngome.groupsync.protocol import (
    HEADER_KEY,
    HEADER_NONCE,
    HEADER_SIG,
    HEADER_TIME,
    b64url,
    sha256_b64url,
    signing_string,
)

DAY_MS = 24 * 60 * 60_000


@dataclass(frozen=True)
class Member:
    private: Ed25519PrivateKey
    key: str


def new_member() -> Member:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return Member(private, b64url(raw))


def random_id(size: int = 16) -> str:
    return b64url(secrets.token_bytes(size))


def sign(
    member: Member, method: str, path: str, body: bytes, time_ms: int, nonce: str | None = None
) -> dict[str, str]:
    """The four signature headers for one request."""
    nonce = nonce or random_id()
    message = signing_string(method, path, str(time_ms), nonce, sha256_b64url(body))
    return {
        HEADER_KEY: member.key,
        HEADER_TIME: str(time_ms),
        HEADER_NONCE: nonce,
        HEADER_SIG: b64url(member.private.sign(message.encode())),
    }


@dataclass(frozen=True)
class Result:
    status: int
    data: Any
    signed: dict[str, str]

    @property
    def error(self) -> str | None:
        return self.data.get("error") if isinstance(self.data, dict) else None


async def call(
    client: httpx.AsyncClient,
    member: Member,
    method: str,
    path: str,
    *,
    time_ms: int,
    body: bytes | Mapping[str, Any] = b"",
    headers: Mapping[str, str] | None = None,
    nonce: str | None = None,
    tamper: Callable[[dict[str, str]], None] | None = None,
    reuse: Mapping[str, str] | None = None,
) -> Result:
    """Send one signed request. ``tamper`` changes the signature headers after signing (for
    forgeries); ``reuse`` sends these exact headers again (for replays)."""
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    signed = sign(member, method, path, raw, time_ms, nonce)
    if tamper is not None:
        tamper(signed)
    if reuse is not None:
        signed = dict(reuse)
    response = await client.request(
        method, path, content=raw or None, headers={**signed, **(headers or {})}
    )
    try:
        data = response.json()
    except ValueError:
        data = response.text
    return Result(response.status_code, data, signed)


def new_licence_seed() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes_raw()


def licence(
    seed: bytes, *, now_ms: int, expires_ms: int, features: tuple[str, ...] = ("group-sync",)
) -> str:
    """A licence in the planned format, signed with the test run's licence key."""
    return licences.mint(seed, expires_ms=expires_ms, issued_ms=now_ms, features=features)


def padded(size: int, fill: int = 7) -> bytes:
    """A batch padded to a size step, as the phone pads it. Not real ciphertext."""
    return bytes([fill]) * size
