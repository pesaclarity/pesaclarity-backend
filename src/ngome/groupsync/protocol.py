"""The wire rules shared by the routes and the tests: encodings, the signed request scheme,
batch size steps and limits. Nothing here touches storage.

The same rules as the Worker this replaces (``sync/src/protocol.ts``), so the app's
``GroupSyncClient`` works against either.
"""

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROTOCOL = "pcsync v1"

# A signed request must be within this much of the server's clock.
CLOCK_WINDOW_MS = 5 * 60_000

# Batches are padded by the phone to one of these sizes, so their length says little about
# what changed: 1 KiB, 2 KiB, ... 1 MiB.
SIZE_STEPS: tuple[int, ...] = tuple(1024 << i for i in range(11))
MAX_BATCH_BYTES = SIZE_STEPS[-1]
# A request body over this is refused before anything else is looked at.
MAX_BODY_BYTES = MAX_BATCH_BYTES + 1024

# The most members a shared space holds (a Savings group, decision 0031).
MAX_MEMBERS = 30

# How much one pull returns at most.
PULL_MAX_BATCHES = 100
PULL_MAX_BYTES = 4 * 1024 * 1024

# JSON numbers the phone can hold exactly (JavaScript's and Dart's safe integers).
MAX_SAFE_INTEGER = 2**53 - 1

ID_LENGTH = 64
KEY_LENGTH = 43
_ID = re.compile(r"[A-Za-z0-9_-]{16,64}")
_KEY = re.compile(r"[A-Za-z0-9_-]{43}")
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_TIME = re.compile(r"[0-9]{1,16}")

# Signature headers.
HEADER_KEY = "x-pc-key"
HEADER_TIME = "x-pc-time"
HEADER_NONCE = "x-pc-nonce"
HEADER_SIG = "x-pc-sig"
HEADER_BATCH = "x-pc-batch"
HEADER_TO = "x-pc-to"


def is_id(value: str | None) -> bool:
    """Space ids, batch ids and nonces: random, url-safe, 16 to 64 characters."""
    return value is not None and _ID.fullmatch(value) is not None


def is_key(value: str | None) -> bool:
    """A member key is its 32-byte Ed25519 public key, base64url without padding."""
    return value is not None and _KEY.fullmatch(value) is not None


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(text: str) -> bytes:
    """Decode base64url without padding. Raises ``ValueError`` for anything else."""
    if _B64URL.fullmatch(text) is None or len(text) % 4 == 1:
        raise ValueError("not base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except binascii.Error as exc:
        raise ValueError("not base64url") from exc


def sha256_b64url(data: bytes) -> str:
    return b64url(hashlib.sha256(data).digest())


def signing_string(method: str, path: str, time: str, nonce: str, body_hash: str) -> str:
    """What a member signs: method, path with query, time, nonce and the body's SHA-256,
    one per line."""
    return "\n".join((PROTOCOL, method.upper(), path, time, nonce, body_hash))


def verify_ed25519(key: str, message: bytes, signature: str) -> bool:
    """Whether ``signature`` (base64url) is ``key``'s (base64url, 32 bytes) over ``message``.
    A malformed key or signature is simply not valid."""
    try:
        public = Ed25519PublicKey.from_public_bytes(from_b64url(key))
        public.verify(from_b64url(signature), message)
    except (ValueError, InvalidSignature):
        return False
    return True


def is_padded_size(size: int) -> bool:
    """Whether ``size`` is one of the padding steps."""
    return size in SIZE_STEPS


def padded_size(size: int) -> int | None:
    """The step a payload of ``size`` bytes is padded up to, or ``None`` when too big."""
    return next((step for step in SIZE_STEPS if step >= size), None)


@dataclass(frozen=True, slots=True)
class SignedParts:
    key: str
    time: str
    nonce: str
    sig: str


SignatureProblem = Literal["clock", "signature", "malformed"]


def check_signature(
    parts: SignedParts, method: str, path: str, body: bytes, now_ms: int
) -> SignatureProblem | None:
    """Check the clock and signature of a request; ``None`` when both are good.

    The nonce's freshness is the caller's job, since it needs storage.
    """
    if (
        not is_key(parts.key)
        or _TIME.fullmatch(parts.time) is None
        or not is_id(parts.nonce)
        or not parts.sig
    ):
        return "malformed"
    if abs(now_ms - int(parts.time)) > CLOCK_WINDOW_MS:
        return "clock"
    message = signing_string(method, path, parts.time, parts.nonce, sha256_b64url(body))
    return None if verify_ed25519(parts.key, message.encode(), parts.sig) else "signature"
