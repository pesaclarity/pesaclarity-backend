"""The space owner's licence (decision 0032), checked offline.

Licence issuing is not built yet. This is the planned format, behind an interface so the
real issuer can change it without touching the routes::

    pclic.1.<payload>.<signature>

``payload`` is base64url JSON ``{"v": 1, "acct": "...", "plan": "premium", "features":
["group-sync", ...], "iat": <ms>, "exp": <ms>}``. ``signature`` is Ed25519 over the ASCII
text ``pclic.1.<payload>``, base64url, made with the licence key whose public half is
``NGOME_LICENCE_PUBLIC_KEY``. Only "valid until" leaves this module: the account id in the
payload is dropped, never stored and never logged.

``ngome-licence-key`` makes a key pair and mints licences for testing::

    uv run ngome-licence-key new licence.key        # writes the private key, prints the public
    uv run ngome-licence-key mint --key-file licence.key --days 365
    uv run ngome-licence-key mint --key-file licence.key --minutes 10   # to watch one run out

The private key is only ever written to the file you name (readable by you alone) or read
from it or from ``NGOME_LICENCE_SIGNING_SEED``. It is never printed.
"""

import argparse
import base64
import binascii
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ngome.groupsync.protocol import MAX_SAFE_INTEGER, b64url, from_b64url, verify_ed25519

SYNC_FEATURE = "group-sync"
PREFIX = "pclic.1."
MAX_LICENCE_LENGTH = 4096
SEED_ENV = "NGOME_LICENCE_SIGNING_SEED"
_SEED_BYTES = 32
_DAY_MS = 24 * 60 * 60_000

LicenceProblem = Literal["malformed", "signature", "expired", "feature", "no_key"]


@dataclass(frozen=True, slots=True)
class LicenceResult:
    """``valid_until`` (milliseconds) when the licence is good, else ``why`` it is not."""

    valid_until: int | None = None
    why: LicenceProblem | None = None

    @property
    def ok(self) -> bool:
        return self.valid_until is not None


class LicenceVerifier(Protocol):
    def verify(self, token: object, now_ms: int) -> LicenceResult: ...


class _RefusedLicenceError(Exception):
    def __init__(self, why: LicenceProblem) -> None:
        super().__init__(why)
        self.why = why


def _no_constants(_name: str) -> None:
    # json accepts NaN and Infinity unless told otherwise; a licence never holds them.
    raise ValueError("not JSON")


class Ed25519LicenceVerifier:
    """Checks a licence against our public key (base64url of its 32 bytes)."""

    def __init__(self, public_key: str | None) -> None:
        self._public_key = public_key or None

    def verify(self, token: object, now_ms: int) -> LicenceResult:
        try:
            return LicenceResult(valid_until=self._valid_until(token, now_ms))
        except _RefusedLicenceError as refused:
            return LicenceResult(why=refused.why)

    def _valid_until(self, token: object, now_ms: int) -> int:
        # No key configured: refuse every licence rather than accept any.
        if self._public_key is None:
            raise _RefusedLicenceError("no_key")
        if not isinstance(token, str) or len(token) > MAX_LICENCE_LENGTH:
            raise _RefusedLicenceError("malformed")
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "pclic" or parts[1] != "1":
            raise _RefusedLicenceError("malformed")
        signed = f"{PREFIX}{parts[2]}".encode()
        if not verify_ed25519(self._public_key, signed, parts[3]):
            raise _RefusedLicenceError("signature")
        try:
            body = json.loads(from_b64url(parts[2]), parse_constant=_no_constants)
        except ValueError:
            raise _RefusedLicenceError("malformed") from None
        if not isinstance(body, dict):
            raise _RefusedLicenceError("malformed")
        expires = _whole_number(body.get("exp"))
        if _whole_number(body.get("v")) != 1 or expires is None:
            raise _RefusedLicenceError("malformed")
        features = body.get("features")
        if not isinstance(features, list) or SYNC_FEATURE not in features:
            raise _RefusedLicenceError("feature")
        if expires <= now_ms:
            raise _RefusedLicenceError("expired")
        return expires


def _whole_number(value: Any) -> int | None:
    """A JSON number that is a whole number of milliseconds the phone can hold, else None."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float):
        if not value.is_integer():
            return None
        value = int(value)
    return value if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER else None


def public_key_of(seed: bytes) -> str:
    """The public key (base64url) for a 32-byte private seed."""
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return b64url(raw.public_bytes(Encoding.Raw, PublicFormat.Raw))


def mint(
    seed: bytes,
    *,
    expires_ms: int,
    issued_ms: int,
    features: tuple[str, ...] = (SYNC_FEATURE,),
    account: str = "test",
    plan: str = "premium",
) -> str:
    """A licence in the planned format. For tests and test builds until the issuer exists."""
    body = {
        "v": 1,
        "acct": account,
        "plan": plan,
        "features": list(features),
        "iat": issued_ms,
        "exp": expires_ms,
    }
    payload = b64url(json.dumps(body, separators=(",", ":")).encode())
    signed = f"{PREFIX}{payload}"
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(signed.encode())
    return f"{signed}.{b64url(signature)}"


def _decode_seed(text: str, source: str) -> bytes:
    try:
        seed = base64.b64decode(text.strip(), validate=True)
    except binascii.Error:
        seed = b""
    if len(seed) != _SEED_BYTES:
        # Never echo what was read: it may be most of a key.
        raise SystemExit(f"{source} does not hold a licence private key (base64 of 32 bytes)")
    return seed


def _read_seed(key_file: Path | None) -> bytes:
    if key_file is not None:
        try:
            return _decode_seed(key_file.read_text(encoding="ascii"), str(key_file))
        except (OSError, UnicodeError):
            raise SystemExit(f"Could not read {key_file}") from None
    from_env = os.environ.get(SEED_ENV)
    if from_env:
        return _decode_seed(from_env, SEED_ENV)
    raise SystemExit(f"Give the private key with --key-file, or set {SEED_ENV}")


def _new(args: argparse.Namespace) -> None:
    key_file: Path = args.key_file
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    try:
        # Only for a file that does not exist yet, readable by its owner alone.
        handle = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SystemExit(f"{key_file} already exists; it was left alone") from None
    with os.fdopen(handle, "w", encoding="ascii") as out:
        out.write(base64.b64encode(seed).decode() + "\n")
    _say(f"# Private key written to {key_file}. Keep it secret; never commit it.")
    _say("# Public key for the server (not a secret):")
    _say(f"NGOME_LICENCE_PUBLIC_KEY={public_key_of(seed)}")


def _public(args: argparse.Namespace) -> None:
    _say(public_key_of(_read_seed(args.key_file)))


def _mint(args: argparse.Namespace) -> None:
    seed = _read_seed(args.key_file)
    now = int(time.time() * 1000)
    features = tuple(args.feature) if args.feature else (SYNC_FEATURE,)
    lasts = args.minutes * 60_000 if args.minutes is not None else args.days * _DAY_MS
    _say(mint(seed, expires_ms=now + lasts, issued_ms=now, features=features))


def _say(line: str) -> None:
    sys.stdout.write(line + "\n")


def main(argv: list[str] | None = None) -> None:
    """Entry point for ``ngome-licence-key``."""
    parser = argparse.ArgumentParser(
        prog="ngome-licence-key",
        description="Make the licence key pair, or mint a licence for testing group sync.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    new = commands.add_parser(
        "new", help="make a key pair: the private key goes to a new file, the public is printed"
    )
    new.add_argument("key_file", type=Path, help="where to write the private key (must not exist)")
    new.set_defaults(run=_new)

    key_help = f"the private key file (otherwise {SEED_ENV} is read)"
    public = commands.add_parser("public", help="print the public key of a private key")
    public.add_argument("--key-file", type=Path, help=key_help)
    public.set_defaults(run=_public)

    minted = commands.add_parser(
        "mint", help="print a test licence (account 'test'); real licences come with 0032"
    )
    minted.add_argument("--key-file", type=Path, help=key_help)
    lasts = minted.add_mutually_exclusive_group()
    lasts.add_argument("--days", type=int, default=365, help="how long it lasts (default 365)")
    lasts.add_argument(
        "--minutes", type=int, help="minutes instead of days, to watch a space go read-only"
    )
    minted.add_argument(
        "--feature",
        action="append",
        help=f"a feature it carries; repeat for more (default {SYNC_FEATURE})",
    )
    minted.set_defaults(run=_mint)

    args = parser.parse_args(argv)
    args.run(args)
