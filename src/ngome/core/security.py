"""Token, code and contact hashing primitives."""

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from ngome.core.config import Settings

_ISSUER = "ngome"
_ALGORITHM = "HS256"


class InvalidTokenError(Exception):
    """The access token is missing, malformed, expired or not ours."""


@dataclass(frozen=True, slots=True)
class AccessClaims:
    account_id: uuid.UUID
    device_id: uuid.UUID


def utcnow() -> datetime:
    return datetime.now(UTC)


def _hmac(key: str, *parts: str) -> str:
    message = "\x1f".join(parts).encode()
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def hash_contact(settings: Settings, kind: str, value: str) -> str:
    """Keyed hash of a sign-in contact, so the database never holds the number or Google id."""
    return _hmac(settings.contact_pepper.get_secret_value(), "contact", kind, value)


def generate_otp(length: int) -> str:
    return f"{secrets.randbelow(10**length):0{length}d}"


def hash_otp(settings: Settings, challenge_id: uuid.UUID, code: str) -> str:
    return _hmac(settings.contact_pepper.get_secret_value(), "otp", str(challenge_id), code)


def new_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:
    # Refresh tokens carry 256 bits of entropy, so a plain digest is enough.
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def create_access_token(
    settings: Settings, account_id: uuid.UUID, device_id: uuid.UUID, *, now: datetime | None = None
) -> str:
    issued = now or utcnow()
    claims = {
        "iss": _ISSUER,
        "sub": str(account_id),
        "sid": str(device_id),
        "typ": "access",
        "iat": issued,
        "exp": issued + timedelta(seconds=settings.access_token_ttl_seconds),
    }
    return jwt.encode(claims, settings.jwt_secret.get_secret_value(), algorithm=_ALGORITHM)


def decode_access_token(settings: Settings, token: str) -> AccessClaims:
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=[_ALGORITHM],
            issuer=_ISSUER,
            options={"require": ["exp", "iat", "sub", "sid", "iss"]},
        )
        if claims.get("typ") != "access":
            raise InvalidTokenError
        return AccessClaims(account_id=uuid.UUID(claims["sub"]), device_id=uuid.UUID(claims["sid"]))
    except (jwt.PyJWTError, ValueError, KeyError) as exc:
        raise InvalidTokenError from exc
