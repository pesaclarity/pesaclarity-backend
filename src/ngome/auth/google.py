"""Google ID-token verification against Google's published signing keys."""

import asyncio
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from ngome.auth.providers import (
    GoogleIdentity,
    GoogleVerifier,
    InvalidGoogleTokenError,
    UnconfiguredGoogleVerifier,
)
from ngome.core.config import Settings
from ngome.core.logging import get_logger

log = get_logger(__name__)

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
_ALGORITHM = "RS256"
_MAX_AGE = re.compile(r"(?:^|,)\s*max-age=(\d+)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class FetchedJwks:
    """A JWKS document and how long its publisher says it may be cached, in seconds."""

    jwks: Mapping[str, Any]
    max_age: float | None = None


JwksFetcher = Callable[[], Awaitable[FetchedJwks]]


class HttpJwksFetcher:
    """Fetches a JWKS over HTTPS and honours its ``Cache-Control: max-age``."""

    def __init__(
        self,
        url: str = GOOGLE_JWKS_URL,
        *,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._transport = transport

    async def __call__(self) -> FetchedJwks:
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            response = await client.get(self._url)
            response.raise_for_status()
        match = _MAX_AGE.search(response.headers.get("cache-control", ""))
        return FetchedJwks(jwks=response.json(), max_age=float(match.group(1)) if match else None)


class JwksCache:
    """Caches signing keys by ``kid`` and refetches on expiry or when an unknown ``kid`` appears.

    Refetches for unknown keys are rate limited, so a stream of tokens with made-up ``kid``
    values cannot turn into a stream of requests to Google.
    """

    def __init__(
        self,
        fetcher: JwksFetcher,
        *,
        default_ttl: float = 3600.0,
        min_refetch_interval: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetcher = fetcher
        self._default_ttl = default_ttl
        self._min_refetch_interval = min_refetch_interval
        self._clock = clock
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def get(self, kid: str) -> jwt.PyJWK:
        if not self._fresh() or (kid not in self._keys and self._may_refetch()):
            async with self._lock:
                # Another task may have refreshed while this one waited.
                if not self._fresh() or (kid not in self._keys and self._may_refetch()):
                    await self._refresh()
        key = self._keys.get(kid)
        if key is None:
            raise InvalidGoogleTokenError("unknown signing key")
        return key

    def _fresh(self) -> bool:
        return self._fetched_at is not None and self._clock() < self._expires_at

    def _may_refetch(self) -> bool:
        return (
            self._fetched_at is None
            or self._clock() - self._fetched_at >= self._min_refetch_interval
        )

    async def _refresh(self) -> None:
        try:
            fetched = await self._fetcher()
            key_set = jwt.PyJWKSet.from_dict(dict(fetched.jwks))
        except (httpx.HTTPError, jwt.PyJWTError, ValueError, TypeError) as exc:
            # Keep serving the old keys: a brief outage at Google should not sign everyone out.
            log.warning("google.jwks_fetch_failed", error=type(exc).__name__)
            if self._fetched_at is None:
                raise InvalidGoogleTokenError("signing keys unavailable") from exc
            self._expires_at = self._clock() + self._min_refetch_interval
            return
        now = self._clock()
        self._keys = {k.key_id: k for k in key_set.keys if k.key_id}
        self._fetched_at = now
        ttl = fetched.max_age if fetched.max_age is not None else self._default_ttl
        self._expires_at = now + ttl
        log.info("google.jwks_refreshed", keys=len(self._keys))


class GoogleIdTokenVerifier:
    """Verifies a Google ID token: RS256 signature, audience, issuer, expiry and issue time."""

    def __init__(
        self,
        client_ids: Sequence[str],
        keys: JwksCache,
        *,
        leeway_seconds: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not client_ids:
            raise ValueError("at least one Google client id is required")
        self._client_ids = list(client_ids)
        self._keys = keys
        self._leeway = leeway_seconds
        self._clock = clock

    async def verify(self, id_token: str) -> GoogleIdentity:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise InvalidGoogleTokenError("malformed token") from exc
        kid = header.get("kid")
        if header.get("alg") != _ALGORITHM or not isinstance(kid, str):
            raise InvalidGoogleTokenError("unexpected token header")

        key = await self._keys.get(kid)
        try:
            claims = jwt.decode(
                id_token,
                key,
                algorithms=[_ALGORITHM],
                audience=self._client_ids,
                issuer=GOOGLE_ISSUERS,
                leeway=self._leeway,
                options={"require": ["iss", "aud", "sub", "exp", "iat"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidGoogleTokenError(type(exc).__name__) from exc

        iat = claims["iat"]
        if not isinstance(iat, int | float) or iat > self._clock() + self._leeway:
            raise InvalidGoogleTokenError("issued in the future")
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject:
            raise InvalidGoogleTokenError("missing subject")
        # Only the subject is used. If email is ever read from the token, require
        # email_verified first.
        return GoogleIdentity(subject=subject)


def build_google_verifier(settings: Settings, fetcher: JwksFetcher | None = None) -> GoogleVerifier:
    """A real verifier when Google sign-in is enabled, otherwise one that refuses every token."""
    if not settings.google_sign_in_enabled:
        return UnconfiguredGoogleVerifier()
    return GoogleIdTokenVerifier(
        settings.google_client_ids,
        JwksCache(fetcher or HttpJwksFetcher()),
        leeway_seconds=settings.google_token_leeway_seconds,
    )
