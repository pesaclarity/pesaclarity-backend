"""Play Integrity: decode a token with Google and check its verdict.

The app binds each token to the request it sends (``requestHash`` is the base64url SHA-256 of
the body), so a token cannot be replayed on another request. F-Droid builds cannot attest;
what an unattested request may do is a deployment setting.
"""

import base64
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ngome.core.config import Settings
from ngome.core.logging import get_logger

log = get_logger(__name__)

DECODE_URL = "https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken"
SCOPE = "https://www.googleapis.com/auth/playintegrity"
# The Cloud Run (and Compute Engine) metadata server, which issues tokens for the
# service account the server runs as.
METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"  # noqa: S105
)
_FUTURE_SKEW_MS = 60_000


class IntegrityFailedError(Exception):
    """The token is invalid or its verdict does not meet the policy."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class IntegrityUnavailableError(Exception):
    """Google could not be asked; the request may be retried."""


class IntegrityVerifier(Protocol):
    @property
    def enabled(self) -> bool: ...

    async def verify(self, token: str, request_hash: str) -> None:
        """Return if ``token`` passes, else raise :class:`IntegrityFailedError`."""
        ...


@dataclass(frozen=True, slots=True)
class IntegrityPolicy:
    package_name: str
    device_verdict: str
    max_token_age_seconds: int


def request_hash_of_sha256_hex(sha256_hex: str) -> str:
    """The ``requestHash`` the app sends for a body with this SHA-256: base64url, no padding."""
    return base64.urlsafe_b64encode(bytes.fromhex(sha256_hex)).rstrip(b"=").decode()


def check_verdict(
    payload: Mapping[str, Any], policy: IntegrityPolicy, request_hash: str, now_ms: int
) -> None:
    """Raise :class:`IntegrityFailedError` unless the decoded verdict meets ``policy``."""
    details = payload.get("requestDetails") or {}
    if details.get("requestPackageName") != policy.package_name:
        raise IntegrityFailedError("package")
    if details.get("requestHash") != request_hash:
        raise IntegrityFailedError("request_hash")
    try:
        issued_ms = int(str(details.get("timestampMillis")))
    except ValueError:
        raise IntegrityFailedError("timestamp") from None
    if issued_ms > now_ms + _FUTURE_SKEW_MS or now_ms - issued_ms > (
        policy.max_token_age_seconds * 1000
    ):
        raise IntegrityFailedError("timestamp")

    app = payload.get("appIntegrity") or {}
    if app.get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
        raise IntegrityFailedError("app")
    if app.get("packageName") != policy.package_name:
        raise IntegrityFailedError("package")

    device = payload.get("deviceIntegrity") or {}
    if policy.device_verdict not in (device.get("deviceRecognitionVerdict") or []):
        raise IntegrityFailedError("device")


AccessTokenSource = Callable[[], Awaitable[str]]


class MetadataAccessTokenSource:
    """Access tokens for the server's own service account, cached until shortly before expiry."""

    def __init__(
        self,
        url: str = METADATA_TOKEN_URL,
        *,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._transport = transport
        self._clock = clock
        self._token: str | None = None
        self._expires_at = 0.0

    async def __call__(self) -> str:
        if self._token is not None and self._clock() < self._expires_at:
            return self._token
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                response = await client.get(
                    self._url, params={"scopes": SCOPE}, headers={"Metadata-Flavor": "Google"}
                )
                response.raise_for_status()
            body = response.json()
            token = str(body["access_token"])
            lifetime = float(body.get("expires_in", 0))
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise IntegrityUnavailableError("no access token") from exc
        self._token = token
        self._expires_at = self._clock() + max(lifetime - 60, 0)
        return token


class PlayIntegrityVerifier:
    """Decodes tokens with the Play Integrity API and checks them against a policy."""

    enabled = True

    def __init__(
        self,
        policy: IntegrityPolicy,
        access_token: AccessTokenSource,
        *,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._policy = policy
        self._access_token = access_token
        self._timeout = timeout
        self._transport = transport
        self._clock = clock

    async def verify(self, token: str, request_hash: str) -> None:
        access = await self._access_token()
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport
            ) as client:
                response = await client.post(
                    DECODE_URL.format(package=self._policy.package_name),
                    json={"integrity_token": token},
                    headers={"Authorization": f"Bearer {access}"},
                )
        except httpx.HTTPError as exc:
            raise IntegrityUnavailableError("decode request failed") from exc
        if response.status_code == httpx.codes.BAD_REQUEST:
            raise IntegrityFailedError("token")
        if response.status_code != httpx.codes.OK:
            log.warning("integrity.decode_failed", status=response.status_code)
            raise IntegrityUnavailableError(f"decode returned {response.status_code}")
        try:
            payload = response.json()["tokenPayloadExternal"]
        except (KeyError, ValueError):
            raise IntegrityFailedError("token") from None
        check_verdict(payload, self._policy, request_hash, int(self._clock() * 1000))


class DisabledIntegrityVerifier:
    """Used when Play Integrity is off: tokens are ignored."""

    enabled = False

    async def verify(self, token: str, request_hash: str) -> None:
        raise IntegrityUnavailableError("Play Integrity is not enabled")


def build_integrity_verifier(
    settings: Settings, access_token: AccessTokenSource | None = None
) -> IntegrityVerifier:
    if not settings.play_integrity_enabled:
        return DisabledIntegrityVerifier()
    package = settings.play_integrity_package_name
    verdict = settings.play_integrity_device_verdict
    max_age = settings.play_integrity_max_token_age_seconds
    if package is None or verdict is None or max_age is None:
        # The settings validator rejects this; kept for type narrowing.
        raise ValueError("Play Integrity settings are incomplete")
    return PlayIntegrityVerifier(
        IntegrityPolicy(
            package_name=package, device_verdict=verdict, max_token_age_seconds=max_age
        ),
        access_token or MetadataAccessTokenSource(),
    )
