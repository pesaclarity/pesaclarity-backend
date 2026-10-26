import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI

from ngome.api.app import create_app
from ngome.auth.google import (
    FetchedJwks,
    GoogleIdTokenVerifier,
    HttpJwksFetcher,
    JwksCache,
    build_google_verifier,
)
from ngome.auth.providers import InvalidGoogleTokenError, UnconfiguredGoogleVerifier
from ngome.db.models import Base
from tests.conftest import make_settings

CLIENT_ID = "test-client.apps.example"


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class FakeClock:
    now: float = 1_000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class FakeJwks:
    """Serves locally generated public keys as a JWKS, counting fetches."""

    keys: dict[str, rsa.RSAPrivateKey] = field(default_factory=dict)
    max_age: float | None = None
    fail: bool = False
    fetches: int = 0

    async def __call__(self) -> FetchedJwks:
        self.fetches += 1
        if self.fail:
            raise httpx.ConnectError("offline in tests")
        jwks = {
            "keys": [
                {
                    **jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True),
                    "kid": kid,
                    "alg": "RS256",
                    "use": "sig",
                }
                for kid, key in self.keys.items()
            ]
        }
        return FetchedJwks(jwks=jwks, max_age=self.max_age)


def _token(
    key: rsa.RSAPrivateKey, kid: str = "key-1", *, algorithm: str = "RS256", **overrides: Any
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": "google-subject-1",
        "iat": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid})


@pytest.fixture
def key() -> rsa.RSAPrivateKey:
    return _new_key()


@pytest.fixture
def jwks(key: rsa.RSAPrivateKey) -> FakeJwks:
    return FakeJwks(keys={"key-1": key})


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def verifier(jwks: FakeJwks, clock: FakeClock) -> GoogleIdTokenVerifier:
    return GoogleIdTokenVerifier(
        [CLIENT_ID], JwksCache(jwks, default_ttl=3600, min_refetch_interval=60, clock=clock)
    )


async def test_valid_token_returns_subject(
    verifier: GoogleIdTokenVerifier, key: rsa.RSAPrivateKey
) -> None:
    identity = await verifier.verify(_token(key))
    assert identity.subject == "google-subject-1"


@pytest.mark.parametrize("issuer", ["accounts.google.com", "https://accounts.google.com"])
async def test_both_google_issuers_are_accepted(
    verifier: GoogleIdTokenVerifier, key: rsa.RSAPrivateKey, issuer: str
) -> None:
    assert (await verifier.verify(_token(key, iss=issuer))).subject == "google-subject-1"


async def test_any_configured_client_id_is_accepted(jwks: FakeJwks, key: rsa.RSAPrivateKey) -> None:
    verifier = GoogleIdTokenVerifier(["other.apps.example", CLIENT_ID], JwksCache(jwks))
    assert (await verifier.verify(_token(key))).subject == "google-subject-1"


async def test_small_clock_skew_is_tolerated(
    verifier: GoogleIdTokenVerifier, key: rsa.RSAPrivateKey
) -> None:
    now = int(time.time())
    token = _token(key, iat=now - 3600, exp=now - 30)
    assert (await verifier.verify(token)).subject == "google-subject-1"


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"aud": "someone-else.apps.example"}, id="wrong-audience"),
        pytest.param({"iss": "https://evil.example"}, id="wrong-issuer"),
        pytest.param({"exp": int(time.time()) - 600}, id="expired"),
        pytest.param({"iat": int(time.time()) + 600}, id="issued-in-future"),
        pytest.param({"sub": ""}, id="empty-subject"),
        pytest.param({"sub": None}, id="no-subject"),
        pytest.param({"exp": None}, id="no-expiry"),
        pytest.param({"iat": None}, id="no-issued-at"),
        pytest.param({"aud": None}, id="no-audience"),
    ],
)
async def test_bad_claims_are_rejected(
    verifier: GoogleIdTokenVerifier, key: rsa.RSAPrivateKey, overrides: dict[str, Any]
) -> None:
    with pytest.raises(InvalidGoogleTokenError):
        await verifier.verify(_token(key, **overrides))


async def test_token_signed_by_another_key_is_rejected(verifier: GoogleIdTokenVerifier) -> None:
    with pytest.raises(InvalidGoogleTokenError):
        await verifier.verify(_token(_new_key(), kid="key-1"))


async def test_non_rs256_tokens_are_rejected(verifier: GoogleIdTokenVerifier) -> None:
    forged = _token("shared-secret-" + "z" * 32, algorithm="HS256")  # type: ignore[arg-type]
    with pytest.raises(InvalidGoogleTokenError):
        await verifier.verify(forged)
    with pytest.raises(InvalidGoogleTokenError):
        await verifier.verify("not-a-jwt")


async def test_keys_are_cached_until_max_age(
    verifier: GoogleIdTokenVerifier, jwks: FakeJwks, key: rsa.RSAPrivateKey, clock: FakeClock
) -> None:
    await verifier.verify(_token(key))
    await verifier.verify(_token(key))
    assert jwks.fetches == 1

    clock.now += 3601
    await verifier.verify(_token(key))
    assert jwks.fetches == 2


async def test_published_max_age_overrides_default(
    jwks: FakeJwks, key: rsa.RSAPrivateKey, clock: FakeClock
) -> None:
    jwks.max_age = 120
    verifier = GoogleIdTokenVerifier(
        [CLIENT_ID], JwksCache(jwks, default_ttl=3600, min_refetch_interval=60, clock=clock)
    )
    await verifier.verify(_token(key))
    clock.now += 121
    await verifier.verify(_token(key))
    assert jwks.fetches == 2


async def test_rotated_key_is_picked_up(
    verifier: GoogleIdTokenVerifier, jwks: FakeJwks, key: rsa.RSAPrivateKey, clock: FakeClock
) -> None:
    await verifier.verify(_token(key))
    rotated = _new_key()
    jwks.keys = {"key-2": rotated}
    clock.now += 61

    assert (await verifier.verify(_token(rotated, kid="key-2"))).subject == "google-subject-1"
    assert jwks.fetches == 2
    with pytest.raises(InvalidGoogleTokenError):
        await verifier.verify(_token(key, kid="key-1"))


async def test_unknown_kid_refetches_are_rate_limited(
    verifier: GoogleIdTokenVerifier, jwks: FakeJwks, key: rsa.RSAPrivateKey
) -> None:
    await verifier.verify(_token(key))
    for _ in range(5):
        with pytest.raises(InvalidGoogleTokenError):
            await verifier.verify(_token(_new_key(), kid="made-up"))
    assert jwks.fetches == 1


async def test_fetch_failure_without_cached_keys_rejects(
    verifier: GoogleIdTokenVerifier, jwks: FakeJwks, key: rsa.RSAPrivateKey
) -> None:
    jwks.fail = True
    with pytest.raises(InvalidGoogleTokenError):
        await verifier.verify(_token(key))


async def test_fetch_failure_keeps_serving_cached_keys(
    verifier: GoogleIdTokenVerifier, jwks: FakeJwks, key: rsa.RSAPrivateKey, clock: FakeClock
) -> None:
    await verifier.verify(_token(key))
    jwks.fail = True
    clock.now += 3601

    assert (await verifier.verify(_token(key))).subject == "google-subject-1"
    await verifier.verify(_token(key))
    assert jwks.fetches == 2


async def test_http_fetcher_reads_max_age() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://keys.example/certs"
        return httpx.Response(
            200,
            json={"keys": []},
            headers={"Cache-Control": "public, max-age=19800, must-revalidate"},
        )

    fetcher = HttpJwksFetcher("https://keys.example/certs", transport=httpx.MockTransport(handler))
    fetched = await fetcher()
    assert fetched.jwks == {"keys": []}
    assert fetched.max_age == 19800


def test_builder_refuses_tokens_when_disabled(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, google_sign_in_enabled=False, google_client_ids=[])
    assert isinstance(build_google_verifier(settings), UnconfiguredGoogleVerifier)


@pytest.fixture
async def google_app(tmp_path: Path, jwks: FakeJwks) -> AsyncIterator[FastAPI]:
    settings = make_settings(tmp_path)
    application = create_app(settings)
    application.state.google_verifier = build_google_verifier(settings, fetcher=jwks)
    async with application.state.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield application
    await application.state.engine.dispose()


async def test_endpoint_signs_in_with_a_real_token(
    google_app: FastAPI, key: rsa.RSAPrivateKey
) -> None:
    transport = httpx.ASGITransport(app=google_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        ok = await client.post(
            "/v1/auth/google", json={"id_token": _token(key), "device_name": "Pixel"}
        )
        forged = await client.post(
            "/v1/auth/google",
            json={"id_token": _token(_new_key()), "device_name": "Pixel"},
        )
    assert ok.status_code == 200, ok.text
    assert forged.status_code == 401
