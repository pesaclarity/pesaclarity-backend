import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from ngome.core.config import Settings
from ngome.integrity.play import (
    DECODE_URL,
    IntegrityFailedError,
    IntegrityPolicy,
    IntegrityUnavailableError,
    MetadataAccessTokenSource,
    PlayIntegrityVerifier,
    check_verdict,
    request_hash_of_sha256_hex,
)
from tests.conftest import FakeMail, bearer, make_settings, sign_in

PACKAGE = "com.example.app"
NOW_MS = 1_800_000_000_000
POLICY = IntegrityPolicy(
    package_name=PACKAGE, device_verdict="MEETS_DEVICE_INTEGRITY", max_token_age_seconds=300
)
OCTET = {"Content-Type": "application/octet-stream"}


def payload(request_hash: str, **changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "requestDetails": {
            "requestPackageName": PACKAGE,
            "requestHash": request_hash,
            "timestampMillis": str(NOW_MS - 1000),
        },
        "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": PACKAGE},
        "deviceIntegrity": {
            "deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"]
        },
    }
    for path, value in changes.items():
        section, key = path.split("__")
        body[section][key] = value
    return body


def test_request_hash_matches_the_app() -> None:
    body = os.urandom(300)
    # The app sends base64url(SHA-256(body)) without padding.
    expected = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
    assert request_hash_of_sha256_hex(hashlib.sha256(body).hexdigest()) == expected


def test_a_good_verdict_passes() -> None:
    check_verdict(payload("h"), POLICY, "h", NOW_MS)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"requestDetails__requestPackageName": "com.other"}, "package"),
        ({"requestDetails__requestHash": "other"}, "request_hash"),
        ({"requestDetails__timestampMillis": str(NOW_MS - 301_000)}, "timestamp"),
        ({"requestDetails__timestampMillis": str(NOW_MS + 120_000)}, "timestamp"),
        ({"requestDetails__timestampMillis": "soon"}, "timestamp"),
        ({"appIntegrity__appRecognitionVerdict": "UNRECOGNIZED_VERSION"}, "app"),
        ({"appIntegrity__packageName": "com.other"}, "package"),
        ({"deviceIntegrity__deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"]}, "device"),
        ({"deviceIntegrity__deviceRecognitionVerdict": []}, "device"),
    ],
)
def test_a_failing_verdict_is_refused(changes: dict[str, Any], reason: str) -> None:
    with pytest.raises(IntegrityFailedError) as caught:
        check_verdict(payload("h", **changes), POLICY, "h", NOW_MS)
    assert caught.value.reason == reason


def test_an_empty_payload_is_refused() -> None:
    with pytest.raises(IntegrityFailedError):
        check_verdict({}, POLICY, "h", NOW_MS)


async def _access() -> str:
    return "access-token"


def verifier(handler: Any) -> PlayIntegrityVerifier:
    return PlayIntegrityVerifier(
        POLICY,
        _access,
        transport=httpx.MockTransport(handler),
        clock=lambda: NOW_MS / 1000,
    )


async def test_decodes_with_google_and_checks_the_verdict() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"tokenPayloadExternal": payload("h")})

    await verifier(handler).verify("integrity-token", "h")
    assert str(seen[0].url) == DECODE_URL.format(package=PACKAGE)
    assert seen[0].headers["authorization"] == "Bearer access-token"
    assert json.loads(seen[0].content) == {"integrity_token": "integrity-token"}


async def test_a_token_google_rejects_fails() -> None:
    with pytest.raises(IntegrityFailedError):
        await verifier(lambda _: httpx.Response(400, json={})).verify("bad", "h")


async def test_a_verdict_for_another_request_fails() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"tokenPayloadExternal": payload("other")})

    with pytest.raises(IntegrityFailedError):
        await verifier(handler).verify("t", "h")


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
async def test_google_errors_are_retryable_not_failures(status: int) -> None:
    with pytest.raises(IntegrityUnavailableError):
        await verifier(lambda _: httpx.Response(status, json={})).verify("t", "h")


async def test_metadata_tokens_are_cached_until_near_expiry() -> None:
    calls: list[httpx.Request] = []
    now = [0.0]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"access_token": f"t{len(calls)}", "expires_in": 3600})

    source = MetadataAccessTokenSource(transport=httpx.MockTransport(handler), clock=lambda: now[0])
    assert await source() == "t1"
    now[0] = 3000
    assert await source() == "t1"
    now[0] = 3541
    assert await source() == "t2"
    assert calls[0].headers["metadata-flavor"] == "Google"
    assert "playintegrity" in calls[0].url.params["scopes"]


async def test_metadata_failure_is_retryable() -> None:
    source = MetadataAccessTokenSource(transport=httpx.MockTransport(lambda _: httpx.Response(500)))
    with pytest.raises(IntegrityUnavailableError):
        await source()


def test_enabling_play_integrity_needs_every_setting(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="play_integrity_package_name"):
        make_settings(tmp_path, play_integrity_enabled=True)


# The vault upload endpoint.


class FakeVerifier:
    enabled = True

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.unavailable = False

    async def verify(self, token: str, request_hash: str) -> None:
        self.calls.append((token, request_hash))
        if self.unavailable:
            raise IntegrityUnavailableError("down")
        if token != "good":
            raise IntegrityFailedError("token")


@pytest.fixture(params=["allow", "reject"])
def unattested(request: pytest.FixtureRequest) -> str:
    value: str = request.param
    return value


@pytest.fixture
def settings(tmp_path: Path, unattested: str) -> Settings:
    return make_settings(
        tmp_path,
        play_integrity_enabled=True,
        play_integrity_package_name=PACKAGE,
        play_integrity_device_verdict="MEETS_DEVICE_INTEGRITY",
        play_integrity_max_token_age_seconds=300,
        vault_unattested_uploads=unattested,
    )


@pytest.fixture
def fake_verifier(app: FastAPI) -> FakeVerifier:
    fake = FakeVerifier()
    app.state.integrity_verifier = fake
    return fake


async def upload(
    client: httpx.AsyncClient, mail: FakeMail, blob: bytes, **headers: str
) -> httpx.Response:
    auth = bearer(await sign_in(client, mail))
    return await client.post(
        "/v1/vault/backups", content=blob, headers={**auth, **OCTET, **headers}
    )


async def test_a_verified_upload_is_stored(
    client: httpx.AsyncClient, mail: FakeMail, fake_verifier: FakeVerifier
) -> None:
    blob = os.urandom(256)
    digest = hashlib.sha256(blob).hexdigest()
    response = await upload(
        client,
        mail,
        blob,
        **{"X-Content-SHA256": digest, "X-Pesaclarity-Integrity": "good"},
    )
    assert response.status_code == 201, response.text
    assert fake_verifier.calls == [("good", request_hash_of_sha256_hex(digest))]


async def test_a_failed_token_is_refused_before_storing(
    client: httpx.AsyncClient, mail: FakeMail, fake_verifier: FakeVerifier
) -> None:
    blob = os.urandom(256)
    response = await upload(
        client,
        mail,
        blob,
        **{
            "X-Content-SHA256": hashlib.sha256(blob).hexdigest(),
            "X-Pesaclarity-Integrity": "tampered",
        },
    )
    assert response.status_code == 403
    auth = bearer(await sign_in(client, mail))
    assert (await client.get("/v1/vault/backups", headers=auth)).json() == []


async def test_a_token_needs_the_body_checksum(
    client: httpx.AsyncClient, mail: FakeMail, fake_verifier: FakeVerifier
) -> None:
    response = await upload(client, mail, os.urandom(256), **{"X-Pesaclarity-Integrity": "good"})
    assert response.status_code == 422
    assert fake_verifier.calls == []


async def test_a_token_for_other_bytes_fails_the_checksum(
    client: httpx.AsyncClient, mail: FakeMail, fake_verifier: FakeVerifier
) -> None:
    signed = os.urandom(256)
    response = await upload(
        client,
        mail,
        os.urandom(256),
        **{
            "X-Content-SHA256": hashlib.sha256(signed).hexdigest(),
            "X-Pesaclarity-Integrity": "good",
        },
    )
    assert response.status_code == 422


async def test_google_down_is_a_retryable_error(
    client: httpx.AsyncClient, mail: FakeMail, fake_verifier: FakeVerifier
) -> None:
    fake_verifier.unavailable = True
    blob = os.urandom(256)
    response = await upload(
        client,
        mail,
        blob,
        **{
            "X-Content-SHA256": hashlib.sha256(blob).hexdigest(),
            "X-Pesaclarity-Integrity": "good",
        },
    )
    assert response.status_code == 503
    assert response.headers["retry-after"] == "60"


async def test_uploads_without_a_token_follow_the_setting(
    client: httpx.AsyncClient, mail: FakeMail, fake_verifier: FakeVerifier, unattested: str
) -> None:
    blob = os.urandom(256)
    response = await upload(
        client, mail, blob, **{"X-Content-SHA256": hashlib.sha256(blob).hexdigest()}
    )
    assert response.status_code == (201 if unattested == "allow" else 403)
    assert fake_verifier.calls == []
