"""App status: admin notices, what each build sees, the signature, and no logging of
who asked."""

import base64
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import FastAPI
from pydantic import SecretStr, ValidationError
from sqlalchemy import func, select

from ngome.api.app import create_app
from ngome.appstatus.signing import SIGNING_CONTEXT, AppStatusSigner, main
from ngome.appstatus.versions import Version
from ngome.core.config import Settings
from ngome.db.models import Base
from tests.conftest import make_settings

# A throwaway key made for each test run; never a real one.
_TEST_KEY = Ed25519PrivateKey.generate()
TEST_SEED = base64.b64encode(_TEST_KEY.private_bytes_raw()).decode()
TEST_PUBLIC: Ed25519PublicKey = _TEST_KEY.public_key()
ADMIN_TOKEN = "test-admin-token-" + "z" * 32
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(
        tmp_path,
        admin_token=SecretStr(ADMIN_TOKEN),
        app_status_signing_seed=SecretStr(TEST_SEED),
    )


def verified(response: httpx.Response) -> dict[str, Any]:
    """The payload, after checking its signature with the test public key."""
    assert response.status_code == 200, response.text
    envelope = response.json()
    assert envelope["alg"] == "Ed25519"
    data = base64.b64decode(envelope["payload"])
    TEST_PUBLIC.verify(base64.b64decode(envelope["signature"]), SIGNING_CONTEXT + data)
    payload: dict[str, Any] = json.loads(data)
    return payload


async def status_for(
    client: httpx.AsyncClient, version: str = "0.3.0", build: str = "play"
) -> dict[str, Any]:
    platform = "ios" if build == "ios" else "android"
    response = await client.get(
        "/v1/app-status", params={"version": version, "build": build, "platform": platform}
    )
    return verified(response)


async def create(client: httpx.AsyncClient, **fields: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "update",
        "title": "Pesa Clarity 0.4.0 is ready",
        "body": "Reads Equity card payments and fixes Fuliza totals.",
        "latest_version": "0.4.0",
        "builds": ["play", "foss", "ios", "website"],
    }
    body.update(fields)
    response = await client.post("/v1/admin/app-notices", json=body, headers=ADMIN)
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def test_versions_compare_the_semver_way() -> None:
    ordered = ["0.2.9", "0.3.0-dev.2", "0.3.0-dev.10", "0.3.0", "0.3.2", "0.4.0", "1.0.0"]
    versions = [Version(v) for v in ordered]
    assert versions == sorted(versions)
    assert Version("0.3.0+7") == Version("0.3.0")
    with pytest.raises(ValueError, match="not a version"):
        Version("0.3")


async def test_create_list_and_disable(client: httpx.AsyncClient) -> None:
    notice = await create(client)
    assert notice["kind"] == "update"
    assert notice["disabled_at"] is None

    listed = await client.get("/v1/admin/app-notices", headers=ADMIN)
    assert [n["id"] for n in listed.json()] == [notice["id"]]
    assert (await status_for(client))["notices"][0]["id"] == notice["id"]

    disabled = await client.post(f"/v1/admin/app-notices/{notice['id']}/disable", headers=ADMIN)
    assert disabled.status_code == 200
    assert disabled.json()["disabled_at"] is not None
    assert (await status_for(client))["notices"] == []


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong-token"}, {"Authorization": f"Basic {ADMIN_TOKEN}"}],
)
async def test_admin_routes_need_the_token(
    client: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    body = {"kind": "info", "title": "T", "body": "B", "builds": ["play"]}
    for response in (
        await client.post("/v1/admin/app-notices", json=body, headers=headers),
        await client.get("/v1/admin/app-notices", headers=headers),
    ):
        assert response.status_code in {401, 403}
    assert (await client.get("/v1/admin/app-notices", headers=ADMIN)).json() == []


async def test_admin_routes_are_off_without_a_token(tmp_path: Path) -> None:
    application = create_app(make_settings(tmp_path))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.get("/v1/admin/app-notices", headers=ADMIN)
        assert response.status_code == 404
        response = await c.get(
            "/v1/app-status", params={"version": "0.3.0", "build": "play", "platform": "android"}
        )
        assert response.status_code == 503
    await application.state.engine.dispose()


@pytest.mark.parametrize(
    "fields",
    [
        {"latest_version": None},
        {"latest_version": "0.4"},
        {"min_version": "0.5.0"},
        {"required_reason": "amounts_wrong"},
        {"min_version": "0.3.2", "required_reason": "looks_old"},
        {"builds": []},
        {"builds": ["play", "play"]},
        {"builds": ["huawei"]},
        {"kind": "info"},
        {"title": "x" * 81},
        {"starts_at": "2026-11-20T00:00:00Z", "ends_at": "2026-11-19T00:00:00Z"},
        {"starts_at": "2026-11-20T00:00:00"},
        {"surprise": True},
    ],
)
async def test_rejects_inconsistent_notices(
    client: httpx.AsyncClient, fields: dict[str, Any]
) -> None:
    body: dict[str, Any] = {
        "kind": "update",
        "title": "Pesa Clarity 0.4.0 is ready",
        "body": "Fixes.",
        "latest_version": "0.4.0",
        "builds": ["play"],
    }
    body.update(fields)
    response = await client.post("/v1/admin/app-notices", json=body, headers=ADMIN)
    assert response.status_code == 422


async def test_filters_by_build(client: httpx.AsyncClient) -> None:
    await create(client, builds=["foss", "website"])
    assert (await status_for(client, build="play"))["notices"] == []
    assert len((await status_for(client, build="foss"))["notices"]) == 1
    assert (await status_for(client, build="play"))["latest_version"] is None
    assert (await status_for(client, build="website"))["latest_version"] == "0.4.0"


async def test_filters_by_version(client: httpx.AsyncClient) -> None:
    await create(client)
    assert len((await status_for(client, version="0.3.0"))["notices"]) == 1
    assert len((await status_for(client, version="0.4.0-dev.3"))["notices"]) == 1
    newer = await status_for(client, version="0.4.0")
    assert newer["notices"] == []
    assert newer["latest_version"] == "0.4.0"


async def test_filters_by_time(client: httpx.AsyncClient) -> None:
    now = datetime.now(UTC)
    await create(client, title="Later", starts_at=(now + timedelta(days=1)).isoformat())
    await create(
        client,
        title="Over",
        starts_at=(now - timedelta(days=2)).isoformat(),
        ends_at=(now - timedelta(days=1)).isoformat(),
    )
    await create(
        client, title="Now", ends_at=(now + timedelta(days=1)).isoformat(), builds=["play"]
    )
    assert [n["title"] for n in (await status_for(client))["notices"]] == ["Now"]


async def test_an_info_notice_and_a_required_update(client: httpx.AsyncClient) -> None:
    await create(
        client,
        kind="info",
        title="KCB changed its messages",
        body="Some KCB payments from 10 Nov were missed. We read them again: 4 found.",
        latest_version=None,
        reread_from="2026-11-10",
        builds=["play"],
    )
    await create(
        client,
        title="Please update Pesa Clarity",
        body="This version reads some M-PESA messages wrongly, so your totals may be off.",
        latest_version="0.3.2",
        min_version="0.3.2",
        required_reason="amounts_wrong",
        builds=["play"],
    )
    payload = await status_for(client, version="0.3.0")
    by_kind = {n["kind"]: n for n in payload["notices"]}
    assert by_kind["info"]["reread_from"] == "2026-11-10"
    assert by_kind["info"]["latest_version"] is None
    assert by_kind["update"]["min_version"] == "0.3.2"
    assert by_kind["update"]["required_reason"] == "amounts_wrong"
    # A build that already has the fix sees only the news.
    assert [n["kind"] for n in (await status_for(client, version="0.3.2"))["notices"]] == ["info"]


async def test_the_signed_payload_names_the_request_and_time(client: httpx.AsyncClient) -> None:
    before = datetime.now(UTC).replace(microsecond=0)
    payload = await status_for(client, version="0.3.0-dev.4", build="ios")
    issued = datetime.fromisoformat(payload["issued_at"])
    assert before <= issued <= datetime.now(UTC)
    assert payload["format"] == 1
    assert (payload["version"], payload["build"], payload["platform"]) == (
        "0.3.0-dev.4",
        "ios",
        "ios",
    )


async def test_a_changed_payload_fails_the_signature(client: httpx.AsyncClient) -> None:
    await create(client)
    response = await client.get(
        "/v1/app-status", params={"version": "0.3.0", "build": "play", "platform": "android"}
    )
    envelope = response.json()
    data = json.loads(base64.b64decode(envelope["payload"]))
    data["notices"][0]["required_reason"] = "amounts_wrong"
    forged = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    with pytest.raises(InvalidSignature):
        TEST_PUBLIC.verify(base64.b64decode(envelope["signature"]), SIGNING_CONTEXT + forged)
    other = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(InvalidSignature):
        other.verify(
            base64.b64decode(envelope["signature"]),
            SIGNING_CONTEXT + base64.b64decode(envelope["payload"]),
        )


async def test_no_account_no_cookie_and_cacheable(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/v1/app-status", params={"version": "0.3.0", "build": "foss", "platform": "android"}
    )
    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert response.headers["cache-control"] == "public, max-age=300"


@pytest.mark.parametrize(
    "params",
    [
        {"version": "0.3", "build": "play", "platform": "android"},
        {"version": "0.3.0", "build": "huawei", "platform": "android"},
        {"version": "0.3.0", "build": "play", "platform": "windows"},
        {"version": "1." * 40 + "0", "build": "play", "platform": "android"},
        {"build": "play", "platform": "android"},
    ],
)
async def test_rejects_a_bad_query(client: httpx.AsyncClient, params: dict[str, str]) -> None:
    assert (await client.get("/v1/app-status", params=params)).status_code == 422


@pytest.fixture
async def remote_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client calling from a documentation address (RFC 5737), as a phone would."""
    transport = httpx.ASGITransport(app=app, client=("203.0.113.77", 51234))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _row_counts(app: FastAPI) -> dict[str, int]:
    counts: dict[str, int] = {}
    async with app.state.sessionmaker() as session:
        for table in Base.metadata.sorted_tables:
            counts[table.name] = await session.scalar(select(func.count()).select_from(table))
    return counts


async def test_app_status_logs_and_stores_nothing_about_the_caller(
    app: FastAPI, remote_client: httpx.AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    before = await _row_counts(app)
    capsys.readouterr()
    response = await remote_client.get(
        "/v1/app-status",
        params={"version": "0.3.0-dev.987654", "build": "website", "platform": "android"},
        headers={"X-Forwarded-For": "198.51.100.23", "User-Agent": "test-agent/9.9"},
    )
    assert response.status_code == 200
    logged = capsys.readouterr().out
    assert "http.request" in logged  # the access log line was written and captured
    assert "/v1/app-status" in logged
    for secret in ("203.0.113.77", "198.51.100.23", "987654", "website", "test-agent"):
        assert secret not in logged
    assert await _row_counts(app) == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"admin_token": SecretStr("short")},
        {"app_status_signing_seed": SecretStr("not base64!")},
        {"app_status_signing_seed": SecretStr(base64.b64encode(b"x" * 16).decode())},
    ],
)
def test_settings_check_the_token_and_seed(tmp_path: Path, overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_settings(tmp_path, **overrides)


def test_the_key_command_prints_a_working_pair(capsys: pytest.CaptureFixture[str]) -> None:
    main()
    lines = [line for line in capsys.readouterr().out.splitlines() if not line.startswith("#")]
    seed = lines[0].removeprefix("NGOME_APP_STATUS_SIGNING_SEED=")
    assert AppStatusSigner.from_base64(seed).public_key_base64 == lines[1]
    assert len(base64.b64decode(lines[1])) == 32
