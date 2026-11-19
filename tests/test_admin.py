"""The admin dashboard: off until configured, passkey-only, its headers, and what its pages
show, with small counts hidden (ADR 0024)."""

import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.admin.downloads import summarise
from ngome.admin.models import AdminEnrolment, AdminSession
from ngome.admin.router import COOKIE
from ngome.core.config import Settings
from ngome.counting.models import DAY, MONTH, CountTotal
from ngome.counting.suppress import shown_total, suppress
from tests.conftest import make_settings
from tests.soft_passkey import SoftPasskey
from tests.test_app_status import TEST_SEED

ORIGIN = "https://admin.test"
ADMIN_TOKEN = "test-admin-token-" + "z" * 32
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
SAME = {"Origin": ORIGIN}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(
        tmp_path,
        admin_token=SecretStr(ADMIN_TOKEN),
        admin_origin=ORIGIN,
        app_status_signing_seed=SecretStr(TEST_SEED),
        downloads_csv_url=None,
    )


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as c:
        yield c


@pytest.fixture
def maker(app: FastAPI) -> async_sessionmaker[AsyncSession]:
    sessions: async_sessionmaker[AsyncSession] = app.state.sessionmaker
    return sessions


async def enrol(client: httpx.AsyncClient, passkey: SoftPasskey, label: str = "Phone") -> None:
    minted = await client.post("/v1/admin/passkey-enrolments", json={"label": label}, headers=ADMIN)
    assert minted.status_code == 201, minted.text
    url = minted.json()["url"]
    assert url.startswith(f"{ORIGIN}/admin/enrol/")
    token = url.rsplit("/", 1)[1]
    page = await client.get(f"/admin/enrol/{token}")
    assert "Add a passkey" in page.text
    start = await client.post("/admin/enrol/options", json={"token": token}, headers=SAME)
    assert start.status_code == 200, start.text
    body = start.json()
    finish = await client.post(
        "/admin/enrol/verify",
        json={
            "token": token,
            "challenge_id": body["challenge_id"],
            "credential": passkey.register(body["options"]),
        },
        headers=SAME,
    )
    assert finish.status_code == 200, finish.text
    client.cookies.clear()


async def sign_in(client: httpx.AsyncClient, passkey: SoftPasskey) -> httpx.Response:
    start = await client.post("/admin/sign-in/options", headers=SAME)
    assert start.status_code == 200, start.text
    body = start.json()
    return await client.post(
        "/admin/sign-in/verify",
        json={"challenge_id": body["challenge_id"], "credential": passkey.sign_in(body["options"])},
        headers=SAME,
    )


@pytest.fixture
async def signed_in(client: httpx.AsyncClient) -> SoftPasskey:
    passkey = SoftPasskey("admin.test", ORIGIN)
    await enrol(client, passkey)
    response = await sign_in(client, passkey)
    assert response.status_code == 200, response.text
    return passkey


def test_suppression_hides_small_cells_and_their_complement() -> None:
    assert suppress({"KE": 120, "UG": 40, "TZ": 12}) == {"KE": 120, "UG": 40, "TZ": 12}
    # One hidden cell would be given away by the total, so the next smallest goes too.
    assert suppress({"KE": 120, "UG": 40, "TZ": 12, "RW": 3}) == {
        "KE": 120,
        "UG": 40,
        "TZ": None,
        "RW": None,
    }
    assert suppress({"KE": 120, "RW": 3, "NG": 2}) == {"KE": 120, "RW": None, "NG": None}
    assert suppress({"KE": 9}) == {"KE": None}
    assert shown_total(9) is None
    assert shown_total(10) == 10


async def test_off_until_the_origin_is_set(app: FastAPI, tmp_path: Path) -> None:
    app.state.settings = make_settings(tmp_path, admin_token=SecretStr(ADMIN_TOKEN))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as client:
        assert (await client.get("/admin")).status_code == 404
        assert (await client.get("/admin/sign-in")).status_code == 404
        minted = await client.post(
            "/v1/admin/passkey-enrolments", json={"label": "x"}, headers=ADMIN
        )
        assert minted.status_code == 404


async def test_pages_need_a_passkey_sign_in(client: httpx.AsyncClient) -> None:
    for path in ("/admin", "/admin/installs", "/admin/crashes"):
        response = await client.get(path)
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/sign-in"
    page = await client.get("/admin/sign-in")
    assert page.status_code == 200
    assert "Sign in with a passkey" in page.text
    assert page.headers["content-security-policy"].startswith("default-src 'self'")
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["referrer-policy"] == "no-referrer"
    # No third-party anything: every script, style and font is our own.
    assert "http" not in page.text.replace(ORIGIN, "")
    assert "<style" not in page.text
    assert " style=" not in page.text


async def test_static_files_are_ours(client: httpx.AsyncClient) -> None:
    for path in ("admin.css", "admin.js", "fonts/Inter-Variable.ttf"):
        response = await client.get(f"/admin/static/{path}")
        assert response.status_code == 200, path
        assert response.headers["cache-control"] == "no-store"


async def test_enrolment_needs_the_admin_token(client: httpx.AsyncClient) -> None:
    response = await client.post("/v1/admin/passkey-enrolments", json={"label": "x"})
    assert response.status_code == 401
    wrong = {"Authorization": "Bearer " + "w" * 48}
    response = await client.post("/v1/admin/passkey-enrolments", json={"label": "x"}, headers=wrong)
    assert response.status_code == 401


async def test_enrol_sign_in_and_sign_out(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    passkey = SoftPasskey("admin.test", ORIGIN)
    await enrol(client, passkey)
    assert (await client.get("/admin")).status_code == 303

    response = await sign_in(client, passkey)
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/", "Max-Age=43200"):
        assert flag.lower() in cookie.lower()
    assert "domain" not in cookie.lower()
    async with maker() as session:
        stored = list(await session.scalars(select(AdminSession)))
    # Enrolling signed in once, and so did this. Only digests of the session ids are stored.
    assert len(stored) == 2
    assert client.cookies[COOKIE] not in {row.id_hash for row in stored}

    overview = await client.get("/admin")
    assert overview.status_code == 200
    assert "Monthly active installs" in overview.text

    # Sign-out needs the dashboard's own origin.
    assert (await client.post("/admin/sign-out")).status_code == 403
    out = await client.post("/admin/sign-out", headers=SAME)
    assert out.status_code == 303
    async with maker() as session:
        assert len(list(await session.scalars(select(AdminSession)))) == 1
    assert (await client.get("/admin")).status_code == 303


async def test_enrolment_links_are_single_use_and_expire(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    minted = await client.post("/v1/admin/passkey-enrolments", json={"label": "Key"}, headers=ADMIN)
    token = minted.json()["url"].rsplit("/", 1)[1]
    first = await client.post("/admin/enrol/options", json={"token": token}, headers=SAME)
    body = first.json()
    passkey = SoftPasskey("admin.test", ORIGIN)
    finish = {
        "token": token,
        "challenge_id": body["challenge_id"],
        "credential": passkey.register(body["options"]),
    }
    assert (await client.post("/admin/enrol/verify", json=finish, headers=SAME)).status_code == 200
    again = await client.post("/admin/enrol/options", json={"token": token}, headers=SAME)
    assert again.status_code == 400
    assert "has been used or has expired" in (await client.get(f"/admin/enrol/{token}")).text

    minted = await client.post("/v1/admin/passkey-enrolments", json={"label": "Old"}, headers=ADMIN)
    old = minted.json()["url"].rsplit("/", 1)[1]
    async with maker() as session:
        await session.execute(
            update(AdminEnrolment).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()
    expired = await client.post("/admin/enrol/options", json={"token": old}, headers=SAME)
    assert expired.status_code == 400


@pytest.mark.parametrize("mistake", ["origin", "rp", "challenge", "unknown", "replay"])
async def test_sign_in_refuses(client: httpx.AsyncClient, mistake: str) -> None:
    passkey = SoftPasskey("admin.test", ORIGIN)
    await enrol(client, passkey)
    start = (await client.post("/admin/sign-in/options", headers=SAME)).json()
    options: dict[str, Any] = start["options"]
    challenge_id = start["challenge_id"]
    signer = passkey
    if mistake == "origin":
        credential = passkey.sign_in(options, origin="https://evil.example")
    elif mistake == "rp":
        signer = SoftPasskey("evil.example", ORIGIN)
        signer.credential_id = passkey.credential_id
        credential = signer.sign_in(options)
    elif mistake == "challenge":
        credential = passkey.sign_in({"challenge": "AAAA"})
    elif mistake == "unknown":
        credential = SoftPasskey("admin.test", ORIGIN).sign_in(options)
    else:
        credential = passkey.sign_in(options)
        body = {"challenge_id": challenge_id, "credential": credential}
        assert (
            await client.post("/admin/sign-in/verify", json=body, headers=SAME)
        ).status_code == 200
        client.cookies.clear()
    body = {"challenge_id": challenge_id, "credential": credential}
    response = await client.post("/admin/sign-in/verify", json=body, headers=SAME)
    assert response.status_code == 400
    assert "set-cookie" not in response.headers


async def test_ceremonies_check_the_origin(client: httpx.AsyncClient) -> None:
    assert (await client.post("/admin/sign-in/options")).status_code == 403
    evil = {"Origin": "https://evil.example"}
    assert (await client.post("/admin/sign-in/options", headers=evil)).status_code == 403


async def test_removing_a_passkey_ends_its_sessions(
    client: httpx.AsyncClient, signed_in: SoftPasskey
) -> None:
    assert (await client.get("/admin")).status_code == 200
    listed = await client.get("/v1/admin/passkeys", headers=ADMIN)
    assert [p["label"] for p in listed.json()] == ["Phone"]
    removed = await client.delete(f"/v1/admin/passkeys/{listed.json()[0]['id']}", headers=ADMIN)
    assert removed.status_code == 204
    assert (await client.get("/admin")).status_code == 303
    assert (await sign_in(client, signed_in)).status_code == 400


async def test_expired_sessions_end(
    client: httpx.AsyncClient, signed_in: SoftPasskey, maker: async_sessionmaker[AsyncSession]
) -> None:
    async with maker() as session:
        await session.execute(
            update(AdminSession).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()
    assert (await client.get("/admin")).status_code == 303


async def add_totals(
    maker: async_sessionmaker[AsyncSession],
    kind: str,
    period: Any,
    cells: dict[str, dict[str, int]],
) -> None:
    async with maker() as session:
        for dimension, values in cells.items():
            for value, n in values.items():
                session.add(
                    CountTotal(kind=kind, period=period, dimension=dimension, value=value, n=n)
                )
        await session.commit()


async def test_overview_and_installs_hide_small_counts(
    client: httpx.AsyncClient,
    signed_in: SoftPasskey,
    maker: async_sessionmaker[AsyncSession],
    app: FastAPI,
) -> None:
    today = datetime.now(UTC).date()
    month = today.replace(day=1)
    await add_totals(
        maker,
        MONTH,
        month,
        {
            "all": {"all": 3412},
            "build": {"play": 2611, "foss": 402, "website": 396, "ios": 3},
            "version": {
                "0.5.2": 2104,
                "0.5.1": 861,
                "0.5.0": 274,
                "0.4.3": 131,
                "0.4.2": 35,
                "0.4.1": 4,
                "0.3.0": 3,
            },
            "country": {"KE": 2981, "UG": 164, "TZ": 97, "GB": 41, "RW": 7, "NG": 2, "ZZ": 120},
        },
    )
    yesterday = today - timedelta(days=1)
    await add_totals(maker, DAY, yesterday, {"all": {"all": 1122}})
    await add_totals(maker, DAY, yesterday - timedelta(days=1), {"all": {"all": 4}})

    class Csv:
        async def csv_text(self) -> str:
            return (
                "date,release,file,downloads\n"
                "2026-10-01,v0.4.0,pesaclarity-play.apk,100\n"
                "2026-11-17,v0.4.0,pesaclarity-play.apk,160\n"
                "2026-11-17,v0.5.0,pesaclarity-play.apk,40\n"
                "2026-11-17,v0.5.0,pesaclarity-foss.apk,12\n"
            )

    app.state.downloads_source = Csv()
    page = (await client.get("/admin")).text
    assert "3,412" in page
    assert "1,122" in page
    assert "2,611" in page
    assert "Older" in page
    assert "pesaclarity-foss.apk" in page
    # iPhone's 3 is hidden, and so is the next smallest build, so neither can be worked out.
    assert ">396<" not in page
    assert page.count("&lt;10") >= 2
    assert ">3<" not in page
    assert "DB-IP" not in page  # country lookup is off

    installs = (await client.get("/admin/installs")).text
    assert "Country lookup is off" in installs


async def test_installs_by_country_when_lookup_is_on(
    app: FastAPI,
    client: httpx.AsyncClient,
    signed_in: SoftPasskey,
    maker: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> None:
    app.state.settings = settings.model_copy(update={"country_lookup_enabled": True})
    month = datetime.now(UTC).date().replace(day=1)
    await add_totals(
        maker,
        MONTH,
        month,
        {"all": {"all": 3300}, "country": {"KE": 2981, "UG": 164, "RW": 7, "NG": 2, "ZZ": 146}},
    )
    page = (await client.get("/admin/installs")).text
    assert "Kenya" in page
    assert "2,981" in page
    assert "Rwanda" in page
    assert ">7<" not in page
    assert "Unknown" in page
    assert "IP Geolocation by DB-IP" in page
    assert "4 more under 10" not in page
    assert "2 more under 10" in page


async def test_crash_pages(app: FastAPI, client: httpx.AsyncClient, signed_in: SoftPasskey) -> None:
    from tests.test_crash_reports import report  # noqa: PLC0415

    for build in ("play", "play", "foss"):
        sent = await client.post("/v1/crash-reports", json=report(build=build))
        assert sent.status_code == 202
    page = await client.get("/admin/crashes")
    assert page.status_code == 200
    assert "TypeError" in page.text
    assert "#00 pc 0x2f4b3c" in page.text
    assert "Not decoded" in page.text
    group_link = page.text.split('href="/admin/crashes/', 1)[1].split('"', 1)[0]
    filtered = await client.get("/admin/crashes", params={"build": "foss", "days": 7})
    assert ">1<" in filtered.text

    detail = await client.get(f"/admin/crashes/{group_link}")
    assert detail.status_code == 200
    assert "Play 2" in detail.text
    assert "F-Droid 1" in detail.text
    assert "13: 3" in detail.text
    assert "&#34;build_id&#34;: &#34;b6f1c4e09a2d7f35&#34;" in detail.text
    missing = await client.get(
        f"/admin/crashes/{secrets.token_hex(16)[:8]}-0000-0000-0000-000000000000"
    )
    assert missing.status_code == 404


def test_downloads_summary_counts_the_last_30_days() -> None:
    text = (
        "date,release,file,downloads\n"
        "2026-10-10,v0.3.0,pesaclarity-play.apk,50\n"
        "2026-11-17,v0.3.0,pesaclarity-play.apk,80\n"
        "2026-11-17,v0.4.0,pesaclarity-play.apk,7\n"
        "2026-11-17,v0.4.0,pesaclarity-foss.apk,3\n"
        "bad,row,here,x\n"
    )
    summary = summarise(text)
    assert summary is not None
    # 80 - 50 for the old release (its total 30 days back), all 7 of the new one.
    assert summary.by_file == [("pesaclarity-play.apk", 37), ("pesaclarity-foss.apk", 3)]
    assert summary.total == 40
    assert summarise("date,release,file,downloads\n") is None
