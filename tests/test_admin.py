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
from ngome.admin.views import installs_for
from ngome.core.config import Settings
from ngome.counting.models import DAY, MONTH, CountTotal
from ngome.counting.suppress import Shown, derived, pair, shown_total, suppress, suppress_marked
from ngome.crashes.models import CrashReportRow
from tests.conftest import make_settings
from tests.soft_passkey import SoftPasskey
from tests.test_app_status import TEST_SEED

ORIGIN = "https://admin.test"
OTHER = "https://other.test"
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


async def enrol(
    client: httpx.AsyncClient, passkey: SoftPasskey, label: str = "Phone", origin: str = ORIGIN
) -> None:
    # The default origin is left out of the request, as a terminal would.
    request: dict[str, str] = {"label": label} | ({} if origin == ORIGIN else {"origin": origin})
    minted = await client.post("/v1/admin/passkey-enrolments", json=request, headers=ADMIN)
    assert minted.status_code == 201, minted.text
    url = minted.json()["url"]
    assert url.startswith(f"{origin}/admin/enrol/")
    token = url.rsplit("/", 1)[1]
    page = await client.get(f"/admin/enrol/{token}")
    assert "Add a passkey" in page.text
    here = {"Origin": origin}
    start = await client.post("/admin/enrol/options", json={"token": token}, headers=here)
    assert start.status_code == 200, start.text
    body = start.json()
    assert body["options"]["rp"]["id"] == passkey.rp_id
    finish = await client.post(
        "/admin/enrol/verify",
        json={
            "token": token,
            "challenge_id": body["challenge_id"],
            "credential": passkey.register(body["options"]),
        },
        headers=here,
    )
    assert finish.status_code == 200, finish.text
    client.cookies.clear()


async def sign_in(
    client: httpx.AsyncClient, passkey: SoftPasskey, origin: str = ORIGIN
) -> httpx.Response:
    start = await client.post("/admin/sign-in/options", headers={"Origin": origin})
    assert start.status_code == 200, start.text
    body = start.json()
    return await client.post(
        "/admin/sign-in/verify",
        json={"challenge_id": body["challenge_id"], "credential": passkey.sign_in(body["options"])},
        headers={"Origin": origin},
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


async def test_a_second_origin_has_its_own_passkeys(
    app: FastAPI, settings: Settings, client: httpx.AsyncClient
) -> None:
    app.state.settings = settings.model_copy(update={"admin_extra_origins": [OTHER]})
    first = SoftPasskey("admin.test", ORIGIN)
    await enrol(client, first)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=OTHER) as other:
        second = SoftPasskey("other.test", OTHER)
        await enrol(other, second, label="Mac", origin=OTHER)
        response = await sign_in(other, second, origin=OTHER)
        assert response.status_code == 200, response.text
        assert COOKIE in response.cookies
        other.cookies.clear()
        # A passkey works only on the host it was added on, whichever origin the page claims.
        assert (await sign_in(other, first, origin=OTHER)).status_code == 400
        start = (await other.post("/admin/sign-in/options", headers={"Origin": OTHER})).json()
        body = {
            "challenge_id": start["challenge_id"],
            "credential": first.sign_in(start["options"], origin=OTHER),
        }
        refused = await other.post("/admin/sign-in/verify", json=body, headers={"Origin": OTHER})
        assert refused.status_code == 400
    assert (await sign_in(client, second)).status_code == 400
    assert (await sign_in(client, first)).status_code == 200
    listed = await client.get("/v1/admin/passkeys", headers=ADMIN)
    assert [p["label"] for p in listed.json()] == ["Phone", "Mac"]


async def test_enrolment_links_open_only_on_the_dashboards_origins(
    app: FastAPI, settings: Settings, client: httpx.AsyncClient
) -> None:
    for origin in (OTHER, "https://evil.example"):
        minted = await client.post(
            "/v1/admin/passkey-enrolments", json={"label": "x", "origin": origin}, headers=ADMIN
        )
        assert minted.status_code == 422
    from_other = {"Origin": OTHER}
    assert (await client.post("/admin/sign-in/options", headers=from_other)).status_code == 403
    app.state.settings = settings.model_copy(update={"admin_extra_origins": [OTHER]})
    assert (await client.post("/admin/sign-in/options", headers=from_other)).status_code == 200


def test_extra_origins_need_the_main_one(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="admin_extra_origins needs admin_origin"):
        make_settings(tmp_path, admin_extra_origins=[OTHER])
    with pytest.raises(ValueError, match="admin_extra_origins"):
        make_settings(tmp_path, admin_origin=ORIGIN, admin_extra_origins=["other.test"])


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
    builds = detail.text.split(">Build</h3>", 1)[1].split("</table>", 1)[0]
    assert ">Play</td>" in builds
    assert '<td class="n">2</td>' in builds
    assert ">F-Droid</td>" in builds
    assert ">Android 13</td>" in detail.text
    assert "&#34;build_id&#34;: &#34;b6f1c4e09a2d7f35&#34;" in detail.text
    missing = await client.get(
        f"/admin/crashes/{secrets.token_hex(16)[:8]}-0000-0000-0000-000000000000"
    )
    assert missing.status_code == 404
    assert "No such crash group" in missing.text

    # The list's filters go with a group's link, and its page reads them.
    foss = await client.get("/admin/crashes", params={"build": "foss"})
    assert f'href="/admin/crashes/{group_link}?build=foss"' in foss.text
    only_foss = await client.get(f"/admin/crashes/{group_link}", params={"build": "foss"})
    assert ">Play</td>" not in only_foss.text.split(">Build</h3>", 1)[1].split("</table>", 1)[0]


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
    # The snapshot does not go back 60 days, so there is nothing to compare with.
    assert summary.previous_total is None


def test_downloads_summary_compares_with_the_30_days_before() -> None:
    text = (
        "date,release,file,downloads\n"
        "2026-09-01,v0.3.0,pesaclarity-play.apk,10\n"
        "2026-10-18,v0.3.0,pesaclarity-play.apk,50\n"
        "2026-11-17,v0.3.0,pesaclarity-play.apk,80\n"
    )
    summary = summarise(text)
    assert summary is not None
    assert summary.total == 30
    assert summary.previous_total == 40
    assert summary.files[0].previous == 40
    assert summarise("date,release,file,downloads\n") is None


def test_suppression_says_why_a_cell_is_hidden() -> None:
    shown = suppress_marked({"play": 2610, "foss": 403, "website": 396, "ios": 3})
    assert shown["ios"] == Shown(None, "small")
    # Website is not small: it is hidden so iPhone cannot be worked out from the total.
    assert shown["website"] == Shown(None, "secondary")
    assert shown["play"] == Shown(2610)
    assert suppress_marked({"a": 5, "b": 4, "c": 40})["c"] == Shown(40)


def test_sums_beside_a_table_cannot_give_a_hidden_cell_away() -> None:
    raw = {"0.6.0": 900, "0.5.2": 500, "0.5.1": 20, "0.4.0": 50, "0.3.0": 4}
    shown = suppress_marked(raw)
    assert shown["0.5.1"] == Shown(None, "secondary")
    # "Older" holds 0.4.0 (shown, 50) and 0.3.0 (hidden): 54 less 50 would be 0.3.0.
    assert derived(shown, raw, ["0.4.0", "0.3.0"]) == Shown(None, "secondary")
    # Holding both hidden cells, the sum gives neither away.
    assert derived(shown, raw, ["0.5.1", "0.3.0"]) == Shown(24)
    assert derived(shown, raw, ["0.3.0"]) == Shown(None, "small")
    # Two parts of a shown total: if one is hidden, the other would give it away.
    assert pair(3000, 4) == (Shown(None, "secondary"), Shown(None, "small"))
    assert pair(3000, 400) == (Shown(3000), Shown(400))


def test_installs_for_some_builds_follow_the_builds_suppression() -> None:
    cells = {"all": {"all": 3412}, "build": {"play": 2610, "foss": 403, "website": 396, "ios": 3}}
    assert installs_for(cells, None) == Shown(3412)
    assert installs_for(cells, ("ios",)) == Shown(None, "small")
    assert installs_for(cells, ("website",)) == Shown(None, "secondary")
    # Android is three builds, one of them hidden: shown, it would give iPhone away.
    assert installs_for(cells, ("play", "foss", "website")) == Shown(None, "secondary")
    assert installs_for(cells, ("play", "foss")) == Shown(3013)


async def test_pages_mark_hidden_cells_and_derived_sums(
    client: httpx.AsyncClient,
    signed_in: SoftPasskey,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    month = datetime.now(UTC).date().replace(day=1)
    previous = (month - timedelta(days=1)).replace(day=1)
    await add_totals(
        maker,
        MONTH,
        month,
        {
            "all": {"all": 1574},
            "build": {"play": 1200, "foss": 370, "ios": 4},
            # The newest release has 4: the stacked bar must not show "earlier" (1,570).
            "version": {
                "0.7.0": 4,
                "0.6.0": 900,
                "0.5.2": 500,
                "0.5.1": 20,
                "0.5.0": 60,
                "0.4.0": 50,
                "0.3.0": 40,
            },
        },
    )
    await add_totals(maker, MONTH, previous, {"all": {"all": 1000}, "version": {"0.6.0": 1000}})
    page = (await client.get("/admin")).text
    assert "hidden</span>" in page  # F-Droid hidden beside iPhone's 4
    assert ">370<" not in page
    assert "1,570" not in page
    assert ">20<" not in page  # 0.5.1, the next smallest version, is hidden too
    assert " style=" not in page
    assert "<style" not in page

    monthly = await client.get("/admin/monthly.csv")
    assert monthly.headers["content-disposition"].startswith("attachment;")
    rows = monthly.text.splitlines()
    assert rows[-1].endswith(",1574,<10,hidden")
    assert "1570" not in monthly.text

    csv_text = (await client.get("/admin/installs.csv", params={"dim": "build"})).text
    assert "iPhone,<10," in csv_text
    assert "F-Droid,hidden," in csv_text
    assert ",370," not in csv_text
    versions = (await client.get("/admin/adoption.csv")).text
    assert "0.7.0" in versions
    assert ",4" not in versions.replace(",40", "")


async def test_filters_are_checked_and_said_when_dropped(
    client: httpx.AsyncClient, signed_in: SoftPasskey
) -> None:
    page = await client.get("/admin/crashes", params={"days": "45", "build": "nokia"})
    assert page.status_code == 200
    assert "is not a choice for days" in page.text
    assert "is not a choice for build" in page.text
    assert "Reports, 30 days" in page.text.replace("REPORTS", "Reports")
    clash = await client.get("/admin/crashes", params={"build": "ios", "platform": "android"})
    assert "is not an Android build" in clash.text


async def test_crash_rate_uses_one_month_on_both_sides(
    app: FastAPI,
    client: httpx.AsyncClient,
    signed_in: SoftPasskey,
    maker: async_sessionmaker[AsyncSession],
) -> None:
    from tests.test_crash_reports import report  # noqa: PLC0415

    today = datetime.now(UTC).date()
    month = today.replace(day=1)
    await add_totals(maker, MONTH, month, {"all": {"all": 2000}})
    for _ in range(4):
        assert (await client.post("/v1/crash-reports", json=report())).status_code == 202
    # A report from before this month counts in a 30-day window but not in the rate.
    async with maker() as session:
        row = (await session.scalars(select(CrashReportRow))).first()
        assert row is not None
        session.add(
            CrashReportRow(
                group_id=row.group_id,
                received_on=month - timedelta(days=1),
                app="0.5.2",
                build_number=412,
                build="play",
                os="Android 13",
                cpu="arm64",
                error="TypeError",
                stack=row.stack,
            )
        )
        await session.commit()
    page = (await client.get("/admin/crashes")).text
    assert ">2.0<" in page  # 4 reports this month per 2,000 installs, times 1,000
    assert "a floor" in page


async def test_notices_and_learning_pages(
    app: FastAPI, client: httpx.AsyncClient, signed_in: SoftPasskey
) -> None:
    notices = await client.get("/admin/notices")
    assert notices.status_code == 200
    assert "No notices yet" in notices.text
    learning = await client.get("/admin/learning")
    assert learning.status_code == 200
    assert "No rounds have been recorded" in learning.text
    for path in ("/admin/notices", "/admin/learning", "/admin/installs.csv"):
        client.cookies.clear()
        assert (await client.get(path)).status_code == 303
