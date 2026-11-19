"""The admin dashboard: off until configured, its headers, and what its pages show, with
small counts hidden (ADR 0024). Sign-in itself is tested in test_admin_sign_in.py."""

import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.admin.downloads import summarise
from ngome.admin.views import installs_for, short_day
from ngome.core.config import Settings
from ngome.counting.models import DAY, MONTH, CountTotal
from ngome.counting.suppress import Shown, derived, pair, shown_total, suppress, suppress_marked
from ngome.crashes.models import CrashReportRow
from tests.admin_flow import (  # noqa: F401 - totp_clock is a fixture
    ADMIN,
    ADMIN_TOKEN,
    ORIGIN,
    Owner,
    admin_settings,
    first_sign_in,
    totp_clock,
)
from tests.conftest import FakeMail, make_settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return admin_settings(tmp_path)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=ORIGIN) as c:
        yield c


@pytest.fixture
def maker(app: FastAPI) -> async_sessionmaker[AsyncSession]:
    sessions: async_sessionmaker[AsyncSession] = app.state.sessionmaker
    return sessions


@pytest.fixture
async def signed_in(client: httpx.AsyncClient, mail: FakeMail) -> Owner:
    return await first_sign_in(client, mail)


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
        assert (await client.get("/favicon.ico")).status_code == 404
        made = await client.post("/v1/admin/starter-user", json={"username": "x"}, headers=ADMIN)
        assert made.status_code == 404


async def test_pages_need_a_sign_in(client: httpx.AsyncClient) -> None:
    for path in ("/admin", "/admin/installs", "/admin/crashes"):
        response = await client.get(path)
        assert response.status_code == 303
        assert response.headers["location"] == "/admin/sign-in"
    page = await client.get("/admin/sign-in")
    assert page.status_code == 200
    assert "Not set up yet" in page.text
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


async def test_favicon_is_the_brand_mark_and_may_be_cached(client: httpx.AsyncClient) -> None:
    svg = await client.get("/admin/static/favicon.svg")
    assert svg.status_code == 200
    assert svg.headers["content-type"].startswith("image/svg+xml")
    assert 'fill="#C8102E"' in svg.text
    ico = await client.get("/admin/static/favicon.ico")
    assert ico.status_code == 200
    assert ico.content[:4] == b"\x00\x00\x01\x00"  # an ICO file's header
    # Browsers ask the site root whatever the page links to: the same file, no redirect.
    root = await client.get("/favicon.ico")
    assert root.status_code == 200
    assert root.headers["content-type"] == "image/vnd.microsoft.icon"
    assert root.content == ico.content
    for response in (svg, ico, root):
        assert response.headers["cache-control"] == "public, max-age=604800"
    # Every page links both; nothing else under /admin is cached.
    page = await client.get("/admin/sign-in")
    assert '<link rel="icon" href="/admin/static/favicon.ico" sizes="32x32">' in page.text
    assert '<link rel="icon" href="/admin/static/favicon.svg" type="image/svg+xml">' in page.text
    assert page.headers["cache-control"] == "no-store"
    # The API is untouched.
    health = await client.get("/health")
    assert health.status_code == 200
    assert "cache-control" not in health.headers


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
    signed_in: Owner,
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
                f"{yesterday - timedelta(days=45)},v0.4.0,pesaclarity-play.apk,100\n"
                f"{yesterday},v0.4.0,pesaclarity-play.apk,160\n"
                f"{yesterday},v0.5.0,pesaclarity-play.apk,40\n"
                f"{yesterday},v0.5.0,pesaclarity-foss.apk,12\n"
                f"{yesterday},screenshots,phone-1.png,900\n"
                f"{yesterday},screenshots-main,manifest.json,500\n"
                # Today's snapshot is newer than the page's day, so it is left out.
                f"{today},v0.5.0,pesaclarity-foss.apk,5000\n"
            )

    app.state.downloads_source = Csv()
    page = (await client.get("/admin")).text
    # Only app files count: 60 + 40 + 12, never the screenshots or their manifest.
    assert ">112<" in page
    assert "phone-1.png" not in page
    assert "manifest.json" not in page
    # One date for the page: counts close at the end of yesterday (UTC), and downloads are
    # cut to the same day, so neither the header nor the downloads card names another.
    assert f"Up to {short_day(yesterday)} (UTC)" in page
    assert page.lower().count("up to ") == 1
    assert f" to {short_day(today)}" not in page
    assert "5,0" not in page
    assert 'class="card kpi lead"' in page  # the red lead card, now there is a figure
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
    signed_in: Owner,
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


async def test_crash_pages(app: FastAPI, client: httpx.AsyncClient, signed_in: Owner) -> None:
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


def test_downloads_count_only_app_files() -> None:
    text = (
        "date,release,file,downloads\n"
        "2026-09-01,v0.3.0,pesaclarity-play.apk,10\n"
        "2026-09-01,screenshots,phone-1.png,5\n"
        "2026-10-18,v0.3.0,pesaclarity-play.apk,50\n"
        "2026-10-18,screenshots,phone-1.png,300\n"
        "2026-11-17,v0.3.0,pesaclarity-play.apk,80\n"
        "2026-11-17,v0.3.0,PesaClarity.IPA,4\n"
        "2026-11-17,screenshots,phone-1.png,700\n"
        "2026-11-17,screenshots-main,manifest.json,90\n"
    )
    summary = summarise(text)
    assert summary is not None
    assert summary.by_file == [("pesaclarity-play.apk", 30), ("PesaClarity.IPA", 4)]
    assert summary.total == 34
    assert summary.previous_total == 40  # the PNG's 295 the month before is not in it
    # A snapshot of only other files still has a day; it just has no app downloads.
    only_pictures = summarise("date,release,file,downloads\n2026-11-17,screenshots,a.png,9\n")
    assert only_pictures is not None
    assert (only_pictures.as_of.isoformat(), only_pictures.total) == ("2026-11-17", 0)
    assert only_pictures.files == []


async def test_lead_card_is_neutral_until_there_is_a_figure(
    client: httpx.AsyncClient, signed_in: Owner
) -> None:
    page = (await client.get("/admin")).text
    tiles = page.split('<div class="grid kpis">', 1)[1].split('<div class="grid g21 mt">', 1)[0]
    # Nothing counted: the lead tile is on the neutral surface with its explanation as text,
    # and no tile shows a big placeholder word (or a dash) where a figure would go.
    assert "kpi lead" not in tiles
    assert tiles.count('class="card kpi pending"') == 3  # installs, daily, crash rate
    assert "No figure yet. It shows once 10 or more phones have checked in" in tiles
    assert "Shows from the first day with 10 or more." in tiles
    assert "Soon" not in tiles
    assert "Counting has not started" not in tiles
    assert "\N{EM DASH}" not in tiles
    assert "\N{EN DASH}" not in tiles


async def test_overview_lists_show_five_and_count_the_rest(
    client: httpx.AsyncClient, signed_in: Owner, maker: async_sessionmaker[AsyncSession]
) -> None:
    from tests.test_crash_reports import report  # noqa: PLC0415

    for i in range(7):
        sent = await client.post("/v1/crash-reports", json=report(build_id=f"b6f1c4e09a2d7f3{i}"))
        assert sent.status_code == 202
    month = datetime.now(UTC).date().replace(day=1)
    versions = {f"0.{i}.0": 100 + i for i in range(8)}
    await add_totals(maker, MONTH, month, {"all": {"all": 828}, "version": versions})
    page = (await client.get("/admin")).text
    crashes = page.split('id="crash-h"', 1)[1].split("</section>", 1)[0]
    assert crashes.count('<a class="row"') == 5
    assert "See all crash groups (7)" in crashes
    assert "See all versions (8)" in page


async def test_downloads_page_searches_sorts_and_hides_zeros(
    client: httpx.AsyncClient, signed_in: Owner, app: FastAPI
) -> None:
    yesterday = datetime.now(UTC).date() - timedelta(days=1)
    start = yesterday - timedelta(days=30)
    earlier = start - timedelta(days=30)

    class Csv:
        async def csv_text(self) -> str:
            rows = [
                (earlier, "v0.4.0", "pesaclarity-play.apk", 0),
                (start, "v0.4.0", "pesaclarity-play.apk", 100),
                (yesterday, "v0.4.0", "pesaclarity-play.apk", 130),
                (start, "v0.4.0", "pesaclarity-foss.apk", 10),
                (yesterday, "v0.4.0", "pesaclarity-foss.apk", 90),
                (yesterday, "v0.5.0", "pesaclarity.ipa", 7),
                (start, "v0.3.0", "pesaclarity-old.apk", 4),
                (yesterday, "v0.3.0", "pesaclarity-old.apk", 4),
                (yesterday, "screenshots", "phone-1.png", 900),
                (yesterday, "screenshots-main", "manifest.json", 500),
            ]
            return "date,release,file,downloads\n" + "".join(
                f"{d},{r},{f},{n}\n" for d, r, f, n in rows
            )

    app.state.downloads_source = Csv()

    def files(html: str) -> list[str]:
        table = html.split('<table class="sticky-head dtable">', 1)[1].split("</table>", 1)[0]
        return [cell.split("<", 1)[0] for cell in table.split('<td class="mono">')[1:]]

    page = (await client.get("/admin/downloads")).text
    assert files(page) == ["pesaclarity-foss.apk", "pesaclarity-play.apk", "pesaclarity.ipa"]
    assert "png" not in page
    assert "manifest.json" not in page
    assert "117 downloads in all" in page
    assert "Show 0s (1)" in page

    by_name = (await client.get("/admin/downloads", params={"sort": "name"})).text
    assert files(by_name) == ["pesaclarity-foss.apk", "pesaclarity-play.apk", "pesaclarity.ipa"]
    by_change = (await client.get("/admin/downloads", params={"sort": "change"})).text
    # Biggest rise first: foss 10 -> 80, the iPhone file 0 -> 7, play 100 -> 30.
    assert files(by_change) == ["pesaclarity-foss.apk", "pesaclarity.ipa", "pesaclarity-play.apk"]

    found = (await client.get("/admin/downloads", params={"q": "PLAY"})).text
    assert files(found) == ["pesaclarity-play.apk"]
    missing = (await client.get("/admin/downloads", params={"q": "<b>x"})).text
    assert "No app file matches “&lt;b&gt;x”" in missing

    zeros = (await client.get("/admin/downloads", params={"zeros": "1"})).text
    assert "pesaclarity-old.apk" in files(zeros)
    assert 'aria-pressed="true"' in zeros


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
    signed_in: Owner,
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
    client: httpx.AsyncClient, signed_in: Owner
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
    signed_in: Owner,
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
    app: FastAPI, client: httpx.AsyncClient, signed_in: Owner
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


def test_extra_origins_need_the_main_one(tmp_path: Path) -> None:
    other = "https://other.test"
    with pytest.raises(ValueError, match="admin_extra_origins needs admin_origin"):
        make_settings(tmp_path, admin_extra_origins=[other])
    with pytest.raises(ValueError, match="admin_extra_origins"):
        make_settings(tmp_path, admin_origin=ORIGIN, admin_extra_origins=["other.test"])
