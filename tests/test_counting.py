"""Counting installs: once a day and once a month per token, digests only, totals that name no
one, the flood ceiling, and deletion when a period closes (ADR 0024)."""

import secrets
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.core.config import Settings
from ngome.counting import service
from ngome.counting.models import DAY, MONTH, CountFlood, CountKey, CountSeen, CountTotal
from ngome.counting.retention import purge_counting
from ngome.counting.service import FloodGate, Outcome, record_check_in
from tests.conftest import make_settings
from tests.test_app_status import ADMIN, TEST_SEED, create

NOW = datetime(2026, 11, 18, 9, 30, tzinfo=UTC)


def token() -> str:
    """A token as the app makes it: 128 random bits, base64url without padding."""
    return secrets.token_urlsafe(16)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(
        tmp_path,
        admin_token=SecretStr("test-admin-token-" + "z" * 32),
        app_status_signing_seed=SecretStr(TEST_SEED),
    )


@pytest.fixture
def maker(app: FastAPI) -> async_sessionmaker[AsyncSession]:
    sessions: async_sessionmaker[AsyncSession] = app.state.sessionmaker
    return sessions


async def totals(
    maker: async_sessionmaker[AsyncSession], kind: str, period: date, dimension: str
) -> dict[str, int]:
    async with maker() as session:
        rows = await session.execute(
            select(CountTotal.value, CountTotal.n).where(
                CountTotal.kind == kind,
                CountTotal.period == period,
                CountTotal.dimension == dimension,
            )
        )
        return dict(rows.all())


async def check_in(
    maker: async_sessionmaker[AsyncSession],
    settings: Settings,
    gate: FloodGate,
    value: str | None,
    *,
    now: datetime = NOW,
    version: str = "0.5.2",
    build: str = "play",
    country: str | None = None,
) -> Outcome:
    async with maker() as session:
        return await record_check_in(
            session,
            settings,
            gate,
            token=value,
            build=build,
            version=version,
            country=country,
            now=now,
        )


def test_token_format() -> None:
    assert service.is_valid_token(token())
    assert len(token()) == 22
    for bad in (None, "", "short", "a" * 23, "a" * 21 + "=", "a" * 21 + "/", "a" * 21 + " "):
        assert not service.is_valid_token(bad)


def test_flood_gate_resets_each_hour() -> None:
    gate = FloodGate(ceiling=2)
    gate.note_new(NOW)
    gate.note_new(NOW)
    assert not gate.allows(NOW)
    assert gate.allows(NOW + timedelta(hours=1))


async def test_counts_a_token_once_a_day_and_once_a_month(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    gate = FloodGate(100)
    phone = token()
    assert await check_in(maker, settings, gate, phone) is Outcome.COUNTED
    assert await check_in(maker, settings, gate, phone) is Outcome.SEEN
    assert await check_in(maker, settings, gate, token(), build="foss") is Outcome.COUNTED

    today, month = NOW.date(), NOW.date().replace(day=1)
    assert await totals(maker, DAY, today, "all") == {"all": 2}
    assert await totals(maker, MONTH, month, "all") == {"all": 2}
    assert await totals(maker, MONTH, month, "build") == {"play": 1, "foss": 1}

    # The next day the phone counts again for that day, not again for the month, and its
    # month total keeps the version it had when first seen.
    tomorrow = NOW + timedelta(days=1)
    assert await check_in(maker, settings, gate, phone, now=tomorrow, version="0.5.3") is (
        Outcome.COUNTED
    )
    assert await totals(maker, DAY, tomorrow.date(), "version") == {"0.5.3": 1}
    assert await totals(maker, MONTH, month, "version") == {"0.5.2": 2}
    assert await totals(maker, MONTH, month, "all") == {"all": 2}


async def test_stores_digests_never_the_token(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    phone = token()
    await check_in(maker, settings, FloodGate(100), phone, country="KE")
    async with maker() as session:
        seen = list(await session.scalars(select(CountSeen)))
        keys = list(await session.scalars(select(CountKey)))
        values = list(await session.scalars(select(CountTotal.value)))
    assert len(seen) == 2
    assert all(len(row.digest) == 16 for row in seen)
    # A day digest cannot be matched to the month's: each period has its own key.
    assert seen[0].digest != seen[1].digest
    assert len({k.key for k in keys}) == 2
    assert phone.encode() not in b"".join(row.digest for row in seen)
    assert phone not in values


async def test_country_only_for_the_month(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    await check_in(maker, settings, FloodGate(100), token(), country="KE")
    await check_in(maker, settings, FloodGate(100), token(), country=None)
    assert await totals(maker, MONTH, NOW.date().replace(day=1), "country") == {"KE": 1}
    assert await totals(maker, DAY, NOW.date(), "country") == {}


async def test_malformed_tokens_and_counting_off_are_ignored(
    maker: async_sessionmaker[AsyncSession], settings: Settings, tmp_path: Path
) -> None:
    gate = FloodGate(100)
    assert await check_in(maker, settings, gate, "not a token") is Outcome.IGNORED
    assert await check_in(maker, settings, gate, None) is Outcome.IGNORED
    off = make_settings(tmp_path, counting_enabled=False)
    assert await check_in(maker, off, gate, token()) is Outcome.IGNORED
    async with maker() as session:
        assert list(await session.scalars(select(CountSeen))) == []


async def test_flood_ceiling_marks_the_hour(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    gate = FloodGate(ceiling=2)
    outcomes = [await check_in(maker, settings, gate, token()) for _ in range(4)]
    assert outcomes == [Outcome.COUNTED, Outcome.COUNTED, Outcome.FLOOD, Outcome.FLOOD]
    async with maker() as session:
        flood = (await session.scalars(select(CountFlood))).one()
    assert flood.dropped == 2
    assert flood.hour == NOW.replace(minute=0, second=0, microsecond=0)
    assert await totals(maker, MONTH, NOW.date().replace(day=1), "all") == {"all": 2}


async def test_row_cap_per_period(maker: async_sessionmaker[AsyncSession], tmp_path: Path) -> None:
    capped = make_settings(tmp_path, counting_max_per_period=1)
    gate = FloodGate(100)
    assert await check_in(maker, capped, gate, token()) is Outcome.COUNTED
    assert await check_in(maker, capped, gate, token()) is Outcome.FULL
    assert await totals(maker, DAY, NOW.date(), "all") == {"all": 1}


async def test_purge_deletes_closed_periods(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    gate = FloodGate(100)
    october = datetime(2026, 10, 31, 12, tzinfo=UTC)
    await check_in(maker, settings, gate, token(), now=october)
    await check_in(maker, settings, gate, token(), now=october + timedelta(days=1))

    async def left() -> set[tuple[str, date]]:
        async with maker() as session:
            seen = {(r.kind, r.period) for r in await session.scalars(select(CountSeen))}
            keys = {(k.kind, k.period) for k in await session.scalars(select(CountKey))}
        assert seen == keys
        return seen

    # 1 November: yesterday's day set stays, and October's month set has a day's grace.
    async with maker() as session:
        await purge_counting(session, settings, now=datetime(2026, 11, 1, 3, tzinfo=UTC))
    assert await left() == {
        (DAY, date(2026, 10, 31)),
        (DAY, date(2026, 11, 1)),
        (MONTH, date(2026, 10, 1)),
        (MONTH, date(2026, 11, 1)),
    }
    # 2 November: 31 October's day set and October's month set go.
    async with maker() as session:
        await purge_counting(session, settings, now=datetime(2026, 11, 2, 3, tzinfo=UTC))
    assert await left() == {(DAY, date(2026, 11, 1)), (MONTH, date(2026, 11, 1))}
    # Totals stay.
    assert await totals(maker, MONTH, date(2026, 10, 1), "all") == {"all": 1}

    # Daily totals go after 13 months; monthly totals are kept.
    async with maker() as session:
        await purge_counting(session, settings, now=datetime(2027, 12, 15, tzinfo=UTC))
    assert await totals(maker, DAY, date(2026, 10, 31), "all") == {}
    assert await totals(maker, MONTH, date(2026, 10, 1), "all") == {"all": 1}


async def test_app_status_counts_the_header_and_notice_reach(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    notice = await create(
        client,
        kind="info",
        title="Equity changed its messages",
        body="Read them again.",
        latest_version=None,
    )
    params = {"version": "0.3.0", "build": "foss", "platform": "android"}
    phone = token()
    for _ in range(2):
        response = await client.get("/v1/app-status", params=params, headers={"Count-Token": phone})
        assert response.status_code == 200
    # A bad token is ignored and the check-in still answered.
    bad = await client.get("/v1/app-status", params=params, headers={"Count-Token": "x" * 5})
    assert bad.status_code == 200
    plain = await client.get("/v1/app-status", params=params)
    assert plain.status_code == 200

    today = datetime.now(UTC).date()
    assert await totals(maker, DAY, today, "build") == {"foss": 1}
    assert await totals(maker, MONTH, today.replace(day=1), "version") == {"0.3.0": 1}
    # Country lookup is off by default: no country totals at all.
    assert await totals(maker, MONTH, today.replace(day=1), "country") == {}
    reach = await client.get("/v1/admin/app-notices", headers=ADMIN)
    assert reach.status_code == 200
    from ngome.counting.models import NoticeReach  # noqa: PLC0415

    async with maker() as session:
        row = (await session.scalars(select(NoticeReach))).one()
    assert str(row.notice_id) == notice["id"]
    assert row.n == 4


async def test_country_comes_from_the_lookup(
    app: FastAPI, client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    class FakeLookup:
        def __init__(self) -> None:
            self.addresses: list[str | None] = []

        def country(self, address: str | None) -> str:
            self.addresses.append(address)
            return "KE"

    lookup = FakeLookup()
    app.state.country_lookup = lookup
    params = {"version": "0.3.0", "build": "play", "platform": "android"}
    await client.get("/v1/app-status", params=params, headers={"Count-Token": token()})
    today = datetime.now(UTC).date()
    assert await totals(maker, MONTH, today.replace(day=1), "country") == {"KE": 1}
    assert lookup.addresses == ["127.0.0.1"]


async def test_the_token_is_never_logged(
    client: httpx.AsyncClient, capsys: pytest.CaptureFixture[str]
) -> None:
    phone = token()
    params = {"version": "0.3.0", "build": "play", "platform": "android"}
    await client.get("/v1/app-status", params=params, headers={"Count-Token": phone})
    out = capsys.readouterr()
    assert phone not in out.out + out.err
    assert "/v1/app-status" in out.out + out.err


def test_country_lookup_needs_a_database(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="country_db_path"):
        make_settings(tmp_path, country_lookup_enabled=True)


def test_mmdb_lookup_keeps_only_global_addresses() -> None:
    from ngome.counting.country import UNKNOWN, MmdbCountryLookup, country_name  # noqa: PLC0415

    class Reader:
        def get(self, ip: object) -> object:
            return {"country": {"iso_code": "ke"}}

    lookup = MmdbCountryLookup.__new__(MmdbCountryLookup)
    lookup._reader = Reader()  # type: ignore[assignment]
    assert lookup.country("197.248.0.1") == "KE"
    assert lookup.country("10.0.0.1") == UNKNOWN
    assert lookup.country("not an address") == UNKNOWN
    assert lookup.country(None) == UNKNOWN
    assert country_name("KE") == "Kenya"
    assert country_name("GB") == "United Kingdom"
    assert country_name(UNKNOWN) == "Unknown"
