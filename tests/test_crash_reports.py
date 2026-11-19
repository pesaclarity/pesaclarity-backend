"""Crash reports: only the allow-listed schema is stored, nothing that looks like personal data
gets through, and the size cap, daily cap, grouping and retention hold (ADR 0024)."""

import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ngome.core.config import Settings
from ngome.crashes.models import CrashGroup, CrashGroupDay, CrashReportRow
from ngome.crashes.schemas import CrashReport
from ngome.crashes.service import fingerprint, purge_crashes, store
from tests.conftest import make_settings


def report(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "format": 1,
        "app": "0.5.2",
        "build_number": 412,
        "build": "play",
        "os": "Android 13",
        "cpu": "arm64",
        "error": "TypeError",
        "build_id": "b6f1c4e09a2d7f35",
        "stack": ["#00 pc 0x2f4b3c", "#01 pc 0x2f49e0", "#02 pc 0x1c07a8", "#03 pc 0x1bff14"],
    }
    body.update(changes)
    return body


@pytest.fixture
def maker(app: FastAPI) -> async_sessionmaker[AsyncSession]:
    sessions: async_sessionmaker[AsyncSession] = app.state.sessionmaker
    return sessions


async def count(maker: async_sessionmaker[AsyncSession], model: type[Any]) -> int:
    async with maker() as session:
        return await session.scalar(select(func.count()).select_from(model)) or 0


async def test_stores_a_report_and_sets_no_cookie(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    response = await client.post("/v1/crash-reports", json=report())
    assert response.status_code == 202, response.text
    assert "set-cookie" not in response.headers
    async with maker() as session:
        row = (await session.scalars(select(CrashReportRow))).one()
        group = (await session.scalars(select(CrashGroup))).one()
    assert row.stack[0] == "#00 pc 0x2f4b3c"
    assert row.group_id == group.id
    assert group.reports == 1


def test_unobfuscated_frames_from_our_code_and_the_sdk() -> None:
    CrashReport.model_validate(
        report(
            build_id=None,
            stack=[
                "#00 InsightsController._monthTotals "
                "(package:pesaclarity/src/features/insights/insights_controller.dart:212:7)",
                "#01 <anonymous closure> (package:riverpod/src/core/element.dart:301)",
                "#02 _RootZone.runUnary (dart:async/zone.dart:1849:19)",
            ],
        )
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"extra": "field"},
        {"message": "Paid Ksh 1,250.00 to Wanjiku"},
        {"error": "Null check operator used on a null value"},
        {"error": "Other: KES 5,000"},
        {"os": "Android 13 (build fingerprint samsung/a52)"},
        {"cpu": "Snapdragon 720G"},
        {"app": "0.5.2 Wanjiku"},
        {"build": "beta"},
        {"format": 2},
        {"build_number": "412"},
        {"build_id": "not-hex"},
        {"stack": ["#00 pc 0x2f4b3c Paid KES 500"]},
        {"stack": ["#00 pc 0x2f4b3c", "+254700000000"]},
        {"stack": ["wanjiku@example.com"]},
        {"stack": ["#00 open (/data/user/0/com.pesaclarity.app/files/ledger.db)"]},
        {"stack": ["#00 send (file:///data/user/0/com.pesaclarity.app/x.dart:1)"]},
        {"stack": ["#00 Paid Ksh 500 to Wanjiku (dart:core)"]},
        {"stack": ["#00 MPESA (package:pesaclarity/RKT4ABC12 Confirmed Ksh 300.dart:1)"]},
        {"stack": [f"#{i:02d} pc 0x1" for i in range(65)]},
        {"time": "2026-11-18T09:30:00Z"},
        {"locale": "en_KE"},
        {"device": "SM-A525F"},
    ],
)
async def test_refuses_anything_but_the_schema(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession], changes: dict[str, Any]
) -> None:
    response = await client.post("/v1/crash-reports", json=report(**changes))
    assert response.status_code == 422
    # The refusal does not echo the body.
    for value in changes.values():
        assert json.dumps(value) not in response.text
    assert await count(maker, CrashReportRow) == 0


async def test_refuses_more_than_16_kb(client: httpx.AsyncClient) -> None:
    body = json.dumps(report()).encode() + b" " * (16 * 1024)
    response = await client.post(
        "/v1/crash-reports", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413


async def test_same_error_and_frames_share_a_group(
    client: httpx.AsyncClient, maker: async_sessionmaker[AsyncSession]
) -> None:
    for _ in range(3):
        assert (await client.post("/v1/crash-reports", json=report())).status_code == 202
    other = report(error="StateError")
    assert (await client.post("/v1/crash-reports", json=other)).status_code == 202
    assert await count(maker, CrashGroup) == 2
    assert await count(maker, CrashReportRow) == 4
    async with maker() as session:
        days = list(await session.scalars(select(CrashGroupDay.n).order_by(CrashGroupDay.n)))
    assert days == [1, 3]


def test_fingerprint_uses_error_build_and_first_three_frames() -> None:
    base = CrashReport.model_validate(report())
    later_frames = CrashReport.model_validate(report(stack=[*report()["stack"][:3], "#03 pc 0x9"]))
    assert fingerprint(base) == fingerprint(later_frames)
    assert fingerprint(base) != fingerprint(CrashReport.model_validate(report(error="Other")))


async def test_daily_cap(
    maker: async_sessionmaker[AsyncSession], app: FastAPI, tmp_path: Path
) -> None:
    capped = make_settings(tmp_path, crash_reports_max_per_day=2)
    app.state.settings = capped
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        codes = [
            (await client.post("/v1/crash-reports", json=report())).status_code for _ in range(3)
        ]
    assert codes == [202, 202, 429]


async def test_off_returns_404(app: FastAPI, tmp_path: Path) -> None:
    app.state.settings = make_settings(tmp_path, crash_reports_enabled=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.post("/v1/crash-reports", json=report())).status_code == 404


async def test_purge_keeps_groups_after_their_reports(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    start = date(2026, 8, 1)
    async with maker() as session:
        await store(session, settings, CrashReport.model_validate(report()), today=start)
        await store(
            session,
            settings,
            CrashReport.model_validate(report(error="RangeError")),
            today=start + timedelta(days=80),
        )
    async with maker() as session:
        assert await purge_crashes(session, settings, today=start + timedelta(days=91)) == (1, 0)
    assert await count(maker, CrashReportRow) == 1
    assert await count(maker, CrashGroup) == 2
    async with maker() as session:
        reports, groups = await purge_crashes(session, settings, today=start + timedelta(days=366))
    assert (reports, groups) == (1, 1)
    assert await count(maker, CrashGroup) == 1
    assert await count(maker, CrashGroupDay) == 1


def test_strict_types() -> None:
    with pytest.raises(ValidationError):
        CrashReport.model_validate_json(json.dumps(report(build_number=412.0)))
