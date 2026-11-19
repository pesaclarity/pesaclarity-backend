"""Storing a crash report under its group, within the daily cap."""

import hashlib
from datetime import date, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.core.config import Settings
from ngome.crashes.models import CrashGroup, CrashGroupDay, CrashReportRow
from ngome.crashes.schemas import CrashReport
from ngome.db.upsert import insert_for

FINGERPRINT_FRAMES = 3


class DailyCapError(Exception):
    """Today's reports are at the cap."""


def fingerprint(report: CrashReport) -> str:
    """Error type, build id and the first frames. Offsets differ between builds, so until the
    decode job regroups by decoded frames, an obfuscated build's groups are per build."""
    parts = [report.error, report.build_id or "", *report.stack[:FINGERPRINT_FRAMES]]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def payload(row: CrashReportRow) -> dict[str, Any]:
    """The report as the phone sent it, in the schema's field order."""
    return {
        "format": 1,
        "app": row.app,
        "build_number": row.build_number,
        "build": row.build,
        "os": row.os,
        "cpu": row.cpu,
        "error": row.error,
        "build_id": row.build_id,
        "stack": list(row.stack),
    }


async def store(
    session: AsyncSession, settings: Settings, report: CrashReport, *, today: date
) -> CrashReportRow:
    received_today = await session.scalar(
        select(func.coalesce(func.sum(CrashGroupDay.n), 0)).where(CrashGroupDay.day == today)
    )
    if (received_today or 0) >= settings.crash_reports_max_per_day:
        raise DailyCapError

    insert = insert_for(session)
    print_ = fingerprint(report)
    await session.execute(
        insert(CrashGroup)
        .values(
            fingerprint=print_,
            error=report.error,
            frames=report.stack[:FINGERPRINT_FRAMES],
            first_seen=today,
            last_seen=today,
            reports=0,
        )
        .on_conflict_do_nothing(index_elements=["fingerprint"])
    )
    group = (
        await session.scalars(
            select(CrashGroup).where(CrashGroup.fingerprint == print_).with_for_update()
        )
    ).one()
    group.reports += 1
    group.first_seen = min(group.first_seen, today)
    group.last_seen = max(group.last_seen, today)
    await session.execute(
        insert(CrashGroupDay)
        .values(group_id=group.id, day=today, n=1)
        .on_conflict_do_update(index_elements=["group_id", "day"], set_={"n": CrashGroupDay.n + 1})
    )
    row = CrashReportRow(
        group_id=group.id,
        received_on=today,
        app=report.app,
        build_number=report.build_number,
        build=report.build,
        os=report.os,
        cpu=report.cpu,
        error=report.error,
        build_id=report.build_id,
        stack=list(report.stack),
    )
    session.add(row)
    await session.commit()
    return row


async def purge_crashes(
    session: AsyncSession, settings: Settings, *, today: date
) -> tuple[int, int]:
    """Reports after ``retention_crash_report_days``; groups (with their daily counts) a
    year after they were last seen. Returns ``(reports, groups)`` deleted."""
    report_cutoff = today - timedelta(days=settings.retention_crash_report_days)
    group_cutoff = today - timedelta(days=settings.retention_crash_group_days)
    reports = await session.execute(
        delete(CrashReportRow).where(CrashReportRow.received_on < report_cutoff)
    )
    old_groups = select(CrashGroup.id).where(CrashGroup.last_seen < group_cutoff)
    # SQLite does not enforce the cascade unless asked to, so delete the children first.
    await session.execute(delete(CrashReportRow).where(CrashReportRow.group_id.in_(old_groups)))
    await session.execute(delete(CrashGroupDay).where(CrashGroupDay.group_id.in_(old_groups)))
    groups = await session.execute(delete(CrashGroup).where(CrashGroup.last_seen < group_cutoff))
    await session.commit()
    return (
        cast(CursorResult[Any], reports).rowcount,
        cast(CursorResult[Any], groups).rowcount,
    )
