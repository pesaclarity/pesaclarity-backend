"""What each dashboard page shows, read from the counts and crash tables.

Install counts under 10 are hidden here, on display (``ngome.counting.suppress``); the
stored totals stay exact. Crash report counts are counts of reports, not of people, and are
shown as they are.
"""

import json
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta

from markupsafe import Markup
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.admin.charts import line_chart, sparkline
from ngome.admin.downloads import Downloads
from ngome.appstatus.models import AppNotice
from ngome.appstatus.versions import Version
from ngome.core.config import Settings
from ngome.counting.country import UNKNOWN, country_name
from ngome.counting.models import DAY, MONTH, CountFlood, CountTotal, NoticeReach
from ngome.counting.service import ALL, month_of
from ngome.counting.suppress import THRESHOLD, shown_total, suppress
from ngome.crashes.models import CrashGroup, CrashGroupDay, CrashReportRow
from ngome.crashes.service import payload
from ngome.fl.config import FLSettings

BUILD_NAMES = {"play": "Play", "foss": "F-Droid", "website": "Website APK", "ios": "iPhone"}
TOP_VERSIONS = 5
NEW_GROUP_DAYS = 2


def short_day(day: date) -> str:
    return f"{day.day} {day:%b}"


def month_name(month: date) -> str:
    return f"{month:%B %Y}"


def number(n: int | None) -> str:
    return "<10" if n is None else f"{n:,}"


@dataclass(frozen=True, slots=True)
class Bar:
    label: str
    n: int | None  # None: hidden as "<10"
    width: int  # percent of the widest shown bar, 3 to 100
    share: str
    lead: bool = False
    mono: bool = False


def bars(cells: list[tuple[str, int]], *, total: int | None = None) -> list[Bar]:
    """Rows for a bar table, in the given order, with small cells hidden."""
    shown = suppress(dict(cells))
    widest = max((v for v in shown.values() if v is not None), default=0)
    total = total if total is not None else sum(n for _, n in cells)
    rows = []
    lead_done = False
    for label, _ in cells:
        n = shown[label]
        if n is None or widest == 0:
            rows.append(Bar(label, None, 3, ""))
            continue
        share = n / total * 100 if total else 0
        rows.append(
            Bar(
                label,
                n,
                max(3, round(n / widest * 100)),
                "<1%" if share < 0.5 else f"{share:.0f}%",
                lead=not lead_done and n == widest,
            )
        )
        lead_done = lead_done or n == widest
    return rows


async def _totals(session: AsyncSession, kind: str, period: date, dimension: str) -> dict[str, int]:
    rows = await session.execute(
        select(CountTotal.value, CountTotal.n).where(
            CountTotal.kind == kind, CountTotal.period == period, CountTotal.dimension == dimension
        )
    )
    return dict(rows.all())


async def _all(session: AsyncSession, kind: str, period: date) -> int:
    return (await _totals(session, kind, period, ALL)).get(ALL, 0)


async def months(session: AsyncSession, today: date) -> list[date]:
    stored = await session.scalars(
        select(CountTotal.period).where(CountTotal.kind == MONTH).distinct()
    )
    return sorted({month_of(today), *stored}, reverse=True)


def pick_month(raw: str | None, available: list[date]) -> date:
    if raw:
        try:
            wanted = date.fromisoformat(f"{raw}-01")
        except ValueError:
            wanted = None
        if wanted in available:
            return wanted
    return available[0]


def _previous_month(month: date) -> date:
    return month_of(month - timedelta(days=1))


@dataclass
class Tile:
    label: str
    value: str
    delta: str = ""


@dataclass
class NoticeRow:
    title: str
    tag: str
    must_update: bool
    reach: str
    since: str


@dataclass
class Overview:
    month: date
    months: list[date]
    as_of: str
    tiles: list[Tile]
    daily_chart: Markup
    versions: list[Bar]
    builds: list[Bar]
    notices: list[NoticeRow]
    downloads: Downloads | None
    fl_min_cohort: int
    country_on: bool


async def _daily_series(session: AsyncSession, first: date, last: date) -> list[int]:
    rows = await session.execute(
        select(CountTotal.period, CountTotal.n).where(
            CountTotal.kind == DAY,
            CountTotal.dimension == ALL,
            CountTotal.value == ALL,
            CountTotal.period >= first,
            CountTotal.period <= last,
        )
    )
    by_day = dict(rows.all())
    span = (last - first).days + 1
    return [by_day.get(first + timedelta(days=i), 0) for i in range(span)]


def _version_cells(totals: dict[str, int]) -> list[tuple[str, int]]:
    def key(text: str) -> Version:
        try:
            return Version(text)
        except ValueError:
            return Version("0.0.0")

    ordered = sorted(totals, key=key, reverse=True)
    cells = [(v, totals[v]) for v in ordered[:TOP_VERSIONS]]
    rest = sum(totals[v] for v in ordered[TOP_VERSIONS:])
    if rest:
        cells.append(("Older", rest))
    return cells


async def crash_summary(session: AsyncSession, since: date) -> tuple[int, int, int]:
    """Reports, groups and new groups since ``since``."""
    reports = await session.scalar(
        select(func.count()).select_from(CrashReportRow).where(CrashReportRow.received_on >= since)
    )
    groups = await session.scalar(
        select(func.count(func.distinct(CrashReportRow.group_id))).where(
            CrashReportRow.received_on >= since
        )
    )
    new = await session.scalar(
        select(func.count()).select_from(CrashGroup).where(CrashGroup.first_seen >= since)
    )
    return reports or 0, groups or 0, new or 0


async def overview(
    session: AsyncSession,
    settings: Settings,
    *,
    today: date,
    month_param: str | None,
    downloads: Downloads | None,
) -> Overview:
    available = await months(session, today)
    month = pick_month(month_param, available)
    previous = _previous_month(month)
    mai = await _all(session, MONTH, month)
    before = await _all(session, MONTH, previous)
    delta = f"{previous:%B}: {number(shown_total(before))}"
    if shown_total(before) is not None and shown_total(mai) is not None and before:
        delta += f" · {(mai - before) / before * 100:+.0f}%"

    yesterday = today - timedelta(days=1)
    last_week = await _daily_series(session, yesterday - timedelta(days=6), yesterday)
    average = round(sum(last_week) / len(last_week))
    reports, groups, new = await crash_summary(session, today - timedelta(days=6))

    first = yesterday - timedelta(days=29)
    series = await _daily_series(session, first, yesterday)
    chart = line_chart(
        [n if n >= THRESHOLD else None for n in series],
        [(i, short_day(first + timedelta(days=i))) for i in (0, 7, 14, 21, 29)],
        label="Daily active installs, 30 days",
    )

    builds = await _totals(session, MONTH, month, "build")
    build_cells = sorted(
        ((BUILD_NAMES.get(b, b), n) for b, n in builds.items()), key=lambda c: -c[1]
    )

    reach_rows = await session.execute(
        select(AppNotice, func.sum(NoticeReach.n), func.min(NoticeReach.day))
        .join(NoticeReach, NoticeReach.notice_id == AppNotice.id)
        .group_by(AppNotice.id)
        .order_by(func.min(NoticeReach.day).desc())
        .limit(10)
    )
    notices = [
        NoticeRow(
            title=notice.title,
            tag="must update" if notice.required_reason else notice.kind,
            must_update=notice.required_reason is not None,
            reach=number(shown_total(int(total))),
            since=short_day(since),
        )
        for notice, total, since in reach_rows.all()
    ]

    tiles = [
        Tile("Monthly active installs", number(shown_total(mai)), delta),
        Tile(
            "Daily, yesterday",
            number(shown_total(last_week[-1])),
            f"7-day average {number(shown_total(average))}",
        ),
        Tile(
            "Downloads, 30 days",
            f"{downloads.total:,}" if downloads else "\u2013",
            "GitHub release files only" if downloads else "The snapshot could not be read",
        ),
        Tile(
            "Crash reports, 7 days",
            f"{reports:,}",
            f"{groups} group{'s' if groups != 1 else ''} · {new} new",
        ),
    ]
    return Overview(
        month=month,
        months=available,
        as_of=short_day(today),
        tiles=tiles,
        daily_chart=chart,
        versions=bars(_version_cells(await _totals(session, MONTH, month, "version"))),
        builds=bars(build_cells),
        notices=notices,
        downloads=downloads,
        fl_min_cohort=FLSettings().min_cohort_size,
        country_on=settings.country_lookup_enabled,
    )


@dataclass
class Installs:
    month: date
    months: list[date]
    country_on: bool
    countries: list[Bar]
    shown: int
    hidden: int
    ceiling: int
    flood_hours: int
    flood_dropped: int
    last_flood: str | None


async def installs(
    session: AsyncSession, settings: Settings, *, today: date, month_param: str | None
) -> Installs:
    available = await months(session, today)
    month = pick_month(month_param, available)
    totals = await _totals(session, MONTH, month, "country")
    unknown = totals.pop(UNKNOWN, 0)
    cells = sorted(((country_name(c), n) for c, n in totals.items()), key=lambda c: -c[1])
    if unknown:
        cells.append((country_name(UNKNOWN), unknown))
    rows = bars(cells, total=await _all(session, MONTH, month))
    known = [r for r in rows if r.label != country_name(UNKNOWN)]
    next_month = month_of(month + timedelta(days=32))
    floods = await session.execute(
        select(CountFlood.hour, CountFlood.dropped)
        .where(
            CountFlood.hour >= datetime.combine(month, time(), tzinfo=UTC),
            CountFlood.hour < datetime.combine(next_month, time(), tzinfo=UTC),
        )
        .order_by(CountFlood.hour.desc())
    )
    in_month = list(floods.all())
    last = in_month[0][0] if in_month else None
    return Installs(
        month=month,
        months=available,
        country_on=settings.country_lookup_enabled,
        countries=rows,
        shown=sum(1 for r in known if r.n is not None),
        hidden=sum(1 for r in known if r.n is None),
        ceiling=settings.counting_max_new_per_hour,
        flood_hours=len(in_month),
        flood_dropped=sum(d for _, d in in_month),
        last_flood=f"{short_day(last.date())} {last:%H:00} UTC" if last else None,
    )


@dataclass
class GroupRow:
    id: uuid.UUID
    error: str
    function: str | None
    location: str | None
    first_frame: str
    is_new: bool
    versions: str
    reports: int
    trend: Markup
    first_seen: str
    last_seen: str


@dataclass
class Crashes:
    days: int
    build: str | None
    tiles: list[Tile]
    groups: list[GroupRow] = field(default_factory=list)


def version_span(versions: set[str]) -> str:
    def key(text: str) -> Version:
        try:
            return Version(text)
        except ValueError:
            return Version("0.0.0")

    ordered = sorted(versions, key=key)
    if len(ordered) <= 2:
        return ", ".join(ordered)
    return f"{ordered[0]} to {ordered[-1]}"


async def crashes(session: AsyncSession, *, today: date, days: int, build: str | None) -> Crashes:
    since = today - timedelta(days=days - 1)
    query = select(CrashReportRow).where(CrashReportRow.received_on >= since)
    if build:
        query = query.where(CrashReportRow.build == build)
    reports = list(await session.scalars(query))
    by_group: dict[uuid.UUID, list[CrashReportRow]] = {}
    for report in reports:
        by_group.setdefault(report.group_id, []).append(report)
    groups = (
        {
            g.id: g
            for g in await session.scalars(select(CrashGroup).where(CrashGroup.id.in_(by_group)))
        }
        if by_group
        else {}
    )
    rows = []
    for group_id, items in sorted(by_group.items(), key=lambda kv: -len(kv[1])):
        group = groups[group_id]
        per_day = Counter(r.received_on for r in items)
        rows.append(
            GroupRow(
                id=group.id,
                error=group.error,
                function=group.decoded_function,
                location=group.decoded_location,
                first_frame=group.frames[0] if group.frames else "no frames",
                is_new=group.first_seen >= today - timedelta(days=NEW_GROUP_DAYS - 1),
                versions=version_span({r.app for r in items}),
                reports=len(items),
                trend=sparkline([per_day.get(since + timedelta(days=i), 0) for i in range(days)]),
                first_seen=short_day(group.first_seen),
                last_seen=short_day(max(r.received_on for r in items)),
            )
        )
    mai = await _all(session, MONTH, month_of(today))
    not_decoded = sum(1 for r in reports if not r.decoded)
    tiles = [
        Tile(f"Reports, {days} days", f"{len(reports):,}"),
        Tile("Groups", f"{len(rows):,}"),
        Tile(
            "Reports per 1,000 installs",
            f"{len(reports) / mai * 1000:.1f}" if mai >= THRESHOLD else "Not enough installs",
            "Sent reports only",
        ),
        Tile(
            "Not decoded",
            f"{not_decoded:,}",
            "Symbols for every release" if not not_decoded else "Waiting for release symbols",
        ),
    ]
    return Crashes(days=days, build=build, tiles=tiles, groups=rows)


@dataclass
class GroupDetail:
    group: CrashGroup
    title: str
    lead_delta: str
    builds: list[str]
    systems: list[str]
    system_label: str
    cpus: list[str]
    stack_note: str
    stack: list[str]
    chart: Markup
    chart_first: str
    example: str | None


def _facet(values: list[str]) -> list[str]:
    counted = Counter(values).most_common()
    return [f"{value} {n}" for value, n in counted]


def _pairs(items: list[str], per_line: int = 2) -> list[str]:
    return [" · ".join(items[i : i + per_line]) for i in range(0, len(items), per_line)]


async def crash_group(
    session: AsyncSession, group_id: uuid.UUID, *, today: date
) -> GroupDetail | None:
    group = await session.get(CrashGroup, group_id)
    if group is None:
        return None
    reports = list(
        await session.scalars(
            select(CrashReportRow)
            .where(CrashReportRow.group_id == group_id)
            .order_by(CrashReportRow.received_on.desc())
        )
    )
    versions = {r.app for r in reports}
    lead_delta = (
        f"All on {next(iter(versions))}"
        if len(versions) == 1
        else f"On {version_span(versions)}"
        if versions
        else "Reports older than 90 days are deleted"
    )
    systems = Counter(r.os for r in reports).most_common()
    first = max(group.first_seen, today - timedelta(days=89))
    days = await session.execute(
        select(CrashGroupDay.day, CrashGroupDay.n).where(
            CrashGroupDay.group_id == group_id, CrashGroupDay.day >= first
        )
    )
    per_day = dict(days.all())
    span = (today - first).days + 1
    series: list[int | None] = [per_day.get(first + timedelta(days=i), 0) for i in range(span)]
    marks = sorted({0, span // 2, span - 1})
    latest = reports[0] if reports else None
    where = group.decoded_function or group.error
    return GroupDetail(
        group=group,
        title=f"{group.error} in {group.decoded_function}" if group.decoded_function else where,
        lead_delta=lead_delta,
        builds=_pairs(_facet([BUILD_NAMES.get(r.build, r.build) for r in reports]), 1),
        systems=_pairs([f"{os.split(' ')[-1]}: {n}" for os, n in systems]),
        system_label=(
            "Android"
            if systems and all(os.startswith("Android") for os, _ in systems)
            else "iOS"
            if systems and all(os.startswith("iOS") for os, _ in systems)
            else "System"
        ),
        cpus=_pairs(_facet([r.cpu for r in reports]), 1),
        stack_note=(
            "Decoded on the server with the release's symbols. Our frames are bold."
            if latest is not None and latest.decoded
            else "Not decoded yet: the release's symbols are not on the server, so these are "
            "offsets in the app's instructions, as sent."
        ),
        stack=list(latest.stack) if latest else list(group.frames),
        chart=line_chart(
            series,
            [(i, short_day(first + timedelta(days=i))) for i in marks],
            label="Reports per day",
            width=520,
            height=180,
        ),
        chart_first=short_day(group.first_seen),
        example=json.dumps(payload(latest), indent=1) if latest else None,
    )
