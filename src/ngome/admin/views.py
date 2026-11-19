"""What each dashboard page shows, read from the counts and crash tables.

Install counts under 10 are hidden here, on display (``ngome.counting.suppress``), and so
is any sum shown beside a table that would give a hidden cell away; the stored totals stay
exact. Crash report counts are counts of reports, not of people, and are shown as they are.
"""

import json
import re
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, time, timedelta

from markupsafe import Markup
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ngome.admin.charts import (
    S1,
    S2,
    Segment,
    day_bars,
    line_chart,
    mini_bars,
    responsive,
    sparkline,
    stacked_bars,
)
from ngome.admin.downloads import Downloads
from ngome.admin.filters import BUILD_NAMES, PLATFORM_BUILDS, Filters
from ngome.appstatus.models import AppNotice
from ngome.appstatus.versions import Version
from ngome.core.config import Settings
from ngome.counting.country import UNKNOWN, country_name
from ngome.counting.models import DAY, MONTH, CountFlood, CountTotal, NoticeReach
from ngome.counting.service import ALL, month_of
from ngome.counting.suppress import THRESHOLD, Shown, derived, pair, suppress_marked
from ngome.crashes.models import CrashGroup, CrashGroupDay, CrashReportRow
from ngome.crashes.service import payload
from ngome.fl.config import FLSettings

BUILD_ORDER = ("play", "foss", "website", "ios")
TOP_VERSIONS = 5
OVERVIEW_ROWS = 5  # rows in each overview table; the rest are a "See all" away
TREND_MONTHS = 6
NEW_DAYS = 7
QUIET_DAYS = 14
OVERVIEW_DAYS = (30, 90)
CRASH_DAYS = (7, 30, 90)
DETAIL_DAYS = (30, 90)


# Formatting.


def short_day(day: date) -> str:
    return f"{day.day} {day:%b}"


def month_name(month: date) -> str:
    return f"{month:%B %Y}"


def number(n: int | None) -> str:
    return "<10" if n is None else f"{n:,}"


def delta(current: int | None, previous: int | None) -> str:
    """ "▲ 17%" or "▼ 8%", or nothing when either side is hidden or there is no base."""
    if current is None or previous is None or previous <= 0:
        return ""
    change = (current - previous) / previous * 100
    return f"{'▲' if change >= 0 else '▼'} {abs(change):.0f}%"


def share(n: int | None, total: int) -> str:
    if n is None or total <= 0:
        return ""
    s = n / total * 100
    return "<1%" if s < 0.5 else f"{s:.0f}%"


def ago(day: date, today: date) -> str:
    gap = (today - day).days
    return "today" if gap <= 0 else "yesterday" if gap == 1 else f"{gap} days ago"


def _version_key(text: str) -> Version:
    try:
        return Version(text)
    except ValueError:
        return Version("0.0.0")


def version_span(versions: Iterable[str]) -> str:
    ordered = sorted(set(versions), key=_version_key)
    if len(ordered) <= 3:
        return ", ".join(ordered)
    return f"{ordered[0]} to {ordered[-1]} ({len(ordered)} versions)"


def _months_back(month: date, n: int) -> list[date]:
    out = [month]
    for _ in range(n - 1):
        out.append(month_of(out[-1] - timedelta(days=1)))
    return out[::-1]


# Shared pieces.


@dataclass(frozen=True, slots=True)
class Bar:
    label: str
    shown: Shown
    width: int  # percent of the widest shown bar, 0 to 100 (a CSS class, not a style)
    share: str = ""
    lead: bool = False
    mono: bool = False

    @property
    def n(self) -> int | None:
        return self.shown.n


def bars(
    cells: Sequence[tuple[str, int]],
    *,
    total: int | None = None,
    suppressed: bool = True,
    lead_first: bool = False,
    shown: dict[str, Shown] | None = None,
) -> list[Bar]:
    """Rows for a bar table, in the given order, with small cells hidden (``suppressed``),
    or as ``shown`` when the caller has already suppressed them."""
    raw = dict(cells)
    if shown is None:
        shown = suppress_marked(raw) if suppressed else {k: Shown(v) for k, v in raw.items()}
    widest = max((s.n for s in shown.values() if s.n is not None), default=0)
    total = total if total is not None else sum(raw.values())
    lead_index = (
        0
        if lead_first
        else next((i for i, (label, _) in enumerate(cells) if shown[label].n == widest), None)
    )
    rows = []
    for i, (label, _) in enumerate(cells):
        s = shown[label]
        width = max(round(s.n / widest * 100), 2) if widest and s.n else 0
        rows.append(Bar(label, s, width, share(s.n, total), i == lead_index and widest > 0))
    return rows


@dataclass
class Tile:
    label: str
    value: str
    note: str = ""
    delta: str = ""
    lead: bool = False
    wordy: bool = False  # a phrase rather than a figure
    pending: bool = False  # no figure yet: a neutral card with plain text, never the red lead


async def _totals(session: AsyncSession, kind: str, period: date, dimension: str) -> dict[str, int]:
    rows = await session.execute(
        select(CountTotal.value, CountTotal.n).where(
            CountTotal.kind == kind, CountTotal.period == period, CountTotal.dimension == dimension
        )
    )
    return dict(rows.all())


async def _month_cells(
    session: AsyncSession, first: date, last: date
) -> dict[date, dict[str, dict[str, int]]]:
    """Monthly totals from ``first`` to ``last``: month -> dimension -> value -> n."""
    rows = await session.execute(
        select(CountTotal.period, CountTotal.dimension, CountTotal.value, CountTotal.n).where(
            CountTotal.kind == MONTH, CountTotal.period >= first, CountTotal.period <= last
        )
    )
    out: dict[date, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(dict))
    for period, dimension, value, n in rows.all():
        out[period][dimension][value] = n
    return out


async def months(session: AsyncSession, today: date) -> list[date]:
    stored = await session.scalars(
        select(CountTotal.period).where(CountTotal.kind == MONTH).distinct()
    )
    return sorted({month_of(today), *stored}, reverse=True)


def pick_month(wanted: date | None, available: list[date]) -> date:
    return wanted if wanted in available else available[0]


def installs_for(cells: dict[str, dict[str, int]], builds: tuple[str, ...] | None) -> Shown:
    """A month's (or day's) active installs, for every build or for some of them. A sum of
    builds is shown only if it cannot give a hidden build away."""
    if builds is None:
        n = cells.get(ALL, {}).get(ALL, 0)
        return Shown(n) if n >= THRESHOLD else Shown(None, "small")
    raw = cells.get("build", {})
    if not raw:
        return Shown(None, "small")
    return derived(suppress_marked(raw), raw, builds)


def _crash_conditions[*Ts](
    query: Select[*Ts], filters: Filters, *, since: date | None, until: date | None = None
) -> Select[*Ts]:
    if since is not None:
        query = query.where(CrashReportRow.received_on >= since)
    if until is not None:
        query = query.where(CrashReportRow.received_on <= until)
    if filters.build:
        query = query.where(CrashReportRow.build == filters.build)
    elif filters.platform:
        query = query.where(CrashReportRow.build.in_(PLATFORM_BUILDS[filters.platform]))
    if filters.version:
        query = query.where(CrashReportRow.app == filters.version)
    return query


async def _report_count(
    session: AsyncSession, filters: Filters, since: date, until: date | None = None
) -> int:
    query = _crash_conditions(
        select(func.count()).select_from(CrashReportRow), filters, since=since, until=until
    )
    return await session.scalar(query) or 0


async def new_groups(session: AsyncSession, today: date) -> int:
    since = today - timedelta(days=NEW_DAYS - 1)
    return (
        await session.scalar(
            select(func.count()).select_from(CrashGroup).where(CrashGroup.first_seen >= since)
        )
        or 0
    )


async def crash_rate(session: AsyncSession, filters: Filters, month: date, today: date) -> Tile:
    """Reports per 1,000 installs in one calendar month: both sides cover the same days.
    A floor, since reports are sent only when someone says yes."""
    label = f"Crash rate, {month:%B}"
    if filters.version and filters.builds():
        return Tile(
            label, "Not split", "Installs are not counted by build and version together", wordy=True
        )
    cells = await _month_cells(session, month, month)
    if filters.version:
        raw = cells[month].get("version", {})
        installs = (
            suppress_marked(raw).get(filters.version, Shown(None, "small"))
            if raw
            else (Shown(None, "small"))
        )
    else:
        installs = installs_for(cells[month], filters.builds())
    end = min(today, month_of(month + timedelta(days=32)) - timedelta(days=1))
    reports = await _report_count(session, filters, month, end)
    if installs.n is None:
        return Tile(label, "", "Shows once this month has 10 or more installs.", pending=True)
    return Tile(
        label,
        f"{reports / installs.n * 1000:.1f}",
        "per 1,000 installs · a floor: sent reports only",
    )


# Overview.


@dataclass
class TrendRow:
    month: str
    total: Shown
    first: Shown | None
    second: Shown | None


@dataclass
class Multiple:
    name: str
    shown: Shown
    chart: Markup
    note: str


@dataclass
class CrashBrief:
    id: uuid.UUID
    error: str
    where: str
    is_new: bool
    reports: int
    trend: Markup


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
    filters: Filters
    # The page's one "up to" day. Counts close at the end of the previous UTC day, so it is
    # yesterday; downloads are cut to the same day (``summarise(until=...)``) rather than
    # showing the newest snapshot, which is usually today's live counters.
    as_of: str
    started: bool
    tiles: list[Tile]
    trend: Markup | None
    trend_rows: list[TrendRow]
    trend_legend: tuple[str, str] | None
    trend_note: str
    multiples: list[Multiple]
    builds_note: str
    daily: Markup | None
    daily_hidden: list[str]
    daily_days: int
    versions: list[Bar]
    versions_note: str
    crash_rows: list[CrashBrief]
    crash_summary: str
    crash_groups_n: int
    notices: list[NoticeRow]
    notices_n: int
    versions_n: int
    downloads: Downloads | None
    downloads_state: str  # "ok", "unread" or "off"
    fl_min_cohort: int
    country_on: bool
    downloads_late: bool = False  # the newest snapshot ends before the page's "up to" day


def _trend(
    cells: dict[date, dict[str, dict[str, int]]], span: list[date], filters: Filters
) -> tuple[Markup | None, list[TrendRow], tuple[str, str] | None, str]:
    labels, stacks, totals, rows = [], [], [], []
    builds = filters.builds()
    newest_names = []
    for m in span:
        c = cells.get(m, {})
        total = installs_for(c, builds)
        labels.append(f"{m:%b}")
        first = second = None
        if builds is None and filters.split == "release" and c.get("version"):
            raw = c["version"]
            newest = max(raw, key=_version_key)
            newest_names.append(f"{m:%b} {newest}")
            shown = suppress_marked(raw)
            rest = [v for v in raw if v != newest]
            first, second = _split(
                pair(raw[newest], sum(raw[v] for v in rest)),
                shown[newest],
                derived(shown, raw, rest),
            )
        elif builds is None and filters.split == "build" and c.get("build"):
            raw = c["build"]
            shown = suppress_marked(raw)
            rest = [b for b in raw if b != "play"]
            first, second = _split(
                pair(raw.get("play", 0), sum(raw[b] for b in rest)),
                shown.get("play", Shown(None, "small")),
                derived(shown, raw, rest),
            )
        if total.hidden:
            first = second = None
        names = _split_names(filters)
        stacks.append(
            [Segment(first.n, names[0], S1), Segment(second.n, names[1], S2)]
            if first is not None and second is not None
            else [Segment(total.n, "installs", S1)]
        )
        totals.append(total.n)
        rows.append(TrendRow(f"{m:%B %Y}", total, first, second))
    if not any(totals):
        return None, rows, None, ""
    chart = responsive(
        stacked_bars(labels, stacks, totals, label="Monthly active installs", width=600),
        stacked_bars(
            labels, stacks, totals, label="Monthly active installs", width=326, height=210
        ),
    )
    if builds is not None:
        return chart, rows, None, "Not split by release: counts keep one dimension per row."
    legend = (
        (f"Newest release that month ({', '.join(newest_names[-3:])})", "Earlier releases")
        if filters.split == "release"
        else ("Play", "Other builds")
    )
    return chart, rows, legend, ""


def _split(parts: tuple[Shown, Shown], lead: Shown, rest: Shown) -> tuple[Shown, Shown]:
    """A stacked bar's two segments: hidden together if either part, or the lead cell or the
    rest's sum in the table they come from, is hidden; each keeps its own reason."""
    first, second = parts
    if first.hidden or second.hidden:
        return first, second
    if lead.hidden or rest.hidden:
        return Shown(None, lead.why or "secondary"), Shown(None, rest.why or "secondary")
    return first, second


def _split_names(filters: Filters) -> tuple[str, str]:
    if filters.split == "build":
        return ("Play", "other builds")
    return ("newest release", "earlier releases")


def _multiples(
    cells: dict[date, dict[str, dict[str, int]]], span: list[date]
) -> tuple[list[Multiple], str]:
    month, previous = span[-1], span[-2]
    shown_by_month = {m: suppress_marked(cells.get(m, {}).get("build", {})) for m in span}
    out = []
    for b in BUILD_ORDER:
        series = [shown_by_month[m].get(b, Shown(None, "small")).n for m in span]
        now = shown_by_month[month].get(b, Shown(None, "small"))
        before = shown_by_month[previous].get(b, Shown(None, "small"))
        if now.why == "secondary":
            note = "Hidden to protect a small cell"
        elif now.hidden:
            note = "Under 10 this month"
        elif d := delta(now.n, before.n):
            note = f"{d} vs {previous:%b}"
        else:
            note = f"Under 10 in {previous:%b}" if before.hidden else ""
        out.append(Multiple(BUILD_NAMES[b], now, mini_bars(series), note))
    small = [BUILD_NAMES[b] for b, s in shown_by_month[month].items() if s.why == "small"]
    second = [BUILD_NAMES[b] for b, s in shown_by_month[month].items() if s.why == "secondary"]
    note = ""
    if small and second:
        note = (
            f"{' and '.join(small)} {'is' if len(small) == 1 else 'are'} under 10, so "
            f"{second[0]} is hidden too: the total would otherwise give it away."
        )
    return out, note


async def _day_cells(
    session: AsyncSession, first: date, last: date
) -> dict[date, dict[str, dict[str, int]]]:
    rows = await session.execute(
        select(CountTotal.period, CountTotal.dimension, CountTotal.value, CountTotal.n).where(
            CountTotal.kind == DAY,
            CountTotal.dimension.in_((ALL, "build")),
            CountTotal.period >= first,
            CountTotal.period <= last,
        )
    )
    out: dict[date, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(dict))
    for period, dimension, value, n in rows.all():
        out[period][dimension][value] = n
    return out


def _daily(
    days: dict[date, dict[str, dict[str, int]]], yesterday: date, span: int, filters: Filters
) -> tuple[Markup | None, list[str], list[int | None]]:
    first = yesterday - timedelta(days=span - 1)
    lead = [first - timedelta(days=6 - i) for i in range(6)]
    every = [*lead, *(first + timedelta(days=i) for i in range(span))]
    shown = {d: installs_for(days.get(d, {}), filters.builds()).n for d in every}
    values = [shown[d] for d in every[6:]]
    average: list[float | None] = []
    for i in range(6, len(every)):
        window = [v for d in every[i - 6 : i + 1] if (v := shown[d]) is not None]
        average.append(sum(window) / len(window) if window else None)
    if not any(values):
        return None, [], values
    titles = [short_day(d) for d in every[6:]]
    marks_wide = sorted({0, span // 4, span // 2, 3 * span // 4, span - 1})
    marks_narrow = [0, span // 2, span - 1]
    chart = responsive(
        line_chart(
            values,
            [(i, titles[i]) for i in marks_wide],
            label="Daily active installs",
            titles=titles,
            width=600,
            average=average,
        ),
        line_chart(
            values,
            [(i, titles[i]) for i in marks_narrow],
            label="Daily active installs",
            titles=titles,
            width=326,
            height=180,
            average=average,
        ),
    )
    hidden = [titles[i] for i, v in enumerate(values) if v is None]
    return chart, hidden, values


def version_bars(totals: dict[str, int], total: int) -> list[Bar]:
    """The newest versions, then "Older". The whole version table is suppressed first, and
    "Older" is a sum beside it, so it follows :func:`derived`."""
    shown = suppress_marked(totals)
    ordered = sorted(totals, key=_version_key, reverse=True)
    top, rest = ordered[:TOP_VERSIONS], ordered[TOP_VERSIONS:]
    cells = [(v, totals[v]) for v in top]
    marks = {v: shown[v] for v in top}
    if rest:
        cells.append(("Older", sum(totals[v] for v in rest)))
        marks["Older"] = derived(shown, totals, rest)
    return bars(cells, total=total, shown=marks)


async def _crash_brief(
    session: AsyncSession, filters: Filters, today: date
) -> tuple[list[CrashBrief], str, int]:
    since7 = today - timedelta(days=NEW_DAYS - 1)
    since30 = today - timedelta(days=29)
    counts = await session.execute(
        _crash_conditions(
            select(CrashReportRow.group_id, func.count()).group_by(CrashReportRow.group_id),
            filters,
            since=since7,
        )
    )
    by_group = dict(counts.all())
    previous = await _report_count(
        session, filters, since7 - timedelta(days=NEW_DAYS), since7 - timedelta(days=1)
    )
    top = sorted(by_group.items(), key=lambda kv: -kv[1])[:OVERVIEW_ROWS]
    groups = (
        {
            g.id: g
            for g in await session.scalars(
                select(CrashGroup).where(CrashGroup.id.in_([g for g, _ in top]))
            )
        }
        if top
        else {}
    )
    per_day = await _group_days(session, filters, [g for g, _ in top], since30)
    peak = max((n for days in per_day.values() for n in days.values()), default=1)
    rows = []
    for group_id, n in top:
        g = groups[group_id]
        days = per_day.get(group_id, {})
        rows.append(
            CrashBrief(
                id=g.id,
                error=g.error,
                where=g.decoded_function or "Not decoded yet",
                is_new=g.first_seen >= since7,
                reports=n,
                trend=sparkline(
                    [days.get(since30 + timedelta(days=i), 0) for i in range(30)],
                    peak=peak,
                    width=90,
                    height=22,
                ),
            )
        )
    total = sum(by_group.values())
    new = sum(1 for g in groups.values() if g.first_seen >= since7)
    summary = (
        f"Last 7 days: {total} report{'s' if total != 1 else ''} in {len(by_group)} "
        f"group{'s' if len(by_group) != 1 else ''}, {new} new. Previous 7 days: {previous}."
        if total
        else f"No reports in the last 7 days. Previous 7 days: {previous}."
    )
    return rows, summary, len(by_group)


async def _group_days(
    session: AsyncSession, filters: Filters, group_ids: Sequence[uuid.UUID], since: date
) -> dict[uuid.UUID, dict[date, int]]:
    if not group_ids:
        return {}
    rows = await session.execute(
        _crash_conditions(
            select(CrashReportRow.group_id, CrashReportRow.received_on, func.count())
            .where(CrashReportRow.group_id.in_(group_ids))
            .group_by(CrashReportRow.group_id, CrashReportRow.received_on),
            filters,
            since=since,
        )
    )
    out: dict[uuid.UUID, dict[date, int]] = defaultdict(dict)
    for group_id, day, n in rows.all():
        out[group_id][day] = n
    return out


async def _notices(session: AsyncSession) -> list[NoticeRow]:
    """Every notice that reached a check-in, most reached first."""
    reach_rows = await session.execute(
        select(AppNotice, func.sum(NoticeReach.n), func.min(NoticeReach.day))
        .join(NoticeReach, NoticeReach.notice_id == AppNotice.id)
        .group_by(AppNotice.id)
        .order_by(func.sum(NoticeReach.n).desc())
    )
    return [
        NoticeRow(
            title=notice.title,
            tag="must update" if notice.required_reason else notice.kind,
            must_update=notice.required_reason is not None,
            reach=number(int(total) if int(total) >= THRESHOLD else None),
            since=short_day(since),
        )
        for notice, total, since in reach_rows.all()
    ]


async def overview(
    session: AsyncSession,
    settings: Settings,
    *,
    today: date,
    filters: Filters,
    downloads: Downloads | None,
    downloads_state: str,
) -> Overview:
    available = await months(session, today)
    month = pick_month(filters.month, available)
    span = _months_back(month, TREND_MONTHS)
    cells = await _month_cells(session, span[0], month)
    builds = filters.builds()
    started = bool(cells.get(month))
    mai = installs_for(cells.get(month, {}), builds)
    before = installs_for(cells.get(span[-2], {}), builds)

    yesterday = today - timedelta(days=1)
    days_span = filters.days if filters.days in OVERVIEW_DAYS else 30
    day_cells = await _day_cells(session, yesterday - timedelta(days=days_span + 13), yesterday)
    daily, daily_hidden, values = _daily(day_cells, yesterday, days_span, filters)
    week = values[-7:]
    previous_week = [
        installs_for(day_cells.get(yesterday - timedelta(days=7 + i), {}), builds).n
        for i in range(7)
    ]
    week_delta = (
        delta(sum(v or 0 for v in week), sum(v or 0 for v in previous_week))
        if all(v is not None for v in [*week, *previous_week])
        else ""
    )
    shown_week = [v for v in week if v is not None]

    trend, trend_rows, legend, trend_note = _trend(cells, span, filters)
    multiples, builds_note = _multiples(cells, span)
    crash_rows, crash_summary, crash_groups_n = await _crash_brief(session, filters, today)

    if started:
        lead = Tile(
            "Monthly active installs",
            number(mai.n),
            f"{span[-2]:%B}: {number(before.n)}",
            delta(mai.n, before.n),
            lead=True,
        )
    else:
        lead = Tile(
            "Monthly active installs",
            "",
            "No figure yet. It shows once 10 or more phones have checked in this month.",
            pending=True,
        )
    if daily is None:
        daily_tile = Tile(
            "Daily, yesterday", "", "Shows from the first day with 10 or more.", pending=True
        )
    else:
        average = round(sum(shown_week) / len(shown_week)) if shown_week else None
        daily_tile = Tile(
            "Daily, yesterday",
            number(week[-1]),
            f"7-day average {number(average)}",
            f"{week_delta} on last week" if week_delta else "",
        )
    if downloads is not None:
        down = Tile(
            "Downloads, 30 days",
            f"{downloads.total:,}",
            "App files (.apk, .ipa) from GitHub releases",
            delta(downloads.total, downloads.previous_total),
        )
    elif downloads_state == "off":
        down = Tile("Downloads, 30 days", "Off", "No snapshot address is set", wordy=True)
    else:
        down = Tile(
            "Downloads, 30 days",
            "Not read",
            "The snapshot could not be read just now; it is tried again on the next visit",
            wordy=True,
        )
    tiles = [lead, daily_tile, await crash_rate(session, filters, month, today), down]

    version_raw = cells.get(month, {}).get("version", {})
    all_notices = await _notices(session)
    return Overview(
        month=month,
        months=available,
        filters=replace(filters, month=month, days=days_span),
        as_of=short_day(yesterday),
        started=started,
        tiles=tiles,
        trend=trend,
        trend_rows=trend_rows,
        trend_legend=legend,
        trend_note=trend_note,
        multiples=multiples,
        builds_note=builds_note,
        daily=daily,
        daily_hidden=daily_hidden,
        daily_days=days_span,
        versions=version_bars(version_raw, sum(version_raw.values())),
        versions_note=(
            "Counted for all builds together: counts keep one dimension per row." if builds else ""
        ),
        crash_rows=crash_rows,
        crash_summary=crash_summary,
        crash_groups_n=crash_groups_n,
        notices=all_notices[:OVERVIEW_ROWS],
        notices_n=len(all_notices),
        versions_n=len(version_raw),
        downloads=downloads,
        downloads_state=downloads_state,
        downloads_late=downloads is not None and downloads.as_of < yesterday,
        fl_min_cohort=FLSettings().min_cohort_size,
        country_on=settings.country_lookup_enabled,
    )


# Installs.


@dataclass
class AdoptionRow:
    version: str
    cells: list[tuple[Shown, str] | None]  # per month: shown count and share, or not seen


@dataclass
class Installs:
    month: date
    months: list[date]
    filters: Filters
    country_on: bool
    dim: str
    tiles: list[Tile]
    rows: list[Bar]
    hidden_count: int
    adoption_months: list[date]
    adoption: list[AdoptionRow]
    ceiling: int
    flood_hours: int
    flood_dropped: int
    last_flood: str | None
    last_flood_day: str | None


DIM_NAMES = {"country": "Countries", "version": "Versions", "build": "Builds"}


def _dimension_rows(dim: str, raw: dict[str, int], total: int) -> list[Bar]:
    if dim == "country":
        totals = dict(raw)
        unknown = totals.pop(UNKNOWN, 0)
        cells = sorted(((country_name(c), n) for c, n in totals.items()), key=lambda c: -c[1])
        if unknown:
            cells.append((country_name(UNKNOWN), unknown))
    elif dim == "version":
        return version_bars(raw, total)
    else:
        cells = sorted(((BUILD_NAMES.get(b, b), n) for b, n in raw.items()), key=lambda c: -c[1])
    return bars(cells, total=total)


def adoption(
    cells: dict[date, dict[str, dict[str, int]]], span: list[date], limit: int = 8
) -> list[AdoptionRow]:
    """Versions by month. Each month is suppressed as its own table."""
    seen = {v for m in span for v in cells.get(m, {}).get("version", {})}
    versions = sorted(seen, key=_version_key, reverse=True)[:limit]
    shown = {m: suppress_marked(cells.get(m, {}).get("version", {})) for m in span}
    rows = []
    for v in versions:
        row: list[tuple[Shown, str] | None] = []
        for m in span:
            if v not in shown[m]:
                row.append(None)
                continue
            total = sum(cells[m]["version"].values())
            row.append((shown[m][v], share(shown[m][v].n, total)))
        rows.append(AdoptionRow(v, row))
    return rows


async def installs(
    session: AsyncSession, settings: Settings, *, today: date, filters: Filters
) -> Installs:
    available = await months(session, today)
    month = pick_month(filters.month, available)
    span = _months_back(month, TREND_MONTHS)
    cells = await _month_cells(session, span[0], month)
    country_on = settings.country_lookup_enabled
    dim = filters.dim if (filters.dim != "country" or country_on) else "country"
    here = cells.get(month, {})
    total = here.get(ALL, {}).get(ALL, 0)
    raw = here.get(dim, {}) if (dim != "country" or country_on) else {}
    rows = _dimension_rows(dim, raw, total)
    known = [r for r in rows if r.label != country_name(UNKNOWN)]
    shown_known = [r for r in known if r.n is not None]
    small = sum(1 for r in known if r.shown.why == "small")
    mai = installs_for(here, None)
    before = installs_for(cells.get(span[-2], {}), None)
    tiles = [
        Tile(
            "Monthly active installs",
            number(mai.n),
            f"{span[-2]:%B}: {number(before.n)}",
            delta(mai.n, before.n),
            lead=True,
        ),
        Tile(
            f"{DIM_NAMES[dim]} with 10 or more",
            str(len(shown_known)),
            f"{small} more under 10"
            + (" and 1 hidden" if any(r.shown.why == "secondary" for r in known) else ""),
        ),
    ]
    if shown_known:
        largest = max(shown_known, key=lambda r: r.n or 0)
        tiles.append(
            Tile(f"{largest.label}'s share", largest.share, f"{number(largest.n)} installs")
        )
    else:
        tiles.append(Tile("Largest share", "", "Shows once one has 10 or more.", pending=True))
    if dim == "country":
        unknown = next((r for r in rows if r.label == country_name(UNKNOWN)), None)
        tiles.append(
            Tile(
                "Not placed",
                number(unknown.n) if unknown else "0",
                "Addresses the database does not place",
            )
        )
    elif dim == "version" and raw:
        newest = max(raw, key=_version_key)
        n = suppress_marked(raw)[newest]
        tiles.append(
            Tile("Newest release", newest, f"{share(n.n, total) or 'under 10'} of installs")
        )
    else:
        tiles.append(Tile("Under 10", str(small), "Builds hidden this month"))

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
        filters=replace(filters, month=month, dim=dim),
        country_on=country_on,
        dim=dim,
        tiles=tiles,
        rows=rows if (dim != "country" or country_on) else [],
        hidden_count=sum(1 for r in rows if r.n is None),
        adoption_months=span,
        adoption=adoption(cells, span),
        ceiling=settings.counting_max_new_per_hour,
        flood_hours=len(in_month),
        flood_dropped=sum(d for _, d in in_month),
        last_flood=f"{short_day(last.date())}, {last:%H:00} UTC" if last else None,
        last_flood_day=short_day(last.date()) if last else None,
    )


# Crashes.


@dataclass
class GroupRow:
    id: uuid.UUID
    error: str
    function: str | None
    location: str | None
    first_frame: str
    is_new: bool
    quiet: bool
    versions: list[str]
    more_versions: int
    reports: int
    share: str
    trend: Markup
    first_seen: str
    last_seen: str
    sort_first: date = field(repr=False, default=date.min)
    sort_last: date = field(repr=False, default=date.min)


@dataclass
class Crashes:
    filters: Filters
    days: int
    tiles: list[Tile]
    chart: Markup | None
    groups: list[GroupRow]
    total: int


async def crashes(session: AsyncSession, *, today: date, filters: Filters) -> Crashes:
    days = filters.days if filters.days in CRASH_DAYS else 30
    since = today - timedelta(days=days - 1)
    agg = await session.execute(
        _crash_conditions(
            select(
                CrashReportRow.group_id, func.count(), func.max(CrashReportRow.received_on)
            ).group_by(CrashReportRow.group_id),
            filters,
            since=since,
        )
    )
    by_group = {g: (n, last) for g, n, last in agg.all()}
    total = sum(n for n, _ in by_group.values())
    groups = (
        {
            g.id: g
            for g in await session.scalars(
                select(CrashGroup).where(CrashGroup.id.in_(list(by_group)))
            )
        }
        if by_group
        else {}
    )
    versions_rows = await session.execute(
        _crash_conditions(
            select(CrashReportRow.group_id, CrashReportRow.app).distinct(), filters, since=since
        )
    )
    versions: dict[uuid.UUID, set[str]] = defaultdict(set)
    for group_id, app in versions_rows.all():
        versions[group_id].add(app)
    per_day = await _group_days(session, filters, list(by_group), since)
    peak = max((n for d in per_day.values() for n in d.values()), default=1)
    span = [since + timedelta(days=i) for i in range(days)]
    rows = []
    for group_id, (n, last) in by_group.items():
        g = groups[group_id]
        ordered = sorted(versions[group_id], key=_version_key, reverse=True)
        series = per_day.get(group_id, {})
        rows.append(
            GroupRow(
                id=g.id,
                error=g.error,
                function=g.decoded_function,
                location=g.decoded_location,
                first_frame=g.frames[0] if g.frames else "no frames",
                is_new=g.first_seen >= today - timedelta(days=NEW_DAYS - 1),
                quiet=(today - last).days >= QUIET_DAYS,
                versions=ordered[:3],
                more_versions=max(len(ordered) - 3, 0),
                reports=n,
                share=share(n, total),
                trend=sparkline([series.get(d, 0) for d in span], peak=peak),
                first_seen=short_day(g.first_seen),
                last_seen=short_day(last),
                sort_first=g.first_seen,
                sort_last=last,
            )
        )
    if filters.sort == "newest":
        rows.sort(key=lambda r: (r.sort_first, r.reports), reverse=True)
    elif filters.sort == "last":
        rows.sort(key=lambda r: (r.sort_last, r.reports), reverse=True)
    else:
        rows.sort(key=lambda r: (r.reports, r.sort_last), reverse=True)

    totals_by_day: Counter[date] = Counter()
    for series in per_day.values():
        totals_by_day.update(series)
    values = [totals_by_day.get(d, 0) for d in span]
    titles = [short_day(d) for d in span]
    chart = (
        responsive(
            day_bars(
                values,
                titles,
                sorted({0, days // 3, 2 * days // 3, days - 1}),
                label=f"Crash reports per day, {days} days",
                width=936,
            ),
            day_bars(
                values,
                titles,
                [0, days // 2, days - 1],
                label=f"Crash reports per day, {days} days",
                width=326,
                height=140,
            ),
        )
        if total
        else None
    )
    previous = await _report_count(
        session, filters, since - timedelta(days=days), since - timedelta(days=1)
    )
    not_decoded = (
        await session.scalar(
            _crash_conditions(
                select(func.count())
                .select_from(CrashReportRow)
                .where(CrashReportRow.decoded.is_(False)),
                filters,
                since=since,
            )
        )
        or 0
    )
    new = sum(1 for r in rows if r.is_new)
    tiles = [
        Tile(
            f"Reports, {days} days",
            f"{total:,}" if total else "None",
            f"previous {days} days: {previous:,}"
            if previous
            else f"none in the {days} days before",
            delta(total, previous),
            wordy=not total,
        ),
        Tile(
            "Groups",
            f"{len(rows):,}" if rows else "None",
            f"{new} new this week" if rows else "A group forms with its first report",
            wordy=not rows,
        ),
        await crash_rate(session, filters, month_of(today), today),
        Tile(
            "Not decoded",
            f"{not_decoded:,}",
            "Waiting for the release's symbols upload"
            if not_decoded
            else "Symbols are on the server for every release",
        ),
    ]
    return Crashes(replace(filters, days=days), days, tiles, chart, rows, total)


# A crash group.


@dataclass(frozen=True, slots=True)
class Frame:
    index: str
    function: str
    location: str
    ours: bool


_FRAME = re.compile(r"^(#\d+)\s+(.*?)\s+\((.+)\)$")


def frame(line: str) -> Frame:
    """A stack line, split into its parts when decoded ("#00 Fn (file.dart:12)")."""
    if match := _FRAME.match(line):
        location = match[3]
        return Frame(match[1], match[2], location, not location.startswith(("dart:", "package:")))
    index, _, rest = line.partition(" ")
    return Frame(index, rest, "", False)


@dataclass
class VersionRow:
    version: str
    reports: int
    width: int
    rate: str


@dataclass
class GroupDetail:
    group: CrashGroup
    filters: Filters
    tiles: list[Tile]
    chart: Markup | None
    versions: list[VersionRow]
    stack: list[Frame]
    decoded: bool
    facets: list[tuple[str, list[Bar]]]
    example: str | None
    received: str | None
    is_new: bool


async def crash_group(
    session: AsyncSession, group_id: uuid.UUID, *, today: date, filters: Filters
) -> GroupDetail | None:
    group = await session.get(CrashGroup, group_id)
    if group is None:
        return None
    days = filters.days if filters.days in DETAIL_DAYS else None
    since = today - timedelta(days=days - 1) if days else None
    reports = list(
        await session.scalars(
            _crash_conditions(
                select(CrashReportRow).where(CrashReportRow.group_id == group_id),
                filters,
                since=since,
            ).order_by(CrashReportRow.received_on.desc())
        )
    )
    filtered = bool(filters.builds() or filters.version)

    # Reports per day: from the group's daily counts (kept after its reports are deleted)
    # unless a filter needs the reports themselves.
    first = since or max(group.first_seen, today - timedelta(days=89))
    first = min(first, today - timedelta(days=13))
    if filtered:
        per_day: dict[date, int] = Counter(r.received_on for r in reports)
    else:
        stored = await session.execute(
            select(CrashGroupDay.day, CrashGroupDay.n).where(
                CrashGroupDay.group_id == group_id, CrashGroupDay.day >= first
            )
        )
        per_day = dict(stored.all())
    span = [first + timedelta(days=i) for i in range((today - first).days + 1)]
    values = [per_day.get(d, 0) for d in span]
    titles = [short_day(d) for d in span]
    n = len(span)
    chart = (
        responsive(
            day_bars(
                values, titles, sorted({0, n // 2, n - 1}), label="Reports per day", width=442
            ),
            day_bars(values, titles, [0, n - 1], label="Reports per day", width=326, height=150),
        )
        if any(values)
        else None
    )

    # Versions affected, with reports per 1,000 installs on each this month.
    month = month_of(today)
    month_versions = await _totals(session, MONTH, month, "version")
    shown_versions = suppress_marked(month_versions)
    by_version = Counter(r.app for r in reports)
    month_by_version = Counter(r.app for r in reports if r.received_on >= month)
    listed = sorted(
        {*sorted(month_versions, key=_version_key, reverse=True)[:4], *by_version},
        key=_version_key,
        reverse=True,
    )[:6]
    widest = max(by_version.values(), default=1)
    version_rows = []
    for v in listed:
        installs = shown_versions.get(v, Shown(None, "small")).n
        rate = (
            f"{month_by_version[v] / installs * 1000:.1f} per 1,000"
            if month_by_version[v] and installs
            else ""
        )
        version_rows.append(VersionRow(v, by_version[v], round(by_version[v] / widest * 100), rate))

    all_30 = await _report_count(session, Filters(), today - timedelta(days=29))
    group_30 = sum(1 for r in reports if r.received_on >= today - timedelta(days=29))
    count = len(reports) if (filtered or days) else max(group.reports, len(reports))
    affected = sorted(by_version, key=_version_key, reverse=True)
    if len(affected) == 1:
        older = [
            v
            for v in sorted(month_versions, key=_version_key, reverse=True)
            if _version_key(v) < _version_key(affected[0])
        ]
        versions_note = f"{affected[0]} only" + (f"; not seen in {older[0]}" if older else "")
    elif affected:
        versions_note = version_span(affected)
    else:
        versions_note = "Reports older than 90 days are deleted"
    earliest = min(reports, key=lambda r: r.received_on) if reports else None
    tiles = [
        Tile(
            "Reports",
            f"{count:,}",
            f"{group_30 / all_30 * 100:.0f}% of all reports in 30 days"
            if all_30
            else "None in the last 30 days",
            lead=True,
        ),
        Tile(
            "First seen",
            short_day(group.first_seen),
            f"in {earliest.app} (build {earliest.build_number})"
            if earliest and group.first_seen >= today - timedelta(days=89)
            else "its first reports are deleted after 90 days",
        ),
        Tile("Last seen", short_day(group.last_seen), ago(group.last_seen, today)),
        Tile("Versions affected", str(len(affected)), versions_note),
    ]

    def facet(values: list[str]) -> list[Bar]:
        rows = bars(Counter(values).most_common(), suppressed=False)
        return [Bar(r.label, r.shown, r.width, r.share) for r in rows]

    systems = [r.os for r in reports]
    system_label = (
        "Android"
        if systems and all(s.startswith("Android") for s in systems)
        else "iOS"
        if systems and all(s.startswith("iOS") for s in systems)
        else "System"
    )
    latest = reports[0] if reports else None
    return GroupDetail(
        group=group,
        filters=replace(filters, days=days),
        tiles=tiles,
        chart=chart,
        versions=version_rows,
        stack=[frame(line) for line in (latest.stack if latest else group.frames)],
        decoded=bool(latest and latest.decoded),
        facets=[
            ("Build", facet([BUILD_NAMES.get(r.build, r.build) for r in reports])),
            (system_label, facet(systems)),
            ("CPU", facet([r.cpu for r in reports])),
        ]
        if reports
        else [],
        example=json.dumps(payload(latest), indent=1) if latest else None,
        received=short_day(latest.received_on) if latest else None,
        is_new=group.first_seen >= today - timedelta(days=NEW_DAYS - 1),
    )


# Notices and federated learning.


@dataclass
class NoticeDetail:
    title: str
    body: str
    kind: str
    must_update: bool
    status: str
    builds: str
    reach: str
    reach_7: str
    first: str
    last: str
    chart: Markup


async def notices_page(session: AsyncSession, *, today: date) -> list[NoticeDetail]:
    since = today - timedelta(days=29)
    notices = list(await session.scalars(select(AppNotice).order_by(AppNotice.created_at.desc())))
    reach = await session.execute(select(NoticeReach.notice_id, NoticeReach.day, NoticeReach.n))
    by_notice: dict[uuid.UUID, dict[date, int]] = defaultdict(dict)
    for notice_id, day, n in reach.all():
        by_notice[notice_id][day] = n
    now = datetime.now(UTC)
    out = []
    for notice in notices:
        days = by_notice.get(notice.id, {})
        total = sum(days.values())
        week = sum(n for d, n in days.items() if d >= today - timedelta(days=6))
        if notice.disabled_at:
            status = "turned off"
        elif notice.ends_at and notice.ends_at <= now:
            status = "ended"
        elif notice.starts_at > now:
            status = "scheduled"
        else:
            status = "showing"
        series = [days.get(since + timedelta(days=i)) for i in range(30)]
        out.append(
            NoticeDetail(
                title=notice.title,
                body=notice.body,
                kind="must update" if notice.required_reason else notice.kind,
                must_update=notice.required_reason is not None,
                status=status,
                builds=", ".join(BUILD_NAMES.get(b, b) for b in notice.builds),
                reach=number(total if total >= THRESHOLD else None) if days else "None yet",
                reach_7=number(week if week >= THRESHOLD else None),
                first=short_day(min(days)) if days else "",
                last=short_day(max(days)) if days else "",
                chart=mini_bars(
                    [n if n is not None and n >= THRESHOLD else (None if n else 0) for n in series],
                    width=180,
                    height=32,
                ),
            )
        )
    return out


# Tables for CSV export: the shown values only, never the stored ones.


def cell_text(s: Shown | None) -> str:
    if s is None:
        return ""
    if s.n is None:
        return "hidden" if s.why == "secondary" else "<10"
    return str(s.n)


def installs_csv(data: Installs) -> list[list[str]]:
    rows = [[DIM_NAMES[data.dim][:-1] if data.dim != "country" else "Country", "Installs", "Share"]]
    rows += [[r.label, cell_text(r.shown), r.share] for r in data.rows]
    return rows


def adoption_csv(data: Installs) -> list[list[str]]:
    rows = [["Version", *(f"{m:%Y-%m}" for m in data.adoption_months)]]
    rows += [[r.version, *(cell_text(c[0]) if c else "" for c in r.cells)] for r in data.adoption]
    return rows


def monthly_csv(data: Overview) -> list[list[str]]:
    first, second = data.trend_legend or ("", "")
    rows = [["Month", "Installs", *([first.split(" (")[0], second] if data.trend_legend else [])]]
    for r in data.trend_rows:
        rows.append(
            [
                r.month,
                cell_text(r.total),
                *([cell_text(r.first), cell_text(r.second)] if data.trend_legend else []),
            ]
        )
    return rows


# Downloads, the full list.


@dataclass
class DownloadRow:
    name: str
    n: int
    previous: int | None
    change: str
    width: int
    share: str


@dataclass
class DownloadList:
    as_of: date | None
    total: int
    rows: list[DownloadRow]
    files_n: int  # app files in the snapshot
    zeros_n: int  # of those, at 0 in the window
    q: str
    sort: str
    zeros: bool


DOWNLOAD_SORTS = ("downloads", "name", "change")


def download_list(
    downloads: Downloads | None, *, q: str = "", sort: str = "downloads", zeros: bool = False
) -> DownloadList:
    files = downloads.files if downloads else []
    widest = max((f.n for f in files), default=0)
    total = sum(f.n for f in files)
    picked = [f for f in files if (zeros or f.n) and (not q or q.lower() in f.name.lower())]
    if sort == "name":
        picked.sort(key=lambda f: f.name)
    elif sort == "change":
        picked.sort(key=lambda f: -((f.n - f.previous) if f.previous is not None else -1e9))
    rows = [
        DownloadRow(
            f.name,
            f.n,
            f.previous,
            delta(f.n, f.previous),
            max(round(f.n / widest * 100), 2) if widest and f.n else 0,
            share(f.n, total) if f.n else "·",
        )
        for f in picked
    ]
    return DownloadList(
        as_of=downloads.as_of if downloads else None,
        total=total,
        rows=rows,
        files_n=len(files),
        zeros_n=sum(1 for f in files if not f.n),
        q=q,
        sort=sort if sort in DOWNLOAD_SORTS else "downloads",
        zeros=zeros,
    )
