"""GitHub release downloads, from the daily snapshot in pesaclarity/.github.

The ``Download stats`` workflow appends GitHub's public download counters (running totals per
release file) to ``stats/downloads.csv`` on the ``stats`` branch once a day. The file is
public, so no token is needed. It is read at most every few hours and kept in memory.
"""

import csv
import io
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Protocol

import httpx

from ngome.core.logging import get_logger

log = get_logger(__name__)

CACHE_SECONDS = 6 * 3600
MAX_CSV_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Downloads:
    as_of: date
    total: int
    by_file: list[tuple[str, int]]


class DownloadsSource(Protocol):
    async def csv_text(self) -> str | None:
        """The CSV, or ``None`` if it cannot be read now."""


class HttpDownloadsSource:
    def __init__(self, url: str) -> None:
        self._url = url
        self._cached: tuple[float, str] | None = None

    async def csv_text(self) -> str | None:
        if self._cached and time.monotonic() - self._cached[0] < CACHE_SECONDS:
            return self._cached[1]
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(self._url)
            response.raise_for_status()
            if len(response.content) > MAX_CSV_BYTES:
                return None
            text = response.text
        except httpx.HTTPError:
            log.warning("downloads.unavailable")
            return self._cached[1] if self._cached else None
        self._cached = (time.monotonic(), text)
        return text


def summarise(text: str, days: int = 30) -> Downloads | None:
    """Downloads per file name in the ``days`` before the newest snapshot, across releases.

    The counters are running totals, so a file's downloads in the window are its newest total
    less its total on the day the window starts (zero if it was not out yet).
    """
    totals: dict[tuple[str, str], dict[date, int]] = defaultdict(dict)
    for row in csv.DictReader(io.StringIO(text)):
        try:
            day = date.fromisoformat(row["date"])
            count = int(row["downloads"])
        except (KeyError, TypeError, ValueError):
            continue
        totals[(row.get("release") or "", row.get("file") or "")][day] = count
    if not totals:
        return None
    as_of = max(day for series in totals.values() for day in series)
    start = as_of - timedelta(days=days)
    by_file: dict[str, int] = defaultdict(int)
    for (_, name), series in totals.items():
        newest = series[max(series)]
        before = [day for day in series if day <= start]
        base = series[max(before)] if before else 0
        by_file[name] += max(newest - base, 0)
    ordered = sorted(by_file.items(), key=lambda item: (-item[1], item[0]))
    return Downloads(as_of=as_of, total=sum(by_file.values()), by_file=ordered)
