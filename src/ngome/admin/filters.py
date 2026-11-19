"""The dashboard's filters, read the same way on every page and carried from page to page.

Values that are not choices are dropped with a note on the page, never silently.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import date
from typing import Any, Literal
from urllib.parse import urlencode

from ngome.appstatus.versions import Version

BUILD_NAMES = {"play": "Play", "foss": "F-Droid", "website": "Website APK", "ios": "iPhone"}
PLATFORM_NAMES = {"android": "Android", "ios": "iPhone"}
PLATFORM_BUILDS = {"android": ("play", "foss", "website"), "ios": ("ios",)}
DAY_CHOICES = (7, 30, 90)
DIMENSIONS = ("country", "version", "build")
SORTS = ("reports", "newest", "last")
SPLITS = ("release", "build")
_MONTH = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")

Dimension = Literal["country", "version", "build"]


@dataclass(frozen=True)
class Filters:
    month: date | None = None
    days: int | None = None  # None: since first seen (a crash group's page)
    build: str | None = None
    platform: str | None = None
    version: str | None = None
    dim: str = "country"
    sort: str = "reports"
    split: str = "release"
    notes: tuple[str, ...] = field(default=(), compare=False)

    def builds(self) -> tuple[str, ...] | None:
        """The builds the filters cover, or ``None`` for all of them."""
        if self.build:
            return (self.build,)
        if self.platform:
            return PLATFORM_BUILDS[self.platform]
        return None

    def query(self, **changes: object) -> str:
        """This page's filters as a query string, with ``changes``; ``None`` drops one."""
        values = replace(self, **changes)  # type: ignore[arg-type]
        params: dict[str, str] = {}
        if values.month:
            params["month"] = f"{values.month:%Y-%m}"
        if values.days is not None:
            params["days"] = str(values.days)
        elif "days" in changes:
            params["days"] = "all"
        for key in ("build", "platform", "version"):
            value = getattr(values, key)
            if value:
                params[key] = value
        if values.dim != "country":
            params["dim"] = values.dim
        if values.sort != "reports":
            params["sort"] = values.sort
        if values.split != "release":
            params["split"] = values.split
        return urlencode(params)

    def carried(self) -> str:
        """What a crash group's page keeps from the list: build, platform and version."""
        return urlencode(
            {k: v for k in ("build", "platform", "version") if (v := getattr(self, k))}
        )


def _choice(
    params: Mapping[str, str],
    key: str,
    allowed: tuple[str, ...],
    name: str,
    notes: list[str],
    default: str | None = "",
) -> Any:
    """``params[key]`` if it is one of ``allowed``; else the default (the first choice
    unless ``default`` is given), with a note when something else was asked for."""
    fallback = allowed[0] if default == "" else default
    value = params.get(key) or None
    if value is None:
        return fallback
    if value not in allowed:
        notes.append(f"“{value[:24]}” is not a choice for {name}, so it is not applied.")
        return fallback
    return value


def parse(
    params: Mapping[str, str],
    *,
    default_days: int | None = 30,
    allow_all_days: bool = False,
    day_choices: tuple[int, ...] = DAY_CHOICES,
) -> Filters:
    notes: list[str] = []

    def bad(name: str, value: str) -> None:
        notes.append(f"“{value[:24]}” is not a choice for {name}, so it is not applied.")

    month = None
    if raw := params.get("month"):
        if _MONTH.match(raw):
            month = date.fromisoformat(f"{raw}-01")
        else:
            bad("month", raw)
    days = default_days
    if raw := params.get("days"):
        if raw == "all" and allow_all_days:
            days = None
        elif raw.isdigit() and int(raw) in day_choices:
            days = int(raw)
        else:
            bad("days", raw)
    build = _choice(params, "build", tuple(BUILD_NAMES), "build", notes, None)
    platform = _choice(params, "platform", tuple(PLATFORM_NAMES), "platform", notes, None)
    if build and platform and build not in PLATFORM_BUILDS[platform]:
        notes.append(
            f"{BUILD_NAMES[build]} is not an {PLATFORM_NAMES[platform]} build, so the "
            "platform is not applied."
        )
        platform = None
    version = params.get("version") or None
    if version:
        try:
            Version(version)
        except ValueError:
            bad("version", version)
            version = None
    dim = _choice(params, "dim", DIMENSIONS, "breakdown", notes)
    sort = _choice(params, "sort", SORTS, "sort", notes)
    split = _choice(params, "split", SPLITS, "split", notes)
    return Filters(month, days, build, platform, version, dim, sort, split, tuple(notes))


def options(
    path: str, filters: Filters, key: str, items: list[tuple[object, str]], **also: object
) -> list[tuple[str, str, bool]]:
    """Links for one filter's choices, keeping the others: (href, text, chosen)."""
    current = getattr(filters, key)
    return [
        (f"{path}?{filters.query(**{key: value}, **also)}".rstrip("?"), text, current == value)
        for value, text in items
    ]


BUILD_ITEMS: list[tuple[object, str]] = [(None, "All builds"), *BUILD_NAMES.items()]
PLATFORM_ITEMS: list[tuple[object, str]] = [(None, "All"), *PLATFORM_NAMES.items()]


def month_items(months: list[date]) -> list[tuple[object, str]]:
    return [(m, f"{m:%B %Y}") for m in months]
