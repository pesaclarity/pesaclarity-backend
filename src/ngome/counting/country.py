"""Country from the caller's address, looked up in memory and then dropped.

The database is DB-IP IP to Country Lite (CC BY 4.0, "IP Geolocation by DB-IP"). It is off
until its licence is confirmed (``NGOME_COUNTRY_LOOKUP_ENABLED``). The address is never
stored, logged or hashed: only the two-letter code that comes back is used, and only for the
month's totals.
"""

import ipaddress
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

import maxminddb

from ngome.core.config import Settings

# CLDR's code for an unknown region: addresses the database does not place.
UNKNOWN = "ZZ"
ATTRIBUTION = "IP Geolocation by DB-IP"
ATTRIBUTION_URL = "https://db-ip.com"

# The tz table's names are for choosing a time zone; these read better on a dashboard.
_NAME_OVERRIDES = {"GB": "United Kingdom", UNKNOWN: "Unknown"}


class CountryLookup(Protocol):
    def country(self, address: str | None) -> str:
        """The ISO 3166 alpha-2 code for ``address``, or :data:`UNKNOWN`."""


class MmdbCountryLookup:
    """Reads a country MMDB file (DB-IP Lite's layout) fully into memory."""

    def __init__(self, path: Path) -> None:
        self._reader = maxminddb.open_database(str(path), mode=maxminddb.MODE_MEMORY)

    def country(self, address: str | None) -> str:
        if not address:
            return UNKNOWN
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return UNKNOWN
        if not ip.is_global:
            return UNKNOWN
        record: Any = self._reader.get(ip)
        code = record.get("country", {}).get("iso_code") if isinstance(record, dict) else None
        if isinstance(code, str) and len(code) == 2 and code.isalpha():
            return code.upper()
        return UNKNOWN

    def close(self) -> None:
        self._reader.close()


def build_country_lookup(settings: Settings) -> CountryLookup | None:
    """The lookup, or ``None`` while country lookup is off (no country totals are kept)."""
    if not settings.country_lookup_enabled or settings.country_db_path is None:
        return None
    return MmdbCountryLookup(settings.country_db_path)


@cache
def _names() -> dict[str, str]:
    text = resources.files("ngome.counting").joinpath("iso3166.tab").read_text("utf-8")
    names = {}
    for line in text.splitlines():
        if line.startswith("#") or "\t" not in line:
            continue
        code, name = line.split("\t", 1)
        names[code] = name
    names.update(_NAME_OVERRIDES)
    return names


def country_name(code: str) -> str:
    return _names().get(code, code)
