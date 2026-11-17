"""Semantic version strings, compared the SemVer way (a pre-release sorts before its
release; build metadata is ignored)."""

import re
from functools import total_ordering

VERSION_PATTERN = (
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)
_VERSION = re.compile(VERSION_PATTERN)
MAX_VERSION_LENGTH = 64


@total_ordering
class Version:
    __slots__ = ("core", "pre")

    def __init__(self, text: str) -> None:
        match = _VERSION.match(text) if len(text) <= MAX_VERSION_LENGTH else None
        if match is None:
            raise ValueError(f"not a version: {text!r}")
        self.core = (int(match[1]), int(match[2]), int(match[3]))
        self.pre: tuple[str, ...] = tuple(match[4].split(".")) if match[4] else ()

    def _key(self) -> tuple[tuple[int, int, int], int, tuple[tuple[int, int, str], ...]]:
        # No pre-release sorts after any pre-release of the same core.
        parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pre)
        return (self.core, 0 if self.pre else 1, parts)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._key() == other._key()

    def __lt__(self, other: "Version") -> bool:
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())


def is_version(text: str) -> bool:
    try:
        Version(text)
    except ValueError:
        return False
    return True
