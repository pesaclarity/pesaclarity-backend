"""Hiding small numbers on display. Stored totals stay exact; only what is shown changes.

A cell is hidden for one of two reasons, and the dashboard says which: it is under the
threshold ("<10"), or it is the next smallest cell, hidden so the total cannot give the
small one away ("hidden"). Sums shown beside a table (such as "earlier releases" in a
stacked bar) go through :func:`derived` so they cannot give a hidden cell away either.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

THRESHOLD = 10

Why = Literal["small", "secondary"]


@dataclass(frozen=True, slots=True)
class Shown:
    """A count as displayed: ``n`` is ``None`` when hidden, and ``why`` says why."""

    n: int | None
    why: Why | None = None

    @property
    def hidden(self) -> bool:
        return self.n is None


def suppress_marked(cells: Mapping[str, int], threshold: int = THRESHOLD) -> dict[str, Shown]:
    """Each cell as shown. A cell under ``threshold`` is hidden ("small"). When exactly one
    is hidden, the next smallest is hidden too ("secondary"), so the total cannot give the
    hidden one away."""
    shown = {k: Shown(v) if v >= threshold else Shown(None, "small") for k, v in cells.items()}
    small = [k for k, s in shown.items() if s.hidden]
    if len(small) == 1:
        candidates = sorted((v, k) for k, v in cells.items() if not shown[k].hidden)
        if candidates:
            shown[candidates[0][1]] = Shown(None, "secondary")
    return shown


def suppress(cells: Mapping[str, int], threshold: int = THRESHOLD) -> dict[str, int | None]:
    """Each cell's count, or ``None`` where it must not be shown."""
    return {k: s.n for k, s in suppress_marked(cells, threshold).items()}


def derived(
    shown: Mapping[str, Shown],
    raw: Mapping[str, int],
    members: Iterable[str],
    threshold: int = THRESHOLD,
) -> Shown:
    """A sum of some cells of a suppressed table, as it may be shown beside that table.

    Hidden when it is under ``threshold``, or when it holds exactly one hidden cell: the
    sum less its shown members would then be that cell.
    """
    keys = [k for k in members if k in raw]
    total = sum(raw[k] for k in keys)
    if total < threshold:
        return Shown(None, "small")
    if sum(1 for k in keys if shown[k].hidden) == 1:
        return Shown(None, "secondary")
    return Shown(total)


def pair(a: int, b: int, threshold: int = THRESHOLD) -> tuple[Shown, Shown]:
    """Two parts of a shown total (such as a stacked bar's two segments). If either is
    hidden, so is the other, since the total gives one from the other."""
    if a < threshold or b < threshold:
        return (
            Shown(None, "small" if a < threshold else "secondary"),
            Shown(None, "small" if b < threshold else "secondary"),
        )
    return Shown(a), Shown(b)


def shown_total(n: int, threshold: int = THRESHOLD) -> int | None:
    """A single figure (a total or a tile): ``None`` below the threshold."""
    return n if n >= threshold else None
