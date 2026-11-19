"""Hiding small numbers on display. Stored totals stay exact; only what is shown changes."""

from collections.abc import Mapping

THRESHOLD = 10


def suppress(cells: Mapping[str, int], threshold: int = THRESHOLD) -> dict[str, int | None]:
    """Each cell's count, or ``None`` where it must show as "<10".

    A cell under ``threshold`` is hidden. When exactly one is hidden, the next smallest is
    hidden too, so the total cannot give the hidden one away.
    """
    shown: dict[str, int | None] = {k: (v if v >= threshold else None) for k, v in cells.items()}
    hidden = [k for k, v in shown.items() if v is None]
    if len(hidden) == 1:
        candidates = sorted((v, k) for k, v in shown.items() if v is not None)
        if candidates:
            shown[candidates[0][1]] = None
    return shown


def shown_total(n: int, threshold: int = THRESHOLD) -> int | None:
    """A single figure (a total or a tile): ``None`` below the threshold."""
    return n if n >= threshold else None
