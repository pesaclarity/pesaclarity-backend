"""Charts drawn on the server as inline SVG: no scripts, no third-party libraries."""

import math
from collections.abc import Sequence
from html import escape

from markupsafe import Markup

_STEPS = (1.0, 2.0, 2.5, 5.0, 10.0)


def _nice_step(top: float, intervals: int) -> float:
    raw = max(top, 1.0) / intervals
    power = 10.0 ** math.floor(math.log10(raw))
    return next(s * power for s in _STEPS if s * power >= raw)


def _fmt(value: float) -> str:
    return f"{value:,.0f}" if value >= 10 or value == int(value) else f"{value:g}"


def line_chart(
    values: Sequence[int | None],
    x_labels: Sequence[tuple[int, str]],
    *,
    label: str,
    width: int = 760,
    height: int = 220,
) -> Markup:
    """A line over ``values``; ``None`` leaves a gap (a day under the threshold).

    ``x_labels`` are ``(index, text)`` pairs placed under those points.
    """
    left, right, top, bottom = 44.0, width - 8.0, 10.0, height - 24.0
    intervals = 4
    peak = max((v for v in values if v is not None), default=0)
    step = _nice_step(peak, intervals)
    y_max = step * intervals
    n = len(values)

    def x(i: int) -> float:
        return left if n <= 1 else left + (right - left) * i / (n - 1)

    def y(v: float) -> float:
        return bottom - (bottom - top) * v / y_max

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="{escape(label)}">'
    ]
    for k in range(intervals + 1):
        level = step * k
        yy = y(level)
        parts.append(
            f'<line x1="{left:.0f}" x2="{right:.0f}" y1="{yy:.1f}" y2="{yy:.1f}" '
            f'stroke="var(--border)"/><text x="{left - 8:.0f}" y="{yy + 4:.1f}" '
            f'text-anchor="end">{_fmt(level)}</text>'
        )
    run: list[str] = []
    for i, v in enumerate([*values, None]):
        if v is None:
            if len(run) == 1:
                cx, cy = run[0].split(",")
                parts.append(f'<circle cx="{cx}" cy="{cy}" r="2.5" fill="var(--link)"/>')
            elif run:
                parts.append(
                    f'<polyline points="{" ".join(run)}" fill="none" stroke="var(--link)" '
                    'stroke-width="2.2" stroke-linejoin="round"/>'
                )
            run = []
        else:
            run.append(f"{x(i):.1f},{y(v):.1f}")
    for index, text in x_labels:
        anchor = "start" if index == 0 else "end" if index == n - 1 else "middle"
        parts.append(
            f'<text x="{x(index):.1f}" y="{height - 6}" text-anchor="{anchor}">'
            f"{escape(text)}</text>"
        )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - numbers and escaped labels only


def sparkline(values: Sequence[int], *, width: int = 120, height: int = 28) -> Markup:
    peak = max(values, default=0) or 1
    n = len(values)
    points = " ".join(
        f"{1 + (width - 2) * i / max(n - 1, 1):.1f},{height - 2 - (height - 4) * v / peak:.1f}"
        for i, v in enumerate(values)
    )
    return Markup(  # noqa: S704 - numbers only
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'aria-hidden="true"><polyline points="{points}" fill="none" stroke="var(--link)" '
        'stroke-width="1.6"/></svg>'
    )
