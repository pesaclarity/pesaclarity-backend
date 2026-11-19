"""Charts drawn on the server as inline SVG: no scripts, no third-party libraries.

Each mark carries a ``<title>``, so hovering shows its figure without a script. Charts are
drawn for a given width and the page shows a wide or a narrow drawing (``responsive``), so
axis text stays the same size on a phone instead of shrinking with the drawing. Colours are
the page's tokens: ``--s1`` (the lead series) and ``--s2`` (the rest).
"""

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from html import escape

from markupsafe import Markup

_STEPS = (1.0, 2.0, 2.5, 5.0, 10.0)
S1 = "var(--s1)"
S2 = "var(--s2)"


def _nice_step(top: float, intervals: int) -> float:
    raw = max(top, 1.0) / intervals
    power = 10.0 ** math.floor(math.log10(raw))
    return next(s * power for s in _STEPS if s * power >= raw)


def _scale(peak: float, intervals: int = 4) -> tuple[float, int]:
    """A tick step and the number of steps that cover ``peak`` (whole numbers only)."""
    step = max(_nice_step(peak, intervals), 1.0)
    return step, max(1, math.ceil(max(peak, 1.0) / step))


def _tick(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:g}k"
    return f"{value:g}"


def _n(value: int) -> str:
    return f"{value:,}"


def _top_rounded(x: float, y: float, w: float, h: float, r: float = 4.0) -> str:
    """A bar path with rounded top corners, anchored square on the baseline."""
    r = max(0.0, min(r, w / 2, h))
    return (
        f"M{x:.1f},{y + h:.1f}L{x:.1f},{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}"
        f"L{x + w - r:.1f},{y:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}"
        f"L{x + w:.1f},{y + h:.1f}Z"
    )


def _grid(
    parts: list[str],
    step: float,
    steps: int,
    y: Callable[[float], float],
    left: float,
    right: float,
) -> None:
    for k in range(steps + 1):
        yy = y(step * k)
        parts.append(
            f'<line x1="{left:.0f}" x2="{right:.0f}" y1="{yy:.1f}" y2="{yy:.1f}" '
            f'stroke="var(--grid)"/><text x="{left - 8:.0f}" y="{yy + 4:.1f}" '
            f'text-anchor="end">{_tick(step * k)}</text>'
        )


def responsive(wide: Markup, narrow: Markup) -> Markup:
    return Markup(  # noqa: S704 - both are our own SVG
        f'<div class="chart c-wide">{wide}</div><div class="chart c-narrow">{narrow}</div>'
    )


@dataclass(frozen=True, slots=True)
class Segment:
    """One part of a stacked bar. ``n`` is ``None`` when hidden; ``name`` is for its title."""

    n: int | None
    name: str
    colour: str


def stacked_bars(
    labels: Sequence[str],
    stacks: Sequence[Sequence[Segment]],
    totals: Sequence[int | None],
    *,
    label: str,
    width: int,
    height: int = 220,
) -> Markup:
    """Bars of ``totals`` split into segments, bottom first. A hidden segment is not drawn
    apart: its bar is one neutral block with the shown total on top."""
    left, right, top, bottom = 40.0, width - 4.0, 20.0, height - 22.0
    peak = max((t or 0 for t in totals), default=0)
    step, steps = _scale(peak)
    y_max = step * steps
    pitch = (right - left) / max(len(labels), 1)
    bar = min(pitch * 0.58, 56.0)

    def y(v: float) -> float:
        return bottom - (bottom - top) * v / y_max

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{escape(label)}">']
    _grid(parts, step, steps, y, left, right)
    for i, (text, segments, total) in enumerate(zip(labels, stacks, totals, strict=True)):
        x = left + pitch * i + (pitch - bar) / 2
        if total is None:
            parts.append(
                f'<rect x="{x:.1f}" y="{bottom - 5:.1f}" width="{bar:.1f}" height="5" '
                f'fill="var(--hatch)"><title>{escape(text)}: under 10</title></rect>'
                f'<text class="v" x="{x + bar / 2:.1f}" y="{bottom - 10:.1f}" '
                'text-anchor="middle">&lt;10</text>'
            )
        elif any(s.n is None for s in segments):
            h = bottom - y(total)
            parts.append(
                f'<path d="{_top_rounded(x, y(total), bar, h)}" fill="{S2}"><title>'
                f"{escape(text)}: {_n(total)} (split hidden to protect a small cell)"
                "</title></path>"
            )
        else:
            base = 0
            drawn = [s for s in segments if s.n]
            for k, s in enumerate(drawn):
                n = s.n or 0
                y0, y1 = y(base), y(base + n)
                last = k == len(drawn) - 1
                tip = f"{escape(text)}: {escape(s.name)} {_n(n)}"
                if last:
                    parts.append(
                        f'<path d="{_top_rounded(x, y1, bar, y0 - y1)}" fill="{s.colour}">'
                        f"<title>{tip}</title></path>"
                    )
                else:  # a 2px surface gap above each lower segment
                    parts.append(
                        f'<rect x="{x:.1f}" y="{y1 + 2:.1f}" width="{bar:.1f}" '
                        f'height="{max(y0 - y1 - 2, 0):.1f}" fill="{s.colour}">'
                        f"<title>{tip}</title></rect>"
                    )
                base += n
        if total is not None:
            parts.append(
                f'<text class="v" x="{x + bar / 2:.1f}" y="{y(total) - 6:.1f}" '
                f'text-anchor="middle">{_n(total)}</text>'
            )
        parts.append(
            f'<text x="{x + bar / 2:.1f}" y="{height - 6}" text-anchor="middle">'
            f"{escape(text)}</text>"
        )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - numbers and escaped labels only


def line_chart(
    values: Sequence[int | None],
    x_labels: Sequence[tuple[int, str]],
    *,
    label: str,
    titles: Sequence[str],
    width: int,
    height: int = 200,
    average: Sequence[float | None] | None = None,
) -> Markup:
    """A line over ``values``. ``None`` is a day under the threshold: a gap, marked with a
    shaded band and "<10". ``average`` is drawn dashed in the second series colour."""
    left, right, top, bottom = 40.0, width - 6.0, 12.0, height - 22.0
    peak = max((v for v in values if v is not None), default=0)
    step, steps = _scale(peak, 3)
    y_max = step * steps
    n = len(values)

    def x(i: int) -> float:
        return left if n <= 1 else left + (right - left) * i / (n - 1)

    def y(v: float) -> float:
        return bottom - (bottom - top) * v / y_max

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{escape(label)}">']
    _grid(parts, step, steps, y, left, right)
    for i, v in enumerate(values):
        if v is None:
            parts.append(
                f'<rect x="{x(i) - 4:.1f}" y="{top:.0f}" width="8" height="{bottom - top:.0f}" '
                f'fill="var(--soft)"><title>{escape(titles[i])}: under 10, hidden</title></rect>'
                f'<text x="{x(i):.1f}" y="{top + 12:.0f}" text-anchor="middle">&lt;10</text>'
            )
    if average:
        points = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(average) if v is not None)
        parts.append(
            f'<polyline points="{points}" fill="none" stroke="{S2}" stroke-width="1.5" '
            'stroke-dasharray="4 3"/>'
        )
    run: list[str] = []
    for i, v in enumerate([*values, None]):
        if v is None:
            if len(run) == 1:
                cx, cy = run[0].split(",")
                parts.append(f'<circle cx="{cx}" cy="{cy}" r="2.5" fill="{S1}"/>')
            elif run:
                parts.append(
                    f'<polyline points="{" ".join(run)}" fill="none" stroke="{S1}" '
                    'stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
                )
            run = []
        else:
            run.append(f"{x(i):.1f},{y(v):.1f}")
    for i, v in enumerate(values):
        if v is not None:  # a hit target bigger than the line, for the title
            parts.append(
                f'<circle cx="{x(i):.1f}" cy="{y(v):.1f}" r="7" fill="transparent">'
                f"<title>{escape(titles[i])}: {_n(v)}</title></circle>"
            )
    if values and values[-1] is not None:
        parts.append(
            f'<circle cx="{x(n - 1):.1f}" cy="{y(values[-1]):.1f}" r="4" fill="{S1}" '
            'stroke="var(--surface)" stroke-width="2"/>'
        )
    for index, text in x_labels:
        anchor = "start" if index == 0 else "end" if index == n - 1 else "middle"
        parts.append(
            f'<text x="{x(index):.1f}" y="{height - 6}" text-anchor="{anchor}">'
            f"{escape(text)}</text>"
        )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - numbers and escaped labels only


def day_bars(
    values: Sequence[int],
    titles: Sequence[str],
    marks: Sequence[int],
    *,
    label: str,
    width: int,
    height: int = 170,
) -> Markup:
    """Counts per day as bars (reports are whole, separate events, not a level)."""
    left, right, top, bottom = 28.0, width - 2.0, 10.0, height - 22.0
    step, steps = _scale(max(values, default=0), 2)
    y_max = step * steps
    n = max(len(values), 1)
    pitch = (right - left) / n
    bar = max(pitch - 2, 1.5)

    def y(v: float) -> float:
        return bottom - (bottom - top) * v / y_max

    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{escape(label)}">']
    _grid(parts, step, steps, y, left + 2, right)
    for i, v in enumerate(values):
        x = left + pitch * i + 1
        if v:
            reports = f"{v} report{'s' if v != 1 else ''}"
            parts.append(
                f'<path d="{_top_rounded(x, y(v), bar, bottom - y(v), 2)}" fill="{S1}">'
                f"<title>{escape(titles[i])}: {reports}</title></path>"
            )
        else:
            parts.append(
                f'<rect x="{x:.1f}" y="{bottom - 1:.1f}" width="{bar:.1f}" height="1" '
                'fill="var(--s2-soft)"/>'
            )
    for i in marks:
        anchor = "start" if i == 0 else "end" if i == n - 1 else "middle"
        xx = (
            left + pitch * i + (0 if anchor == "start" else pitch if anchor == "end" else pitch / 2)
        )
        parts.append(
            f'<text x="{xx:.1f}" y="{height - 6}" text-anchor="{anchor}">{escape(titles[i])}</text>'
        )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - numbers and escaped labels only


def sparkline(values: Sequence[int], *, peak: int, width: int = 96, height: int = 24) -> Markup:
    """Reports per day as tiny bars, on a scale shared by every row (``peak``), so a group
    with one report does not look like one with fourteen."""
    top = max(peak, 1)
    n = max(len(values), 1)
    pitch = width / n
    parts = [
        f'<svg class="spark" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        'aria-hidden="true">'
    ]
    for i, v in enumerate(values):
        h = (height - 2) * v / top if v else 1.0
        fill = S1 if v else "var(--s2-soft)"
        parts.append(
            f'<rect x="{i * pitch:.1f}" y="{height - h:.1f}" width="{max(pitch - 1, 1):.1f}" '
            f'height="{h:.1f}" fill="{fill}"/>'
        )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - numbers only


def mini_bars(values: Sequence[int | None], *, width: int = 150, height: int = 40) -> Markup:
    """A build's months, the newest in the lead colour; a hidden month is a low stub."""
    peak = max((v for v in values if v), default=1)
    n = max(len(values), 1)
    pitch = width / n
    bar = pitch * 0.62
    parts = [
        f'<svg class="mini" viewBox="0 0 {width} {height}" preserveAspectRatio="none" '
        'aria-hidden="true">'
    ]
    for i, v in enumerate(values):
        x = i * pitch + (pitch - bar) / 2
        if v is None:
            parts.append(
                f'<rect x="{x:.1f}" y="{height - 5}" width="{bar:.1f}" height="5" '
                'fill="var(--hatch)"/>'
            )
        else:
            h = (height - 2) * v / peak
            fill = S1 if i == n - 1 else S2
            parts.append(
                f'<rect x="{x:.1f}" y="{height - h:.1f}" width="{bar:.1f}" height="{h:.1f}" '
                f'rx="2" fill="{fill}"/>'
            )
    parts.append("</svg>")
    return Markup("".join(parts))  # noqa: S704 - numbers only
