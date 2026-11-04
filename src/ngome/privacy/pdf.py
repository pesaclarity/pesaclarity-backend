"""A plain one-column PDF of a text document, with no dependencies.

Uses the built-in Helvetica font, which covers Latin-1; other characters are written as their
nearest Latin-1 form so the copy is always readable.
"""

import textwrap

_PAGE_WIDTH = 595  # A4, in points
_PAGE_HEIGHT = 842
_MARGIN = 56
_FONT_SIZE = 10.5
_LEADING = 15
_WRAP_CHARACTERS = 92

# Typographic characters outside Latin-1, by code point, and their plain forms.
_REPLACEMENTS = {
    0x2018: "'",
    0x2019: "'",
    0x201C: '"',
    0x201D: '"',
    0x2013: "-",
    0x2014: "-",
    0x2022: "-",
    0x2026: "...",
    0x00A0: " ",
    0x203A: ">",
    0x2192: "->",
}


def _latin1(text: str) -> str:
    text = text.translate(_REPLACEMENTS)
    return text.encode("latin-1", "replace").decode("latin-1")


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _lines(text: str) -> list[str]:
    lines: list[str] = []
    for paragraph in _latin1(text).splitlines():
        if not paragraph.strip():
            lines.append("")
            continue
        indent = len(paragraph) - len(paragraph.lstrip())
        bullet = paragraph.lstrip()[:2] in ("- ", "* ")
        lines.extend(
            textwrap.wrap(
                paragraph.strip(),
                width=_WRAP_CHARACTERS - indent,
                initial_indent=" " * indent,
                subsequent_indent=" " * (indent + 2 if bullet else indent),
            )
            or [""]
        )
    return lines


def text_to_pdf(text: str, title: str) -> bytes:
    """Lay [text] out on A4 pages and return the PDF file."""
    per_page = int((_PAGE_HEIGHT - 2 * _MARGIN) // _LEADING)
    lines = _lines(text)
    pages = [lines[i : i + per_page] for i in range(0, max(len(lines), 1), per_page)] or [[]]

    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog = add(b"")  # filled once the page tree exists
    tree = add(b"")
    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    info = add(
        f"<< /Title ({_escape(_latin1(title))}) /Producer (Pesa Clarity) >>".encode("latin-1")
    )
    kids: list[int] = []
    for page_lines in pages:
        stream = [f"BT /F1 {_FONT_SIZE} Tf {_LEADING} TL {_MARGIN} {_PAGE_HEIGHT - _MARGIN} Td"]
        for line in page_lines:
            stream.append(f"({_escape(line)}) Tj T*")
        stream.append("ET")
        content = "\n".join(stream).encode("latin-1")
        header = f"<< /Length {len(content)} >>\nstream\n".encode()
        body = add(header + content + b"\nendstream")
        kids.append(
            add(
                f"<< /Type /Page /Parent {tree} 0 R /MediaBox [0 0 {_PAGE_WIDTH} {_PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 {font} 0 R >> >> /Contents {body} 0 R >>".encode()
            )
        )
    objects[catalog - 1] = f"<< /Type /Catalog /Pages {tree} 0 R >>".encode()
    refs = " ".join(f"{k} 0 R" for k in kids)
    objects[tree - 1] = f"<< /Type /Pages /Kids [{refs}] /Count {len(kids)} >>".encode()

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R /Info {info} 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n"
    ).encode()
    return bytes(out)
