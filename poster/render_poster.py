"""Render the reviewed claim manifest without browser, network or live services.

PDF is the canonical visual; PNG is rasterized from its sole page. Evidence
dates/commits are printed, and reported benchmarks stay separate from CI tests.
"""

from __future__ import annotations

import html
import json
import shutil
import sys
from pathlib import Path

import fitz
import reportlab
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

WIDTH, HEIGHT = 2592, 3456  # 36 x 48 inches
MARGIN, GAP = 150, 70
INK = colors.HexColor("#122c40")
PAPER = colors.HexColor("#f4f1e9")
ACCENT = colors.HexColor("#a34f28")


def paragraph(text: str, size: float, *, bold: bool = False, light: bool = False):
    return Paragraph(
        html.escape(text),
        ParagraphStyle(
            "poster",
            fontName="EvidenceBold" if bold else "Evidence",
            fontSize=size,
            leading=size * 1.32,
            textColor=colors.white if light else INK,
            splitLongWords=True,
            spaceAfter=0,
        ),
    )


def measure_blocks(blocks, width, size):
    height = 0
    for _title, items in blocks:
        height += 80
        for text in items:
            height += paragraph(text, size).wrap(width - 70, HEIGHT)[1] + 24
        height += 40
    return height


def draw_blocks(c, blocks, x, y, width, size):
    for title, items in blocks:
        c.setFillColor(ACCENT)
        c.rect(x, y - 4, 50, 4, fill=1, stroke=0)
        p = paragraph(title.upper(), 34, bold=True)
        _, h = p.wrap(width, HEIGHT)
        p.drawOn(c, x, y - 30 - h)
        y -= 80
        for text in items:
            p = paragraph(text, size)
            _, h = p.wrap(width - 70, HEIGHT)
            p.drawOn(c, x + 35, y - h)
            c.setFillColor(ACCENT)
            c.circle(x + 10, y - size * 0.55, 5, fill=1, stroke=0)
            y -= h + 24
        y -= 40
    return y


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
    poster = root / "poster"
    data = json.loads((poster / "verified_claims.json").read_text(encoding="utf-8"))
    required = {
        "repository",
        "title",
        "subtitle",
        "source_commit",
        "test_commit",
        "ci_run",
        "ci_date",
        "cards",
        "contribution",
        "methods",
        "evidence",
        "limitations",
        "reproduction",
    }
    if not required <= data.keys():
        raise ValueError("incomplete reviewed claim manifest")
    if len(data["cards"]) != 4:
        raise ValueError("exactly four scoped headline cards required")
    for key in ["source_commit", "test_commit"]:
        if len(data[key]) != 40 or any(c not in "0123456789abcdef" for c in data[key]):
            raise ValueError("full immutable commit anchor required")
    fonts = Path(reportlab.__file__).resolve().parent / "fonts"
    pdfmetrics.registerFont(TTFont("Evidence", str(fonts / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont("EvidenceBold", str(fonts / "VeraBd.ttf")))

    pdf = poster / "poster_36x48.pdf"
    png = poster / "poster.png"
    c = canvas.Canvas(str(pdf), pagesize=(WIDTH, HEIGHT), invariant=1, pageCompression=1)
    c.setTitle(data["title"])
    c.setAuthor("Pooja Kiran")
    c.setSubject("Dated repository evidence; scoped tests and reported measurements")
    c.setFillColor(PAPER)
    c.rect(0, 0, WIDTH, HEIGHT, fill=1, stroke=0)
    c.setFillColor(INK)
    c.rect(0, HEIGHT - 680, WIDTH, 680, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#d7c4ad"))
    c.setFont("EvidenceBold", 28)
    c.drawString(MARGIN, HEIGHT - 95, "POOJA KIRAN  |  SECURITY ENGINEERING")
    title_size = 82
    while title_size >= 58:
        title = paragraph(data["title"], title_size, bold=True, light=True)
        _, title_height = title.wrap(WIDTH - 2 * MARGIN, HEIGHT)
        if title_height <= 180:
            break
        title_size -= 2
    else:
        raise ValueError("title exceeds reviewed layout")
    title.drawOn(c, MARGIN, HEIGHT - 150 - title_height)
    subtitle = paragraph(data["subtitle"], 32, light=True)
    _, h = subtitle.wrap(WIDTH - 2 * MARGIN, HEIGHT)
    if h > 90:
        raise ValueError("subtitle overlaps provenance")
    subtitle.drawOn(c, MARGIN, HEIGHT - 180 - title_height - h)
    c.setFont("Evidence", 25)
    for y, text in [
        (HEIGHT - 470, "Source inventory: " + data["source_commit"]),
        (HEIGHT - 520, "Test snapshot: " + data["test_commit"]),
        (
            HEIGHT - 570,
            "CI run "
            + str(data["ci_run"])
            + " | initiated "
            + data["ci_date"]
            + " UTC | "
            + data["license"],
        ),
        (HEIGHT - 620, "https://github.com/poojakira/" + data["repository"]),
    ]:
        c.drawString(MARGIN, y, text)

    card_width = (WIDTH - 2 * MARGIN - 3 * 35) / 4
    for i, card in enumerate(data["cards"]):
        x = MARGIN + i * (card_width + 35)
        c.setFillColor(colors.white)
        c.roundRect(x, HEIGHT - 1000, card_width, 260, 20, fill=1, stroke=0)
        value = paragraph(str(card["value"]), 70, bold=True)
        _, h = value.wrap(card_width - 65, HEIGHT)
        value.drawOn(c, x + 30, HEIGHT - 790 - h)
        label = paragraph(card["label"], 27)
        _, h = label.wrap(card_width - 65, HEIGHT)
        if h > 100:
            raise ValueError("headline scope label does not fit")
        label.drawOn(c, x + 30, HEIGHT - 895 - h)

    columns = [
        [
            ("Contribution", [data["contribution"]]),
            (
                "Implemented method",
                [str(i + 1) + ". " + t for i, t in enumerate(data["methods"])],
            ),
            ("Limitations and evidence boundary", data["limitations"]),
        ],
        [("Scoped evidence", data["evidence"]), ("Reproduction", data["reproduction"])],
    ]
    width = (WIDTH - 2 * MARGIN - GAP) / 2
    top, bottom = HEIGHT - 1090, 230
    size = 45
    while size >= 31:
        if max(measure_blocks(b, width, size) for b in columns) <= top - bottom:
            break
        size -= 1
    else:
        raise ValueError("reviewed claims overflow: shorten copy, do not clip or omit claims")
    for i, blocks in enumerate(columns):
        end = draw_blocks(c, blocks, MARGIN + i * (width + GAP), top, width, size)
        if end < bottom:
            raise ValueError("poster content clipped")
    c.setFillColor(INK)
    c.rect(MARGIN, 170, WIDTH - 2 * MARGIN, 3, fill=1, stroke=0)
    footer = paragraph(
        "Dated tests and committed fixtures do not establish universal detection, "
        "production deployment or an SLO.",
        28,
    )
    _, h = footer.wrap(WIDTH - 2 * MARGIN, HEIGHT)
    footer.drawOn(c, MARGIN, 120 - h)
    c.showPage()
    c.save()
    with fitz.open(pdf) as document:
        if len(document) != 1:
            raise ValueError("poster must be one page")
        document[0].get_pixmap(matrix=fitz.Matrix(1800 / WIDTH, 1800 / WIDTH), alpha=False).save(
            png
        )
    if data["repository"] == "mcp-agent-security-gateway":
        shutil.copyfile(pdf, root / "MCP_Gateway_Poster.pdf")
    print(
        json.dumps(
            {
                "repository": data["repository"],
                "pages": 1,
                "body_font_pt": size,
                "pdf_bytes": pdf.stat().st_size,
                "png_bytes": png.stat().st_size,
            }
        )
    )


if __name__ == "__main__":
    main()
