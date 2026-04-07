"""
PDF report generator for VerifAI Security Vendor Risk Manager.

Produces four professional report types:
  1. Vendor Risk Card — executive summary of a single vendor
  2. Executive Portfolio Report — organization-wide vendor risk overview
  3. Annual Attestation Report — HIPAA-required verification documentation
  4. Remediation Tracker Report — open findings across all vendors

Fonts: Inter (body), DM Sans Bold (headings) — downloaded from Google Fonts.
Colors: Teal/dark professional scheme for healthcare cybersecurity.

VerifAI Security | Created by Nathan Mills
"""

from __future__ import annotations

import math
import os
import urllib.request
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.colors import Color, HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    FrameBreak,
    HRFlowable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle, Wedge

from vrm.models import (
    Vendor,
    VendorType,
    VendorTier,
    VendorStatus,
    BAA,
    BAAStatus,
    VendorAssessment,
    AssessmentType,
    AssessmentStatus,
    Finding,
    FindingSeverity,
    RemediationTimeline,
    FindingStatus,
    Verification,
    VerificationStatus,
    RiskScore,
    Answer,
)


# ============================================================================
# Font Setup
# ============================================================================

FONT_DIR = Path("/tmp/fonts")
FONT_DIR.mkdir(exist_ok=True)

_FONT_URLS = {
    "Inter": (
        "https://github.com/google/fonts/raw/main/ofl/inter/"
        "Inter%5Bopsz%2Cwght%5D.ttf"
    ),
    "DMSans": (
        "https://github.com/google/fonts/raw/main/ofl/dmsans/"
        "DMSans%5Bopsz%2Cwght%5D.ttf"
    ),
}

_fonts_registered = False


def _register_fonts() -> None:
    """Download and register Inter + DM Sans with ReportLab (idempotent)."""
    global _fonts_registered
    if _fonts_registered:
        return

    for name, url in _FONT_URLS.items():
        local = FONT_DIR / f"{name}.ttf"
        if not local.exists():
            urllib.request.urlretrieve(url, local)
        try:
            pdfmetrics.registerFont(TTFont(name, str(local)))
        except Exception:
            pass  # already registered

    _fonts_registered = True


# ============================================================================
# Color Palette — Healthcare Cybersecurity Professional Theme
# ============================================================================

TEAL = HexColor("#01696F")
TEAL_HOVER = HexColor("#0C4E54")
TEAL_LIGHT = HexColor("#E0F0F1")
TEAL_MUTED = HexColor("#4F98A3")
DARK = HexColor("#1A2332")
DARK_SURFACE = HexColor("#243040")
SURFACE = HexColor("#F7F6F2")
SURFACE_ALT = HexColor("#FBFBF9")
WHITE = HexColor("#FFFFFF")
TEXT_PRIMARY = HexColor("#28251D")
TEXT_MUTED = HexColor("#7A7974")
TEXT_FAINT = HexColor("#BAB9B4")
BORDER = HexColor("#D4D1CA")
BORDER_LIGHT = HexColor("#E8E7E3")

# Semantic colors
RED = HexColor("#C13030")
RED_BG = HexColor("#FFF0F0")
ORANGE = HexColor("#D97706")
ORANGE_BG = HexColor("#FFF8EC")
YELLOW = HexColor("#B8860B")
YELLOW_BG = HexColor("#FFFBEB")
GREEN = HexColor("#437A22")
GREEN_BG = HexColor("#F0F8EC")

# Severity palette
SEVERITY_COLORS = {
    "critical": (RED, HexColor("#FEE2E2")),
    "high": (HexColor("#EA580C"), HexColor("#FFF1E6")),
    "medium": (ORANGE, ORANGE_BG),
    "low": (GREEN, GREEN_BG),
}

# Risk level colors for gauges/badges
RISK_LEVEL_COLORS = {
    "CRITICAL": RED,
    "HIGH": HexColor("#EA580C"),
    "MEDIUM": ORANGE,
    "LOW": GREEN,
}

# Tier badge colors
TIER_COLORS = {
    "critical": (RED, WHITE),
    "high": (HexColor("#EA580C"), WHITE),
    "medium": (ORANGE, WHITE),
    "low": (GREEN, WHITE),
}

# Status colors
STATUS_COLORS = {
    "active": GREEN,
    "expired": RED,
    "pending": ORANGE,
    "draft": TEXT_MUTED,
    "terminated": RED,
    "renewal_pending": ORANGE,
    "pending_review": ORANGE,
    "pending_signature": YELLOW,
    "verified": GREEN,
    "failed": RED,
    "overdue": RED,
    "submitted": TEAL,
    "under_review": TEAL_MUTED,
}

# Chart color sequence
CHART_COLORS = [
    HexColor("#20808D"),
    HexColor("#A84B2F"),
    HexColor("#1B474D"),
    HexColor("#BCE2E7"),
    HexColor("#944454"),
    HexColor("#FFC553"),
    HexColor("#848456"),
    HexColor("#6E522B"),
]

# ============================================================================
# Page Dimensions
# ============================================================================

PAGE_W, PAGE_H = letter
MARGIN_LEFT = 54
MARGIN_RIGHT = 54
MARGIN_TOP = 54
MARGIN_BOTTOM = 60
CONTENT_W = PAGE_W - MARGIN_LEFT - MARGIN_RIGHT
HEADER_HEIGHT = 44
FOOTER_HEIGHT = 36

BODY_FONT = "Inter"
HEADING_FONT = "DMSans"
FALLBACK_BODY = "Helvetica"
FALLBACK_HEADING = "Helvetica-Bold"


# ============================================================================
# Paragraph Styles
# ============================================================================

def _build_styles() -> Dict[str, ParagraphStyle]:
    """Build a complete style dictionary for reports."""
    _register_fonts()
    bf = BODY_FONT
    hf = HEADING_FONT

    s = {}
    s["title"] = ParagraphStyle(
        "VTitle", fontName=hf, fontSize=22, leading=28,
        textColor=DARK, spaceAfter=4,
    )
    s["subtitle"] = ParagraphStyle(
        "VSubtitle", fontName=bf, fontSize=11, leading=15,
        textColor=TEXT_MUTED, spaceAfter=12,
    )
    s["h1"] = ParagraphStyle(
        "VH1", fontName=hf, fontSize=16, leading=22,
        textColor=DARK, spaceBefore=18, spaceAfter=8,
    )
    s["h2"] = ParagraphStyle(
        "VH2", fontName=hf, fontSize=13, leading=18,
        textColor=TEAL_HOVER, spaceBefore=14, spaceAfter=6,
    )
    s["h3"] = ParagraphStyle(
        "VH3", fontName=hf, fontSize=11, leading=15,
        textColor=DARK, spaceBefore=10, spaceAfter=4,
    )
    s["body"] = ParagraphStyle(
        "VBody", fontName=bf, fontSize=9.5, leading=14,
        textColor=TEXT_PRIMARY, spaceAfter=6, alignment=TA_JUSTIFY,
    )
    s["body_small"] = ParagraphStyle(
        "VBodySmall", fontName=bf, fontSize=8.5, leading=12,
        textColor=TEXT_PRIMARY, spaceAfter=4,
    )
    s["body_bold"] = ParagraphStyle(
        "VBodyBold", fontName=hf, fontSize=9.5, leading=14,
        textColor=TEXT_PRIMARY, spaceAfter=6,
    )
    s["caption"] = ParagraphStyle(
        "VCaption", fontName=bf, fontSize=8, leading=11,
        textColor=TEXT_MUTED, spaceAfter=4,
    )
    s["label"] = ParagraphStyle(
        "VLabel", fontName=hf, fontSize=8, leading=11,
        textColor=TEXT_MUTED, spaceAfter=2,
    )
    s["value"] = ParagraphStyle(
        "VValue", fontName=hf, fontSize=10, leading=14,
        textColor=DARK, spaceAfter=4,
    )
    s["kpi_value"] = ParagraphStyle(
        "VKPIValue", fontName=hf, fontSize=26, leading=30,
        textColor=TEAL, alignment=TA_CENTER,
    )
    s["kpi_label"] = ParagraphStyle(
        "VKPILabel", fontName=bf, fontSize=8, leading=11,
        textColor=TEXT_MUTED, alignment=TA_CENTER, spaceAfter=2,
    )
    s["table_header"] = ParagraphStyle(
        "VTableHeader", fontName=hf, fontSize=8, leading=11,
        textColor=WHITE,
    )
    s["table_cell"] = ParagraphStyle(
        "VTableCell", fontName=bf, fontSize=8, leading=11,
        textColor=TEXT_PRIMARY,
    )
    s["table_cell_bold"] = ParagraphStyle(
        "VTableCellBold", fontName=hf, fontSize=8, leading=11,
        textColor=TEXT_PRIMARY,
    )
    s["footer"] = ParagraphStyle(
        "VFooter", fontName=bf, fontSize=7, leading=10,
        textColor=TEXT_MUTED,
    )
    s["legal"] = ParagraphStyle(
        "VLegal", fontName=bf, fontSize=7.5, leading=10.5,
        textColor=TEXT_MUTED, spaceAfter=4, alignment=TA_JUSTIFY,
    )
    s["cover_title"] = ParagraphStyle(
        "VCoverTitle", fontName=hf, fontSize=30, leading=38,
        textColor=WHITE, alignment=TA_LEFT,
    )
    s["cover_subtitle"] = ParagraphStyle(
        "VCoverSubtitle", fontName=bf, fontSize=13, leading=18,
        textColor=TEAL_LIGHT, alignment=TA_LEFT,
    )
    s["cover_org"] = ParagraphStyle(
        "VCoverOrg", fontName=hf, fontSize=16, leading=22,
        textColor=TEAL_MUTED, alignment=TA_LEFT,
    )
    s["badge"] = ParagraphStyle(
        "VBadge", fontName=hf, fontSize=8, leading=11,
        textColor=WHITE, alignment=TA_CENTER,
    )
    s["section_intro"] = ParagraphStyle(
        "VSectionIntro", fontName=bf, fontSize=9.5, leading=14,
        textColor=TEXT_MUTED, spaceAfter=10, alignment=TA_JUSTIFY,
    )
    s["checklist_yes"] = ParagraphStyle(
        "VCheckYes", fontName=hf, fontSize=9.5, leading=14,
        textColor=GREEN, spaceAfter=4,
    )
    s["checklist_no"] = ParagraphStyle(
        "VCheckNo", fontName=hf, fontSize=9.5, leading=14,
        textColor=RED, spaceAfter=4,
    )
    s["signature_line"] = ParagraphStyle(
        "VSignature", fontName=bf, fontSize=9, leading=13,
        textColor=TEXT_PRIMARY, spaceBefore=6,
    )
    return s


# ============================================================================
# Drawing Utilities
# ============================================================================

def _draw_rounded_rect(c: canvas.Canvas, x: float, y: float, w: float, h: float,
                       r: float, fill_color: Color, stroke: bool = False,
                       stroke_color: Color = BORDER) -> None:
    """Draw a rounded rectangle on the canvas."""
    c.saveState()
    c.setFillColor(fill_color)
    if stroke:
        c.setStrokeColor(stroke_color)
        c.setLineWidth(0.5)
    else:
        c.setStrokeColor(fill_color)
    c.roundRect(x, y, w, h, r, fill=1, stroke=1 if stroke else 0)
    c.restoreState()


def _draw_badge(c: canvas.Canvas, x: float, y: float, text: str,
                bg_color: Color, text_color: Color = WHITE,
                font: str = "", font_size: float = 7.5) -> float:
    """Draw a pill-shaped badge. Returns badge width."""
    _register_fonts()
    fn = font or HEADING_FONT
    tw = c.stringWidth(text, fn, font_size)
    pad_x = 8
    pad_y = 3
    bw = tw + pad_x * 2
    bh = font_size + pad_y * 2
    _draw_rounded_rect(c, x, y - pad_y, bw, bh, bh / 2, bg_color)
    c.saveState()
    c.setFillColor(text_color)
    c.setFont(fn, font_size)
    c.drawString(x + pad_x, y + 1.5, text.upper())
    c.restoreState()
    return bw


def _draw_risk_gauge(c: canvas.Canvas, cx: float, cy: float, radius: float,
                     score: float, label: str = "") -> None:
    """
    Draw a semicircular risk gauge with colored segments and a needle.
    Score is 0-100 where 0=lowest risk, 100=highest risk.
    """
    _register_fonts()
    c.saveState()

    # Gauge segments: green (0-25), yellow (25-50), orange (50-75), red (75-100)
    segments = [
        (GREEN, 0, 25),
        (HexColor("#B8B816"), 25, 50),
        (ORANGE, 50, 75),
        (RED, 75, 100),
    ]

    # Draw background arc
    _draw_rounded_rect(c, cx - radius - 8, cy - radius * 0.35,
                       radius * 2 + 16, radius + radius * 0.35 + 8,
                       6, SURFACE)

    # Draw colored arc segments
    arc_width = 14
    for seg_color, seg_start, seg_end in segments:
        start_angle = 180 - (seg_end / 100 * 180)
        end_angle = 180 - (seg_start / 100 * 180)
        c.setStrokeColor(seg_color)
        c.setLineWidth(arc_width)
        c.setLineCap(0)
        c.arc(cx - radius, cy - radius, cx + radius, cy + radius,
              start_angle, end_angle - start_angle)

    # Thin white separators between segments
    for pct in [25, 50, 75]:
        angle_rad = math.pi * (1 - pct / 100)
        lx = cx + (radius) * math.cos(angle_rad)
        ly = cy + (radius) * math.sin(angle_rad)
        c.setStrokeColor(WHITE)
        c.setLineWidth(2)
        inner_r = radius - arc_width / 2 - 1
        outer_r = radius + arc_width / 2 + 1
        ix = cx + inner_r * math.cos(angle_rad)
        iy = cy + inner_r * math.sin(angle_rad)
        ox = cx + outer_r * math.cos(angle_rad)
        oy = cy + outer_r * math.sin(angle_rad)
        c.line(ix, iy, ox, oy)

    # Needle
    needle_angle = math.pi * (1 - score / 100)
    needle_len = radius - arc_width - 4
    nx = cx + needle_len * math.cos(needle_angle)
    ny = cy + needle_len * math.sin(needle_angle)

    # Needle shadow
    c.setStrokeColor(HexColor("#00000022"))
    c.setLineWidth(3)
    c.line(cx, cy, nx - 0.5, ny - 0.5)

    # Needle line
    c.setStrokeColor(DARK)
    c.setLineWidth(2)
    c.line(cx, cy, nx, ny)

    # Center dot
    c.setFillColor(DARK)
    c.circle(cx, cy, 4, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.circle(cx, cy, 2, fill=1, stroke=0)

    # Score value
    c.setFont(HEADING_FONT, 22)
    c.setFillColor(DARK)
    score_str = f"{score:.0f}"
    sw = c.stringWidth(score_str, HEADING_FONT, 22)
    c.drawString(cx - sw / 2, cy - 22, score_str)

    # Score label
    if label:
        c.setFont(BODY_FONT, 8)
        c.setFillColor(TEXT_MUTED)
        lw = c.stringWidth(label, BODY_FONT, 8)
        c.drawString(cx - lw / 2, cy - 34, label)

    # Min/max labels
    c.setFont(BODY_FONT, 7)
    c.setFillColor(TEXT_MUTED)
    c.drawString(cx - radius - 4, cy - 10, "0")
    c.drawRightString(cx + radius + 4, cy - 10, "100")

    c.restoreState()


def _draw_horizontal_bar_chart(c: canvas.Canvas, x: float, y: float,
                               width: float, data: Dict[str, float],
                               max_val: float = 100,
                               bar_height: float = 14,
                               gap: float = 6,
                               show_values: bool = True) -> float:
    """
    Draw a horizontal bar chart with domain labels. Returns total height used.
    data: dict of label -> value (0-100).
    """
    _register_fonts()
    c.saveState()

    label_width = 120
    bar_area = width - label_width - 40
    items = list(data.items())
    total_height = len(items) * (bar_height + gap)
    curr_y = y

    for i, (label, value) in enumerate(items):
        # Label
        c.setFont(BODY_FONT, 7.5)
        c.setFillColor(TEXT_PRIMARY)
        # Truncate long labels
        display_label = label[:22] + "..." if len(label) > 25 else label
        c.drawRightString(x + label_width - 8, curr_y + 3, display_label)

        # Background bar
        bar_x = x + label_width
        _draw_rounded_rect(c, bar_x, curr_y, bar_area, bar_height,
                           3, BORDER_LIGHT)

        # Value bar
        if value > 0:
            bar_w = max((value / max_val) * bar_area, 4)
            bar_color = _score_color(value)
            _draw_rounded_rect(c, bar_x, curr_y, bar_w, bar_height,
                               3, bar_color)

        # Value text
        if show_values:
            c.setFont(HEADING_FONT, 7.5)
            c.setFillColor(TEXT_MUTED)
            c.drawString(bar_x + bar_area + 4, curr_y + 3, f"{value:.0f}")

        curr_y -= (bar_height + gap)

    c.restoreState()
    return total_height


def _score_color(score: float) -> Color:
    """Map a 0-100 risk score to a color (lower = better/green)."""
    if score >= 75:
        return RED
    elif score >= 50:
        return ORANGE
    elif score >= 25:
        return HexColor("#B8B816")
    else:
        return GREEN


def _score_color_inverted(score: float) -> Color:
    """Map a 0-100 assessment score to a color (higher = better/green)."""
    if score >= 75:
        return GREEN
    elif score >= 50:
        return HexColor("#B8B816")
    elif score >= 25:
        return ORANGE
    else:
        return RED


def _risk_level_color(level: str) -> Color:
    """Map risk level string to color."""
    return RISK_LEVEL_COLORS.get(level.upper(), TEXT_MUTED)


def _severity_sort_key(sev: FindingSeverity) -> int:
    """Sort key: CRITICAL=0 (highest priority) ... LOW=3."""
    order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
    }
    return order.get(sev, 99)


def _fmt_date(d: Any) -> str:
    """Format a date/datetime to readable string."""
    if d is None:
        return "N/A"
    if isinstance(d, datetime):
        return d.strftime("%b %d, %Y")
    if isinstance(d, date):
        return d.strftime("%b %d, %Y")
    return str(d)


def _fmt_enum(val: Any) -> str:
    """Format an enum value for display."""
    if val is None:
        return "N/A"
    if hasattr(val, "value"):
        return str(val.value).replace("_", " ").title()
    return str(val).replace("_", " ").title()


def _safe_str(val: Any) -> str:
    """Safely convert to string, handling None."""
    if val is None:
        return "N/A"
    return str(val)


def _xml_escape(text: str) -> str:
    """Escape XML special characters for ReportLab Paragraph markup."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ============================================================================
# Header / Footer Rendering
# ============================================================================

def _draw_header(c: canvas.Canvas, doc_or_width: Any, title: str = "",
                 show_brand: bool = True) -> None:
    """Draw the standard VerifAI Security header bar."""
    _register_fonts()
    c.saveState()

    # Teal header bar
    c.setFillColor(TEAL)
    c.rect(0, PAGE_H - HEADER_HEIGHT, PAGE_W, HEADER_HEIGHT, fill=1, stroke=0)

    # Brand name
    if show_brand:
        c.setFont(HEADING_FONT, 11)
        c.setFillColor(WHITE)
        c.drawString(MARGIN_LEFT, PAGE_H - HEADER_HEIGHT + 16, "VerifAI Security")

    # Title on right
    if title:
        c.setFont(BODY_FONT, 8)
        c.setFillColor(TEAL_LIGHT)
        c.drawRightString(PAGE_W - MARGIN_RIGHT, PAGE_H - HEADER_HEIGHT + 16, title)

    c.restoreState()


def _draw_footer(c: canvas.Canvas, page_num: int,
                 confidential: bool = True) -> None:
    """Draw the standard footer with page number and confidentiality notice."""
    _register_fonts()
    c.saveState()

    # Thin line
    c.setStrokeColor(BORDER)
    c.setLineWidth(0.5)
    c.line(MARGIN_LEFT, MARGIN_BOTTOM - 4, PAGE_W - MARGIN_RIGHT, MARGIN_BOTTOM - 4)

    y = MARGIN_BOTTOM - 18

    # Confidentiality notice
    if confidential:
        c.setFont(BODY_FONT, 6.5)
        c.setFillColor(TEXT_FAINT)
        c.drawString(
            MARGIN_LEFT, y,
            "CONFIDENTIAL — This document contains proprietary risk assessment data. "
            "Do not distribute without authorization."
        )

    # Page number
    c.setFont(HEADING_FONT, 7.5)
    c.setFillColor(TEXT_MUTED)
    c.drawRightString(PAGE_W - MARGIN_RIGHT, y, f"Page {page_num}")

    # Generation date
    c.setFont(BODY_FONT, 6.5)
    c.setFillColor(TEXT_FAINT)
    gen_date = datetime.now().strftime("%Y-%m-%d %H:%M")
    c.drawCentredString(PAGE_W / 2, y, f"Generated {gen_date}")

    c.restoreState()


# ============================================================================
# Common Table Helpers
# ============================================================================

def _make_info_table(data: List[Tuple[str, str]], styles: Dict,
                     col_widths: Optional[List[float]] = None) -> Table:
    """Create a two-column label-value info table."""
    rows = []
    for label, value in data:
        rows.append([
            Paragraph(f"<b>{_xml_escape(label)}</b>", styles["label"]),
            Paragraph(_xml_escape(str(value)), styles["body_small"]),
        ])
    cw = col_widths or [110, CONTENT_W - 110]
    t = Table(rows, colWidths=cw)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _make_styled_table(headers: List[str], rows: List[List[Any]],
                       styles: Dict, col_widths: Optional[List[float]] = None,
                       alt_rows: bool = True) -> Table:
    """Create a professionally styled data table."""
    header_row = [Paragraph(_xml_escape(h), styles["table_header"]) for h in headers]
    data_rows = []
    for row in rows:
        cells = []
        for cell in row:
            if isinstance(cell, Paragraph):
                cells.append(cell)
            else:
                cells.append(Paragraph(_xml_escape(str(cell)), styles["table_cell"]))
        data_rows.append(cells)

    all_data = [header_row] + data_rows
    t = Table(all_data, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), HEADING_FONT),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, 0), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("LINEBELOW", (0, 0), (-1, 0), 1, TEAL),
    ]

    if alt_rows:
        style_cmds.append(
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURFACE])
        )

    t.setStyle(TableStyle(style_cmds))
    return t


# ============================================================================
# Report 1: Vendor Risk Card
# ============================================================================

def generate_vendor_risk_card(
    vendor: Vendor,
    assessment: Optional[VendorAssessment],
    baa: Optional[BAA],
    verification: Optional[Verification],
    risk_score: Optional[RiskScore],
    output_path: str,
) -> str:
    """
    Generate a 1-2 page Vendor Risk Card PDF.

    Returns the output file path.
    """
    _register_fonts()
    styles = _build_styles()

    c = canvas.Canvas(output_path, pagesize=letter)
    c.setTitle(f"Vendor Risk Card — {vendor.name}")
    c.setAuthor("Perplexity Computer")

    page_num = 1
    y = PAGE_H  # current y position (top down)

    # --- Header ---
    _draw_header(c, None, title="Vendor Risk Card")
    y = PAGE_H - HEADER_HEIGHT - 20

    # --- Vendor Name & Tier Badge ---
    c.setFont(HEADING_FONT, 20)
    c.setFillColor(DARK)
    c.drawString(MARGIN_LEFT, y, vendor.name)

    tier_val = vendor.tier.value if vendor.tier else "medium"
    tier_bg, tier_fg = TIER_COLORS.get(tier_val, (TEXT_MUTED, WHITE))
    badge_x = MARGIN_LEFT + c.stringWidth(vendor.name, HEADING_FONT, 20) + 12
    _draw_badge(c, badge_x, y + 2, f"{tier_val} TIER", tier_bg, tier_fg, font_size=7)
    y -= 14

    # Report date
    c.setFont(BODY_FONT, 9)
    c.setFillColor(TEXT_MUTED)
    c.drawString(MARGIN_LEFT, y, f"Report Date: {datetime.now().strftime('%B %d, %Y')}")
    y -= 22

    # --- Vendor Info Box ---
    box_h = 90
    _draw_rounded_rect(c, MARGIN_LEFT, y - box_h, CONTENT_W, box_h, 6,
                       SURFACE, stroke=True, stroke_color=BORDER_LIGHT)

    # Info grid inside box
    info_x = MARGIN_LEFT + 14
    info_y = y - 16
    col_w = CONTENT_W / 3 - 10

    info_items = [
        ("Legal Name", vendor.legal_name or vendor.name),
        ("Vendor Type", _fmt_enum(vendor.vendor_type)),
        ("Status", _fmt_enum(vendor.status)),
        ("PHI Access", ("Yes" if vendor.phi_access else "No")),
        ("Integration", ", ".join(vendor.integration_type[:3]) if vendor.integration_type else "N/A"),
        ("Contact", vendor.contact_name or "N/A"),
        ("PHI Types", ", ".join(vendor.phi_types[:3]) if vendor.phi_types else "N/A"),
        ("Data Volume", _fmt_enum(vendor.data_volume) if hasattr(vendor, 'data_volume') else "N/A"),
        ("Onboarded", _fmt_date(vendor.onboarded_date)),
    ]

    for i, (lbl, val) in enumerate(info_items):
        col = i % 3
        row = i // 3
        ix = info_x + col * (col_w + 10)
        iy = info_y - row * 22
        c.setFont(HEADING_FONT, 7)
        c.setFillColor(TEXT_MUTED)
        c.drawString(ix, iy, lbl.upper())
        c.setFont(BODY_FONT, 8.5)
        c.setFillColor(TEXT_PRIMARY)
        # Truncate long values
        display_val = str(val)[:38]
        c.drawString(ix, iy - 11, display_val)

    y -= box_h + 16

    # --- Risk Score Section (left) + Domain Scores (right) ---
    overall = risk_score.overall_score if risk_score else 0
    risk_level = risk_score.risk_level if risk_score else "N/A"

    # Gauge on the left
    gauge_cx = MARGIN_LEFT + 90
    gauge_cy = y - 55
    _draw_risk_gauge(c, gauge_cx, gauge_cy, 60, overall, label="Overall Risk Score")

    # Risk level badge below gauge
    rl_color = _risk_level_color(risk_level)
    _draw_badge(c, gauge_cx - 30, gauge_cy - 52, risk_level, rl_color)

    # Inherent / Residual mini stats
    if risk_score:
        stat_y = gauge_cy - 72
        c.setFont(HEADING_FONT, 7)
        c.setFillColor(TEXT_MUTED)
        c.drawString(MARGIN_LEFT + 12, stat_y, "INHERENT")
        c.setFont(HEADING_FONT, 12)
        c.setFillColor(DARK)
        c.drawString(MARGIN_LEFT + 12, stat_y - 14,
                     f"{risk_score.inherent_risk_score:.0f}")

        c.setFont(HEADING_FONT, 7)
        c.setFillColor(TEXT_MUTED)
        c.drawString(MARGIN_LEFT + 80, stat_y, "RESIDUAL")
        c.setFont(HEADING_FONT, 12)
        c.setFillColor(DARK)
        c.drawString(MARGIN_LEFT + 80, stat_y - 14,
                     f"{risk_score.residual_risk_score:.0f}")

        trend_str = risk_score.trend or "STABLE"
        trend_arrow = {"IMPROVING": "↓", "STABLE": "→", "WORSENING": "↑"}.get(
            trend_str.upper(), "→"
        )
        c.setFont(HEADING_FONT, 7)
        c.setFillColor(TEXT_MUTED)
        c.drawString(MARGIN_LEFT + 148, stat_y, "TREND")
        c.setFont(HEADING_FONT, 12)
        trend_color = {"IMPROVING": GREEN, "STABLE": TEXT_MUTED, "WORSENING": RED}.get(
            trend_str.upper(), TEXT_MUTED
        )
        c.setFillColor(trend_color)
        c.drawString(MARGIN_LEFT + 148, stat_y - 14,
                     f"{trend_arrow} {trend_str.title()}")

    # Domain scores bar chart on the right
    domain_scores = {}
    if risk_score and risk_score.domain_scores:
        domain_scores = risk_score.domain_scores
    elif assessment and assessment.domain_scores:
        domain_scores = assessment.domain_scores

    if domain_scores:
        chart_x = MARGIN_LEFT + 210
        chart_y = y - 6
        c.setFont(HEADING_FONT, 9)
        c.setFillColor(DARK)
        c.drawString(chart_x, chart_y, "Domain Risk Scores")
        chart_y -= 14
        chart_w = CONTENT_W - 210
        _draw_horizontal_bar_chart(c, chart_x, chart_y, chart_w, domain_scores,
                                   bar_height=12, gap=4)

    y -= 200

    # --- Top Findings Summary ---
    c.setFont(HEADING_FONT, 11)
    c.setFillColor(DARK)
    c.drawString(MARGIN_LEFT, y, "Top Findings")

    # Teal accent line
    c.setStrokeColor(TEAL)
    c.setLineWidth(2)
    c.line(MARGIN_LEFT, y - 4, MARGIN_LEFT + 80, y - 4)
    y -= 18

    findings = []
    if assessment and assessment.findings:
        findings = sorted(assessment.findings, key=lambda f: _severity_sort_key(f.severity))[:5]

    if findings:
        for f in findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_color, sev_bg = SEVERITY_COLORS.get(sev_val, (TEXT_MUTED, SURFACE))

            # Severity badge
            bw = _draw_badge(c, MARGIN_LEFT, y + 1, sev_val.upper(), sev_color, font_size=6.5)

            # Finding title
            c.setFont(HEADING_FONT, 8.5)
            c.setFillColor(DARK)
            title_x = MARGIN_LEFT + bw + 8
            c.drawString(title_x, y + 2, _safe_str(f.title)[:65])

            # Finding domain + ref
            c.setFont(BODY_FONT, 7)
            c.setFillColor(TEXT_MUTED)
            ref_parts = []
            if f.domain:
                ref_parts.append(f.domain)
            if f.hipaa_reference:
                ref_parts.append(f.hipaa_reference)
            c.drawString(title_x, y - 9, " | ".join(ref_parts))

            # Status on right
            status_val = f.status.value if hasattr(f.status, "value") else str(f.status)
            status_color = STATUS_COLORS.get(status_val, TEXT_MUTED)
            c.setFont(HEADING_FONT, 7)
            c.setFillColor(status_color)
            c.drawRightString(PAGE_W - MARGIN_RIGHT, y + 2, _fmt_enum(f.status))

            y -= 26
    else:
        c.setFont(BODY_FONT, 9)
        c.setFillColor(TEXT_MUTED)
        c.drawString(MARGIN_LEFT + 8, y, "No findings recorded.")
        y -= 20

    y -= 10

    # --- BAA & Verification Status Row ---
    mid_x = PAGE_W / 2

    # BAA box
    box_w = (CONTENT_W - 12) / 2
    box_h_small = 56
    _draw_rounded_rect(c, MARGIN_LEFT, y - box_h_small, box_w, box_h_small,
                       6, SURFACE, stroke=True, stroke_color=BORDER_LIGHT)

    c.setFont(HEADING_FONT, 9)
    c.setFillColor(DARK)
    c.drawString(MARGIN_LEFT + 12, y - 16, "BAA Status")

    if baa:
        baa_status_val = baa.status.value if hasattr(baa.status, "value") else str(baa.status)
        baa_color = STATUS_COLORS.get(baa_status_val, TEXT_MUTED)
        _draw_badge(c, MARGIN_LEFT + 90, y - 14, _fmt_enum(baa.status), baa_color, font_size=7)

        c.setFont(BODY_FONT, 7.5)
        c.setFillColor(TEXT_MUTED)
        c.drawString(MARGIN_LEFT + 12, y - 32,
                     f"Effective: {_fmt_date(baa.effective_date)}")
        c.drawString(MARGIN_LEFT + 12, y - 44,
                     f"Expires: {_fmt_date(baa.expiration_date)}")
        c.drawString(MARGIN_LEFT + box_w / 2 + 4, y - 32,
                     f"Breach Notify: {baa.breach_notification_hours}h")
        c.drawString(MARGIN_LEFT + box_w / 2 + 4, y - 44,
                     f"Subcontractor Flow-Down: {'Yes' if baa.subcontractor_flow_down else 'No'}")
    else:
        c.setFont(BODY_FONT, 8)
        c.setFillColor(RED)
        c.drawString(MARGIN_LEFT + 12, y - 34, "No BAA on file")

    # Verification box
    vbox_x = MARGIN_LEFT + box_w + 12
    _draw_rounded_rect(c, vbox_x, y - box_h_small, box_w, box_h_small,
                       6, SURFACE, stroke=True, stroke_color=BORDER_LIGHT)

    c.setFont(HEADING_FONT, 9)
    c.setFillColor(DARK)
    c.drawString(vbox_x + 12, y - 16, "Verification Status")

    if verification:
        v_status_val = verification.status.value if hasattr(verification.status, "value") else str(verification.status)
        v_color = STATUS_COLORS.get(v_status_val, TEXT_MUTED)
        _draw_badge(c, vbox_x + 130, y - 14, _fmt_enum(verification.status), v_color, font_size=7)

        c.setFont(BODY_FONT, 7.5)
        c.setFillColor(TEXT_MUTED)
        c.drawString(vbox_x + 12, y - 32,
                     f"Due: {_fmt_date(verification.due_date)}")
        c.drawString(vbox_x + 12, y - 44,
                     f"Completed: {_fmt_date(verification.completed_date)}")

        # Checklist indicators
        checks = [
            ("Safeguards", len(verification.safeguards_confirmed) > 0),
            ("Analysis", verification.professional_analysis_attached),
            ("Certified", verification.authorized_representative_certified),
        ]
        cx_start = vbox_x + box_w / 2 + 4
        for i, (ck_label, ck_val) in enumerate(checks):
            ck_y = y - 32 - i * 11
            ck_color = GREEN if ck_val else RED
            ck_sym = "●" if ck_val else "○"
            c.setFont(HEADING_FONT, 7.5)
            c.setFillColor(ck_color)
            c.drawString(cx_start, ck_y, f"{ck_sym} {ck_label}")
    else:
        c.setFont(BODY_FONT, 8)
        c.setFillColor(ORANGE)
        c.drawString(vbox_x + 12, y - 34, "No verification on file")

    y -= box_h_small + 16

    # --- Next Action Items ---
    if y > MARGIN_BOTTOM + 80:
        c.setFont(HEADING_FONT, 11)
        c.setFillColor(DARK)
        c.drawString(MARGIN_LEFT, y, "Recommended Next Actions")
        c.setStrokeColor(TEAL)
        c.setLineWidth(2)
        c.line(MARGIN_LEFT, y - 4, MARGIN_LEFT + 150, y - 4)
        y -= 18

        actions = _generate_action_items(vendor, assessment, baa, verification, risk_score)
        for i, action in enumerate(actions[:5]):
            c.setFont(HEADING_FONT, 8)
            c.setFillColor(TEAL)
            c.drawString(MARGIN_LEFT + 4, y, f"{i + 1}.")
            c.setFont(BODY_FONT, 8)
            c.setFillColor(TEXT_PRIMARY)
            c.drawString(MARGIN_LEFT + 18, y, action[:90])
            y -= 14

    # Footer
    _draw_footer(c, page_num)

    c.save()
    return output_path


def _generate_action_items(vendor: Vendor, assessment: Optional[VendorAssessment],
                           baa: Optional[BAA], verification: Optional[Verification],
                           risk_score: Optional[RiskScore]) -> List[str]:
    """Generate prioritized action items based on vendor data."""
    actions = []

    if not baa:
        actions.append("Execute Business Associate Agreement immediately — required for PHI access.")
    elif baa.status == BAAStatus.EXPIRED:
        actions.append("Renew expired BAA — vendor is non-compliant until renewed.")
    elif baa.status == BAAStatus.RENEWAL_PENDING:
        actions.append("Complete BAA renewal process before expiration.")

    if not verification:
        actions.append("Initiate annual verification process per HIPAA requirements.")
    elif verification.status == VerificationStatus.OVERDUE:
        actions.append("Complete overdue annual verification — compliance risk increasing.")
    elif verification.status == VerificationStatus.FAILED:
        actions.append("Address failed verification — escalate to vendor management.")

    if assessment:
        crit_findings = [f for f in assessment.findings
                         if f.severity == FindingSeverity.CRITICAL
                         and f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)]
        if crit_findings:
            actions.append(
                f"Remediate {len(crit_findings)} critical finding(s) — immediate action required."
            )
        high_findings = [f for f in assessment.findings
                         if f.severity == FindingSeverity.HIGH
                         and f.status == FindingStatus.OPEN]
        if high_findings:
            actions.append(
                f"Address {len(high_findings)} open high-severity finding(s) within 30 days."
            )

    if risk_score and risk_score.overall_score >= 75:
        actions.append("Escalate vendor to Risk Committee — score exceeds critical threshold.")

    if risk_score and risk_score.trend and risk_score.trend.upper() == "WORSENING":
        actions.append("Investigate worsening risk trend — schedule targeted reassessment.")

    if vendor.phi_access and not vendor.phi_types:
        actions.append("Document PHI types accessed by this vendor.")

    if not actions:
        actions.append("Vendor is in good standing. Continue routine monitoring cycle.")

    return actions


# ============================================================================
# Report 2: Executive Portfolio Report
# ============================================================================

def generate_executive_report(
    vendors_data: List[Dict[str, Any]],
    org_name: str,
    output_path: str,
) -> str:
    """
    Generate a multi-page Executive Portfolio Report PDF.

    vendors_data: list of dicts with keys:
        vendor, assessment, baa, verification, risk_score

    Returns the output file path.
    """
    _register_fonts()
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        title=f"Executive Vendor Risk Portfolio — {org_name}",
        author="Perplexity Computer",
        leftMargin=MARGIN_LEFT,
        rightMargin=MARGIN_RIGHT,
        topMargin=MARGIN_TOP + HEADER_HEIGHT + 4,
        bottomMargin=MARGIN_BOTTOM + 10,
    )

    story: List[Any] = []
    _page_info = {"page_num": 0, "is_cover": True}

    # ---- Cover Page ----
    story.append(Spacer(1, 120))
    story.append(Paragraph(org_name, styles["cover_org"]))
    story.append(Spacer(1, 12))
    story.append(
        Paragraph("Vendor Risk<br/>Portfolio Report", styles["cover_title"])
    )
    story.append(Spacer(1, 16))
    story.append(
        Paragraph(
            f"Assessment Period: {datetime.now().strftime('%B %Y')}<br/>"
            f"Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
            styles["cover_subtitle"],
        )
    )
    story.append(Spacer(1, 30))
    story.append(
        Paragraph(
            "This report provides a comprehensive overview of third-party vendor "
            "risk across your organization, including risk distribution, compliance "
            "status, and prioritized recommendations.",
            ParagraphStyle(
                "CoverBody", parent=styles["body"], fontSize=10, leading=15,
                textColor=HexColor("#C8D8DA"),
            ),
        )
    )
    story.append(PageBreak())

    # ---- Compute KPIs ----
    total_vendors = len(vendors_data)
    vendors_by_tier = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    vendors_by_risk = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    scores = []
    all_findings: List[Finding] = []
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    baa_active = 0
    baa_expiring = 0
    baa_expired = 0
    baa_missing = 0
    verif_complete = 0
    verif_total = 0
    immediate_attention = []

    for vd in vendors_data:
        v: Vendor = vd["vendor"]
        a: Optional[VendorAssessment] = vd.get("assessment")
        b: Optional[BAA] = vd.get("baa")
        vr: Optional[Verification] = vd.get("verification")
        rs: Optional[RiskScore] = vd.get("risk_score")

        tier_val = v.tier.value if v.tier else "medium"
        vendors_by_tier[tier_val] = vendors_by_tier.get(tier_val, 0) + 1

        if rs:
            scores.append(rs.overall_score)
            rl = rs.risk_level.upper() if rs.risk_level else "MEDIUM"
            vendors_by_risk[rl] = vendors_by_risk.get(rl, 0) + 1
            if rl in ("CRITICAL", "HIGH"):
                immediate_attention.append((v, rs, a))

        if a:
            for f in a.findings:
                if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS):
                    all_findings.append(f)
                    sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    findings_by_severity[sev_val] = findings_by_severity.get(sev_val, 0) + 1

        if b:
            if b.status == BAAStatus.ACTIVE:
                baa_active += 1
            elif b.status == BAAStatus.EXPIRED:
                baa_expired += 1
            elif b.status in (BAAStatus.RENEWAL_PENDING,):
                baa_expiring += 1
            else:
                baa_missing += 1
        else:
            baa_missing += 1

        if vr:
            verif_total += 1
            if vr.status == VerificationStatus.VERIFIED:
                verif_complete += 1
        else:
            verif_total += 1

    avg_score = sum(scores) / len(scores) if scores else 0
    open_findings_count = len(all_findings)
    baa_compliance_rate = (baa_active / total_vendors * 100) if total_vendors else 0
    verif_rate = (verif_complete / verif_total * 100) if verif_total else 0

    # ---- Executive Summary ----
    story.append(Paragraph("Executive Summary", styles["h1"]))
    story.append(
        Paragraph(
            f"This report covers <b>{total_vendors}</b> third-party vendors across your "
            f"organization. The analysis below summarizes risk posture, compliance status, "
            f"and areas requiring immediate attention.",
            styles["section_intro"],
        )
    )
    story.append(Spacer(1, 6))

    # KPI Cards as a table
    kpi_data = [
        [
            _kpi_cell(str(total_vendors), "Total Vendors", styles),
            _kpi_cell(f"{avg_score:.0f}", "Avg Risk Score", styles),
            _kpi_cell(str(open_findings_count), "Open Findings", styles),
            _kpi_cell(f"{baa_compliance_rate:.0f}%", "BAA Compliance", styles),
        ],
        [
            _kpi_cell(str(verif_complete), "Verifications Complete", styles),
            _kpi_cell(f"{verif_rate:.0f}%", "Verification Rate", styles),
            _kpi_cell(str(len(immediate_attention)), "Immediate Attention", styles,
                      RED if immediate_attention else GREEN),
            _kpi_cell(
                str(findings_by_severity.get("critical", 0)),
                "Critical Findings",
                styles,
                RED if findings_by_severity.get("critical", 0) > 0 else GREEN,
            ),
        ],
    ]

    kpi_table = Table(kpi_data, colWidths=[CONTENT_W / 4] * 4, rowHeights=[56, 56])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 6))

    # Tier breakdown mini table
    tier_row = []
    for tier_name in ["critical", "high", "medium", "low"]:
        cnt = vendors_by_tier.get(tier_name, 0)
        t_bg, t_fg = TIER_COLORS.get(tier_name, (TEXT_MUTED, WHITE))
        tier_row.append(
            Paragraph(
                f'<font color="{t_bg.hexval()}">{tier_name.upper()}: {cnt}</font>',
                ParagraphStyle("TierItem", parent=styles["body_bold"], fontSize=9,
                               alignment=TA_CENTER),
            )
        )

    tier_table = Table([tier_row], colWidths=[CONTENT_W / 4] * 4)
    tier_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(tier_table)
    story.append(Spacer(1, 12))

    # ---- Vendor Risk Distribution ----
    story.append(Paragraph("Vendor Risk Distribution", styles["h2"]))
    story.append(
        Paragraph(
            "Distribution of vendor risk scores across the portfolio. "
            "Lower scores indicate better security posture.",
            styles["caption"],
        )
    )
    story.append(Spacer(1, 4))

    histogram_drawing = _draw_histogram(scores, CONTENT_W, 130)
    story.append(histogram_drawing)
    story.append(Spacer(1, 12))

    # ---- Risk Heatmap Table ----
    story.append(Paragraph("Risk Heatmap — Vendors vs. Domains", styles["h2"]))
    story.append(
        Paragraph(
            "Color-coded domain scores for the top vendors. Green indicates low risk; "
            "red indicates high risk.",
            styles["caption"],
        )
    )
    story.append(Spacer(1, 4))

    heatmap_table = _build_heatmap_table(vendors_data, styles)
    if heatmap_table:
        story.append(heatmap_table)
    story.append(Spacer(1, 8))

    # ---- Top 10 Highest-Risk Vendors ----
    story.append(Paragraph("Top 10 Highest-Risk Vendors", styles["h2"]))

    sorted_vendors = sorted(
        vendors_data,
        key=lambda vd: vd.get("risk_score", RiskScore(vendor_id="")).overall_score,
        reverse=True,
    )[:10]

    top_rows = []
    for i, vd in enumerate(sorted_vendors):
        v = vd["vendor"]
        rs = vd.get("risk_score")
        a = vd.get("assessment")
        score = rs.overall_score if rs else 0
        level = rs.risk_level if rs else "N/A"
        finding_cnt = len(a.findings) if a else 0
        lc = _risk_level_color(level)
        top_rows.append([
            str(i + 1),
            v.name,
            _fmt_enum(v.tier),
            f"{score:.0f}",
            Paragraph(
                f'<font color="{lc.hexval()}">{level}</font>',
                styles["table_cell_bold"],
            ),
            str(finding_cnt),
        ])

    if top_rows:
        top_table = _make_styled_table(
            ["#", "Vendor", "Tier", "Score", "Risk Level", "Findings"],
            top_rows,
            styles,
            col_widths=[24, 150, 60, 50, 70, 55],
        )
        story.append(top_table)
    story.append(Spacer(1, 12))

    # ---- BAA Status Summary ----
    story.append(Paragraph("BAA Compliance Summary", styles["h2"]))

    baa_summary_data = [
        [
            _kpi_cell(str(baa_active), "Active", styles, GREEN),
            _kpi_cell(str(baa_expiring), "Expiring / Renewal", styles, ORANGE),
            _kpi_cell(str(baa_expired), "Expired", styles, RED),
            _kpi_cell(str(baa_missing), "Missing / Other", styles, RED if baa_missing > 0 else TEXT_MUTED),
        ]
    ]
    baa_table = Table(baa_summary_data, colWidths=[CONTENT_W / 4] * 4, rowHeights=[50])
    baa_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(baa_table)
    story.append(Spacer(1, 12))

    # ---- Verification Status Summary ----
    story.append(Paragraph("Verification Status Summary", styles["h2"]))

    verif_pending = sum(
        1 for vd in vendors_data
        if vd.get("verification") and vd["verification"].status == VerificationStatus.PENDING
    )
    verif_overdue = sum(
        1 for vd in vendors_data
        if vd.get("verification") and vd["verification"].status == VerificationStatus.OVERDUE
    )
    verif_failed = sum(
        1 for vd in vendors_data
        if vd.get("verification") and vd["verification"].status == VerificationStatus.FAILED
    )
    verif_missing = sum(1 for vd in vendors_data if not vd.get("verification"))

    verif_summary = [
        [
            _kpi_cell(str(verif_complete), "Verified", styles, GREEN),
            _kpi_cell(str(verif_pending), "Pending", styles, ORANGE),
            _kpi_cell(str(verif_overdue), "Overdue", styles, RED),
            _kpi_cell(str(verif_failed + verif_missing), "Failed / Missing", styles,
                      RED if (verif_failed + verif_missing) > 0 else TEXT_MUTED),
        ]
    ]
    verif_table = Table(verif_summary, colWidths=[CONTENT_W / 4] * 4, rowHeights=[50])
    verif_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(verif_table)
    story.append(Spacer(1, 12))

    # ---- Findings Summary ----
    story.append(Paragraph("Findings Summary by Severity and Domain", styles["h2"]))

    # Severity summary row
    sev_row = []
    for sev_name in ["critical", "high", "medium", "low"]:
        cnt = findings_by_severity.get(sev_name, 0)
        sc, _ = SEVERITY_COLORS.get(sev_name, (TEXT_MUTED, SURFACE))
        sev_row.append(
            Paragraph(
                f'<font color="{sc.hexval()}"><b>{sev_name.upper()}: {cnt}</b></font>',
                ParagraphStyle("SevItem", parent=styles["body_bold"], fontSize=9,
                               alignment=TA_CENTER),
            )
        )
    sev_table = Table([sev_row], colWidths=[CONTENT_W / 4] * 4)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 8))

    # Findings by domain
    domain_findings: Dict[str, Dict[str, int]] = {}
    for f in all_findings:
        d = f.domain or "Other"
        if d not in domain_findings:
            domain_findings[d] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        domain_findings[d][sev_val] = domain_findings[d].get(sev_val, 0) + 1

    if domain_findings:
        df_rows = []
        for domain, counts in sorted(domain_findings.items()):
            total = sum(counts.values())
            df_rows.append([
                domain,
                str(counts.get("critical", 0)),
                str(counts.get("high", 0)),
                str(counts.get("medium", 0)),
                str(counts.get("low", 0)),
                str(total),
            ])
        df_table = _make_styled_table(
            ["Domain", "Critical", "High", "Medium", "Low", "Total"],
            df_rows,
            styles,
            col_widths=[150, 60, 60, 60, 60, 60],
        )
        story.append(df_table)
    story.append(Spacer(1, 12))

    # ---- Recommended Actions ----
    story.append(Paragraph("Prioritized Recommendations", styles["h2"]))

    recommendations = _generate_portfolio_recommendations(
        vendors_data, immediate_attention, all_findings,
        baa_expired, baa_missing, verif_overdue, verif_failed, verif_missing,
    )
    for i, rec in enumerate(recommendations[:8]):
        priority_colors = [RED, RED, ORANGE, ORANGE, YELLOW, YELLOW, GREEN, GREEN]
        pc = priority_colors[i] if i < len(priority_colors) else TEXT_MUTED
        story.append(
            Paragraph(
                f'<font color="{pc.hexval()}"><b>P{i + 1}.</b></font> {_xml_escape(rec)}',
                styles["body"],
            )
        )
    story.append(Spacer(1, 16))

    # ---- Methodology ----
    story.append(Paragraph("Methodology", styles["h2"]))
    story.append(
        Paragraph(
            "The VerifAI Security risk scoring model evaluates vendors across 10 security "
            "domains aligned with the HIPAA Security Rule, NIST Cybersecurity Framework (CSF), "
            "and HITRUST CSF. Each domain is scored 0-100 based on weighted assessment "
            "questions, with critical controls carrying higher weight.",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Risk Score Calculation:</b> The overall risk score combines inherent risk "
            "(based on vendor tier, PHI access, data volume, and integration type) with "
            "control effectiveness (from the security assessment). Inherent risk establishes "
            "the baseline; control scores modify the residual risk. Scores range from 0 "
            "(lowest risk) to 100 (highest risk).",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Risk Levels:</b> CRITICAL (75-100) — Immediate action required. "
            "HIGH (50-74) — Remediation within 30 days. "
            "MEDIUM (25-49) — Address within 90 days. "
            "LOW (0-24) — Routine monitoring.",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Assessment Domains:</b> Access Control, Audit &amp; Accountability, "
            "Configuration Management, Contingency Planning, Encryption &amp; Transmission, "
            "Identity &amp; Authentication, Incident Response, Physical Security, "
            "Risk Assessment, System &amp; Communications Protection.",
            styles["body"],
        )
    )

    # Build
    def on_cover_page(canvas_obj, doc_obj):
        """Cover page: dark background, no header bar."""
        canvas_obj.saveState()
        canvas_obj.setFillColor(DARK)
        canvas_obj.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

        # VerifAI Security brand mark at top
        canvas_obj.setFont(HEADING_FONT, 13)
        canvas_obj.setFillColor(TEAL)
        canvas_obj.drawString(MARGIN_LEFT, PAGE_H - 50, "VerifAI Security")

        # Decorative teal bar
        canvas_obj.setFillColor(TEAL)
        canvas_obj.rect(MARGIN_LEFT, PAGE_H - 60, 60, 3, fill=1, stroke=0)

        # Bottom confidentiality
        canvas_obj.setFont(BODY_FONT, 7)
        canvas_obj.setFillColor(HexColor("#5A6577"))
        canvas_obj.drawString(
            MARGIN_LEFT, 30,
            "CONFIDENTIAL — Proprietary risk assessment data. "
            "Do not distribute without authorization."
        )
        canvas_obj.restoreState()

    def on_later_pages(canvas_obj, doc_obj):
        """Standard header + footer for content pages."""
        canvas_obj.saveState()
        _draw_header(canvas_obj, doc_obj, title="Executive Vendor Risk Portfolio")
        _draw_footer(canvas_obj, doc_obj.page - 1)  # subtract 1 for cover
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=on_cover_page, onLaterPages=on_later_pages)
    return output_path


def _kpi_cell(value: str, label: str, styles: Dict,
              value_color: Optional[Color] = None) -> Table:
    """Create a KPI mini-cell for embedding in tables."""
    vc = value_color or TEAL
    val_style = ParagraphStyle(
        "KPIVal", parent=styles["kpi_value"], fontSize=20, leading=24,
        textColor=vc, alignment=TA_CENTER,
    )
    lbl_style = styles["kpi_label"]
    inner = Table(
        [[Paragraph(value, val_style)], [Paragraph(label, lbl_style)]],
        colWidths=[110],
    )
    inner.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return inner


def _draw_histogram(scores: List[float], width: float, height: float) -> Drawing:
    """Create a histogram drawing of risk scores."""
    d = Drawing(width, height)

    # Define bins
    bins = [(0, 10), (10, 20), (20, 30), (30, 40), (40, 50),
            (50, 60), (60, 70), (70, 80), (80, 90), (90, 100)]
    counts = [0] * len(bins)

    for s in scores:
        for i, (lo, hi) in enumerate(bins):
            if lo <= s < hi or (i == len(bins) - 1 and s == hi):
                counts[i] += 1
                break

    max_count = max(counts) if counts and max(counts) > 0 else 1
    margin_left = 30
    margin_bottom = 22
    margin_top = 10
    chart_w = width - margin_left - 20
    chart_h = height - margin_bottom - margin_top

    # Y axis
    d.add(Line(margin_left, margin_bottom, margin_left, height - margin_top,
               strokeColor=BORDER, strokeWidth=0.5))

    bar_w = chart_w / len(bins) - 2
    bar_colors = [GREEN, GREEN, HexColor("#6B9B37"), HexColor("#9BA816"),
                  HexColor("#B8B816"), ORANGE, ORANGE, HexColor("#D05020"),
                  RED, RED]

    for i, count in enumerate(counts):
        bar_h = (count / max_count) * chart_h if max_count > 0 else 0
        bx = margin_left + i * (chart_w / len(bins)) + 1
        by = margin_bottom

        # Bar
        if bar_h > 0:
            d.add(Rect(bx, by, bar_w, bar_h,
                       fillColor=bar_colors[i % len(bar_colors)],
                       strokeColor=None, strokeWidth=0))

        # Count label on top of bar
        if count > 0:
            d.add(String(bx + bar_w / 2, by + bar_h + 2, str(count),
                         fontName=HEADING_FONT, fontSize=7,
                         fillColor=TEXT_MUTED, textAnchor="middle"))

        # X axis label
        lo, hi = bins[i]
        d.add(String(bx + bar_w / 2, margin_bottom - 12,
                     f"{lo}-{hi}", fontName=BODY_FONT, fontSize=6,
                     fillColor=TEXT_MUTED, textAnchor="middle"))

    # Y axis labels
    for i in range(max_count + 1):
        if i % max(1, max_count // 4) == 0 or i == max_count:
            yy = margin_bottom + (i / max_count) * chart_h if max_count > 0 else margin_bottom
            d.add(String(margin_left - 4, yy - 3, str(i),
                         fontName=BODY_FONT, fontSize=6,
                         fillColor=TEXT_MUTED, textAnchor="end"))
            d.add(Line(margin_left, yy, margin_left + chart_w, yy,
                       strokeColor=BORDER_LIGHT, strokeWidth=0.3))

    # X axis title
    d.add(String(margin_left + chart_w / 2, 2, "Risk Score Range",
                 fontName=BODY_FONT, fontSize=7,
                 fillColor=TEXT_MUTED, textAnchor="middle"))

    return d


def _build_heatmap_table(vendors_data: List[Dict], styles: Dict) -> Optional[Table]:
    """Build a color-coded heatmap table of vendors vs. domains."""
    # Collect all domains
    all_domains: set = set()
    for vd in vendors_data:
        rs = vd.get("risk_score")
        a = vd.get("assessment")
        if rs and rs.domain_scores:
            all_domains.update(rs.domain_scores.keys())
        elif a and a.domain_scores:
            all_domains.update(a.domain_scores.keys())

    if not all_domains:
        return None

    domains = sorted(all_domains)[:8]  # Limit to 8 for readability
    short_domains = [d[:12] for d in domains]

    # Sort vendors by risk score descending, take top 12
    sorted_vd = sorted(
        vendors_data,
        key=lambda vd: vd.get("risk_score", RiskScore(vendor_id="")).overall_score,
        reverse=True,
    )[:12]

    header = ["Vendor"] + short_domains
    rows = []
    cell_colors = []

    for vd in sorted_vd:
        v = vd["vendor"]
        rs = vd.get("risk_score")
        a = vd.get("assessment")
        ds = {}
        if rs and rs.domain_scores:
            ds = rs.domain_scores
        elif a and a.domain_scores:
            ds = a.domain_scores

        row = [v.name[:18]]
        row_colors = [None]
        for domain in domains:
            score = ds.get(domain, None)
            if score is not None:
                row.append(f"{score:.0f}")
                row_colors.append(_heatmap_color(score))
            else:
                row.append("—")
                row_colors.append(SURFACE)
        rows.append(row)
        cell_colors.append(row_colors)

    domain_col_w = (CONTENT_W - 100) / len(domains)
    col_widths = [100] + [domain_col_w] * len(domains)

    all_rows = [header] + rows
    t = Table(all_rows, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), HEADING_FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("FONTNAME", (0, 1), (0, -1), HEADING_FONT),
        ("FONTNAME", (1, 1), (-1, -1), BODY_FONT),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("LINEBELOW", (0, 0), (-1, 0), 1, TEAL),
    ]

    # Apply cell background colors
    for row_idx, row_colors in enumerate(cell_colors):
        for col_idx, color in enumerate(row_colors):
            if color:
                style_cmds.append(
                    ("BACKGROUND", (col_idx, row_idx + 1), (col_idx, row_idx + 1), color)
                )

    t.setStyle(TableStyle(style_cmds))
    return t


def _heatmap_color(score: float) -> Color:
    """Map score to a heatmap background color."""
    if score >= 75:
        return HexColor("#FEE2E2")  # light red
    elif score >= 50:
        return HexColor("#FFF1E6")  # light orange
    elif score >= 25:
        return HexColor("#FFFBEB")  # light yellow
    else:
        return HexColor("#F0F8EC")  # light green


def _generate_portfolio_recommendations(
    vendors_data, immediate_attention, all_findings,
    baa_expired, baa_missing, verif_overdue, verif_failed, verif_missing,
) -> List[str]:
    """Generate portfolio-level prioritized recommendations."""
    recs = []

    crit_count = sum(
        1 for f in all_findings if f.severity == FindingSeverity.CRITICAL
    )
    if crit_count > 0:
        recs.append(
            f"Remediate {crit_count} critical finding(s) immediately — these represent "
            f"the highest compliance and breach risk."
        )

    if baa_expired > 0:
        recs.append(
            f"Renew {baa_expired} expired BAA(s) — vendors without active agreements "
            f"are operating outside HIPAA compliance."
        )

    if baa_missing > 0:
        recs.append(
            f"Execute BAAs for {baa_missing} vendor(s) currently missing agreements."
        )

    if verif_overdue > 0:
        recs.append(
            f"Complete {verif_overdue} overdue verification(s) — annual attestation "
            f"is a HIPAA requirement."
        )

    if immediate_attention:
        names = [v.name for v, _, _ in immediate_attention[:3]]
        recs.append(
            f"Prioritize risk reduction for: {', '.join(names)}. "
            f"These vendors exceed acceptable risk thresholds."
        )

    high_count = sum(
        1 for f in all_findings if f.severity == FindingSeverity.HIGH
    )
    if high_count > 0:
        recs.append(
            f"Address {high_count} high-severity finding(s) within 30-day remediation window."
        )

    if verif_missing > 0:
        recs.append(
            f"Initiate verification requests for {verif_missing} vendor(s) without "
            f"any verification record."
        )

    recs.append(
        "Schedule quarterly risk review meetings to monitor remediation progress "
        "and emerging threats."
    )

    return recs


# ============================================================================
# Report 3: Annual Attestation Report
# ============================================================================

def generate_attestation_report(
    vendor: Vendor,
    verification: Optional[Verification],
    assessment: Optional[VendorAssessment],
    baa: Optional[BAA],
    output_path: str,
) -> str:
    """
    Generate the HIPAA-required Annual Business Associate Verification Report.

    Returns the output file path.
    """
    _register_fonts()
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        title=f"Annual Business Associate Verification — {vendor.name}",
        author="Perplexity Computer",
        leftMargin=MARGIN_LEFT,
        rightMargin=MARGIN_RIGHT,
        topMargin=MARGIN_TOP + HEADER_HEIGHT + 4,
        bottomMargin=MARGIN_BOTTOM + 10,
    )

    story: List[Any] = []

    # --- Title ---
    story.append(Spacer(1, 4))
    story.append(
        Paragraph("Annual Business Associate<br/>Verification Report", styles["title"])
    )
    story.append(
        HRFlowable(width="100%", thickness=2, color=TEAL, spaceAfter=10)
    )

    # Reporting period
    now = datetime.now()
    period_start = date(now.year - 1, now.month, 1)
    period_end = date(now.year, now.month, now.day)

    story.append(
        Paragraph(
            f"<b>Reporting Period:</b> {_fmt_date(period_start)} — {_fmt_date(period_end)}",
            styles["body"],
        )
    )
    story.append(Spacer(1, 10))

    # --- Vendor Information ---
    story.append(Paragraph("Vendor Information", styles["h2"]))
    vendor_info = [
        ("Vendor Name", vendor.name),
        ("Legal Name", vendor.legal_name or vendor.name),
        ("Vendor Type", _fmt_enum(vendor.vendor_type)),
        ("Tier", _fmt_enum(vendor.tier)),
        ("Status", _fmt_enum(vendor.status)),
        ("PHI Access", "Yes" if vendor.phi_access else "No"),
        ("PHI Types", ", ".join(vendor.phi_types) if vendor.phi_types else "N/A"),
        ("Contact", f"{vendor.contact_name} ({vendor.contact_email})" if vendor.contact_name else "N/A"),
    ]
    story.append(_make_info_table(vendor_info, styles))
    story.append(Spacer(1, 10))

    # --- BAA Reference ---
    story.append(Paragraph("Business Associate Agreement Reference", styles["h2"]))
    if baa:
        baa_info = [
            ("BAA Status", _fmt_enum(baa.status)),
            ("Effective Date", _fmt_date(baa.effective_date)),
            ("Expiration Date", _fmt_date(baa.expiration_date)),
            ("Breach Notification", f"{baa.breach_notification_hours} hours"),
            ("Contingency Notification", f"{baa.contingency_notification_hours} hours"),
            ("Subcontractor Flow-Down", "Yes" if baa.subcontractor_flow_down else "No"),
            ("BAA Version", baa.version),
        ]
        story.append(_make_info_table(baa_info, styles))
    else:
        story.append(
            Paragraph(
                '<font color="#C13030"><b>WARNING:</b> No Business Associate Agreement on file.</font>',
                styles["body"],
            )
        )
    story.append(Spacer(1, 14))

    # --- Verification Checklist ---
    story.append(Paragraph("Verification Checklist", styles["h2"]))
    story.append(
        Paragraph(
            "Per HIPAA §164.306(b) and the updated Security Rule requirements, "
            "the following verifications are required annually:",
            styles["section_intro"],
        )
    )
    story.append(Spacer(1, 4))

    has_safeguards = (verification and len(verification.safeguards_confirmed) > 0)
    has_analysis = (verification and verification.professional_analysis_attached)
    has_cert = (verification and verification.authorized_representative_certified)

    checklist_items = [
        (
            "Written Verification of Technical Safeguards",
            "Business associate has provided written verification that required "
            "technical safeguards are deployed and operational.",
            has_safeguards,
        ),
        (
            "Professional Analysis Attached",
            "A qualified professional's written analysis of the deployed safeguards "
            "has been provided and reviewed.",
            has_analysis,
        ),
        (
            "Authorized Representative Certification",
            "An authorized representative of the business associate has certified "
            "the accuracy and completeness of the verification.",
            has_cert,
        ),
    ]

    checklist_rows = []
    for ck_title, ck_desc, ck_val in checklist_items:
        status_text = "YES" if ck_val else "NO"
        status_color = GREEN if ck_val else RED
        indicator = "&#x2713;" if ck_val else "&#x2717;"
        checklist_rows.append([
            Paragraph(
                f'<font color="{status_color.hexval()}" size="14">{indicator}</font>',
                ParagraphStyle("CheckInd", alignment=TA_CENTER, fontSize=14, leading=18),
            ),
            Paragraph(f"<b>{_xml_escape(ck_title)}</b><br/>{_xml_escape(ck_desc)}", styles["body_small"]),
            Paragraph(
                f'<font color="{status_color.hexval()}"><b>{status_text}</b></font>',
                ParagraphStyle("CheckStatus", parent=styles["body_bold"],
                               alignment=TA_CENTER, textColor=status_color),
            ),
        ])

    check_table = Table(checklist_rows, colWidths=[36, CONTENT_W - 100, 64])
    check_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
    ]))
    story.append(check_table)
    story.append(Spacer(1, 14))

    # --- Safeguards Confirmed ---
    story.append(Paragraph("Safeguards Confirmed", styles["h2"]))
    if verification and verification.safeguards_confirmed:
        for sg in verification.safeguards_confirmed:
            story.append(
                Paragraph(
                    f'<font color="{GREEN.hexval()}">&#x2713;</font> {_xml_escape(sg)}',
                    styles["body_small"],
                )
            )
    else:
        story.append(
            Paragraph(
                '<font color="#C13030">No safeguards have been confirmed.</font>',
                styles["body_small"],
            )
        )
    story.append(Spacer(1, 14))

    # --- Assessment Score & Risk Level ---
    story.append(Paragraph("Assessment Score and Risk Level", styles["h2"]))
    if assessment:
        score = assessment.overall_score
        level = assessment.risk_level or "N/A"
        lc = _risk_level_color(level)
        story.append(
            Paragraph(
                f"Overall Assessment Score: <b>{score:.1f}/100</b>",
                styles["body"],
            )
        )
        story.append(
            Paragraph(
                f'Risk Level: <font color="{lc.hexval()}"><b>{level}</b></font>',
                styles["body"],
            )
        )
        if assessment.assessed_by:
            story.append(
                Paragraph(f"Assessed By: {_xml_escape(assessment.assessed_by)}", styles["body_small"])
            )
        if assessment.completed_date:
            story.append(
                Paragraph(
                    f"Assessment Completed: {_fmt_date(assessment.completed_date)}",
                    styles["body_small"],
                )
            )
    else:
        story.append(
            Paragraph(
                '<font color="#C13030">No assessment has been completed for this vendor.</font>',
                styles["body"],
            )
        )
    story.append(Spacer(1, 14))

    # --- Open Findings Requiring Remediation ---
    story.append(Paragraph("Open Findings Requiring Remediation", styles["h2"]))
    open_findings = []
    if assessment:
        open_findings = [
            f for f in assessment.findings
            if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
        ]
        open_findings.sort(key=lambda f: _severity_sort_key(f.severity))

    if open_findings:
        finding_rows = []
        for f in open_findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sc, _ = SEVERITY_COLORS.get(sev_val, (TEXT_MUTED, SURFACE))
            finding_rows.append([
                Paragraph(
                    f'<font color="{sc.hexval()}"><b>{sev_val.upper()}</b></font>',
                    styles["table_cell_bold"],
                ),
                f.title,
                f.domain or "—",
                _fmt_enum(f.remediation_timeline),
                _fmt_enum(f.status),
            ])
        f_table = _make_styled_table(
            ["Severity", "Finding", "Domain", "Timeline", "Status"],
            finding_rows,
            styles,
            col_widths=[60, 180, 80, 70, 70],
        )
        story.append(f_table)
    else:
        story.append(
            Paragraph("No open findings requiring remediation.", styles["body"])
        )
    story.append(Spacer(1, 20))

    # --- Signature Blocks ---
    story.append(Paragraph("Certification and Signatures", styles["h2"]))
    story.append(
        HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8)
    )

    sig_block_style = ParagraphStyle(
        "SigBlock", parent=styles["body"], fontSize=9, leading=13,
    )
    sig_line_style = ParagraphStyle(
        "SigLine", parent=styles["body"], fontSize=8.5, leading=12,
        textColor=TEXT_MUTED, spaceBefore=24,
    )

    # Vendor representative
    story.append(Paragraph("<b>Vendor Representative</b>", sig_block_style))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "I certify that the information provided in this verification is accurate "
            "and complete to the best of my knowledge.",
            styles["body_small"],
        )
    )
    story.append(Spacer(1, 20))

    sig_data_vendor = [
        [
            Paragraph("_" * 45 + "<br/>Signature", sig_line_style),
            Paragraph("_" * 30 + "<br/>Date", sig_line_style),
        ],
        [
            Paragraph("_" * 45 + "<br/>Printed Name", sig_line_style),
            Paragraph("_" * 30 + "<br/>Title", sig_line_style),
        ],
    ]
    sig_table_v = Table(sig_data_vendor, colWidths=[CONTENT_W * 0.6, CONTENT_W * 0.4])
    sig_table_v.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(sig_table_v)
    story.append(Spacer(1, 16))

    # Organization representative
    story.append(Paragraph("<b>Covered Entity Representative</b>", sig_block_style))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            "I acknowledge receipt and review of the business associate verification "
            "documentation referenced above.",
            styles["body_small"],
        )
    )
    story.append(Spacer(1, 20))

    sig_data_org = [
        [
            Paragraph("_" * 45 + "<br/>Signature", sig_line_style),
            Paragraph("_" * 30 + "<br/>Date", sig_line_style),
        ],
        [
            Paragraph("_" * 45 + "<br/>Printed Name", sig_line_style),
            Paragraph("_" * 30 + "<br/>Title", sig_line_style),
        ],
    ]
    sig_table_o = Table(sig_data_org, colWidths=[CONTENT_W * 0.6, CONTENT_W * 0.4])
    sig_table_o.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(sig_table_o)
    story.append(Spacer(1, 20))

    # --- Legal Notice ---
    story.append(
        HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8)
    )
    story.append(
        Paragraph(
            '<font size="8"><b>Legal Notice — HIPAA §164.306(b) Compliance</b></font>',
            styles["legal"],
        )
    )
    story.append(
        Paragraph(
            "This report is prepared in accordance with the Health Insurance Portability "
            "and Accountability Act (HIPAA) Security Rule requirements under 45 CFR "
            "§164.306(b). The covered entity is required to obtain written verification "
            "from each business associate that technical safeguards required by the Security "
            "Rule are deployed. Such verification must be accompanied by a written analysis "
            "by a qualified professional and certification by an authorized representative "
            "of the business associate. Failure to obtain and maintain this verification "
            "may result in regulatory enforcement action and penalties.",
            styles["legal"],
        )
    )
    story.append(
        Paragraph(
            "This document should be retained for a minimum of six (6) years in accordance "
            "with HIPAA documentation requirements at 45 CFR §164.530(j).",
            styles["legal"],
        )
    )

    def on_first(canvas_obj, doc_obj):
        canvas_obj.saveState()
        _draw_header(canvas_obj, doc_obj, title="Annual Business Associate Verification")
        _draw_footer(canvas_obj, doc_obj.page)
        canvas_obj.restoreState()

    def on_later(canvas_obj, doc_obj):
        canvas_obj.saveState()
        _draw_header(canvas_obj, doc_obj, title="Annual Business Associate Verification")
        _draw_footer(canvas_obj, doc_obj.page)
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=on_first, onLaterPages=on_later)
    return output_path


# ============================================================================
# Report 4: Remediation Tracker Report
# ============================================================================

def generate_remediation_report(
    vendors_findings_data: List[Dict[str, Any]],
    org_name: str,
    output_path: str,
) -> str:
    """
    Generate a Remediation Tracker Report PDF.

    vendors_findings_data: list of dicts with keys:
        vendor (Vendor), findings (List[Finding])

    Returns the output file path.
    """
    _register_fonts()
    styles = _build_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        title=f"Remediation Tracker — {org_name}",
        author="Perplexity Computer",
        leftMargin=MARGIN_LEFT,
        rightMargin=MARGIN_RIGHT,
        topMargin=MARGIN_TOP + HEADER_HEIGHT + 4,
        bottomMargin=MARGIN_BOTTOM + 10,
    )

    story: List[Any] = []

    # --- Title ---
    story.append(Spacer(1, 4))
    story.append(Paragraph("Remediation Tracker", styles["title"]))
    story.append(
        Paragraph(
            f"{org_name} — {datetime.now().strftime('%B %d, %Y')}",
            styles["subtitle"],
        )
    )
    story.append(
        HRFlowable(width="100%", thickness=2, color=TEAL, spaceAfter=12)
    )

    # --- Collect all findings ---
    today = date.today()
    all_entries: List[Tuple[Vendor, Finding]] = []
    for vfd in vendors_findings_data:
        v = vfd["vendor"]
        findings = vfd.get("findings", [])
        for f in findings:
            if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS,
                            FindingStatus.DEFERRED):
                all_entries.append((v, f))

    # Sort by severity then due date
    def sort_key(entry):
        _, f = entry
        sev_order = _severity_sort_key(f.severity)
        due = f.due_date or date(2099, 12, 31)
        return (sev_order, due)

    all_entries.sort(key=sort_key)

    # --- Summary Stats ---
    total_open = len(all_entries)
    overdue = sum(1 for _, f in all_entries if f.due_date and f.due_date < today)
    in_progress = sum(1 for _, f in all_entries if f.status == FindingStatus.IN_PROGRESS)
    deferred = sum(1 for _, f in all_entries if f.status == FindingStatus.DEFERRED)

    # Count remediated this period (last 30 days)
    remediated_this_period = 0
    for vfd in vendors_findings_data:
        for f in vfd.get("findings", []):
            if (f.status == FindingStatus.REMEDIATED and f.closed_date
                    and (today - f.closed_date).days <= 30):
                remediated_this_period += 1

    # Approaching deadline (within 14 days)
    approaching = sum(
        1 for _, f in all_entries
        if f.due_date and today <= f.due_date and (f.due_date - today).days <= 14
    )

    summary_data = [
        [
            _kpi_cell(str(total_open), "Total Open", styles, RED if total_open > 0 else GREEN),
            _kpi_cell(str(overdue), "Overdue", styles, RED if overdue > 0 else GREEN),
            _kpi_cell(str(approaching), "Approaching Deadline", styles,
                      ORANGE if approaching > 0 else GREEN),
            _kpi_cell(str(remediated_this_period), "Remediated (30d)", styles, GREEN),
        ]
    ]

    summary_table = Table(summary_data, colWidths=[CONTENT_W / 4] * 4, rowHeights=[56])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 6))

    # Additional stats bar
    add_stats = [
        [
            Paragraph(f"<b>In Progress:</b> {in_progress}", styles["body_small"]),
            Paragraph(f"<b>Deferred:</b> {deferred}", styles["body_small"]),
            Paragraph(
                f"<b>By Severity:</b> "
                f'<font color="{RED.hexval()}">C:{sum(1 for _, f in all_entries if f.severity == FindingSeverity.CRITICAL)}</font> | '
                f'<font color="{HexColor("#EA580C").hexval()}">H:{sum(1 for _, f in all_entries if f.severity == FindingSeverity.HIGH)}</font> | '
                f'<font color="{ORANGE.hexval()}">M:{sum(1 for _, f in all_entries if f.severity == FindingSeverity.MEDIUM)}</font> | '
                f'<font color="{GREEN.hexval()}">L:{sum(1 for _, f in all_entries if f.severity == FindingSeverity.LOW)}</font>',
                styles["body_small"],
            ),
        ]
    ]
    add_table = Table(add_stats, colWidths=[CONTENT_W / 3] * 3)
    add_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(add_table)
    story.append(Spacer(1, 14))

    # --- Findings Table ---
    story.append(Paragraph("Open Findings", styles["h2"]))
    story.append(
        Paragraph(
            "All open findings sorted by severity and due date. "
            "Overdue items are highlighted in red; items approaching deadline are in amber.",
            styles["caption"],
        )
    )
    story.append(Spacer(1, 6))

    if all_entries:
        finding_rows = []
        row_bg_overrides = []

        for vendor, f in all_entries:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sc, _ = SEVERITY_COLORS.get(sev_val, (TEXT_MUTED, SURFACE))

            # Determine row status styling
            is_overdue = f.due_date and f.due_date < today
            is_approaching = (f.due_date and today <= f.due_date
                              and (f.due_date - today).days <= 14)

            if is_overdue:
                row_bg = RED_BG
                due_text = f'<font color="{RED.hexval()}"><b>{_fmt_date(f.due_date)} (OVERDUE)</b></font>'
            elif is_approaching:
                row_bg = ORANGE_BG
                days_left = (f.due_date - today).days
                due_text = f'<font color="{ORANGE.hexval()}"><b>{_fmt_date(f.due_date)} ({days_left}d)</b></font>'
            else:
                row_bg = None
                due_text = _fmt_date(f.due_date)

            status_val = f.status.value if hasattr(f.status, "value") else str(f.status)
            status_c = STATUS_COLORS.get(status_val, TEXT_MUTED)

            finding_rows.append([
                Paragraph(
                    f'<font color="{sc.hexval()}"><b>{sev_val.upper()}</b></font>',
                    styles["table_cell_bold"],
                ),
                vendor.name[:16],
                Paragraph(_xml_escape(f.title[:40]), styles["table_cell"]),
                f.domain[:14] if f.domain else "—",
                Paragraph(due_text, styles["table_cell"]),
                Paragraph(
                    f'<font color="{status_c.hexval()}">{_fmt_enum(f.status)}</font>',
                    styles["table_cell"],
                ),
            ])
            row_bg_overrides.append(row_bg)

        headers = ["Severity", "Vendor", "Finding", "Domain", "Due Date", "Status"]
        col_widths = [52, 80, 130, 68, 100, 60]

        header_row = [Paragraph(_xml_escape(h), styles["table_header"]) for h in headers]
        data_rows_cells = []
        for row in finding_rows:
            cells = []
            for cell in row:
                if isinstance(cell, Paragraph):
                    cells.append(cell)
                else:
                    cells.append(Paragraph(_xml_escape(str(cell)), styles["table_cell"]))
            data_rows_cells.append(cells)

        all_data = [header_row] + data_rows_cells
        t = Table(all_data, colWidths=col_widths, repeatRows=1)

        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), HEADING_FONT),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
            ("LINEBELOW", (0, 0), (-1, 0), 1, TEAL),
        ]

        # Apply overdue/approaching row backgrounds
        for i, bg in enumerate(row_bg_overrides):
            if bg:
                style_cmds.append(
                    ("BACKGROUND", (0, i + 1), (-1, i + 1), bg)
                )
            elif i % 2 == 1:
                style_cmds.append(
                    ("BACKGROUND", (0, i + 1), (-1, i + 1), SURFACE)
                )

        t.setStyle(TableStyle(style_cmds))
        story.append(t)
    else:
        story.append(
            Paragraph(
                "No open findings across the vendor portfolio. All items have been remediated.",
                styles["body"],
            )
        )

    story.append(Spacer(1, 20))

    # --- Legend ---
    story.append(
        HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8)
    )
    legend_items = [
        f'<font color="{RED.hexval()}">&#x25A0;</font> Overdue — Past due date, requires immediate action',
        f'<font color="{ORANGE.hexval()}">&#x25A0;</font> Approaching — Due within 14 days',
        f'<font color="{GREEN.hexval()}">&#x25A0;</font> On Track — Within remediation timeline',
    ]
    for item in legend_items:
        story.append(Paragraph(item, styles["caption"]))

    def on_first(canvas_obj, doc_obj):
        canvas_obj.saveState()
        _draw_header(canvas_obj, doc_obj, title="Remediation Tracker")
        _draw_footer(canvas_obj, doc_obj.page)
        canvas_obj.restoreState()

    def on_later(canvas_obj, doc_obj):
        canvas_obj.saveState()
        _draw_header(canvas_obj, doc_obj, title="Remediation Tracker")
        _draw_footer(canvas_obj, doc_obj.page)
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=on_first, onLaterPages=on_later)
    return output_path
