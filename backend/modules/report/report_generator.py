"""
SentinelX — PDF Report Generator
Uses ReportLab to produce a structured PDF from scan results.
"""

import io
import logging
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

logger = logging.getLogger("sentinelx.report_generator")

_SEV_COLORS = {
    "critical": colors.HexColor("#fde8e8"),
    "high":     colors.HexColor("#fef3e2"),
    "medium":   colors.HexColor("#fefce8"),
    "low":      colors.HexColor("#f0fdf4"),
    "info":     colors.HexColor("#f0f9ff"),
}

_RISK_COLOR = {
    "high":   colors.HexColor("#dc2626"),
    "medium": colors.HexColor("#f97316"),
    "low":    colors.HexColor("#16a34a"),
}


def _risk_level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def generate_report(scan_id: str, scan_result: dict) -> bytes:
    """
    Generate a PDF security report from a scan result dict.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    normal = styles["Normal"]

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontSize=28,
        spaceAfter=12,
        textColor=colors.HexColor("#1e3a5f"),
    )
    subtitle_style = ParagraphStyle(
        "CoverSub",
        parent=normal,
        fontSize=13,
        textColor=colors.HexColor("#4b5563"),
        spaceAfter=6,
    )
    section_style = ParagraphStyle(
        "Section",
        parent=h2,
        fontSize=14,
        textColor=colors.HexColor("#1e3a5f"),
        spaceBefore=16,
        spaceAfter=8,
        borderPad=4,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=normal,
        fontSize=10,
        leading=15,
        textColor=colors.HexColor("#374151"),
        spaceAfter=6,
    )
    bullet_style = ParagraphStyle(
        "Bullet",
        parent=body_style,
        leftIndent=18,
        bulletIndent=6,
        spaceBefore=2,
    )

    target = scan_result.get("target") or scan_result.get("domain", "Unknown Target")
    created_raw = scan_result.get("created_at", "")
    try:
        created_dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
        scan_date = created_dt.strftime("%B %d, %Y %H:%M UTC")
    except Exception:
        scan_date = created_raw or "Unknown"

    ai_report: dict[str, Any] = (
        scan_result.get("ai_report")
        or (scan_result.get("results") or {}).get("ai_report")
        or {}
    )
    risk_score: int = int(ai_report.get("risk_score") or scan_result.get("risk_score") or 0)
    executive_summary: str = ai_report.get("executive_summary", "No analysis available.")
    top_risks: list = ai_report.get("top_risks") or []
    remediation_priorities: list = ai_report.get("remediation_priorities") or []

    raw_findings: list = (
        scan_result.get("findings")
        or (scan_result.get("results") or {}).get("findings")
        or []
    )
    critical_findings: list = ai_report.get("critical_findings") or [
        f for f in raw_findings if f.get("severity") in ("critical", "high")
    ]

    rl = _risk_level(risk_score)
    risk_color = _RISK_COLOR.get(rl, colors.black)

    story = []

    # ── Cover Page ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1 * inch))
    story.append(Paragraph("SentinelX", title_style))
    story.append(Paragraph("Security Assessment Report", title_style))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"<b>Target:</b> {target}", subtitle_style))
    story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", subtitle_style))
    story.append(Spacer(1, 0.4 * inch))

    risk_display_style = ParagraphStyle(
        "RiskDisplay",
        parent=normal,
        fontSize=22,
        textColor=risk_color,
        spaceAfter=6,
    )
    story.append(Paragraph(f"<b>Risk Score: {risk_score}/100</b>", risk_display_style))
    story.append(Paragraph(f"Risk Level: {rl.upper()}", subtitle_style))
    story.append(PageBreak())

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", section_style))
    story.append(Paragraph(executive_summary, body_style))

    if top_risks:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("<b>Top Risks</b>", body_style))
        for risk in top_risks[:5]:
            story.append(Paragraph(f"• {risk}", bullet_style))

    story.append(Spacer(1, 0.2 * inch))

    # ── Critical Findings Table ───────────────────────────────────────────────
    story.append(Paragraph("Critical Findings", section_style))

    def _finding_rows(findings: list) -> list:
        rows = [["Finding", "Severity", "CVE", "Description"]]
        for item in findings:
            if isinstance(item, dict):
                title = item.get("title") or item.get("finding") or str(item)
                sev = str(item.get("severity") or "").upper()
                cve = str(item.get("cve_id") or item.get("cve") or "—")
                desc = str(item.get("description") or item.get("action") or "")[:120]
            else:
                title, sev, cve, desc = str(item)[:60], "", "—", ""
            rows.append([title[:60], sev, cve, desc])
        return rows

    if critical_findings:
        rows = _finding_rows(critical_findings[:20])
        col_widths = [2.2 * inch, 0.8 * inch, 1.0 * inch, 2.7 * inch]
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)

        tbl_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e5e7eb")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ]
        for i, row in enumerate(rows[1:], start=1):
            sev_key = str(row[1]).lower()
            bg = _SEV_COLORS.get(sev_key)
            if bg:
                tbl_style.append(("BACKGROUND", (1, i), (1, i), bg))

        tbl.setStyle(TableStyle(tbl_style))
        story.append(tbl)
    else:
        story.append(Paragraph("No critical findings recorded.", body_style))

    story.append(Spacer(1, 0.3 * inch))

    # ── Remediation Steps ─────────────────────────────────────────────────────
    story.append(Paragraph("Remediation Priorities", section_style))

    if remediation_priorities:
        for idx, item in enumerate(remediation_priorities[:15], start=1):
            if isinstance(item, dict):
                finding = item.get("finding") or item.get("title") or ""
                action = item.get("action") or item.get("description") or str(item)
                text = f"<b>{idx}. {finding}</b><br/>{action}" if finding else f"<b>{idx}.</b> {action}"
            else:
                text = f"<b>{idx}.</b> {item}"
            story.append(Paragraph(text, body_style))
            story.append(Spacer(1, 0.05 * inch))
    else:
        story.append(Paragraph("No remediation priorities recorded.", body_style))

    doc.build(story)
    return buf.getvalue()
