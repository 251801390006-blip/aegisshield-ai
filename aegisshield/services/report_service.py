"""
AegisShield AI – PDF Report Service

Generates professional cybersecurity PDF reports using ReportLab.
"""

import os
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas


# ── Color palette ────────────────────────────────────────────────────────────
DARK_BG = colors.HexColor("#0d1117")
NEON_BLUE = colors.HexColor("#00d4ff")
NEON_GREEN = colors.HexColor("#00ff87")
DANGER_RED = colors.HexColor("#ff4444")
WARN_ORANGE = colors.HexColor("#ff9800")
SAFE_GREEN = colors.HexColor("#4caf50")
TEXT_LIGHT = colors.HexColor("#e6edf3")
PANEL_BG = colors.HexColor("#161b22")
BORDER_COLOR = colors.HexColor("#30363d")


def generate_scan_report(scan_data: dict, user_data: dict) -> bytes:
    """
    Generate a professional PDF report for a scan result.
    Returns the PDF as bytes.
    """
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
        title=f"AegisShield AI – {scan_data.get('scan_type', 'Security').title()} Scan Report",
        author="AegisShield AI Platform",
        subject="Cybersecurity Threat Analysis Report",
    )

    styles = _build_styles()
    story = []

    # ── Header ─────────────────────────────────────────────────────────────
    story.extend(_build_header(styles, scan_data))
    story.append(Spacer(1, 0.5 * cm))

    # ── Scan Overview ──────────────────────────────────────────────────────
    story.extend(_build_overview_section(styles, scan_data, user_data))
    story.append(Spacer(1, 0.4 * cm))

    # ── Risk Score Gauge ───────────────────────────────────────────────────
    story.extend(_build_risk_section(styles, scan_data))
    story.append(Spacer(1, 0.4 * cm))

    # ── Threat Indicators ─────────────────────────────────────────────────
    story.extend(_build_indicators_section(styles, scan_data))
    story.append(Spacer(1, 0.4 * cm))

    # ── AI Threat Summary ─────────────────────────────────────────────────
    story.extend(_build_summary_section(styles, scan_data))
    story.append(Spacer(1, 0.4 * cm))

    # ── Technical Details ─────────────────────────────────────────────────
    story.extend(_build_technical_section(styles, scan_data))
    story.append(Spacer(1, 0.4 * cm))

    # ── Recommendations ────────────────────────────────────────────────────
    story.extend(_build_recommendations_section(styles, scan_data))
    story.append(Spacer(1, 0.4 * cm))

    # ── Footer disclaimer ─────────────────────────────────────────────────
    story.extend(_build_footer_section(styles))

    doc.build(story, onFirstPage=_add_watermark, onLaterPages=_add_watermark)
    return buffer.getvalue()


def _build_styles():
    styles = getSampleStyleSheet()
    custom = {
        "ReportTitle": ParagraphStyle(
            "ReportTitle", parent=styles["Title"],
            fontSize=24, textColor=NEON_BLUE, spaceAfter=4,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        ),
        "ReportSubtitle": ParagraphStyle(
            "ReportSubtitle", parent=styles["Normal"],
            fontSize=11, textColor=TEXT_LIGHT, spaceAfter=2,
            alignment=TA_CENTER, fontName="Helvetica",
        ),
        "SectionHeading": ParagraphStyle(
            "SectionHeading", parent=styles["Heading2"],
            fontSize=13, textColor=NEON_BLUE, spaceBefore=12,
            spaceAfter=6, fontName="Helvetica-Bold",
            borderPad=4,
        ),
        "BodyText": ParagraphStyle(
            "BodyText", parent=styles["Normal"],
            fontSize=10, textColor=colors.HexColor("#8b949e"),
            spaceAfter=4, fontName="Helvetica",
        ),
        "ThreatText": ParagraphStyle(
            "ThreatText", parent=styles["Normal"],
            fontSize=10, textColor=DANGER_RED,
            fontName="Helvetica-Bold",
        ),
        "SafeText": ParagraphStyle(
            "SafeText", parent=styles["Normal"],
            fontSize=10, textColor=SAFE_GREEN,
            fontName="Helvetica-Bold",
        ),
        "MetaText": ParagraphStyle(
            "MetaText", parent=styles["Normal"],
            fontSize=9, textColor=colors.HexColor("#6e7681"),
            fontName="Helvetica",
        ),
    }
    return {**{k: styles[k] for k in styles.byName}, **custom}


def _build_header(styles, scan_data):
    elements = []
    scan_type = scan_data.get("scan_type", "Security").title()
    result = scan_data.get("result", "UNKNOWN")
    is_threat = scan_data.get("is_threat", False)

    elements.append(Paragraph("🛡 AegisShield AI", styles["ReportTitle"]))
    elements.append(Paragraph(
        f"{scan_type} Analysis Report  •  Generated {datetime.now().strftime('%B %d, %Y at %H:%M UTC')}",
        styles["ReportSubtitle"],
    ))
    elements.append(HRFlowable(width="100%", thickness=1, color=NEON_BLUE, spaceAfter=8))

    result_color = DANGER_RED if is_threat else SAFE_GREEN
    result_text = f'<font color="#{result_color.hexval()[2:].upper()}">{result}</font>'
    elements.append(Paragraph(f"Verdict: {result_text}", styles["SectionHeading"]))
    return elements


def _build_overview_section(styles, scan_data, user_data):
    elements = [Paragraph("Scan Overview", styles["SectionHeading"])]

    data = [
        ["Field", "Value"],
        ["Report ID", f"RPT-{scan_data.get('id', 'N/A'):06d}" if scan_data.get("id") else "RPT-PREVIEW"],
        ["Scan Type", scan_data.get("scan_type", "N/A").upper()],
        ["Analyst", user_data.get("username", "N/A")],
        ["Timestamp", scan_data.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))],
        ["Input", str(scan_data.get("input_data", "N/A"))[:80]],
        ["Result", scan_data.get("result", "N/A")],
        ["Risk Score", f"{scan_data.get('risk_score', 0):.1f} / 100"],
        ["Threat Status", "⚠ THREAT DETECTED" if scan_data.get("is_threat") else "✓ SAFE"],
    ]

    table = Table(data, colWidths=[4.5 * cm, 12 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), NEON_BLUE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 9),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#8b949e")),
        ("TEXTCOLOR", (1, 1), (1, -1), TEXT_LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(table)
    return elements


def _build_risk_section(styles, scan_data):
    elements = [Paragraph("Risk Assessment", styles["SectionHeading"])]
    score = scan_data.get("risk_score", 0)

    if score >= 80:
        level, col = "CRITICAL", DANGER_RED
    elif score >= 60:
        level, col = "HIGH", WARN_ORANGE
    elif score >= 40:
        level, col = "MEDIUM", colors.HexColor("#ffd600")
    else:
        level, col = "LOW", SAFE_GREEN

    data = [
        ["Risk Level", "Score", "Category"],
        [level, f"{score:.1f} / 100", scan_data.get("scan_type", "N/A").upper()],
    ]
    table = Table(data, colWidths=[5.5 * cm, 5.5 * cm, 5.5 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), NEON_BLUE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0, 1), (0, 1), col),
        ("TEXTCOLOR", (1, 1), (-1, 1), TEXT_LIGHT),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 14),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(table)
    return elements


def _build_indicators_section(styles, scan_data):
    elements = [Paragraph("Threat Indicators", styles["SectionHeading"])]
    indicators = scan_data.get("indicators") or scan_data.get("details", {}).get("indicators", [])

    if not indicators:
        elements.append(Paragraph("No threat indicators detected.", styles["BodyText"]))
        return elements

    for i, indicator in enumerate(indicators, 1):
        elements.append(Paragraph(f"• {indicator}", styles["ThreatText"] if scan_data.get("is_threat") else styles["BodyText"]))
    return elements


def _build_summary_section(styles, scan_data):
    summary = scan_data.get("details", {}).get("summary") or scan_data.get("summary")
    if not summary:
        summary = _generate_fallback_summary(scan_data)

    elements = [Paragraph("AI Threat Summary", styles["SectionHeading"])]
    
    import re
    formatted_summary = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", summary)
    
    summary_style = ParagraphStyle(
        "SummaryText", parent=styles["BodyText"],
        fontSize=9.5, textColor=TEXT_LIGHT,
        leading=14, fontName="Helvetica",
    )
    
    p = Paragraph(formatted_summary, summary_style)
    
    table = Table([[p]], colWidths=[17.5 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PANEL_BG),
        ("GRID", (0, 0), (-1, -1), 1, BORDER_COLOR),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    
    elements.append(table)
    return elements


def _generate_fallback_summary(scan_data) -> str:
    scan_type = scan_data.get("scan_type", "").lower()
    result = scan_data.get("result", "")
    score = scan_data.get("risk_score") or scan_data.get("confidence") or 0
    is_threat = scan_data.get("is_threat", False)
    
    if scan_type == "password":
        if is_threat:
            return f"This password is classified as **{result}** with a strength score of **{score:.0f}/100**. It is highly vulnerable. The analysis identified critical risk factors: low character diversity or common patterns. It could be cracked almost instantly in a brute-force attack."
        else:
            return f"This password is classified as **{result}** with a strength score of **{score:.0f}/100**. The password has excellent entropy and complexity, featuring a diverse mix of character sets."
    elif scan_type == "phishing":
        if is_threat:
            return f"This URL is classified as **PHISHING** with a threat risk of **{score:.1f}/100**. The model flagged this domain due to multiple suspicious structural features or brand-spoofing characteristics."
        else:
            return f"This URL is classified as **SAFE** with a threat risk of **{score:.1f}/100**. The URL structure is consistent with legitimate web addresses, utilizing secure connection headers."
    elif scan_type == "malware":
        if is_threat:
            return f"This file is classified with a **{result}** risk level and a hazard score of **{score:.0f}/100**. The analysis detected severe indicators of security concern such as high-risk extension or format anomalies."
        else:
            return f"No significant threat vectors were detected. The file extension is generally safe, and its metadata size matches expected parameters."
    elif scan_type == "spam":
        if is_threat:
            return f"This email is classified as **SPAM** with a confidence score of **{score:.1f}%**. The model detected multiple marketing or social engineering keywords offering monetary rewards or urgency language."
        else:
            return f"This email is classified as **SAFE** with a confidence score of **{score:.1f}%**. The content matches clean, standard personal/professional communications."
    else:
        return f"The {scan_type} scan finished with a verdict of **{result}** and score of **{score:.1f}**. No detailed AI Summary is available for this historical record."


def _build_technical_section(styles, scan_data):
    elements = [Paragraph("Technical Details", styles["SectionHeading"])]
    details = scan_data.get("details") or {}

    if not details:
        elements.append(Paragraph("No additional technical details available.", styles["BodyText"]))
        return elements

    rows = [["Parameter", "Value"]]
    for k, v in details.items():
        if isinstance(v, bool):
            v = "Yes" if v else "No"
        rows.append([k.replace("_", " ").title(), str(v)[:60]])

    table = Table(rows, colWidths=[6 * cm, 11 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), NEON_BLUE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0, 1), (0, -1), colors.HexColor("#8b949e")),
        ("TEXTCOLOR", (1, 1), (1, -1), TEXT_LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(table)
    return elements


def _build_recommendations_section(styles, scan_data):
    elements = [Paragraph("Security Recommendations", styles["SectionHeading"])]
    rec = scan_data.get("recommendation", "No specific recommendations.")
    if isinstance(rec, list):
        for r in rec:
            elements.append(Paragraph(f"➤ {r}", styles["BodyText"]))
    else:
        for sentence in rec.split(". "):
            if sentence.strip():
                elements.append(Paragraph(f"➤ {sentence.strip()}.", styles["BodyText"]))
    return elements


def _build_footer_section(styles):
    elements = [
        HRFlowable(width="100%", thickness=0.5, color=BORDER_COLOR, spaceBefore=12),
        Paragraph(
            "⚠ DISCLAIMER: This report is generated by AegisShield AI for informational purposes only. "
            "Always consult a qualified cybersecurity professional for critical decisions. "
            "AegisShield AI does not guarantee 100% detection accuracy.",
            styles["MetaText"],
        ),
        Paragraph(
            f"© {datetime.now().year} AegisShield AI Platform  |  Confidential Security Report",
            styles["MetaText"],
        ),
    ]
    return elements


def _add_watermark(canvas_obj, doc):
    """Add page number and branding to each page."""
    canvas_obj.saveState()
    canvas_obj.setFillColor(colors.HexColor("#1c2128"))
    canvas_obj.rect(0, 0, A4[0], 0.8 * cm, fill=1, stroke=0)
    canvas_obj.setFillColor(colors.HexColor("#6e7681"))
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawString(2 * cm, 0.28 * cm, "AegisShield AI – Confidential")
    canvas_obj.drawRightString(A4[0] - 2 * cm, 0.28 * cm, f"Page {canvas_obj.getPageNumber()}")
    canvas_obj.restoreState()
