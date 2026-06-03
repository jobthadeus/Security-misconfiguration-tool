"""
PDF security report generation using ReportLab.

Produces an auditor-style summary suitable for sharing with IT teams
or attaching to a portfolio demo.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from utils.models import ScanResult, ScanStatus

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High": colors.HexColor("#EA580C"),
    "Medium": colors.HexColor("#CA8A04"),
    "Low": colors.HexColor("#2563EB"),
    "Info": colors.HexColor("#64748B"),
}


def _score_color(score: int):
    if score >= 80:
        return colors.HexColor("#16A34A")
    if score >= 60:
        return colors.HexColor("#CA8A04")
    if score >= 40:
        return colors.HexColor("#EA580C")
    return colors.HexColor("#DC2626")


def export_pdf_report(result: ScanResult, output_path: str | Path | None = None) -> bytes:
    """
    Generate a PDF report from scan results.

    Returns PDF bytes. Optionally writes to disk.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        spaceAfter=12,
        textColor=colors.HexColor("#0F172A"),
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=16,
        spaceAfter=8,
        textColor=colors.HexColor("#1E293B"),
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
    )

    story = []

    # Title block
    story.append(Paragraph("SecureAudit — Security Assessment Report", title_style))
    story.append(Paragraph(f"<b>Host:</b> {result.hostname}", body_style))
    story.append(Paragraph(f"<b>Scan Time (UTC):</b> {result.scanned_at}", body_style))
    story.append(Spacer(1, 0.2 * inch))

    # Score summary table
    summary_data = [
        ["Security Score", f"{result.score} / 100"],
        ["Risk Level", result.risk_level],
        ["Total Findings", str(len(result.findings))],
        [
            "Failed Checks",
            str(sum(1 for f in result.findings if f.status == ScanStatus.FAIL)),
        ],
        [
            "Warnings",
            str(sum(1 for f in result.findings if f.status == ScanStatus.WARNING)),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[2.5 * inch, 3.5 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TEXTCOLOR", (1, 0), (1, 0), _score_color(result.score)),
                ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))

    # Findings
    story.append(Paragraph("Findings", heading_style))

    actionable = [
        f
        for f in result.findings
        if f.status in (ScanStatus.FAIL, ScanStatus.WARNING)
    ]
    if not actionable:
        story.append(
            Paragraph(
                "No critical misconfigurations detected. Continue periodic scanning.",
                body_style,
            )
        )
    else:
        for finding in actionable:
            sev_color = SEVERITY_COLORS.get(finding.severity.value, colors.black)
            story.append(
                Paragraph(
                    f'<font color="{sev_color.hexval()}">'
                    f"[{finding.severity.value}] {finding.title}</font>",
                    body_style,
                )
            )
            story.append(Paragraph(finding.description, body_style))
            story.append(
                Paragraph(f"<b>Recommendation:</b> {finding.recommendation}", body_style)
            )
            if finding.evidence:
                story.append(
                    Paragraph(
                        f"<b>Evidence:</b> {finding.evidence[:500]}",
                        ParagraphStyle(
                            "Evidence",
                            parent=body_style,
                            fontSize=8,
                            textColor=colors.HexColor("#64748B"),
                        ),
                    )
                )
            story.append(Spacer(1, 0.15 * inch))

    # All findings appendix (compact table)
    story.append(Paragraph("Full Check Summary", heading_style))
    table_data = [["Category", "Check", "Status", "Severity"]]
    for f in result.findings:
        table_data.append([f.category, f.title, f.status.value, f.severity.value])

    findings_table = Table(
        table_data,
        colWidths=[1.3 * inch, 2.5 * inch, 0.9 * inch, 0.9 * inch],
        repeatRows=1,
    )
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(findings_table)

    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            "<i>Generated by SecureAudit — For authorized local system assessment only.</i>",
            ParagraphStyle(
                "Footer",
                parent=body_style,
                fontSize=8,
                textColor=colors.HexColor("#94A3B8"),
            ),
        )
    )

    doc.build(story)
    pdf_bytes = buffer.getvalue()

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pdf_bytes)

    return pdf_bytes
