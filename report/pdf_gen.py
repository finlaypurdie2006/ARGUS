"""Build a PDF report from structured findings JSON."""
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#b91c1c"),
    "Medium": colors.HexColor("#b45309"),
    "Low": colors.HexColor("#1d4ed8"),
    "Info": colors.HexColor("#6b7280"),
    "Unknown": colors.HexColor("#6b7280"),
}


def build_pdf(findings: dict, target: str, output_path: str) -> str:
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                             topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", fontSize=9, leading=12))
    story = []

    # Title page
    story.append(Paragraph("ARGUS — Automated Reconnaissance Report", styles["Title"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"Target: {target}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    risk = findings.get("risk_level", "Unknown")
    risk_color = SEVERITY_COLORS.get(risk, colors.black)
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<font color='{risk_color.hexval()}'><b>Overall Risk: {risk}</b></font>", styles["Heading2"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(findings.get("summary", "N/A"), styles["Normal"]))
    story.append(Spacer(1, 16))

    # Open ports table
    ports = findings.get("open_ports", [])
    if ports:
        story.append(Paragraph("Open Ports / Services", styles["Heading2"]))
        data = [["Port", "Service", "Version", "Note"]]
        for p in ports:
            data.append([p.get("port", ""), p.get("service", ""), p.get("version", ""), p.get("note", "")])
        t = Table(data, colWidths=[50, 90, 110, 200])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
        story.append(Spacer(1, 16))

    # Subdomains
    subs = findings.get("subdomains", [])
    if subs:
        story.append(Paragraph("Discovered Subdomains", styles["Heading2"]))
        for s in subs:
            story.append(Paragraph(f"• {s}", styles["Normal"]))
        story.append(Spacer(1, 16))

    # Directories
    dirs = findings.get("directories", [])
    if dirs:
        story.append(Paragraph("Discovered Web Paths", styles["Heading2"]))
        for d in dirs:
            story.append(Paragraph(f"• {d}", styles["Normal"]))
        story.append(Spacer(1, 16))

    story.append(PageBreak())

    # Findings detail
    story.append(Paragraph("Detailed Findings", styles["Heading1"]))
    story.append(Spacer(1, 10))
    for f in findings.get("findings", []):
        sev = f.get("severity", "Info")
        sev_color = SEVERITY_COLORS.get(sev, colors.black)
        story.append(Paragraph(
            f"<font color='{sev_color.hexval()}'><b>[{sev}]</b></font> {f.get('title','')}",
            styles["Heading3"]))
        story.append(Paragraph(f.get("description", ""), styles["Normal"]))
        if f.get("evidence"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<i>Evidence:</i> {f.get('evidence')}", styles["Small"]))
        if f.get("recommendation"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Recommendation:</b> {f.get('recommendation')}", styles["Normal"]))
        story.append(Spacer(1, 14))

    doc.build(story)
    return output_path
