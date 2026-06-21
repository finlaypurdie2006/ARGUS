"""Build a PDF report from structured findings JSON."""
from collections import Counter
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#b91c1c"),
    "Medium": colors.HexColor("#b45309"),
    "Low": colors.HexColor("#1d4ed8"),
    "Info": colors.HexColor("#6b7280"),
    "Unknown": colors.HexColor("#6b7280"),
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
PRIORITY_ORDER = ["Immediate", "Short-term", "Long-term"]

PAGE_MARGIN = 40
PAGE_WIDTH = letter[0] - 2 * PAGE_MARGIN  # usable width


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Cell", fontSize=8.5, leading=11))
    styles.add(ParagraphStyle(name="CellHeader", fontSize=8.5, leading=11,
                               textColor=colors.white, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Small", fontSize=9, leading=12, textColor=colors.HexColor("#374151")))
    styles.add(ParagraphStyle(name="SectionIntro", fontSize=10, leading=14, textColor=colors.HexColor("#374151")))
    return styles


def _p(text, style):
    """Wrap text in a Paragraph so it wraps inside table cells instead of overflowing."""
    return Paragraph(str(text) if text not in (None, "") else "—", style)


def _wrapped_table(data, col_widths, styles, header=True):
    """Build a Table where every cell is a Paragraph, so long text wraps instead of overlapping."""
    wrapped_rows = []
    for i, row in enumerate(data):
        cell_style = styles["CellHeader"] if (header and i == 0) else styles["Cell"]
        wrapped_rows.append([_p(cell, cell_style) for cell in row])

    t = Table(wrapped_rows, colWidths=col_widths, repeatRows=1 if header else 0)
    style_cmds = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]
    if header:
        style_cmds.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")))
    t.setStyle(TableStyle(style_cmds))
    return t


def build_pdf(findings: dict, target: str, output_path: str, scan_meta: dict = None,
               ssl_info: dict = None, headers_info: dict = None, diff: dict = None) -> str:
    scan_meta = scan_meta or {}
    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=PAGE_MARGIN, bottomMargin=PAGE_MARGIN,
        leftMargin=PAGE_MARGIN, rightMargin=PAGE_MARGIN,
    )
    story = []

    # ---------- Title ----------
    story.append(Paragraph("ARGUS — Automated Reconnaissance Report", styles["Title"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Target:</b> {target}", styles["Normal"]))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
    risk = findings.get("risk_level", "Unknown")
    risk_color = SEVERITY_COLORS.get(risk, colors.black)
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"<font color='{risk_color.hexval()}'><b>Overall Risk Level: {risk}</b></font>",
        styles["Heading2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#d1d5db")))
    story.append(Spacer(1, 14))

    # ---------- Executive Summary ----------
    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(findings.get("summary", "N/A"), styles["Normal"]))
    story.append(Spacer(1, 14))

    # ---------- Changes since last scan ----------
    if diff:
        story.append(Paragraph("Changes Since Last Scan", styles["Heading2"]))
        story.append(Paragraph(
            f"Previous risk: <b>{diff.get('previous_risk_level')}</b> &rarr; "
            f"Current risk: <b>{diff.get('current_risk_level')}</b>", styles["Normal"]))
        new_f = diff.get("new_findings", [])
        resolved_f = diff.get("resolved_findings", [])
        changed = diff.get("severity_changes", [])
        if new_f:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<font color='#b91c1c'><b>New findings:</b></font>", styles["Normal"]))
            for nf in new_f:
                story.append(Paragraph(f"• [{nf.get('severity')}] {nf.get('title')}", styles["Normal"]))
        if resolved_f:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<font color='#15803d'><b>Resolved since last scan:</b></font>", styles["Normal"]))
            for rf in resolved_f:
                story.append(Paragraph(f"• {rf.get('title')}", styles["Normal"]))
        if changed:
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Severity changes:</b>", styles["Normal"]))
            for c in changed:
                story.append(Paragraph(f"• {c.get('title')}: {c.get('from')} → {c.get('to')}", styles["Normal"]))
        if not (new_f or resolved_f or changed):
            story.append(Paragraph("No changes from the previous scan.", styles["Small"]))
        story.append(Spacer(1, 14))

    # ---------- Findings-at-a-glance ----------
    all_findings = findings.get("findings", [])
    counts = Counter(f.get("severity", "Info") for f in all_findings)
    if all_findings:
        story.append(Paragraph("Findings at a Glance", styles["Heading2"]))
        glance_data = [["Severity", "Count"]]
        for sev in SEVERITY_ORDER:
            if counts.get(sev):
                glance_data.append([sev, str(counts[sev])])
        story.append(_wrapped_table(glance_data, [PAGE_WIDTH * 0.5, PAGE_WIDTH * 0.5], styles))
        story.append(Spacer(1, 14))

    # ---------- Scope & Methodology ----------
    story.append(Paragraph("Scope &amp; Methodology", styles["Heading2"]))
    story.append(Paragraph(
        f"This assessment covered <b>{target}</b>"
        + (f" (ports {scan_meta.get('ports')})" if scan_meta.get("ports") else "")
        + ". Testing was performed using automated open-source reconnaissance tooling, "
        "with results consolidated and analyzed below. No exploitation was performed beyond "
        "passive/active service identification and default safe-mode vulnerability checks.",
        styles["Normal"]))
    story.append(Spacer(1, 8))
    tools_run = scan_meta.get("tools_run", [])
    if tools_run:
        tool_data = [["Tool", "Command"]]
        for t in tools_run:
            cmd = t.get("command", "") or "(skipped — not run / not installed)"
            tool_data.append([t.get("name", ""), cmd])
        story.append(_wrapped_table(tool_data, [PAGE_WIDTH * 0.2, PAGE_WIDTH * 0.8], styles))
    if scan_meta.get("started_at"):
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"<i>Started: {scan_meta.get('started_at')} — Finished: {scan_meta.get('finished_at')} "
            f"({scan_meta.get('duration_seconds', '?')}s)</i>", styles["Small"]))
    story.append(Spacer(1, 14))

    # ---------- Open ports table ----------
    ports = findings.get("open_ports", [])
    if ports:
        story.append(Paragraph("Open Ports &amp; Services", styles["Heading2"]))
        data = [["Port", "Service", "Version", "Note"]]
        for p in ports:
            data.append([p.get("port", ""), p.get("service", ""), p.get("version", ""), p.get("note", "")])
        col_widths = [PAGE_WIDTH * 0.10, PAGE_WIDTH * 0.18, PAGE_WIDTH * 0.27, PAGE_WIDTH * 0.45]
        story.append(_wrapped_table(data, col_widths, styles))
        story.append(Spacer(1, 14))

    # ---------- TLS / certificate ----------
    if ssl_info:
        story.append(Paragraph("TLS / Certificate", styles["Heading2"]))
        if ssl_info.get("error"):
            story.append(Paragraph(ssl_info["error"], styles["Small"]))
        else:
            rows = [
                ["Protocol", ssl_info.get("protocol", "")],
                ["Cipher", ssl_info.get("cipher", "")],
                ["Subject CN", (ssl_info.get("subject") or {}).get("commonName", "")],
                ["Issuer CN", (ssl_info.get("issuer") or {}).get("commonName", "")],
                ["Valid from", ssl_info.get("not_before", "")],
                ["Valid until", ssl_info.get("not_after", "")],
                ["Days until expiry", str(ssl_info.get("days_until_expiry", ""))],
                ["Expired", str(ssl_info.get("expired", ""))],
            ]
            story.append(_wrapped_table(rows, [PAGE_WIDTH * 0.3, PAGE_WIDTH * 0.7], styles, header=False))
        story.append(Spacer(1, 14))

    # ---------- HTTP security headers ----------
    if headers_info:
        story.append(Paragraph("HTTP Security Headers", styles["Heading2"]))
        if headers_info.get("error"):
            story.append(Paragraph(headers_info["error"], styles["Small"]))
        else:
            story.append(Paragraph(
                f"Checked {headers_info.get('scheme')}://{target}:{headers_info.get('port')}/ "
                f"— status {headers_info.get('status_code')}", styles["Small"]))
            story.append(Spacer(1, 4))
            present = headers_info.get("present_headers", {})
            missing = headers_info.get("missing_headers", [])
            if present:
                rows = [["Header", "Value"]] + [[k, v] for k, v in present.items()]
                story.append(_wrapped_table(rows, [PAGE_WIDTH * 0.35, PAGE_WIDTH * 0.65], styles))
                story.append(Spacer(1, 6))
            if missing:
                story.append(Paragraph("<font color='#b91c1c'><b>Missing recommended headers:</b></font>", styles["Normal"]))
                for h in missing:
                    story.append(Paragraph(f"• {h}", styles["Normal"]))
        story.append(Spacer(1, 14))

    # ---------- Subdomains / directories ----------
    subs = findings.get("subdomains", [])
    if subs:
        story.append(Paragraph("Discovered Subdomains", styles["Heading2"]))
        for s in subs:
            story.append(Paragraph(f"• {s}", styles["Normal"]))
        story.append(Spacer(1, 14))

    dirs = findings.get("directories", [])
    if dirs:
        story.append(Paragraph("Discovered Web Paths", styles["Heading2"]))
        for d in dirs:
            story.append(Paragraph(f"• {d}", styles["Normal"]))
        story.append(Spacer(1, 14))

    story.append(PageBreak())

    # ---------- Detailed findings ----------
    story.append(Paragraph("Detailed Findings", styles["Heading1"]))
    story.append(Paragraph(
        "Each finding below includes supporting evidence pulled directly from tool output, "
        "a plain-language description of risk, and an immediate fix.",
        styles["SectionIntro"]))
    story.append(Spacer(1, 10))

    if not all_findings:
        story.append(Paragraph("No findings were reported for this scan.", styles["Normal"]))

    for f in sorted(all_findings, key=lambda x: SEVERITY_ORDER.index(x.get("severity", "Info"))
                     if x.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER)):
        sev = f.get("severity", "Info")
        sev_color = SEVERITY_COLORS.get(sev, colors.black)
        header = f"<font color='{sev_color.hexval()}'><b>[{sev}]</b></font> {f.get('title','')}"
        if f.get("cve"):
            header += f"  <font color='#6b7280' size='9'>({f.get('cve')})</font>"
        story.append(Paragraph(header, styles["Heading3"]))
        story.append(Paragraph(f.get("description", ""), styles["Normal"]))
        if f.get("evidence"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<i>Evidence:</i> {f.get('evidence')}", styles["Small"]))
        if f.get("attack_vector"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Possible attack vector:</b> {f.get('attack_vector')}", styles["Normal"]))
        if f.get("recommendation"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Immediate fix:</b> {f.get('recommendation')}", styles["Normal"]))
        story.append(Spacer(1, 14))

    # ---------- Remediation plan ----------
    plan = findings.get("remediation_plan", [])
    if plan:
        story.append(PageBreak())
        story.append(Paragraph("Remediation Plan", styles["Heading1"]))
        story.append(Paragraph(
            "Consolidated, prioritized actions to address the root causes behind the findings above.",
            styles["SectionIntro"]))
        story.append(Spacer(1, 10))

        plan_sorted = sorted(
            plan,
            key=lambda x: PRIORITY_ORDER.index(x.get("priority", "Long-term"))
            if x.get("priority") in PRIORITY_ORDER else len(PRIORITY_ORDER)
        )
        for priority in PRIORITY_ORDER:
            items = [p for p in plan_sorted if p.get("priority") == priority]
            if not items:
                continue
            story.append(Paragraph(priority, styles["Heading2"]))
            for item in items:
                story.append(Paragraph(f"<b>{item.get('action','')}</b>", styles["Normal"]))
                story.append(Paragraph(item.get("detail", ""), styles["Normal"]))
                story.append(Spacer(1, 10))
            story.append(Spacer(1, 6))

    doc.build(story)
    return output_path
