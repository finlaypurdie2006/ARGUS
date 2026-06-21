"""Build a self-contained HTML report from structured findings JSON (mirrors the PDF)."""
import html as html_lib
from collections import Counter
from datetime import datetime

from report.common import SEVERITY_HEX as SEVERITY_COLORS, SEVERITY_ORDER, PRIORITY_ORDER, \
    sort_by_severity, sort_plan_by_priority

CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; margin: 0;
       background: #f3f4f6; color: #111827; }
.wrap { max-width: 880px; margin: 0 auto; padding: 32px 24px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 28px 0 10px; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; }
h3 { font-size: 15px; margin: 18px 0 4px; }
p { line-height: 1.5; margin: 6px 0; }
.meta { color: #4b5563; font-size: 14px; }
.badge { display: inline-block; padding: 4px 12px; border-radius: 999px; color: white;
         font-weight: 600; font-size: 14px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13.5px; }
th, td { border: 1px solid #d1d5db; padding: 8px 10px; text-align: left; vertical-align: top; }
th { background: #1f2937; color: white; }
tr:nth-child(even) td { background: #f9fafb; }
.finding { border-left: 4px solid #d1d5db; padding: 10px 14px; margin: 12px 0; background: white;
           border-radius: 4px; }
.finding .sev { font-weight: 700; }
.evidence { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
            color: #374151; background: #f3f4f6; padding: 6px 8px; border-radius: 4px;
            display: block; margin-top: 6px; white-space: pre-wrap; word-break: break-word; }
.card { background: white; border-radius: 6px; padding: 14px 18px; margin: 10px 0;
        box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
.diff-new { color: #b91c1c; font-weight: 600; }
.diff-resolved { color: #15803d; font-weight: 600; }
.priority-block { margin-bottom: 18px; }
.small { font-size: 12.5px; color: #6b7280; }
ul.plain { padding-left: 20px; margin: 6px 0; }
"""


def _e(text) -> str:
    return html_lib.escape(str(text)) if text not in (None, "") else "&mdash;"


def _table(headers, rows) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{_e(c)}</td>" for c in row) + "</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def build_html(findings: dict, target: str, output_path: str, scan_meta: dict = None,
                ssl_info: dict = None, headers_info: dict = None, diff: dict = None) -> str:
    scan_meta = scan_meta or {}
    risk = findings.get("risk_level", "Unknown")
    risk_color = SEVERITY_COLORS.get(risk, "#000")
    all_findings = findings.get("findings", [])
    counts = Counter(f.get("severity", "Info") for f in all_findings)

    parts = [f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ARGUS Report — {_e(target)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>ARGUS — Automated Reconnaissance Report</h1>
<p class="meta"><b>Target:</b> {_e(target)} &nbsp;|&nbsp; <b>Generated:</b> {_e(datetime.now().strftime('%Y-%m-%d %H:%M'))}</p>
<p><span class="badge" style="background:{risk_color}">Overall Risk: {_e(risk)}</span></p>
"""]

    parts.append("<h2>Executive Summary</h2>")
    parts.append(f"<p>{_e(findings.get('summary', 'N/A'))}</p>")

    if diff:
        parts.append("<h2>Changes Since Last Scan</h2>")
        parts.append(f"<div class='card'><p class='small'>Previous risk: "
                      f"<b>{_e(diff.get('previous_risk_level'))}</b> &rarr; Current risk: "
                      f"<b>{_e(diff.get('current_risk_level'))}</b></p>")
        new_f = diff.get("new_findings", [])
        resolved_f = diff.get("resolved_findings", [])
        changed = diff.get("severity_changes", [])
        if new_f:
            parts.append("<p class='diff-new'>New findings:</p><ul class='plain'>")
            parts += [f"<li>[{_e(f.get('severity'))}] {_e(f.get('title'))}</li>" for f in new_f]
            parts.append("</ul>")
        if resolved_f:
            parts.append("<p class='diff-resolved'>Resolved since last scan:</p><ul class='plain'>")
            parts += [f"<li>{_e(f.get('title'))}</li>" for f in resolved_f]
            parts.append("</ul>")
        if changed:
            parts.append("<p>Severity changes:</p><ul class='plain'>")
            parts += [f"<li>{_e(c.get('title'))}: {_e(c.get('from'))} &rarr; {_e(c.get('to'))}</li>" for c in changed]
            parts.append("</ul>")
        if not (new_f or resolved_f or changed):
            parts.append("<p class='small'>No changes from the previous scan.</p>")
        parts.append("</div>")

    if all_findings:
        parts.append("<h2>Findings at a Glance</h2>")
        rows = [[sev, counts[sev]] for sev in SEVERITY_ORDER if counts.get(sev)]
        parts.append(_table(["Severity", "Count"], rows))

    parts.append("<h2>Scope &amp; Methodology</h2>")
    scope_line = f"This assessment covered <b>{_e(target)}</b>"
    if scan_meta.get("ports"):
        scope_line += f" (ports {_e(scan_meta.get('ports'))})"
    scope_line += (". Tools ran in parallel where possible. No exploitation was performed beyond "
                   "passive/active service identification and default safe-mode checks.")
    parts.append(f"<p>{scope_line}</p>")
    tools_run = scan_meta.get("tools_run", [])
    if tools_run:
        rows = [[t.get("name", ""), t.get("command", "") or "(skipped)"] for t in tools_run]
        parts.append(_table(["Tool", "Command"], rows))
    if scan_meta.get("started_at"):
        parts.append(f"<p class='small'>Started: {_e(scan_meta.get('started_at'))} — "
                      f"Finished: {_e(scan_meta.get('finished_at'))} "
                      f"({_e(scan_meta.get('duration_seconds'))}s)</p>")

    ports = findings.get("open_ports", [])
    if ports:
        parts.append("<h2>Open Ports &amp; Services</h2>")
        rows = [[p.get("port", ""), p.get("service", ""), p.get("version", ""), p.get("note", "")] for p in ports]
        parts.append(_table(["Port", "Service", "Version", "Note"], rows))

    if ssl_info:
        parts.append("<h2>TLS / Certificate</h2>")
        if ssl_info.get("error"):
            parts.append(f"<p class='small'>{_e(ssl_info['error'])}</p>")
        else:
            rows = [
                ["Protocol", ssl_info.get("protocol")],
                ["Cipher", ssl_info.get("cipher")],
                ["Subject CN", (ssl_info.get("subject") or {}).get("commonName")],
                ["Issuer CN", (ssl_info.get("issuer") or {}).get("commonName")],
                ["Valid from", ssl_info.get("not_before")],
                ["Valid until", ssl_info.get("not_after")],
                ["Days until expiry", ssl_info.get("days_until_expiry")],
                ["Expired", ssl_info.get("expired")],
            ]
            parts.append(_table(["Property", "Value"], rows))

    if headers_info:
        parts.append("<h2>HTTP Security Headers</h2>")
        if headers_info.get("error"):
            parts.append(f"<p class='small'>{_e(headers_info['error'])}</p>")
        else:
            present = headers_info.get("present_headers", {})
            missing = headers_info.get("missing_headers", [])
            parts.append(f"<p class='small'>Checked {_e(headers_info.get('scheme'))}://"
                          f"{_e(target)}:{_e(headers_info.get('port'))}/ — "
                          f"status {_e(headers_info.get('status_code'))}</p>")
            if present:
                parts.append(_table(["Present Header", "Value"], list(present.items())))
            if missing:
                parts.append("<p class='diff-new'>Missing recommended headers:</p><ul class='plain'>")
                parts += [f"<li>{_e(h)}</li>" for h in missing]
                parts.append("</ul>")

    subs = findings.get("subdomains", [])
    if subs:
        parts.append("<h2>Discovered Subdomains</h2><ul class='plain'>")
        parts += [f"<li>{_e(s)}</li>" for s in subs]
        parts.append("</ul>")

    dirs = findings.get("directories", [])
    if dirs:
        parts.append("<h2>Discovered Web Paths</h2><ul class='plain'>")
        parts += [f"<li>{_e(d)}</li>" for d in dirs]
        parts.append("</ul>")

    parts.append("<h2>Detailed Findings</h2>")
    if not all_findings:
        parts.append("<p>No findings were reported for this scan.</p>")
    sorted_findings = sort_by_severity(all_findings)
    for f in sorted_findings:
        sev = f.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, "#000")
        cve = f" <span class='small'>({_e(f.get('cve'))})</span>" if f.get("cve") else ""
        parts.append(f"""<div class="finding" style="border-color:{color}">
<h3><span class="sev" style="color:{color}">[{_e(sev)}]</span> {_e(f.get('title'))}{cve}</h3>
<p>{_e(f.get('description'))}</p>""")
        if f.get("evidence"):
            parts.append(f"<span class='evidence'>{_e(f.get('evidence'))}</span>")
        if f.get("attack_vector"):
            parts.append(f"<p><b>Possible attack vector:</b> {_e(f.get('attack_vector'))}</p>")
        if f.get("recommendation"):
            parts.append(f"<p><b>Immediate fix:</b> {_e(f.get('recommendation'))}</p>")
        parts.append("</div>")

    plan = findings.get("remediation_plan", [])
    if plan:
        parts.append("<h2>Remediation Plan</h2>")
        plan_sorted = sort_plan_by_priority(plan)
        for priority in PRIORITY_ORDER:
            items = [p for p in plan_sorted if p.get("priority") == priority]
            if not items:
                continue
            parts.append(f"<div class='priority-block'><h3>{_e(priority)}</h3>")
            for item in items:
                parts.append(f"<div class='card'><b>{_e(item.get('action'))}</b>"
                              f"<p>{_e(item.get('detail'))}</p></div>")
            parts.append("</div>")

    parts.append("</div></body></html>")

    html_doc = "\n".join(parts)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return output_path
