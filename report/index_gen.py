"""Build a small per-run index.html linking the PDF/HTML reports and raw JSON files —
so you don't have to hunt through the run folder to find what you want."""
import os

from report.common import SEVERITY_HEX as SEVERITY_COLORS


def build_index(run_dir: str, target: str, timestamp: str, risk_level: str) -> str:
    color = SEVERITY_COLORS.get(risk_level, "#6b7280")
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ARGUS run {timestamp}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
          max-width: 520px; margin: 60px auto; color: #111827; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .meta {{ color: #4b5563; margin-bottom: 20px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; color: white;
            font-weight: 600; font-size: 13px; background: {color}; }}
  a.link {{ display: block; padding: 12px 16px; margin: 8px 0; background: #1f2937;
            color: white; border-radius: 6px; text-decoration: none; font-size: 14px; }}
  a.link:hover {{ background: #374151; }}
</style></head><body>
<h1>ARGUS — {target}</h1>
<p class="meta">Run: {timestamp} &nbsp; <span class="badge">{risk_level}</span></p>
<a class="link" href="recon_report.html">Open HTML report</a>
<a class="link" href="recon_report.pdf">Open PDF report</a>
<a class="link" href="findings.json">View findings.json</a>
<a class="link" href="raw_recon.json">View raw_recon.json</a>
</body></html>"""
    path = os.path.join(run_dir, "index.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
