"""Terminal UI helpers: banner, progress bar, colors, summaries."""
import os
import sys
import threading
import webbrowser
from collections import Counter

from report.common import SEVERITY_ORDER  # single source of truth, shared with the PDF/HTML renderers

BANNER = r"""    ___    ____  ________  _______
   /   |  / __ \/ ____/ / / / ___/
  / /| | / /_/ / / __/ / / /\__ \ 
 / ___ |/ _, _/ /_/ / /_/ /___/ / 
/_/  |_/_/ |_|\____/\____//____/  
"""
TAGLINE = "Automated Reconnaissance, Graphing & Unified Scanner"
DISCLAIMER = "Use responsibly — only scan systems you own or have explicit authorization to test."
CREDIT = "made by @finp2006 on github"

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
SEVERITY_ANSI = {
    "Critical": "\033[1;91m",  # bold bright red
    "High": "\033[91m",        # bright red
    "Medium": "\033[93m",      # bright yellow
    "Low": "\033[94m",         # bright blue
    "Info": "\033[90m",        # grey
    "Unknown": "\033[90m",
}


def _color_enabled() -> bool:
    return sys.stdout.isatty()


def colorize(text: str, severity: str, bold: bool = False) -> str:
    """Wrap text in the ANSI color for a severity level. No-ops if stdout isn't a TTY
    (e.g. piped to a file) or the severity isn't recognized."""
    if not _color_enabled():
        return text
    code = SEVERITY_ANSI.get(severity, "")
    if not code:
        return text
    if bold:
        code = BOLD + code  # stack bold on top of the severity color rather than nesting a second reset
    return f"{code}{text}{RESET}"


def print_banner():
    art_and_tagline = f"{BANNER}\n        {TAGLINE}"
    print(f"{GREEN}{art_and_tagline}{RESET}" if _color_enabled() else art_and_tagline)
    print(f"\n  {DISCLAIMER}")
    print(f"  {CREDIT}\n")


class ProgressBar:
    """Simple in-place terminal progress bar. Thread-safe — safe to call .update()
    from multiple worker threads running scans in parallel."""

    def __init__(self, total: int, width: int = 32):
        self.total = max(total, 1)
        self.current = 0
        self.width = width
        self._lock = threading.Lock()
        self._render("starting...")

    def update(self, label: str = ""):
        with self._lock:
            self.current += 1
            self._render(label)
            if self.current >= self.total:
                sys.stdout.write("\n")
                sys.stdout.flush()

    def _render(self, label: str):
        frac = min(self.current / self.total, 1.0)
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        pct = int(frac * 100)
        line = f"\r[{bar}] {pct:3d}%  {label}"
        pad = max(0, 70 - len(line))
        sys.stdout.write(line + " " * pad)
        sys.stdout.flush()


def print_run_summary(findings: dict):
    """Colored end-of-run summary: overall risk + severity counts + top issues."""
    all_findings = findings.get("findings", [])
    risk = findings.get("risk_level", "Unknown")

    print("\n" + "=" * 50)
    print(f"Overall Risk: {colorize(risk, risk, bold=True)}")

    counts = Counter(f.get("severity", "Info") for f in all_findings)
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            print(f"  {colorize(sev, sev)}: {counts[sev]}")

    top = [f for f in all_findings if f.get("severity") in ("Critical", "High")][:3]
    if top:
        print("\nTop issues:")
        for f in top:
            sev = f.get("severity", "")
            print(f"  • {colorize('[' + sev + ']', sev)} {f.get('title', '')}")
    print("=" * 50 + "\n")


def print_attack_vectors(findings: dict):
    """Print likely exploitation paths for Critical/High findings — general technique only,
    no ready-to-run exploit commands. Intended for authorized practice (e.g. HTB/CTF boxes)."""
    vectors = [
        f for f in findings.get("findings", [])
        if f.get("attack_vector") and f.get("severity") in ("Critical", "High")
    ]
    if not vectors:
        return
    print("Possible Attack Vectors:")
    for f in vectors:
        sev = f.get("severity", "")
        cve = f" ({f.get('cve')})" if f.get("cve") else ""
        print(f"  {colorize('[' + sev + ']', sev)} {f.get('title', '')}{cve}")
        print(f"      -> {f.get('attack_vector')}")
    print()


def print_history(runs: list, target: str):
    """Print a target's scan history with risk-level trend, oldest first."""
    print(f"\nScan history for {target}:\n")
    if not runs:
        print("  (no previous runs found)")
        return
    for r in runs:
        risk = r.get("risk_level", "Unknown")
        print(f"  {r['timestamp']}  ->  {colorize(risk, risk)}")
    print()


def print_raw_results(recon_data: dict):
    """Print unprocessed scan output directly — used when running without AI analysis
    (--no-ai / declined the AI prompt). No severity, no CVEs, no remediation — just
    what each tool actually returned, since there's no Claude call to interpret it."""
    print("\n" + "=" * 50)
    print("Raw Scan Results (no AI analysis)")
    print("=" * 50)

    network = recon_data.get("network", {})
    hosts = network.get("hosts", [])
    if hosts:
        for host in hosts:
            print(f"\nHost: {host.get('ip', '?')}")
            for p in host.get("ports", []):
                version = f"{p.get('product', '')} {p.get('version', '')}".strip()
                line = f"  {p.get('port')}/{p.get('protocol')} {p.get('state')} {p.get('service')}"
                if version:
                    line += f" — {version}"
                print(line)
    if network.get("raw_stderr"):
        print(f"\n  nmap stderr: {network['raw_stderr'].strip()}")

    web = recon_data.get("web", {})
    for name, result in web.items():
        print(f"\n[{name}]")
        out = (result.get("stdout") or "").strip()
        err = (result.get("stderr") or "").strip()
        if out:
            print(out)
        elif err:
            print(f"  {err}")
        else:
            print("  (no output)")

    ssl_info = recon_data.get("ssl")
    if ssl_info:
        print("\n[TLS / Certificate]")
        if ssl_info.get("error"):
            print(f"  {ssl_info['error']}")
        else:
            print(f"  Protocol: {ssl_info.get('protocol')}  Cipher: {ssl_info.get('cipher')}")
            subject = ssl_info.get("subject") or {}
            print(f"  Subject CN: {subject.get('commonName', '?')}")
            print(f"  Valid until: {ssl_info.get('not_after')}  "
                  f"(days left: {ssl_info.get('days_until_expiry', '?')})")

    headers_info = recon_data.get("security_headers")
    if headers_info:
        print("\n[HTTP Security Headers]")
        if headers_info.get("error"):
            print(f"  {headers_info['error']}")
        else:
            present = headers_info.get("present_headers", {})
            missing = headers_info.get("missing_headers", [])
            print(f"  Status: {headers_info.get('status_code')}")
            if present:
                print(f"  Present: {', '.join(present)}")
            if missing:
                print(f"  Missing: {', '.join(missing)}")

    print("\n" + "=" * 50 + "\n")


def try_open(path: str) -> bool:
    """Best-effort open a file in the default browser/app. Never raises."""
    try:
        webbrowser.open("file://" + os.path.abspath(path))
        return True
    except Exception:
        return False
