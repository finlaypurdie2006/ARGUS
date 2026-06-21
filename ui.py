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


def try_open(path: str) -> bool:
    """Best-effort open a file in the default browser/app. Never raises."""
    try:
        webbrowser.open("file://" + os.path.abspath(path))
        return True
    except Exception:
        return False
