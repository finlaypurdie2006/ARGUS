"""Terminal UI helpers: banner, progress bar, colors, summaries."""
import os
import sys
import threading
import webbrowser

BANNER = r"""    ___    ____  ________  _______
   /   |  / __ \/ ____/ / / / ___/
  / /| | / /_/ / / __/ / / /\__ \ 
 / ___ |/ _, _/ /_/ / /_/ /___/ / 
/_/  |_/_/ |_|\____/\____//____/  
        automated recon + report
"""

RESET = "\033[0m"
BOLD = "\033[1m"
SEVERITY_ANSI = {
    "Critical": "\033[1;91m",  # bold bright red
    "High": "\033[91m",        # bright red
    "Medium": "\033[93m",      # bright yellow
    "Low": "\033[94m",         # bright blue
    "Info": "\033[90m",        # grey
    "Unknown": "\033[90m",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _color_enabled() -> bool:
    return sys.stdout.isatty()


def colorize(text: str, severity: str) -> str:
    if not _color_enabled():
        return text
    code = SEVERITY_ANSI.get(severity, "")
    return f"{code}{text}{RESET}" if code else text


def print_banner():
    print(BANNER)


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
    risk = findings.get("risk_level", "Unknown")
    print("\n" + "=" * 50)
    print(f"Overall Risk: {colorize(BOLD + risk + RESET if _color_enabled() else risk, risk)}")

    counts = {}
    for f in findings.get("findings", []):
        sev = f.get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            print(f"  {colorize(sev, sev)}: {counts[sev]}")

    top = [f for f in findings.get("findings", []) if f.get("severity") in ("Critical", "High")][:3]
    if top:
        print("\nTop issues:")
        for f in top:
            sev = f.get("severity", "")
            print(f"  • {colorize('[' + sev + ']', sev)} {f.get('title', '')}")
    print("=" * 50 + "\n")


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
