"""Terminal UI helpers: banner + progress bar."""
import sys

BANNER = r"""    ___    ____  ________  _______
   /   |  / __ \/ ____/ / / / ___/
  / /| | / /_/ / / __/ / / /\__ \ 
 / ___ |/ _, _/ /_/ / /_/ /___/ / 
/_/  |_/_/ |_|\____/\____//____/  
        automated recon + report
"""


def print_banner():
    print(BANNER)


class ProgressBar:
    """Simple in-place terminal progress bar, advanced one step at a time."""

    def __init__(self, total: int, width: int = 32):
        self.total = max(total, 1)
        self.current = 0
        self.width = width
        self._render("starting...")

    def update(self, label: str = ""):
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
