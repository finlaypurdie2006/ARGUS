# Changelog

All notable changes to ARGUS are documented in this file.

## [0.3.0] - testing branch

### Added
- Parallel scan execution — nmap, web tools, TLS check, and header check all run concurrently via a thread pool (previously sequential)
- `recon/ssl_headers.py` — pure-Python TLS certificate inspection and HTTP security header checks (no extra binaries needed)
- HTML report (`recon_report.html`) alongside the PDF, same content/sections
- Timestamped, per-target output folders: `output/<target>/<YYYYMMDD_HHMMSS>/`, with a `latest` symlink
- `report/diff.py` — compares each run against the most recent previous run for the same target; PDF/HTML now show a **Changes Since Last Scan** section
- `--history` flag — lists past runs for a target with risk-level trend
- `--init` flag — interactive wizard that writes `config.yaml` for you
- `--dry-run` flag — prints the exact commands that would run without executing them
- `--all-ports` flag and an interactive y/n prompt — full 65535-port scan is opt-in, not default
- `--yes` flag — skips the authorization confirmation prompt for automation/cron
- `--quiet` flag — suppresses per-tool chatter, keeping just the progress bar + summary
- `--open` flag — auto-opens the HTML report when the run finishes
- Authorization confirmation prompt before any scan runs ("you're about to scan X — confirm authorized")
- Friendlier warning if `target` in config.yaml is still the default placeholder IP
- `preflight.py` — checks which configured recon binaries are actually installed before scanning, warns about missing ones upfront
- Colored end-of-run terminal summary (`ui.print_run_summary`) — overall risk + severity counts + top issues
- `report/index_gen.py` — per-run `index.html` linking the PDF, HTML, and raw JSON outputs
- nmap now runs with `-T4` (aggressive timing) by default

## [0.2.0] - testing branch

### Added
- ASCII art banner displayed on startup (`ui.py`)
- Live in-terminal progress bar that advances after each scan/analysis/report step
- PDF: **Scope & Methodology** section — target, port range, tools run with exact commands, scan duration
- PDF: **Findings at a Glance** table — count of findings per severity
- PDF: **Remediation Plan** section — consolidated, prioritized (Immediate / Short-term / Long-term) fixes with detailed how-to guidance, separate from the per-finding quick fix
- `cve` field on findings — populated when a version/banner clearly matches a known CVE
- `scan_meta` (target, ports, tool commands, timestamps) now passed into PDF generation

### Changed
- PDF table cells now render as wrapped `Paragraph` objects instead of raw strings — fixes text overlapping between columns on long values (versions, notes, commands)
- PDF margins and column widths reworked to use full page width consistently
- Detailed findings are now sorted by severity (Critical → Info)
- Claude system prompt rewritten to produce a fuller, pentest-report-style analysis (richer summary, per-finding CVE field, consolidated remediation plan)
- Report title and docstrings rebranded from generic "Automated Reconnaissance Report" to **ARGUS**

### Fixed
- Long version strings / notes in the Open Ports table no longer overlap adjacent columns

## [0.1.0] - main branch (initial release)

### Added
- `recon/network.py` — nmap wrapper (`-sV -sC`), XML parsing
- `recon/web.py` — subfinder, whatweb, nikto, gobuster wrappers
- `report/analyze.py` — sends raw recon output to Claude, returns structured JSON findings
- `report/pdf_gen.py` — renders findings into a PDF report
- `main.py` — CLI orchestrator (`--config`, `--skip-web`)
- `config.yaml` — target, ports, domain, tool paths, wordlist
- Raw recon output and structured findings saved as JSON alongside the PDF
