# Changelog

All notable changes to ARGUS are documented in this file.

## [0.3.0] - testing branch

### Added
- AI on/off prompt — now the very first question asked, before target/domain, default **no**. Declining means no Claude call is made at all (no `ANTHROPIC_API_KEY` needed), and the raw scan results print straight to the terminal via `ui.print_raw_results()` instead of going through analysis/reports. Saying yes behaves as before: structured findings, CVEs, attack vectors, and PDF+HTML reports. `--no-ai` / `--ai` flags skip the prompt for automation. This replaces the old separate "generate reports or terminal-only" prompt — that choice is now just a consequence of the AI choice.
- Interactive target/domain prompts — no longer need to hand-edit `config.yaml` for the IP/domain to scan; the values there now act as defaults shown in `[brackets]` (or no bracket at all if unset), overridable per run. `config.yaml` ships with `target: ""` — no placeholder IP shipped anymore, so blank input with no config default just aborts with a clear message instead of silently scanning a meaningless example IP. Blank domain displays as N/A and skips subfinder, same as before.
- `attack_vector` field on findings — Claude names the general exploitation technique/class (not exploit code) for each finding; surfaced as a "Possible Attack Vectors" section in the terminal output (Critical/High only) and in the PDF/HTML detailed findings
- Parallel scan execution — nmap, web tools, TLS check, and header check all run concurrently via a thread pool (previously sequential)
- `recon/ssl_headers.py` — pure-Python TLS certificate inspection and HTTP security header checks (no extra binaries needed)
- HTML report (`recon_report.html`) alongside the PDF, same content/sections
- Timestamped, per-target output folders: `output/<target>/<YYYYMMDD_HHMMSS>/`, with a `latest` symlink
- `report/diff.py` — compares each run against the most recent previous run for the same target; PDF/HTML now show a **Changes Since Last Scan** section
- `--history` flag — lists past runs for a target with risk-level trend
- `--init` flag — interactive wizard that writes `config.yaml` for you
- `--dry-run` flag — prints the exact commands that would run without executing them
- `--all-ports` flag and an interactive y/n prompt — full 65535-port scan is opt-in, not default
- `--yes` flag — skips the placeholder-target confirmation prompt for automation/cron
- `--quiet` flag — suppresses per-tool chatter, keeping just the progress bar + summary
- `--open` flag — auto-opens the HTML report when the run finishes
- Friendlier warning if `target` in config.yaml is still the default placeholder IP
- `preflight.py` — checks which configured recon binaries are actually installed before scanning, warns about missing ones upfront
- Colored end-of-run terminal summary (`ui.print_run_summary`) — overall risk + severity counts + top issues
- `report/index_gen.py` — per-run `index.html` linking the PDF, HTML, and raw JSON outputs
- nmap now runs with `-T4` (aggressive timing) by default
- Green startup banner with tagline, responsible-use disclaimer, and credit line

### Changed
- PDF: "Open Ports & Services" now starts on its own page instead of running on directly after Scope & Methodology
- `report/common.py` added as a shared module for severity colors/ordering and sort helpers — removes ~4 copy-pasted constant blocks and sort-key lambdas that had drifted across `pdf_gen.py`, `html_gen.py`, and `index_gen.py`
- `recon/network.py` now catches missing-binary/timeout errors the same way `recon/web.py` already did, and always cleans up its temp XML file (previously leaked on any exception)
- `recon/ssl_headers.py`: shared SSL-context helper instead of duplicating it twice; HTTP connections are now explicitly closed in a `finally` block (previously leaked a socket on a failed request)
- `report/diff.py`: removed duplicate dict-building in `compute_diff` (was building 4 lookup dicts where 2 sufficed)
- `report/analyze.py`: raised `max_tokens` 4000 → 8000 to account for the larger schema (attack_vector + remediation_plan); response now less likely to get cut off mid-JSON

### Removed
- Authorization confirmation prompt before scanning — the startup banner's disclaimer already covers this, so the redundant per-run prompt was removed

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
