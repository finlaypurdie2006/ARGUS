# Changelog

All notable changes to ARGUS are documented in this file.

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
