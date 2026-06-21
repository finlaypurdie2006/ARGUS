# ARGUS

Automated recon → Claude analysis → PDF report.

**Only run against systems you own or are explicitly authorized to test.**

## Setup

Recommended: use a virtual environment to keep dependencies isolated from your system Python.

```bash
cd argus
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key-here"
```

Next time you come back, just `source venv/bin/activate` again before running `main.py` — no need to reinstall. To leave the environment: `deactivate`.

(Without venv, you can also just run `pip install -r requirements.txt` directly.)

Install recon tools (Kali/Debian):
```bash
sudo apt install nmap nikto whatweb gobuster subfinder
```
(If `subfinder` isn't in your apt repos, grab a prebuilt binary from
https://github.com/projectdiscovery/subfinder/releases/latest)

Edit `config.yaml` for tool paths/wordlist/ports if you want different defaults — you no longer need to edit `target`/`domain` here, since `main.py` will ask for them each run (see below).

**Model:** defaults to `claude-sonnet-4-6` for the best analysis quality (catches subtler CVE matches, writes more nuanced remediation guidance). For faster/cheaper iterative runs, set `anthropic_model` to `claude-haiku-4-5-20251001` in `config.yaml`.

## Run

```bash
# first time only — interactively generate config.yaml
python3 main.py --init

# normal run
python3 main.py
```

Before scanning, you'll be prompted for target, domain, port range, and report format:
```
Target IP or hostname to scan [192.168.1.10]: 10.10.11.52
Domain for subdomain enum, optional [N/A]: 
Scan all 65535 ports instead of the configured range (1-1000)? [y/N]:
Generate PDF/HTML reports, or just show terminal output? [reports/terminal] (default: reports):
```
Hitting Enter on target/domain keeps whatever's in `config.yaml`; typing something new uses it for that run only (the file itself isn't rewritten). Leaving domain blank shows as N/A and skips subfinder.

**Flags**

| Flag | What it does |
|---|---|
| `--skip-web` | Network recon only (skip whatweb/nikto/gobuster/subfinder/TLS/headers) |
| `--all-ports` | Scan all 65535 ports, skipping the port-range prompt |
| `--no-report` | Skip the reports-vs-terminal prompt; terminal output only, no PDF/HTML/index |
| `--yes` | Skip the target/domain prompts and placeholder-target confirmation; use config.yaml values as-is (for automation/cron) |
| `--dry-run` | Print the exact commands that would run, without running them |
| `--quiet` | Suppress per-tool chatter; show only the progress bar + final summary |
| `--open` | Auto-open the HTML report when the run finishes (no-op if `--no-report`/terminal-only) |
| `--init` | Interactive wizard to create `config.yaml` |
| `--history` | List past runs for this target with risk-level trend, then exit |

nmap runs with `-T4` (aggressive timing) by default.

## Output

Each run gets its own timestamped folder: `output/<target>/<YYYYMMDD_HHMMSS>/`

- `raw_recon.json` — raw tool output
- `findings.json` — Claude's structured analysis
- `recon_report.pdf` / `recon_report.html` — full reports
- `index.html` — quick links to everything above
- A colored risk/severity summary also prints to the terminal at the end of each run, along with a **Possible Attack Vectors** section for Critical/High findings — names the general exploitation technique (e.g. "unauthenticated RCE via crafted FTP username"), not ready-to-run exploit commands.

If a previous run exists for the same target, the new report includes a **Changes Since Last Scan** section (new findings, resolved findings, severity changes). Use `--history` to see the risk trend across all runs for a target.

## Pipeline

1. `recon/network.py` runs `nmap -sV -sC -T4`, parses XML.
2. `recon/web.py` runs subfinder, whatweb, nikto, gobuster.
3. `recon/ssl_headers.py` inspects the TLS certificate and checks HTTP security headers (pure Python, no extra binaries).
4. All of the above run in parallel via a thread pool.
5. `report/analyze.py` sends raw output to Claude, gets back structured JSON findings + a prioritized remediation plan.
6. `report/diff.py` compares against the most recent previous run for the target.
7. `report/pdf_gen.py` / `report/html_gen.py` render the final reports.

## Notes

- Missing tools are skipped gracefully (logged as errors in raw output), not fatal.
- Claude only reports on what's in the raw tool output — it's instructed not to invent findings.
- Swap/extend tools in `recon/` as needed (e.g. add `sslscan`, `nuclei`).

## License

MIT
