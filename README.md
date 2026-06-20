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

Edit `config.yaml`: set `target`, `domain` (optional), `ports`, wordlist path.

**Model:** defaults to `claude-sonnet-4-6` for the best analysis quality (catches subtler CVE matches, writes more nuanced remediation guidance). For faster/cheaper iterative runs, set `anthropic_model` to `claude-haiku-4-5-20251001` in `config.yaml`.

## Run

```bash
# first time only — interactively generate config.yaml
python3 main.py --init

# normal run
python3 main.py
```

Before scanning, you'll be asked to confirm authorization, then prompted on port range:
```
You are about to scan: 10.0.0.5
Confirm you own this system or have explicit authorization to test it. [y/N]: y
Scan all 65535 ports instead of the configured range (1-1000)? [y/N]:
```

**Flags**

| Flag | What it does |
|---|---|
| `--skip-web` | Network recon only (skip whatweb/nikto/gobuster/subfinder/TLS/headers) |
| `--all-ports` | Scan all 65535 ports, skipping the port-range prompt |
| `--yes` | Skip the authorization confirmation prompt (for automation/cron) |
| `--dry-run` | Print the exact commands that would run, without running them |
| `--quiet` | Suppress per-tool chatter; show only the progress bar + final summary |
| `--open` | Auto-open the HTML report when the run finishes |
| `--init` | Interactive wizard to create `config.yaml` |
| `--history` | List past runs for this target with risk-level trend, then exit |

nmap runs with `-T4` (aggressive timing) by default.

## Output

Each run gets its own timestamped folder: `output/<target>/<YYYYMMDD_HHMMSS>/`

- `raw_recon.json` — raw tool output
- `findings.json` — Claude's structured analysis
- `recon_report.pdf` / `recon_report.html` — full reports
- `index.html` — quick links to everything above
- A colored risk/severity summary also prints to the terminal at the end of each run.

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
