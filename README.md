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
python3 main.py
# or, network-only:
python3 main.py --skip-web
```

## Output

- `output/raw_recon.json` — raw tool output
- `output/findings.json` — Claude's structured analysis
- `output/recon_report.pdf` — final report

## Pipeline

1. `recon/network.py` runs `nmap -sV -sC`, parses XML.
2. `recon/web.py` runs subfinder, whatweb, nikto, gobuster.
3. `report/analyze.py` sends raw output to Claude, gets structured JSON findings.
4. `report/pdf_gen.py` renders findings into a PDF.

## Notes

- Missing tools are skipped gracefully (logged as errors in raw output), not fatal.
- Claude only reports on what's in the raw tool output — it's instructed not to invent findings.
- Swap/extend tools in `recon/` as needed (e.g. add `sslscan`, `nuclei`).

## License

MIT
