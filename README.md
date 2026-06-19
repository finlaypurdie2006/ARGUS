# ARGUS

Automated recon → Claude analysis → PDF report.

**Only run against systems you own or are explicitly authorized to test.**

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key-here"
```

Install recon tools (Kali/Debian):
```bash
sudo apt install nmap nikto whatweb gobuster subfinder
```
(If `subfinder` isn't in your apt repos, grab a prebuilt binary from
https://github.com/projectdiscovery/subfinder/releases/latest)

Edit `config.yaml`: set `target`, `domain` (optional), `ports`, wordlist path.

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
