#!/usr/bin/env python3
"""
ARGUS — Automated recon -> Claude analysis -> PDF report.
Run only against targets you own or are authorized to test.
"""
import argparse
import datetime
import json
import os
import sys
import yaml

from recon.network import run_nmap
from recon.web import run_subfinder, run_whatweb, run_nikto, run_gobuster
from report.analyze import analyze
from report.pdf_gen import build_pdf
from ui import print_banner, ProgressBar


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="ARGUS — automated recon + Claude-generated PDF report")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--skip-web", action="store_true", help="Skip web recon (whatweb/nikto/gobuster/subfinder)")
    args = parser.parse_args()

    print_banner()

    cfg = load_config(args.config)
    target = cfg["target"]
    domain = cfg.get("domain", "")
    ports = cfg.get("ports", "1-1000")
    tools = cfg.get("tools", {})
    output_dir = cfg.get("output_dir", "output")
    os.makedirs(output_dir, exist_ok=True)

    started_at = datetime.datetime.now()
    steps = 2 if args.skip_web else 6  # nmap + analyze + pdf, or + 4 web tools
    progress = ProgressBar(steps)

    print(f"\nTarget: {target}\n")

    progress.update("nmap: service/version scan")
    network_result = run_nmap(target, ports, tools.get("nmap", "nmap"))

    web_results = {}
    if not args.skip_web:
        progress.update("subfinder: subdomain enum")
        web_results["subfinder"] = run_subfinder(domain, tools.get("subfinder", "subfinder"))

        progress.update("whatweb: HTTP fingerprinting")
        web_results["whatweb"] = run_whatweb(target, tools.get("whatweb", "whatweb"))

        progress.update("nikto: vulnerability checks")
        web_results["nikto"] = run_nikto(target, tools.get("nikto", "nikto"))

        progress.update("gobuster: directory brute-force")
        web_results["gobuster"] = run_gobuster(
            target, tools.get("wordlist", "/usr/share/wordlists/dirb/common.txt"), tools.get("gobuster", "gobuster")
        )

    recon_data = {"network": network_result, "web": web_results}

    raw_path = os.path.join(output_dir, "raw_recon.json")
    with open(raw_path, "w") as f:
        json.dump(recon_data, f, indent=2)

    progress.update("Claude: analyzing results")
    try:
        findings = analyze(recon_data, model=cfg.get("anthropic_model", "claude-sonnet-4-6"))
    except RuntimeError as e:
        print(f"\n[!] {e}")
        sys.exit(1)

    findings_path = os.path.join(output_dir, "findings.json")
    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2)

    finished_at = datetime.datetime.now()
    scan_meta = {
        "target": target,
        "ports": ports,
        "domain": domain,
        "started_at": started_at.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": finished_at.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": int((finished_at - started_at).total_seconds()),
        "tools_run": [
            {"name": "nmap", "command": network_result.get("command", "")},
        ] + [
            {"name": name, "command": result.get("command", "")}
            for name, result in web_results.items()
        ],
    }

    progress.update("Building PDF report")
    pdf_path = os.path.join(output_dir, "recon_report.pdf")
    build_pdf(findings, target, pdf_path, scan_meta=scan_meta)

    print(f"\n[+] Raw data:    {raw_path}")
    print(f"[+] Findings:    {findings_path}")
    print(f"[+] Report:      {pdf_path}")


if __name__ == "__main__":
    main()
