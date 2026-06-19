#!/usr/bin/env python3
"""
ARGUS — Automated recon -> Claude analysis -> PDF report.
Run only against targets you own or are authorized to test.
"""
import argparse
import json
import os
import sys
import yaml

from recon.network import run_nmap
from recon.web import run_subfinder, run_whatweb, run_nikto, run_gobuster
from report.analyze import analyze
from report.pdf_gen import build_pdf


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Automated recon + Claude-generated PDF report")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--skip-web", action="store_true", help="Skip web recon (whatweb/nikto/gobuster/subfinder)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    target = cfg["target"]
    domain = cfg.get("domain", "")
    tools = cfg.get("tools", {})
    output_dir = cfg.get("output_dir", "output")
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Target: {target}")
    print("[*] Running network recon (nmap)...")
    network_result = run_nmap(target, cfg.get("ports", "1-1000"), tools.get("nmap", "nmap"))

    web_results = {}
    if not args.skip_web:
        print("[*] Running subfinder...")
        web_results["subfinder"] = run_subfinder(domain, tools.get("subfinder", "subfinder"))
        print("[*] Running whatweb...")
        web_results["whatweb"] = run_whatweb(target, tools.get("whatweb", "whatweb"))
        print("[*] Running nikto...")
        web_results["nikto"] = run_nikto(target, tools.get("nikto", "nikto"))
        print("[*] Running gobuster...")
        web_results["gobuster"] = run_gobuster(target, tools.get("wordlist", "/usr/share/wordlists/dirb/common.txt"), tools.get("gobuster", "gobuster"))

    recon_data = {"network": network_result, "web": web_results}

    raw_path = os.path.join(output_dir, "raw_recon.json")
    with open(raw_path, "w") as f:
        json.dump(recon_data, f, indent=2)
    print(f"[*] Raw recon data saved: {raw_path}")

    print("[*] Sending results to Claude for analysis...")
    try:
        findings = analyze(recon_data, model=cfg.get("anthropic_model", "claude-sonnet-4-6"))
    except RuntimeError as e:
        print(f"[!] {e}")
        sys.exit(1)

    findings_path = os.path.join(output_dir, "findings.json")
    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2)

    print("[*] Building PDF report...")
    pdf_path = os.path.join(output_dir, "recon_report.pdf")
    build_pdf(findings, target, pdf_path)
    print(f"[+] Report ready: {pdf_path}")


if __name__ == "__main__":
    main()
