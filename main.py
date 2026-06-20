#!/usr/bin/env python3
"""
ARGUS — Automated recon -> Claude analysis -> PDF + HTML report.
Run only against targets you own or are authorized to test.
"""
import argparse
import datetime
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

from recon.network import run_nmap
from recon.web import run_subfinder, run_whatweb, run_nikto, run_gobuster
from recon.ssl_headers import get_ssl_certificate, check_security_headers_auto
from report.analyze import analyze
from report.pdf_gen import build_pdf
from report.html_gen import build_html
from report.diff import find_previous_run, load_findings, compute_diff
from ui import print_banner, ProgressBar

LABELS = {
    "nmap": "nmap: service/version scan",
    "subfinder": "subfinder: subdomain enum",
    "whatweb": "whatweb: HTTP fingerprinting",
    "nikto": "nikto: vulnerability checks",
    "gobuster": "gobuster: directory brute-force",
    "ssl_cert": "TLS: certificate inspection",
    "security_headers": "HTTP: security header check",
}


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"


def main():
    parser = argparse.ArgumentParser(description="ARGUS — automated recon + Claude-generated reports")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--skip-web", action="store_true", help="Skip web recon (whatweb/nikto/gobuster/subfinder/TLS/headers)")
    parser.add_argument("--all-ports", action="store_true",
                         help="Scan all 65535 ports without prompting (overrides ports in config.yaml; useful for cron/automation)")
    args = parser.parse_args()

    print_banner()

    cfg = load_config(args.config)
    target = cfg["target"]
    domain = cfg.get("domain", "")
    ports = cfg.get("ports", "1-1000")
    if args.all_ports:
        ports = "1-65535"
        print(f"[*] Scanning all 65535 ports (--all-ports flag set)\n")
    else:
        try:
            answer = input(f"Scan all 65535 ports instead of the configured range ({ports})? [y/N]: ").strip().lower()
        except EOFError:
            answer = "n"
        if answer in ("y", "yes"):
            ports = "1-65535"
            print("[*] Scanning all 65535 ports — this will take significantly longer than the default range.\n")
        else:
            print(f"[*] Using configured port range: {ports}\n")

    tools = cfg.get("tools", {})
    output_dir = cfg.get("output_dir", "output")
    ssl_port = cfg.get("ssl_port", 443)

    # ---------- timestamped, per-target run folder ----------
    target_slug = slugify(target)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, target_slug, timestamp)
    os.makedirs(run_dir, exist_ok=True)

    print(f"\nTarget:  {target}")
    print(f"Run dir: {run_dir}\n")

    # ---------- build task list (runs in parallel) ----------
    tasks = {"nmap": lambda: run_nmap(target, ports, tools.get("nmap", "nmap"))}
    if not args.skip_web:
        tasks["subfinder"] = lambda: run_subfinder(domain, tools.get("subfinder", "subfinder"))
        tasks["whatweb"] = lambda: run_whatweb(target, tools.get("whatweb", "whatweb"))
        tasks["nikto"] = lambda: run_nikto(target, tools.get("nikto", "nikto"))
        tasks["gobuster"] = lambda: run_gobuster(
            target, tools.get("wordlist", "/usr/share/wordlists/dirb/common.txt"), tools.get("gobuster", "gobuster")
        )
        tasks["ssl_cert"] = lambda: get_ssl_certificate(target, port=ssl_port)
        tasks["security_headers"] = lambda: check_security_headers_auto(target)

    total_steps = len(tasks) + 4  # + analyze + diff + pdf + html
    progress = ProgressBar(total_steps)
    started_at = datetime.datetime.now()

    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        future_map = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {"error": str(e)}
            progress.update(LABELS.get(name, name))

    network_result = results.pop("nmap", {})
    ssl_result = results.pop("ssl_cert", None)
    headers_result = results.pop("security_headers", None)
    web_results = results  # whatever's left: subfinder/whatweb/nikto/gobuster

    recon_data = {"network": network_result, "web": web_results}
    if ssl_result is not None:
        recon_data["ssl"] = ssl_result
    if headers_result is not None:
        recon_data["security_headers"] = headers_result

    raw_path = os.path.join(run_dir, "raw_recon.json")
    with open(raw_path, "w") as f:
        json.dump(recon_data, f, indent=2)

    progress.update("Claude: analyzing results")
    try:
        findings = analyze(recon_data, model=cfg.get("anthropic_model", "claude-sonnet-4-6"))
    except RuntimeError as e:
        print(f"\n[!] {e}")
        sys.exit(1)

    findings_path = os.path.join(run_dir, "findings.json")
    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2)

    # ---------- diff against most recent previous run for this target ----------
    progress.update("Comparing to previous run")
    diff = None
    prev_run_dir = find_previous_run(output_dir, target_slug, run_dir)
    if prev_run_dir:
        prev_findings = load_findings(prev_run_dir)
        if prev_findings:
            diff = compute_diff(prev_findings, findings)

    finished_at = datetime.datetime.now()
    tools_run = [{"name": "nmap", "command": network_result.get("command", "")}]
    tools_run += [{"name": name, "command": result.get("command", "")} for name, result in web_results.items()]
    if ssl_result is not None:
        tools_run.append({"name": "ssl_cert", "command": ssl_result.get("command", "")})
    if headers_result is not None:
        tools_run.append({"name": "security_headers", "command": headers_result.get("command", "")})

    scan_meta = {
        "target": target,
        "ports": ports,
        "domain": domain,
        "started_at": started_at.strftime("%Y-%m-%d %H:%M:%S"),
        "finished_at": finished_at.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": int((finished_at - started_at).total_seconds()),
        "tools_run": tools_run,
    }

    progress.update("Building PDF report")
    pdf_path = os.path.join(run_dir, "recon_report.pdf")
    build_pdf(findings, target, pdf_path, scan_meta=scan_meta,
              ssl_info=ssl_result, headers_info=headers_result, diff=diff)

    progress.update("Building HTML report")
    html_path = os.path.join(run_dir, "recon_report.html")
    build_html(findings, target, html_path, scan_meta=scan_meta,
               ssl_info=ssl_result, headers_info=headers_result, diff=diff)

    # convenience "latest" symlink (best-effort, skip silently if unsupported)
    latest_link = os.path.join(output_dir, target_slug, "latest")
    try:
        if os.path.islink(latest_link) or os.path.exists(latest_link):
            os.unlink(latest_link)
        os.symlink(os.path.abspath(run_dir), latest_link)
    except OSError:
        pass

    print(f"\n[+] Raw data:  {raw_path}")
    print(f"[+] Findings:  {findings_path}")
    print(f"[+] PDF:       {pdf_path}")
    print(f"[+] HTML:      {html_path}")
    if diff:
        print(f"[+] Diff vs:   {prev_run_dir}")


if __name__ == "__main__":
    main()
