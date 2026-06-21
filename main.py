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
from report.history import list_runs
from report.index_gen import build_index
from preflight import check_tools
from setup_wizard import run_init_wizard
from ui import print_banner, ProgressBar, print_run_summary, print_attack_vectors, print_history, try_open

LABELS = {
    "nmap": "nmap: service/version scan",
    "subfinder": "subfinder: subdomain enum",
    "whatweb": "whatweb: HTTP fingerprinting",
    "nikto": "nikto: vulnerability checks",
    "gobuster": "gobuster: directory brute-force",
    "ssl_cert": "TLS: certificate inspection",
    "security_headers": "HTTP: security header check",
}
BINARY_BACKED = {"nmap", "subfinder", "whatweb", "nikto", "gobuster"}
PLACEHOLDER_TARGET = "192.168.1.10"


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"


def vprint(quiet: bool, *a, **kw):
    if not quiet:
        print(*a, **kw)


def describe_commands(target, ports, domain, tools, ssl_port, skip_web) -> list:
    """Build the exact command strings that would run — used by --dry-run.

    Note: these strings are deliberately kept in sync by hand with the real commands
    built inside recon/network.py and recon/web.py (run_nmap, run_whatweb, etc).
    --dry-run never calls those functions (the point is to preview without running
    anything), so if you change a tool's flags there, update the matching line here too.
    """
    cmds = [("nmap", f"{tools.get('nmap', 'nmap')} -sV -sC -T4 -p {ports} {target}")]
    if not skip_web:
        cmds.append(("subfinder",
                     f"{tools.get('subfinder', 'subfinder')} -d {domain} -silent" if domain
                     else "(skipped — no domain configured)"))
        cmds.append(("whatweb", f"{tools.get('whatweb', 'whatweb')} -a 3 {target}"))
        cmds.append(("nikto", f"{tools.get('nikto', 'nikto')} -h {target}"))
        cmds.append(("gobuster",
                     f"{tools.get('gobuster', 'gobuster')} dir -u http://{target} "
                     f"-w {tools.get('wordlist', '/usr/share/wordlists/dirb/common.txt')} -q"))
        cmds.append(("ssl_cert", f"TLS handshake inspection on {target}:{ssl_port}"))
        cmds.append(("security_headers", f"GET https://{target}/ (falls back to http) — security header check"))
    return cmds


def main():
    parser = argparse.ArgumentParser(description="ARGUS — automated recon + Claude-generated reports")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--skip-web", action="store_true", help="Skip web recon (whatweb/nikto/gobuster/subfinder/TLS/headers)")
    parser.add_argument("--all-ports", action="store_true",
                         help="Scan all 65535 ports without prompting (overrides ports in config.yaml)")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-tool chatter; show only the progress bar + final summary")
    parser.add_argument("--open", action="store_true", help="Open the HTML report automatically when done")
    parser.add_argument("--yes", action="store_true",
                         help="Skip interactive target/domain prompts and the placeholder-target "
                              "confirmation; use config.yaml values as-is (for automation)")
    parser.add_argument("--dry-run", action="store_true", help="Print the commands that would run, without running them")
    parser.add_argument("--init", action="store_true", help="Interactively create config.yaml and exit")
    parser.add_argument("--history", action="store_true", help="List past runs + risk trend for this target and exit")
    parser.add_argument("--no-report", action="store_true",
                         help="Skip the reports-vs-terminal prompt; terminal output only, no PDF/HTML/index")
    args = parser.parse_args()

    if args.init:
        run_init_wizard(args.config)
        return

    print_banner()
    cfg = load_config(args.config)
    tools = cfg.get("tools", {})
    output_dir = cfg.get("output_dir", "output")
    ssl_port = cfg.get("ssl_port", 443)
    config_target = cfg.get("target", "")
    config_domain = cfg.get("domain", "")

    if args.history:
        runs = list_runs(output_dir, slugify(config_target))
        print_history(runs, config_target)
        return

    # ---------- ask what to scan instead of requiring a config.yaml edit ----------
    # config.yaml's target/domain are now just defaults shown in [brackets] — hitting
    # Enter keeps them, typing something new uses that for this run only (the file
    # itself is never rewritten here). --yes/--dry-run skip this so automated/cron
    # runs never block waiting on stdin.
    if args.yes or args.dry_run:
        target = config_target
        domain = config_domain
    else:
        try:
            target_input = input(f"Target IP or hostname to scan [{config_target or 'none set'}]: ").strip()
        except EOFError:
            target_input = ""
        target = target_input or config_target
        if not target:
            print("[!] No target provided and none set in config.yaml. Aborting.")
            return

        try:
            domain_input = input(f"Domain for subdomain enum, optional [{config_domain or 'N/A'}]: ").strip()
        except EOFError:
            domain_input = ""
        domain = domain_input or config_domain
        print(f"[*] Domain: {domain or 'N/A'}\n")

    target_slug = slugify(target)

    if target == PLACEHOLDER_TARGET:
        print(f"[!] Target is still the default placeholder ({PLACEHOLDER_TARGET}).")
        print("    Enter a real target at the prompt, or edit config.yaml.\n")
        if not args.yes and not args.dry_run:
            try:
                cont = input("Continue anyway with this target? [y/N]: ").strip().lower()
            except EOFError:
                cont = "n"
            if cont not in ("y", "yes"):
                print("Aborted.")
                return

    ports = cfg.get("ports", "1-1000")
    if args.all_ports:
        ports = "1-65535"
        vprint(args.quiet, "[*] Scanning all 65535 ports (--all-ports flag set)\n")
    elif args.dry_run:
        vprint(args.quiet, f"[*] Dry run — using configured port range: {ports}\n")
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

    if args.dry_run:
        print("Planned commands (dry run — nothing will execute):\n")
        for name, cmd in describe_commands(target, ports, domain, tools, ssl_port, args.skip_web):
            print(f"  [{name}] {cmd}")
        print()
        return

    # ---------- reports vs terminal-only ----------
    generate_reports = True
    if args.no_report:
        generate_reports = False
        vprint(args.quiet, "[*] --no-report set: terminal output only, no PDF/HTML/index will be generated\n")
    else:
        try:
            answer = input("Generate PDF/HTML reports, or just show terminal output? [reports/terminal] (default: reports): ").strip().lower()
        except EOFError:
            answer = ""
        if answer in ("terminal", "t", "no", "n"):
            generate_reports = False
            print("[*] Terminal output only — skipping PDF/HTML/index generation.\n")
        else:
            print("[*] Will generate PDF + HTML reports.\n")

    # ---------- preflight: warn about missing binaries before scanning ----------
    binary_tasks = {"nmap"} if args.skip_web else BINARY_BACKED
    binary_tools = {name: tools.get(name, name) for name in binary_tasks}
    availability = check_tools(binary_tools, list(binary_tools))
    missing = [name for name, ok in availability.items() if not ok]
    if missing:
        vprint(args.quiet, f"[!] Missing tools (will be skipped automatically): {', '.join(missing)}\n")

    # ---------- timestamped, per-target run folder ----------
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_dir, target_slug, timestamp)
    os.makedirs(run_dir, exist_ok=True)

    vprint(args.quiet, f"Target:  {target}")
    vprint(args.quiet, f"Run dir: {run_dir}\n")

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

    total_steps = len(tasks) + 2 + (2 if generate_reports else 0)  # + analyze + diff [+ pdf + html]
    progress = ProgressBar(total_steps)
    started_at = datetime.datetime.now()

    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        # Each tool is independent (none reads another's output), so they all run
        # concurrently instead of one-after-another. as_completed() yields futures in
        # whatever order they actually finish — not submission order — which is why
        # the progress bar label is looked up per-future via future_map rather than
        # assumed from a fixed sequence.
        future_map = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as e:
                # A tool wrapper raising here (vs. returning a graceful {"error": ...}
                # dict itself) shouldn't take down the whole run — record it and move on.
                results[name] = {"error": str(e)}
            progress.update(LABELS.get(name, name))

    network_result = results.pop("nmap", {})
    ssl_result = results.pop("ssl_cert", None)
    headers_result = results.pop("security_headers", None)
    web_results = results

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

    pdf_path = html_path = index_path = None
    if generate_reports:
        progress.update("Building PDF report")
        pdf_path = os.path.join(run_dir, "recon_report.pdf")
        build_pdf(findings, target, pdf_path, scan_meta=scan_meta,
                  ssl_info=ssl_result, headers_info=headers_result, diff=diff)

        progress.update("Building HTML report")
        html_path = os.path.join(run_dir, "recon_report.html")
        build_html(findings, target, html_path, scan_meta=scan_meta,
                   ssl_info=ssl_result, headers_info=headers_result, diff=diff)

        index_path = build_index(run_dir, target, timestamp, findings.get("risk_level", "Unknown"))

    # convenience "latest" symlink (best-effort, skip silently if unsupported) —
    # points at the run folder regardless of generate_reports, since raw_recon.json
    # and findings.json are always written there.
    latest_link = os.path.join(output_dir, target_slug, "latest")
    try:
        if os.path.islink(latest_link) or os.path.exists(latest_link):
            os.unlink(latest_link)
        os.symlink(os.path.abspath(run_dir), latest_link)
    except OSError:
        pass

    vprint(args.quiet, f"\n[+] Raw data:  {raw_path}")
    vprint(args.quiet, f"[+] Findings:  {findings_path}")
    if generate_reports:
        vprint(args.quiet, f"[+] PDF:       {pdf_path}")
        vprint(args.quiet, f"[+] HTML:      {html_path}")
        vprint(args.quiet, f"[+] Index:     {index_path}")
    if diff:
        vprint(args.quiet, f"[+] Diff vs:   {prev_run_dir}")

    print_run_summary(findings)
    print_attack_vectors(findings)

    if args.open:
        if generate_reports:
            try_open(html_path)
        else:
            vprint(args.quiet, "[*] --open ignored: no HTML report was generated this run")


if __name__ == "__main__":
    main()
