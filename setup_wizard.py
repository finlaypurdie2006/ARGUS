"""Interactive config.yaml generator — run with `python3 main.py --init`."""
import os
import yaml

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or default


def run_init_wizard(config_path: str = "config.yaml"):
    print("ARGUS setup wizard — press Enter to accept the default in [brackets].\n")

    target = _ask("Target IP or hostname")
    while not target:
        print("A target is required.")
        target = _ask("Target IP or hostname")

    domain = _ask("Domain (for subdomain enum via subfinder, optional)", "")
    ports = _ask("Default nmap port range", "1-1000")
    output_dir = _ask("Output directory", "output")
    model = _ask("Anthropic model", "claude-sonnet-4-6")
    wordlist = _ask("Gobuster wordlist path", DEFAULT_WORDLIST)

    cfg = {
        "target": target,
        "domain": domain,
        "ports": ports,
        "output_dir": output_dir,
        "anthropic_model": model,
        "ssl_port": 443,
        "tools": {
            "nmap": "nmap",
            "subfinder": "subfinder",
            "whatweb": "whatweb",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "wordlist": wordlist,
        },
    }

    if os.path.exists(config_path):
        overwrite = input(f"\n{config_path} already exists — overwrite? [y/N]: ").strip().lower()
        if overwrite not in ("y", "yes"):
            print("Aborted — existing config.yaml left untouched.")
            return None

    with open(config_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)

    print(f"\nWrote {config_path}.")
    print("Next: export ANTHROPIC_API_KEY=... then run: python3 main.py")
    return config_path
