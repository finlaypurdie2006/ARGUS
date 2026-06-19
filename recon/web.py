"""Web reconnaissance: subdomain enum, tech fingerprint, dir brute-force, vuln scan."""
import subprocess


def _run(cmd: list, timeout: int = 600) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"command": " ".join(cmd), "stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except FileNotFoundError:
        return {"command": " ".join(cmd), "stdout": "", "stderr": "tool not installed", "returncode": -1}
    except subprocess.TimeoutExpired:
        return {"command": " ".join(cmd), "stdout": "", "stderr": "timed out", "returncode": -1}


def run_subfinder(domain: str, bin_path: str = "subfinder") -> dict:
    if not domain:
        return {"command": "", "stdout": "", "stderr": "no domain configured, skipped", "returncode": -1}
    return _run([bin_path, "-d", domain, "-silent"])


def run_whatweb(target: str, bin_path: str = "whatweb") -> dict:
    return _run([bin_path, "-a", "3", target])


def run_nikto(target: str, bin_path: str = "nikto") -> dict:
    return _run([bin_path, "-h", target], timeout=1200)


def run_gobuster(target: str, wordlist: str, bin_path: str = "gobuster") -> dict:
    return _run([bin_path, "dir", "-u", f"http://{target}", "-w", wordlist, "-q"], timeout=900)
