"""List past runs for a target — backs the --history flag."""
import json
import os


def list_runs(output_dir: str, target_slug: str) -> list:
    target_dir = os.path.join(output_dir, target_slug)
    if not os.path.isdir(target_dir):
        return []

    runs = []
    for entry in sorted(os.listdir(target_dir)):
        if entry == "latest":
            continue
        full = os.path.join(target_dir, entry)
        if not os.path.isdir(full):
            continue
        findings_path = os.path.join(full, "findings.json")
        risk = "Unknown"
        if os.path.exists(findings_path):
            try:
                with open(findings_path) as f:
                    risk = json.load(f).get("risk_level", "Unknown")
            except (json.JSONDecodeError, OSError):
                pass
        runs.append({"timestamp": entry, "risk_level": risk, "path": full})
    return runs
