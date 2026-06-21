"""Compare current findings against the most recent previous run for the same target."""
import json
import os


def find_previous_run(output_dir: str, target_slug: str, current_run_dir: str):
    """Return the path to the most recent prior run folder for this target, or None."""
    target_dir = os.path.join(output_dir, target_slug)
    if not os.path.isdir(target_dir):
        return None

    current_run_dir = os.path.abspath(current_run_dir)
    candidates = []
    for entry in os.listdir(target_dir):
        full = os.path.join(target_dir, entry)
        if entry == "latest" or not os.path.isdir(full):
            continue
        if os.path.abspath(full) == current_run_dir:
            continue
        candidates.append(entry)

    if not candidates:
        return None

    candidates.sort()  # timestamp-named folders sort chronologically
    return os.path.join(target_dir, candidates[-1])


def load_findings(run_dir: str):
    path = os.path.join(run_dir, "findings.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def compute_diff(previous: dict, current: dict) -> dict:
    """Diff two findings.json structures by finding title (case-insensitive)."""
    # One lookup per side (title -> finding dict) is enough — severity is read straight
    # off the stored finding rather than building a second parallel {title: severity} map.
    prev_lookup = {f.get("title", "").strip().lower(): f for f in previous.get("findings", [])}
    curr_lookup = {f.get("title", "").strip().lower(): f for f in current.get("findings", [])}

    new_titles = set(curr_lookup) - set(prev_lookup)
    resolved_titles = set(prev_lookup) - set(curr_lookup)
    common_titles = set(curr_lookup) & set(prev_lookup)

    return {
        "previous_risk_level": previous.get("risk_level", "Unknown"),
        "current_risk_level": current.get("risk_level", "Unknown"),
        "new_findings": [curr_lookup[t] for t in new_titles],
        "resolved_findings": [prev_lookup[t] for t in resolved_titles],
        "severity_changes": [
            {
                "title": curr_lookup[t].get("title"),
                "from": prev_lookup[t].get("severity", "Info"),
                "to": curr_lookup[t].get("severity", "Info"),
            }
            for t in common_titles
            if prev_lookup[t].get("severity", "Info") != curr_lookup[t].get("severity", "Info")
        ],
    }
