"""Check tool availability before scanning, so missing binaries are flagged upfront
instead of surfacing as confusing per-task errors mid-run."""
import shutil


def check_tools(tool_paths: dict, names: list) -> dict:
    """Return {name: True/False} — whether each binary is found on PATH."""
    status = {}
    for name in names:
        binary = tool_paths.get(name, name)
        status[name] = shutil.which(binary) is not None
    return status
