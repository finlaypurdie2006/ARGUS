"""Shared constants/helpers for the PDF and HTML report renderers.

Both renderers need the same severity colors and the same "sort by severity/priority,
unknown values last" logic. Keeping it here means one change updates both reports
instead of having to remember to edit two near-identical copies.
"""

# Canonical hex colors per severity. pdf_gen.py wraps these in reportlab's
# colors.HexColor(); html_gen.py uses the hex strings directly in inline CSS.
SEVERITY_HEX = {
    "Critical": "#7f1d1d",
    "High": "#b91c1c",
    "Medium": "#b45309",
    "Low": "#1d4ed8",
    "Info": "#6b7280",
    "Unknown": "#6b7280",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
PRIORITY_ORDER = ["Immediate", "Short-term", "Long-term"]


def _order_index(value: str, order: list) -> int:
    """Index of value in order, or len(order) if not found — so unrecognized
    severities/priorities sort to the end instead of raising a ValueError."""
    return order.index(value) if value in order else len(order)


def sort_by_severity(items: list, severity_key: str = "severity") -> list:
    """Sort findings Critical -> Info (or whatever order SEVERITY_ORDER defines)."""
    return sorted(items, key=lambda x: _order_index(x.get(severity_key, "Info"), SEVERITY_ORDER))


def sort_plan_by_priority(plan: list) -> list:
    """Sort a remediation plan Immediate -> Short-term -> Long-term."""
    return sorted(plan, key=lambda x: _order_index(x.get("priority", "Long-term"), PRIORITY_ORDER))
