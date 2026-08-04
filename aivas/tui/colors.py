"""Centralised color palette for AIVAS TUI."""

ACCENT = "#4a9eff"          # steel blue — prompt, commands, active items

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#e53935",  # red    — no bold
    "HIGH":     "#ff6d00",  # orange — distinct from red
    "MEDIUM":   "#fdd835",  # gold   — no bold
    "LOW":      "#9e9e9e",  # gray   — readable on dark bg
}

KEV_BADGE = "bold white on #e53935"    # badge style — "KEV" text only

SUCCESS = "#4caf50"   # green  — ✓ checks, all-clear
DANGER  = "#e53935"   # red    — errors (no bold)
MUTED   = "#888888"   # timestamps, secondary info — projector-safe


def GRADE_COLOR(grade: str) -> str:
    """Return Rich color string for a scan grade."""
    if grade in ("A", "B"):
        return "#4caf50"
    if grade == "C":
        return "#fdd835"
    return "#e53935"   # D, F
