from rich.table import Table

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def cve_table(title: str, rows: list[dict], desc_max: int = 60) -> Table:
    table = Table(title=title, show_lines=True)
    table.add_column("CVE ID", style="bold")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Description", max_width=desc_max)
    for r in rows:
        sev = r.get("cvss_severity") or "N/A"
        table.add_row(
            r["cve_id"],
            str(r.get("cvss_score") or "N/A"),
            f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev}[/]",
            r.get("confidence", "possible"),
            (r.get("description") or "")[:desc_max * 2],
        )
    return table
