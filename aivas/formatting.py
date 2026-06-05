from rich.console import Console
from rich.table import Table

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}

_console = Console()


def cve_table(title: str, rows: list[dict], desc_max: int = 60) -> Table:
    table = Table(title=title, show_lines=True)
    table.add_column("CVE ID", style="bold")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Description", max_width=desc_max)
    for r in rows:
        sev = r.get("cvss_severity") or "N/A"
        cve_cell = r["cve_id"]
        if r.get("kev"):
            cve_cell += "\n[bold magenta][KEV][/bold magenta]"
        table.add_row(
            cve_cell,
            str(r.get("cvss_score") or "N/A"),
            f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev}[/]",
            r.get("confidence", "possible"),
            (r.get("description") or "")[:desc_max * 2],
        )
    return table


MISCONFIG_COLORS = {
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}


def misconfig_table(title: str, rows: list[dict], desc_max: int = 55) -> Table:
    table = Table(title=title, show_lines=True)
    table.add_column("Severity")
    table.add_column("Title", style="bold")
    table.add_column("Description", max_width=desc_max)
    table.add_column("Recommendation", max_width=desc_max)
    for r in rows:
        sev = r.get("severity", "INFO")
        table.add_row(
            f"[{MISCONFIG_COLORS.get(sev, 'white')}]{sev}[/]",
            r.get("title", ""),
            (r.get("description") or "")[:desc_max * 2],
            (r.get("recommendation") or "")[:desc_max * 2],
        )
    return table


def print_narrations(
    findings: list[dict],
    lang: str = "both",
    console: Console | None = None,
) -> None:
    c = console or _console
    c.print("\n[bold]Risk Narrations[/bold]")
    for f in findings:
        c.print(
            f"\n[bold cyan]{f['cve_id']}[/bold cyan] "
            f"(CVSS {f.get('cvss_score') or 'N/A'})"
        )
        if lang in ("en", "both"):
            c.print(f"[blue]EN:[/blue] {f.get('narration_en', '')}")
        if lang in ("sw", "both"):
            c.print(f"[green]SW:[/green] {f.get('narration_sw', '')}")
        if f.get("fix_en") and lang in ("en", "both"):
            c.print(f"[yellow]FIX:[/yellow] {f['fix_en']}")
        if f.get("fix_sw") and lang in ("sw", "both"):
            c.print(f"[yellow]FIX (SW):[/yellow] {f['fix_sw']}")


def print_score(findings: list[dict], console: Console | None = None) -> None:
    from aivas.scorer import score_findings
    from rich.text import Text
    c = console or _console
    s = score_findings(findings)
    grade_color = "red" if s["grade"] in ("D", "F") else "green"
    line = Text("\nRisk Score: ", style="bold")
    line.append(f"{s['score']}/100 — Grade ", style="bold")
    line.append(s["grade"], style=f"bold {grade_color}")
    c.print(line)
