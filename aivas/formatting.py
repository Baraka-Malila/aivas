from rich.console import Console
from rich.table import Table
from rich.text import Text
from aivas.tui.colors import ACCENT, SEVERITY_COLORS, KEV_BADGE, GRADE_COLOR

_console = Console()


def cve_table(title: str, rows: list[dict], desc_max: int = 80) -> Table:
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("#", justify="right", style="dim", width=3)
    table.add_column("CVE ID", style="bold", min_width=16)
    table.add_column("CVSS", justify="right", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Conf.", width=10)
    table.add_column("Description")
    for i, r in enumerate(rows, 1):
        sev = r.get("cvss_severity") or "N/A"
        sev_color = SEVERITY_COLORS.get(sev, "")
        cve_cell = Text(r["cve_id"])
        if r.get("kev"):
            cve_cell.append("\n")
            cve_cell.append(" KEV ", style=KEV_BADGE)
        sev_text = Text(sev, style=sev_color)
        score = r.get("cvss_score")
        table.add_row(
            str(i),
            cve_cell,
            str(score) if score is not None else "N/A",
            sev_text,
            r.get("confidence", "possible"),
            (r.get("description") or "")[:desc_max * 2],
        )
    return table


def misconfig_table(title: str, rows: list[dict], desc_max: int = 80) -> Table:
    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", style="bold", min_width=20)
    table.add_column("Description")
    table.add_column("Recommendation")
    for r in rows:
        sev = r.get("severity", "INFO")
        sev_color = SEVERITY_COLORS.get(sev, "dim")
        table.add_row(
            Text(sev, style=sev_color),
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
    c = console or _console
    s = score_findings(findings)
    grade_color = GRADE_COLOR(s["grade"])
    counts = s.get("sev_counts", {})
    count_parts = [f"{v} {k.lower()}" for k, v in counts.items() if v]
    count_str = f"  ({', '.join(count_parts)})" if count_parts else ""
    line = Text("\nRisk Score: ", style="bold")
    line.append(f"{s['score']}/100 — Grade ", style="bold")
    line.append(s["grade"], style=f"bold {grade_color}")
    line.append(f"  ·  {s.get('total', len(findings))} findings{count_str}", style="dim")
    c.print(line)
