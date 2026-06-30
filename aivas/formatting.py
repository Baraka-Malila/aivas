import re as _re
from rich.console import Console
from rich.table import Table
from rich.text import Text
from aivas.tui.colors import SEVERITY_COLORS, KEV_BADGE, GRADE_COLOR


def _clean(text: str) -> str:
    return _re.sub(r'\s+', ' ', text or "").strip()

_console = Console()


def cve_table(title: str, rows: list[dict], desc_max: int = 0) -> Table:
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
            (r.get("description") or "")[:desc_max or None],
        )
    return table


def misconfig_table(title: str, rows: list[dict], desc_max: int = 0) -> Table:
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
            (r.get("description") or "")[:desc_max or None],
            (r.get("recommendation") or "")[:desc_max or None],
        )
    return table


def print_narrations(
    findings: list[dict],
    lang: str = "both",
    console: Console | None = None,
    print_fn=None,
) -> None:
    _out = print_fn or (console or _console).print
    _out("\n[bold]Risk Narrations[/bold]")
    for f in findings:
        _out(f"\n[bold cyan]{f['cve_id']}[/bold cyan] (CVSS {f.get('cvss_score') or 'N/A'})")
        if lang in ("en", "both") and f.get("narration_en"):
            _out(f"[blue]EN:[/blue] {_clean(f['narration_en'])}")
        if lang in ("sw", "both") and f.get("narration_sw"):
            _out(f"[green]SW:[/green] {_clean(f['narration_sw'])}")
        if lang in ("en", "both") and f.get("fix_en"):
            _out(f"[yellow]FIX:[/yellow] {_clean(f['fix_en'])}")
        if lang in ("sw", "both") and f.get("fix_sw"):
            _out(f"[yellow]FIX (SW):[/yellow] {_clean(f['fix_sw'])}")


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
