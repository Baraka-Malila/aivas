import click
from rich.console import Console
from rich.table import Table

from aivas.history import list_scans, diff_scans

console = Console()

_GRADE_COLORS = {
    "CRITICAL": "bold red", "HIGH": "red",
    "MEDIUM": "yellow", "LOW": "green", "PASS": "bold green",
}


@click.command()
@click.option("--limit", default=20, show_default=True, help="Max scans to show.")
@click.pass_context
def history(ctx: click.Context, limit: int) -> None:
    """List past scans stored in the database."""
    conn = ctx.obj["conn"]
    scans = list_scans(conn, limit=limit)
    if not scans:
        console.print("[yellow]No scans recorded yet.[/yellow] Run: aivas scan --save ...")
        return
    table = Table(title="Scan History", show_lines=True)
    table.add_column("ID", justify="right", style="bold")
    table.add_column("Target")
    table.add_column("Date")
    table.add_column("Findings", justify="right")
    table.add_column("Grade")
    for s in scans:
        grade = s["grade"] or "N/A"
        table.add_row(
            str(s["id"]),
            s["target"],
            (s["started_at"] or "")[:16],
            str(s["finding_count"]),
            f"[{_GRADE_COLORS.get(grade, 'white')}]{grade}[/]",
        )
    console.print(table)


@click.command()
@click.argument("old_id", type=int)
@click.argument("new_id", type=int)
@click.pass_context
def diff(ctx: click.Context, old_id: int, new_id: int) -> None:
    """Show CVE changes between two scans."""
    conn = ctx.obj["conn"]
    result = diff_scans(conn, old_id, new_id)
    console.print(f"\n[bold]Diff: scan #{old_id} → scan #{new_id}[/bold]")
    if result["new"]:
        console.print(f"\n[bold red]New ({len(result['new'])})[/bold red]")
        for cve in result["new"]:
            console.print(f"  + {cve}")
    if result["fixed"]:
        console.print(f"\n[bold green]Fixed ({len(result['fixed'])})[/bold green]")
        for cve in result["fixed"]:
            console.print(f"  - {cve}")
    console.print(f"\n[dim]Unchanged: {len(result['common'])} CVEs[/dim]")
