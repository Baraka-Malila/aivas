import click
from rich.console import Console

from aivas.history import get_scan_findings, list_scans
from aivas.reporter import generate_report
from aivas.formatting import cve_table, print_score

console = Console()


@click.command()
@click.option("--scan", "scan_id", type=int, required=True,
              help="Scan ID from 'aivas history'.")
@click.option("--output", "output_path", default=None,
              type=click.Path(dir_okay=False, writable=True),
              required=True, help="Path to save the HTML report.")
@click.pass_context
def report(ctx: click.Context, scan_id: int, output_path: str) -> None:
    """Re-generate HTML report from a saved scan."""
    conn = ctx.obj["conn"]
    scans = list_scans(conn)
    scan = next((s for s in scans if s["id"] == scan_id), None)
    if scan is None:
        raise click.ClickException(f"Scan #{scan_id} not found. Run 'aivas history'.")
    findings = get_scan_findings(conn, scan_id)
    meta = {"target": scan["target"]}
    saved = generate_report(findings, output_path, meta=meta)
    console.print(f"[green]✓[/green] Report saved to [bold]{saved}[/bold]")
    if findings:
        console.print(cve_table(f"Findings for scan #{scan_id}", findings))
        print_score(findings)
