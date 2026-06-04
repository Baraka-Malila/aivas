import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from aivas.database.schema import get_db, create_schema, DB_PATH
from aivas.database.nvd_ingest import ingest_feeds
from aivas.database.nvd_sync import sync_from_api, get_last_sync
from aivas.database.cpe_query import find_cves, normalize_product

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


@click.group()
@click.option("--db", "db_path", default=None, help="Path to SQLite database file.")
@click.pass_context
def cli(ctx: click.Context, db_path: str | None) -> None:
    path = Path(db_path) if db_path else DB_PATH
    conn = get_db(path)
    create_schema(conn)
    ctx.ensure_object(dict)
    ctx.obj["conn"] = conn
    ctx.call_on_close(conn.close)


@cli.command()
@click.option("--source", default=None, help="Path to local nvd-json-data-feeds directory.")
@click.option("--api-key", default=None, envvar="NIST_API_KEY", help="NIST NVD API key.")
@click.pass_context
def update_db(ctx: click.Context, source: str | None, api_key: str | None) -> None:
    """Download and sync CVE data into the local database."""
    conn = ctx.obj["conn"]

    if source:
        feeds_dir = Path(source)
        if not feeds_dir.is_dir():
            console.print(f"[red]Error:[/red] {source} is not a directory.")
            sys.exit(1)
        console.print(f"[bold]Ingesting CVEs from {feeds_dir} ...[/bold]")
        with console.status("Importing..."):
            count = ingest_feeds(conn, feeds_dir)
        console.print(f"[green]✓[/green] Ingested {count} new CVEs.")
    else:
        last = get_last_sync(conn)
        if last:
            console.print(f"[bold]Syncing CVEs modified since {last}...[/bold]")
        else:
            console.print("[bold]First sync — fetching all CVEs from NVD API...[/bold]")

        with console.status("Syncing from NVD API..."):
            count = sync_from_api(conn, api_key=api_key)
        console.print(f"[green]✓[/green] Synced {count} CVEs.")

    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    console.print(f"Database total: {total:,} CVEs.")


@cli.command()
@click.argument("product")
@click.option("--version", default=None, help="Detected service version (e.g. 2.4.49).")
@click.option("--severity", default=None,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False))
@click.option("--limit", default=20, show_default=True, help="Max results to show.")
@click.pass_context
def search(
    ctx: click.Context,
    product: str,
    version: str | None,
    severity: str | None,
    limit: int,
) -> None:
    """Search the CVE database for a product/version."""
    conn = ctx.obj["conn"]

    if normalize_product(product) is None:
        console.print(
            f"[yellow]Product '{product}' not recognized.[/yellow] "
            "No CVE mappings available for this product name."
        )
        return

    results = find_cves(conn, product, version)

    if severity:
        results = [r for r in results if r.get("cvss_severity") == severity.upper()]

    results = results[:limit]

    if not results:
        console.print("[yellow]No CVEs found[/yellow] for the given product/version.")
        return

    table = Table(title=f"CVEs for {product} {version or '(any version)'}", show_lines=True)
    table.add_column("CVE ID", style="bold")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Description", max_width=60)

    for r in results:
        sev = r.get("cvss_severity") or "N/A"
        table.add_row(
            r["cve_id"],
            str(r.get("cvss_score") or "N/A"),
            f"[{SEVERITY_COLORS.get(sev, 'white')}]{sev}[/]",
            r.get("confidence", "probable"),
            (r.get("description") or "")[:120],
        )

    console.print(table)


def main() -> None:
    cli()
