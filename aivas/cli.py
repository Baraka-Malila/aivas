from pathlib import Path

import click
from rich.console import Console

from aivas.database.schema import get_db, create_schema, DB_PATH
from aivas.database.nvd_ingest import ingest_feeds
from aivas.database.nvd_sync import sync_from_api, get_last_sync
from aivas.database.cpe_query import find_cves, normalize_product
from aivas.formatting import cve_table
from aivas.commands.history_cmds import history, diff as diff_cmd
from aivas.commands.scan_cmd import scan
from aivas.commands.report_cmd import report
from aivas.commands.ask_cmd import ask

console = Console()


@click.group()
@click.option("--db", "db_path", default=None, help="Path to SQLite database file.")
@click.pass_context
def cli(ctx: click.Context, db_path: str | None) -> None:
    ctx.ensure_object(dict)
    if "conn" not in ctx.obj:
        path = Path(db_path) if db_path else DB_PATH
        conn = get_db(path)
        create_schema(conn)
        ctx.obj["conn"] = conn
        ctx.call_on_close(conn.close)


cli.add_command(history)
cli.add_command(diff_cmd)
cli.add_command(scan)
cli.add_command(report)
cli.add_command(ask)


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
            raise click.ClickException(f"{source} is not a directory.")
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

    console.print(cve_table(f"CVEs for {product} {version or '(any version)'}", results))


def main() -> None:
    cli()
