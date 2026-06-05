import shutil
from pathlib import Path

import click
from rich.console import Console

from aivas.formatting import cve_table, print_narrations, print_score
from aivas.reporter import generate_report
from aivas.parser import parse_nmap_xml
from aivas.correlator import correlate
from aivas.scanner import run_scan
from aivas.scanner.nse import scripts_for_level
from aivas.scanner.probe import probe_http, probe_ssl, probe_banner

console = Console()


@click.command()
@click.argument("target", required=False)
@click.option("--import", "import_file", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="Use existing Nmap XML instead of running a live scan.")
@click.option("--level", default=2, type=click.IntRange(1, 3), show_default=True,
              help="Scan depth: 1=quick, 2=full vuln sweep (default), 3=+ SSH packages.")
@click.option("--limit", default=30, show_default=True, help="Max findings to show.")
@click.option("--min-confidence", "min_confidence",
              type=click.Choice(["possible", "probable", "confirmed"]),
              default="probable", show_default=True,
              help="Minimum confidence level to show.")
@click.option("--narrate", is_flag=True, help="Generate bilingual AI risk narration.")
@click.option("--provider", default="groq",
              type=click.Choice(["groq", "ollama"]), show_default=True,
              help="LLM provider for narration.")
@click.option("--api-key", "api_key", default=None, envvar="GROQ_API_KEY",
              help="Groq API key (or set GROQ_API_KEY).")
@click.option("--report", "report_path", default=None,
              type=click.Path(dir_okay=False, writable=True),
              help="Save HTML (or .pdf) report to this path.")
@click.option("--save", "save", is_flag=True,
              help="Persist findings to the scan history database.")
@click.option("--udp", "udp", is_flag=True,
              help="Include UDP scan (requires root; reveals IoT/mDNS/SNMP).")
@click.pass_context
def scan(
    ctx: click.Context,
    target: str | None,
    import_file: str | None,
    level: int,
    limit: int,
    min_confidence: str,
    narrate: bool,
    provider: str,
    api_key: str | None,
    report_path: str | None,
    save: bool,
    udp: bool,
) -> None:
    """Scan a target or analyse existing Nmap XML for vulnerabilities."""
    conn = ctx.obj["conn"]

    if import_file:
        xml = Path(import_file).read_text()
    elif target:
        if shutil.which("nmap") is None:
            raise click.ClickException("nmap not found — install nmap and retry.")
        console.print(f"[bold]Scanning {target}...[/bold]")
        with console.status("Running nmap..."):
            try:
                xml = run_scan(target, scripts=scripts_for_level(level), udp=udp)
            except RuntimeError as exc:
                raise click.ClickException(str(exc))
    else:
        raise click.UsageError("Provide a TARGET or use --import <file.xml>.")

    services = parse_nmap_xml(xml)
    if not services:
        console.print("[yellow]No open services found.[/yellow]")
        return

    for svc in services:
        if svc.get("product"):
            continue
        host, port = svc["host"], svc["port"]
        is_ssl = "ssl" in svc.get("service", "")
        info = probe_http(host, port, ssl=is_ssl)
        if info["server"]:
            svc["product"] = info["server"]
        elif info["title"]:
            svc["product"] = info["title"]
        if not svc.get("product") and is_ssl:
            ssl_info = probe_ssl(host, port)
            if ssl_info["cn"]:
                svc["product"] = ssl_info["cn"]
        if not svc.get("product"):
            banner = probe_banner(host, port)
            if banner:
                svc["product"] = banner[:60]

    _rank = {"possible": 0, "probable": 1, "confirmed": 2}
    findings = [f for f in correlate(conn, services)
                if _rank.get(f.get("confidence", "possible"), 0) >= _rank[min_confidence]][:limit]
    if not findings:
        console.print("[green]No CVEs at this confidence level[/green] "
                      "(try --min-confidence possible to see all).")
        return

    console.print(cve_table("Vulnerability Findings", findings, desc_max=55))
    print_score(findings)

    if narrate:
        import aivas.narrator as _narrator_mod
        try:
            prov = _narrator_mod.get_provider(provider, api_key=api_key)
        except ValueError as exc:
            raise click.ClickException(str(exc))
        with console.status(f"Generating narration with {provider}..."):
            findings = _narrator_mod.narrate(findings, prov)
        print_narrations(findings)

    if report_path:
        meta = {"target": target or (import_file or "")}
        saved = generate_report(findings, report_path, meta=meta)
        console.print(f"\n[green]✓[/green] Report saved to [bold]{saved}[/bold]")

    if save:
        from aivas.history import save_scan as _save_scan
        sid = _save_scan(conn, target or import_file or "", findings,
                         report_path=report_path)
        console.print(f"[dim]Scan saved as #{sid}.[/dim]")
