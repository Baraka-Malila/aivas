import shutil
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from aivas import config as _config

console = Console()


def _check(label: str, ok: bool, detail: str, hint: str = "") -> Text:
    icon = "[bold green]✓[/bold green]" if ok else "[bold red]✗[/bold red]"
    line = Text.from_markup(f"  {icon}  {label}: {detail}")
    if not ok and hint:
        line.append(f"\n       → {hint}", style="dim")
    return line


@click.command()
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Check AIVAS dependencies, database, and configuration."""
    conn = ctx.obj["conn"]
    cfg = _config.load()
    lines: list[Text] = []

    # nmap
    nmap_path = shutil.which("nmap")
    if nmap_path:
        import subprocess
        ver = subprocess.run(
            ["nmap", "--version"], capture_output=True, text=True
        ).stdout.splitlines()[0] if nmap_path else ""
        lines.append(_check("nmap", True, ver))
    else:
        lines.append(_check("nmap", False, "not found",
                             "sudo apt install nmap"))

    # Python
    py = f"Python {sys.version.split()[0]}"
    lines.append(_check("runtime", True, py))

    # Database
    cve_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    ok_db = cve_count > 0
    lines.append(_check(
        "database", ok_db,
        f"{cve_count:,} CVEs" if ok_db else "empty — run update-db first",
        "aivas update-db --source /path/to/nvd-feeds/" if not ok_db else "",
    ))

    # KEV
    from aivas.database.kev import get_kev_status
    kev = get_kev_status(conn)
    ok_kev = kev["count"] > 0
    kev_detail = (
        f"{kev['count']:,} CVEs flagged (updated {kev['last_updated'][:10]})"
        if ok_kev else "not synced"
    )
    lines.append(_check("KEV", ok_kev, kev_detail,
                         "aivas update-kev" if not ok_kev else ""))

    # API key
    api_key = cfg.get("api_key") or ""
    ok_key = bool(api_key)
    lines.append(_check(
        "API key", ok_key,
        f"configured (provider: {cfg['provider']})" if ok_key else "not set — narration disabled",
        "aivas config set api_key YOUR_KEY" if not ok_key else "",
    ))

    # UDP / root
    import os
    is_root = os.geteuid() == 0
    lines.append(_check(
        "permissions", True,
        "root (UDP scans enabled)" if is_root else "user (--udp needs sudo)",
    ))

    all_ok = all("✗" not in l.plain for l in lines)
    status_color = "green" if all_ok else "yellow"
    status = "All checks passed" if all_ok else "Some checks need attention"
    body = "\n".join(l.markup for l in lines)

    console.print(Panel(
        Text.from_markup(body),
        title=f"[bold]AIVAS Doctor — {status}[/bold]",
        border_style=status_color,
        padding=(1, 2),
    ))
