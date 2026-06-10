"""Verbose command handlers: doctor, history, config, copy, kev."""
from __future__ import annotations
import asyncio
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .app import AIVASApp


async def cmd_copy(app: "AIVASApp", _args: str) -> None:
    import shutil, subprocess
    text = app._last_scan_text
    if not text.strip():
        app.tui_print(
            "[yellow]Nothing to copy yet.[/yellow] Run a scan first, then /copy.\n"
            "[dim]Tip: Shift+drag with mouse → Ctrl+Shift+C also works in most terminals.[/dim]"
        )
        return
    if shutil.which("wl-copy"):
        subprocess.run(["wl-copy"], input=text.encode(), check=False)
        app.tui_print("[green]✓[/green] Copied to clipboard (wl-copy).")
    elif shutil.which("xclip"):
        subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=False)
        app.tui_print("[green]✓[/green] Copied to clipboard (xclip).")
    elif shutil.which("xsel"):
        subprocess.run(["xsel", "--clipboard", "--input"], input=text.encode(), check=False)
        app.tui_print("[green]✓[/green] Copied to clipboard (xsel).")
    else:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False, prefix="aivas_scan_") as f:
            f.write(text)
        app.tui_print(
            f"[yellow]No clipboard tool found.[/yellow] Saved to: [bold]{f.name}[/bold]\n"
            "[dim]Install one: sudo apt install xclip[/dim]"
        )


async def cmd_doctor(app: "AIVASApp", _args: str) -> None:
    import shutil, os, subprocess
    from aivas.database.kev import get_kev_status
    from aivas import config as _config
    conn = app.conn
    cfg = _config.load()
    lines = []
    nmap_path = shutil.which("nmap")
    if nmap_path:
        ver = subprocess.run(["nmap", "--version"], capture_output=True, text=True
                             ).stdout.splitlines()[0]
        lines.append(f"  [bold green]✓[/bold green]  nmap: {ver}")
    else:
        lines.append("  [bold red]✗[/bold red]  nmap: not found — sudo apt install nmap")
    cve_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    if cve_count:
        lines.append(f"  [bold green]✓[/bold green]  database: {cve_count:,} CVEs loaded")
    else:
        lines.append("  [bold red]✗[/bold red]  database: empty — run /kev or aivas update-db")
    kev = get_kev_status(conn)
    if kev["count"]:
        lines.append(f"  [bold green]✓[/bold green]  KEV: {kev['count']:,} CVEs flagged")
    else:
        lines.append("  [bold yellow]![/bold yellow]  KEV: not synced — run /kev")
    api_key = cfg.get("api_key")
    if api_key:
        lines.append(f"  [bold green]✓[/bold green]  API key: set (provider: {cfg['provider']})")
    else:
        lines.append(
            "  [bold yellow]![/bold yellow]  API key: not set — AI narration disabled\n"
            "       → /config set api_key YOUR_KEY"
        )
    if os.geteuid() == 0:
        lines.append("  [bold green]✓[/bold green]  permissions: root (UDP + OS detect enabled)")
    else:
        nmap_bin = shutil.which("nmap") or "nmap"
        caps = subprocess.run(["getcap", nmap_bin], capture_output=True, text=True).stdout
        if "cap_net_raw" in caps:
            lines.append("  [bold green]✓[/bold green]  permissions: nmap has raw socket capability (UDP enabled)")
        else:
            lines.append(
                "  [bold yellow]![/bold yellow]  permissions: user — UDP/OS detect need raw sockets\n"
                f"       → one-time fix: [bold]sudo setcap cap_net_raw,cap_net_admin+eip {nmap_bin}[/bold]"
            )
    app.tui_print("[bold]System Status[/bold]\n" + "\n".join(lines))


async def cmd_kev(app: "AIVASApp", _args: str) -> None:
    from aivas.database.kev import fetch_kev, mark_kev
    from datetime import datetime, timezone
    app.tui_print("[dim]Downloading CISA KEV feed...[/dim]")
    try:
        cve_ids = await asyncio.to_thread(fetch_kev)
        count = mark_kev(app.conn, cve_ids)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        app.conn.execute(
            "INSERT OR REPLACE INTO sync_meta (key, value) VALUES (?, ?)",
            ("kev_last_updated", now),
        )
        app.conn.commit()
        app.tui_print(f"[green]✓[/green] KEV sync complete — {count} CVEs marked as exploited in wild.")
    except Exception as exc:
        app.tui_print(f"[red]KEV sync failed:[/red] {exc}")


async def cmd_config(app: "AIVASApp", args: str) -> None:
    from aivas import config as _config
    parts = args.split()
    if not parts or parts[0] == "show":
        cfg = _config.load()
        lines = ["[bold]Configuration[/bold]"]
        for k, v in cfg.items():
            display = "***" if k == "api_key" and v else (str(v) if v else "[dim]not set[/dim]")
            lines.append(f"  {k}: {display}")
        app.tui_print("\n".join(lines))
    elif parts[0] == "set" and len(parts) >= 3:
        key, val = parts[1], parts[2]
        if key not in _config.valid_keys():
            app.tui_print(f"[red]Unknown key:[/red] {key}. Valid: {', '.join(_config.valid_keys())}")
            return
        try:
            _config.save(key, val)
            app.tui_print(f"[green]✓[/green] {key} = {val}")
        except RuntimeError as exc:
            app.tui_print(f"[red]Error:[/red] {exc}")
    else:
        app.tui_print("Usage: /config show  |  /config set <key> <value>")


async def cmd_history(app: "AIVASApp", args: str) -> None:
    from rich.table import Table
    parts = args.split()
    sub = parts[0] if parts else "list"
    if sub == "list":
        rows = app.conn.execute(
            "SELECT id, target, started_at, finding_count, grade "
            "FROM scans ORDER BY id DESC LIMIT 15"
        ).fetchall()
        if not rows:
            app.tui_print("[dim]No scans saved yet. Use /scan ... and it will offer to save.[/dim]")
            return
        t = Table(title="Scan History", show_lines=True)
        t.add_column("#", justify="right")
        t.add_column("Target")
        t.add_column("Date")
        t.add_column("Findings", justify="right")
        t.add_column("Grade")
        for r in rows:
            t.add_row(str(r["id"]), r["target"], r["started_at"][:16],
                      str(r["finding_count"]), r["grade"] or "—")
        app.tui_print(t)
    elif sub == "show" and len(parts) >= 2:
        try:
            sid = int(parts[1])
        except ValueError:
            app.tui_print("[red]Usage:[/red] /history show <id>")
            return
        from aivas.history import get_scan_findings
        from aivas.formatting import cve_table
        from rich.markup import escape
        findings = get_scan_findings(app.conn, sid)
        if not findings:
            app.tui_print(f"[yellow]Scan #{sid} not found.[/yellow]")
            return
        safe = [dict(f) | {"description": escape(f.get("description") or "")} for f in findings]
        app.tui_print(cve_table(f"Scan #{sid} Findings", safe))
    else:
        app.tui_print("Usage: /history list  |  /history show <id>")
