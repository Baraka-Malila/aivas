"""Slash command registry and handlers for the AIVAS TUI."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import AIVASApp

# (usage, description)
REGISTRY: dict[str, tuple[str, str]] = {
    "scan":    ("/scan <target> [--level 1-3] [--udp]", "Full CVE + config probe scan"),
    "quick":   ("/quick <target>",                       "Quick service scan (level 1)"),
    "deep":    ("/deep <target> [--udp]",                "Deep scan with UDP (level 2 + UDP)"),
    "ask":     ("/ask <query>",                           "Natural language scan (needs API key)"),
    "doctor":  ("/doctor",                               "Check dependencies and configuration"),
    "history": ("/history [list|show <id>]",             "View past scan results"),
    "kev":     ("/kev",                                  "Sync CISA Known Exploited Vulnerabilities"),
    "config":  ("/config [set <key> <value>|show]",      "Manage configuration"),
    "clear":   ("/clear",                                "Clear the output pane"),
    "exit":    ("/exit",                                 "Quit AIVAS"),
    "help":    ("/help [command]",                       "List commands or show usage"),
}


async def handle(app: "AIVASApp", raw: str) -> None:
    parts = raw[1:].split(maxsplit=1)
    name = parts[0].lower() if parts else ""
    args = parts[1].strip() if len(parts) > 1 else ""

    handler = _HANDLERS.get(name)
    if handler is None:
        app.tui_print(
            f"[red]Unknown command:[/red] /{name}\n"
            "Type [bold]/help[/bold] for available commands."
        )
        return
    await handler(app, args)


async def _cmd_help(app: "AIVASApp", args: str) -> None:
    if args and args in REGISTRY:
        usage, desc = REGISTRY[args]
        app.tui_print(f"[bold]{usage}[/bold]\n  {desc}")
        return
    lines = ["[bold cyan]Available commands:[/bold cyan]\n"]
    for cmd, (usage, desc) in REGISTRY.items():
        lines.append(f"  [bold]{usage:<40}[/bold] {desc}")
    lines.append(
        "\n[dim]Free text (no /) routes to AI if API key is configured.[/dim]"
    )
    app.tui_print("\n".join(lines))


async def _cmd_clear(app: "AIVASApp", _args: str) -> None:
    app.query_one("#output").clear()


async def _cmd_exit(app: "AIVASApp", _args: str) -> None:
    app.exit()


async def _cmd_doctor(app: "AIVASApp", _args: str) -> None:
    from aivas.commands.doctor_cmd import _check
    import shutil, sys, os
    from aivas.database.kev import get_kev_status
    from aivas import config as _config

    conn = app.conn
    cfg = _config.load()
    lines = []

    nmap_path = shutil.which("nmap")
    if nmap_path:
        import subprocess
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

    is_root = os.geteuid() == 0
    perm = "root (UDP enabled)" if is_root else "user (--udp needs sudo)"
    lines.append(f"  [bold green]✓[/bold green]  permissions: {perm}")

    app.tui_print("[bold]System Status[/bold]\n" + "\n".join(lines))


async def _cmd_kev(app: "AIVASApp", _args: str) -> None:
    from aivas.database.kev import sync_kev
    app.tui_print("[dim]Downloading CISA KEV feed...[/dim]")
    try:
        count = await asyncio.to_thread(sync_kev, app.conn)
        app.tui_print(f"[green]✓[/green] KEV sync complete — {count} CVEs marked as exploited in wild.")
    except Exception as exc:
        app.tui_print(f"[red]KEV sync failed:[/red] {exc}")


async def _cmd_config(app: "AIVASApp", args: str) -> None:
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


async def _cmd_history(app: "AIVASApp", args: str) -> None:
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
        from aivas.history import load_scan
        findings = load_scan(app.conn, sid)
        if not findings:
            app.tui_print(f"[yellow]Scan #{sid} not found.[/yellow]")
            return
        from aivas.formatting import cve_table
        app.tui_print(cve_table(f"Scan #{sid} Findings", findings))
    else:
        app.tui_print("Usage: /history list  |  /history show <id>")


async def _run_scan_pipeline(app: "AIVASApp", target: str, level: int,
                              udp: bool = False) -> None:
    """Core scan: nmap → parse → correlate → display. Runs nmap in thread pool."""
    import os
    from aivas.scanner import run_scan
    from aivas.scanner.nse import scripts_for_level
    from aivas.parser import parse_nmap_xml
    from aivas.correlator import correlate
    from aivas.formatting import cve_table, misconfig_table
    from aivas.scorer import score_findings

    if udp and os.geteuid() != 0:
        app.tui_print("[yellow]Warning:[/yellow] --udp requires root. UDP ports may be skipped.")

    app.tui_print(f"[bold]Scanning {target} (level {level})...[/bold]")
    try:
        xml = await asyncio.to_thread(
            run_scan, target,
            scripts=scripts_for_level(level),
            udp=udp,
            os_detect=True,
        )
    except RuntimeError as exc:
        app.tui_print(f"[red]Scan error:[/red] {exc}")
        return

    services = parse_nmap_xml(xml)
    if not services:
        app.tui_print("[yellow]No open services found.[/yellow]")
        return

    os_hint = services[0].get("os_family") or None
    findings = [f for f in correlate(app.conn, services, os_hint=os_hint)
                if f.get("confidence") in ("probable", "confirmed")][:30]

    if findings:
        app.tui_print(cve_table("Vulnerability Findings", findings, desc_max=55))
        s = score_findings(findings)
        app.tui_print(f"[bold]Risk Score:[/bold] {s['score']}/100 — Grade [bold]{s['grade']}[/bold]")
    else:
        app.tui_print("[green]No CVEs matched at probable confidence.[/green]")

    misconfigs: list[dict] = []
    for svc in services:
        is_http = svc.get("service", "") in ("http", "https", "ssl") or (
            svc.get("port") in (80, 443, 8080, 8443)
        )
        if is_http:
            from aivas.prober import probe_http_service
            mc = await asyncio.to_thread(
                probe_http_service, svc["host"], svc["port"],
                "ssl" in svc.get("service", "")
            )
            misconfigs.extend(mc)

    if misconfigs:
        app.tui_print(misconfig_table("Configuration Issues", misconfigs))


async def _cmd_scan(app: "AIVASApp", args: str) -> None:
    import shlex
    parts = shlex.split(args) if args else []
    if not parts:
        app.tui_print("[red]Usage:[/red] /scan <target> [--level 1-3] [--udp]")
        return
    target = parts[0]
    level = 2
    udp = False
    i = 1
    while i < len(parts):
        if parts[i] == "--level" and i + 1 < len(parts):
            try:
                level = int(parts[i + 1])
            except ValueError:
                pass
            i += 2
        elif parts[i] == "--udp":
            udp = True
            i += 1
        else:
            i += 1
    await _run_scan_pipeline(app, target, level, udp)


async def _cmd_quick(app: "AIVASApp", args: str) -> None:
    target = args.split()[0] if args else ""
    if not target:
        app.tui_print("[red]Usage:[/red] /quick <target>")
        return
    await _run_scan_pipeline(app, target, level=1)


async def _cmd_deep(app: "AIVASApp", args: str) -> None:
    parts = args.split()
    if not parts:
        app.tui_print("[red]Usage:[/red] /deep <target> [--udp]")
        return
    target = parts[0]
    udp = "--udp" in parts
    await _run_scan_pipeline(app, target, level=2, udp=udp)


async def _cmd_ask(app: "AIVASApp", args: str) -> None:
    if not args:
        app.tui_print("[red]Usage:[/red] /ask <natural language query>")
        return
    await _dispatch_ai(app, args)


async def _dispatch_ai(app: "AIVASApp", text: str) -> None:
    from aivas import config as _config
    cfg = _config.load()
    api_key = cfg.get("api_key")
    if not api_key:
        app.tui_print(
            "[yellow]No API key configured.[/yellow] "
            "AIVAS works fully without AI — try [bold]/scan <target>[/bold] directly.\n"
            "To enable AI features: [bold]/config set api_key YOUR_KEY[/bold] "
            "or run [bold]/doctor[/bold]"
        )
        return

    from aivas.narrator.providers import get_provider
    from aivas.narrator.intent import parse_intent
    app.tui_print(f"[dim]Parsing intent: {text}[/dim]")
    try:
        prov = get_provider(cfg["provider"], api_key=api_key)
        intent = await asyncio.to_thread(parse_intent, text, prov)
    except Exception as exc:
        app.tui_print(f"[red]AI parse failed:[/red] {exc}")
        return

    target = intent["target"]
    level = intent.get("level", 2)
    app.tui_print(
        f"[dim]Understood: scan [bold]{target}[/bold] at level {level}"
        + (f" (focus: {intent['focus']})" if intent.get("focus") else "")
        + "[/dim]"
    )
    await _run_scan_pipeline(app, target, level)


# Register all handlers
_HANDLERS: dict[str, object] = {
    "scan":    _cmd_scan,
    "quick":   _cmd_quick,
    "deep":    _cmd_deep,
    "ask":     _cmd_ask,
    "doctor":  _cmd_doctor,
    "history": _cmd_history,
    "kev":     _cmd_kev,
    "config":  _cmd_config,
    "clear":   _cmd_clear,
    "exit":    _cmd_exit,
    "help":    _cmd_help,
}
