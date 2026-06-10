"""Slash command registry and handlers for the AIVAS TUI."""
from __future__ import annotations

import asyncio
import re
import socket
from typing import TYPE_CHECKING

_IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/\d{1,2})?$')
_SCAN_INTENT_RE = re.compile(
    r'\b(scan|check|probe|assess|audit|find|vuln|port|service|network|host|ip)\b'
    r'|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    r'|localhost',
    re.IGNORECASE,
)

if TYPE_CHECKING:
    from .app import AIVASApp

# (usage, description)
REGISTRY: dict[str, tuple[str, str]] = {
    "scan":    ("/scan <target> [--level 1-3] [--udp]", "Full CVE + config probe scan"),
    "quick":   ("/quick <target>",                       "Quick service scan (level 1)"),
    "deep":    ("/deep <target>",                         "Deep scan with UDP (level 2, UDP always on)"),
    "ask":     ("/ask <query>",                           "Natural language scan (needs API key)"),
    "doctor":  ("/doctor",                               "Check dependencies and configuration"),
    "history": ("/history [list|show <id>]",             "View past scan results"),
    "kev":     ("/kev",                                  "Sync CISA Known Exploited Vulnerabilities"),
    "config":  ("/config [set <key> <value>|show]",      "Manage configuration"),
    "clear":   ("/clear",                                "Clear the output pane"),
    "copy":    ("/copy",                                 "Copy last scan output to clipboard"),
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
    app._last_scan_text = ""


async def _cmd_exit(app: "AIVASApp", _args: str) -> None:
    app.exit()


async def _cmd_copy(app: "AIVASApp", _args: str) -> None:
    import shutil, subprocess
    text = app._last_scan_text
    if not text.strip():
        app.tui_print(
            "[yellow]Nothing to copy yet.[/yellow] Run a scan first, then /copy.\n"
            "[dim]Tip: Shift+drag with mouse → Ctrl+Shift+C also works in most terminals.[/dim]"
        )
        return
    # Try Wayland first, then X11, then fallback
    if shutil.which("wl-copy"):
        subprocess.run(["wl-copy"], input=text.encode(), check=False)
        app.tui_print("[green]✓[/green] Copied to clipboard (wl-copy).")
    elif shutil.which("xclip"):
        subprocess.run(["xclip", "-selection", "clipboard"],
                       input=text.encode(), check=False)
        app.tui_print("[green]✓[/green] Copied to clipboard (xclip).")
    elif shutil.which("xsel"):
        subprocess.run(["xsel", "--clipboard", "--input"],
                       input=text.encode(), check=False)
        app.tui_print("[green]✓[/green] Copied to clipboard (xsel).")
    else:
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         delete=False, prefix="aivas_scan_") as f:
            f.write(text)
            fname = f.name
        app.tui_print(
            f"[yellow]No clipboard tool found.[/yellow] Saved to: [bold]{fname}[/bold]\n"
            "[dim]Install one: sudo apt install xclip[/dim]"
        )


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
    if is_root:
        perm_line = "  [bold green]✓[/bold green]  permissions: root (UDP + OS detect enabled)"
    else:
        import subprocess as _sp
        nmap_bin = shutil.which("nmap") or "nmap"
        caps = _sp.run(["getcap", nmap_bin], capture_output=True, text=True).stdout
        if "cap_net_raw" in caps:
            perm_line = "  [bold green]✓[/bold green]  permissions: nmap has raw socket capability (UDP enabled)"
        else:
            perm_line = (
                "  [bold yellow]![/bold yellow]  permissions: user — UDP/OS detect need raw sockets\n"
                f"       → one-time fix: [bold]sudo setcap cap_net_raw,cap_net_admin+eip {nmap_bin}[/bold]"
            )
    lines.append(perm_line)

    app.tui_print("[bold]System Status[/bold]\n" + "\n".join(lines))


async def _cmd_kev(app: "AIVASApp", _args: str) -> None:
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
        from aivas.history import get_scan_findings
        from aivas.formatting import cve_table
        from rich.markup import escape
        findings = get_scan_findings(app.conn, sid)
        if not findings:
            app.tui_print(f"[yellow]Scan #{sid} not found.[/yellow]")
            return
        safe = []
        for f in findings:
            s = dict(f)
            s["description"] = escape(s.get("description") or "")
            safe.append(s)
        app.tui_print(cve_table(f"Scan #{sid} Findings", safe))
    else:
        app.tui_print("Usage: /history list  |  /history show <id>")


async def _nmap_needs_sudo(udp: bool) -> bool:
    import os, shutil, subprocess
    if not udp or os.geteuid() == 0:
        return False
    nmap_bin = shutil.which("nmap") or "nmap"
    caps = subprocess.run(["getcap", nmap_bin], capture_output=True, text=True).stdout
    return "cap_net_raw" not in caps


async def _run_nmap_threaded(app: "AIVASApp", target: str, scripts: str,
                              udp: bool, os_detect: bool, timeout: int = 300) -> str:
    """Run nmap via Popen (non-sudo path), storing handle on app._scan_proc.

    Allows ESC to kill the underlying subprocess.
    """
    import subprocess
    import shutil
    import asyncio

    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = ["nmap", "-sV", "-oX", "-", target]
    if udp:
        cmd += ["-sU"]
    if os_detect:
        cmd += ["-O"]
    if scripts:
        cmd += ["--script", scripts]

    def _run_proc():
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        app._scan_proc = proc
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            if proc.returncode != 0:
                stderr_text = stderr.decode()
                # OS detection requires root — retry without -O
                if os_detect and "root" in stderr_text.lower() and "-O" in cmd:
                    cmd.remove("-O")
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    app._scan_proc = proc
                    stdout, stderr = proc.communicate(timeout=timeout)
                    if proc.returncode != 0:
                        raise RuntimeError(f"nmap exited {proc.returncode}: {stderr.decode()}")
                else:
                    raise RuntimeError(f"nmap exited {proc.returncode}: {stderr_text}")
            return stdout.decode()
        except subprocess.TimeoutExpired:
            proc.kill()
            raise RuntimeError(f"nmap timed out after {timeout}s.")
        finally:
            app._scan_proc = None

    return await asyncio.to_thread(_run_proc)


async def _run_nmap_sudo(app: "AIVASApp", target: str, scripts: str,
                          udp: bool, timeout: int = 300) -> str:
    """Run sudo nmap with stdout XML capture, return XML string.

    Uses -oX - to write XML to stdout — avoids the nmap security check
    that refuses to write to files not owned by the running user (root).
    sudo prompts on /dev/tty so stdout capture does not interfere.
    """
    import sys
    import subprocess
    import shutil

    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = ["sudo", nmap_bin, "-sV", "-oX", "-", target]
    if udp:
        cmd += ["-sU"]
    if scripts:
        cmd += ["--script", scripts]

    result = None
    with app.suspend():
        # TUI is suspended — write directly to terminal, not via app.tui_print
        sys.stdout.write(
            "\n[AIVAS] UDP scan requires root privileges.\n"
            "(One-time fix to avoid this prompt: "
            f"sudo setcap cap_net_raw,cap_net_admin+eip {nmap_bin})\n\n"
        )
        sys.stdout.flush()
        try:
            result = subprocess.run(
                cmd,
                stdin=sys.stdin,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"nmap timed out after {timeout}s.")

    if result is None:
        raise RuntimeError("nmap did not run (TUI suspend failed).")
    if result.returncode != 0:
        raise RuntimeError(
            f"nmap exited {result.returncode} — "
            "sudo password wrong, denied, or nmap not found?"
        )
    xml = result.stdout.decode("utf-8", errors="replace")
    if not xml.strip():
        raise RuntimeError("nmap produced no output (check sudo permissions).")
    return xml


def _bad_ip(target: str) -> str | None:
    """Return error string if target is an invalid IPv4, else None."""
    m = _IPV4_RE.match(target.split('/')[0] if '/' in target else target)
    if not m:
        return None
    if any(int(m.group(i)) > 255 for i in range(1, 5)):
        return f"Invalid IP address: {target!r} — each octet must be 0–255."
    return None


async def _resolves(host: str) -> bool:
    """Returns True if host resolves via DNS, False otherwise."""
    try:
        await asyncio.to_thread(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
        return True
    except (socket.gaierror, OSError):
        return False


async def _run_scan_pipeline(app: "AIVASApp", target: str, level: int,
                              udp: bool = False) -> None:
    """Core scan: nmap → parse → correlate → display. Runs nmap in thread pool."""
    import os, shutil
    from aivas.scanner import run_scan
    from aivas.scanner.nse import scripts_for_level
    from aivas.parser import parse_nmap_xml
    from aivas.correlator import correlate
    from aivas.formatting import cve_table, misconfig_table
    from aivas.scorer import score_findings

    if app._scan_task is not None and not app._scan_task.done():
        app.tui_print("[yellow]A scan is already running. Press ESC to cancel it first.[/yellow]")
        return

    # Validate target before touching nmap
    ip_err = _bad_ip(target)
    if ip_err:
        app.tui_print(f"[red]Invalid target:[/red] {ip_err}")
        return

    # For hostnames (not bare IPs or CIDRs), verify DNS resolution first
    if not _IPV4_RE.match(target.split('/')[0] if '/' in target else target):
        app.tui_print(f"[dim]Resolving {target}…[/dim]")
        await asyncio.sleep(0)  # let display update
        if not await _resolves(target):
            app.tui_print(
                f"[red]Scan error:[/red] Cannot resolve hostname: {target!r}\n"
                "[dim]Check spelling or use an IP address directly.[/dim]"
            )
            return

    app.tui_print(f"Scanning [bold]{target}[/bold]  [dim](level {level}{', UDP' if udp else ''})[/dim]")
    app._last_scan_text = f"# AIVAS Scan — {target}\n"
    app.set_scan_running(target)
    await asyncio.sleep(0)  # yield so progress label renders before blocking

    app._scan_task = asyncio.current_task()
    use_sudo = await _nmap_needs_sudo(udp)
    try:
        if use_sudo:
            xml = await _run_nmap_sudo(app, target, scripts_for_level(level), udp)
        else:
            xml = await _run_nmap_threaded(
                app, target,
                scripts=scripts_for_level(level),
                udp=udp,
                os_detect=True,
            )
    except asyncio.CancelledError:
        app.set_scan_idle()
        app.tui_print("[yellow]Scan cancelled.[/yellow]")
        return
    except RuntimeError as exc:
        app.set_scan_idle()
        app.tui_print(f"[red]Scan error:[/red] {exc}")
        return
    finally:
        app._scan_task = None
        if app._scan_proc is not None:
            try:
                app._scan_proc.kill()
            except OSError:
                pass
            app._scan_proc = None
        app.set_scan_idle()

    try:
        services = parse_nmap_xml(xml)
    except Exception:
        app.tui_print("[red]Scan error:[/red] nmap returned unexpected output (not valid XML).")
        return
    if not services:
        app.tui_print("[yellow]No open services found.[/yellow]")
        return

    app.tui_print(f"[dim]Found {len(services)} service(s) — correlating CVEs…[/dim]")

    os_hint = services[0].get("os_family") or None
    findings = [f for f in correlate(app.conn, services, os_hint=os_hint)
                if f.get("confidence") in ("probable", "confirmed")][:30]

    if findings:
        table = cve_table("Vulnerability Findings", findings, desc_max=55)
        app.tui_print(table)
        app.store_scan_output(table)
        s = score_findings(findings)
        counts = s.get("sev_counts", {})
        count_parts = [f"{v} {k.lower()}" for k, v in counts.items() if v]
        count_str = " (" + ", ".join(count_parts) + ")" if count_parts else ""
        grade_col = "red" if s["grade"] in ("D", "F") else "green"
        score_line = (
            f"Risk Score: {s['score']}/100  Grade [{grade_col}]{s['grade']}[/{grade_col}]"
            f"  [dim]— {s['total']} findings{count_str}[/dim]"
        )
        app.tui_print(score_line)
        app.store_scan_output(score_line)
        # auto-save to history
        try:
            from aivas.history import save_scan
            save_scan(app.conn, target, findings)
            app.tui_print("[dim]Scan saved to history (/history list)[/dim]")
        except Exception:
            pass
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
        mc_table = misconfig_table("Configuration Issues", misconfigs)
        app.tui_print(mc_table)
        app.store_scan_output(mc_table)


async def _cmd_scan(app: "AIVASApp", args: str) -> None:
    import shlex
    parts = shlex.split(args) if args else []
    if not parts:
        app.tui_print("[red]Usage:[/red] /scan <target> [--level 1-3] [--udp]")
        return
    target = parts[0]
    if target.startswith("-"):
        app.tui_print(
            f"[red]Invalid target:[/red] {target!r} looks like a flag, not an IP or hostname.\n"
            "Usage: [bold]/scan <target> [--level 1-3] [--udp][/bold]\n"
            "Example: [bold]/scan 192.168.100.253[/bold]"
        )
        return
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
    if not target or target.startswith("-"):
        app.tui_print("[red]Usage:[/red] /quick <target>  e.g. /quick 192.168.100.253")
        return
    await _run_scan_pipeline(app, target, level=1)


async def _cmd_deep(app: "AIVASApp", args: str) -> None:
    parts = args.split()
    if not parts or parts[0].startswith("-"):
        app.tui_print("[red]Usage:[/red] /deep <target>  e.g. /deep 192.168.100.253")
        return
    target = parts[0]
    await _run_scan_pipeline(app, target, level=2, udp=True)


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

    # Guard: only route to AI if text looks like a scan request
    if not _SCAN_INTENT_RE.search(text):
        app.tui_print(
            "[dim]AIVAS understands scan commands. Try:[/dim]\n"
            "  [bold]/scan 192.168.1.1[/bold]       — direct scan\n"
            "  [bold]/ask scan my router[/bold]      — natural language (with API key)\n"
            "  [bold]/help[/bold]                    — all commands"
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
    "copy":    _cmd_copy,
    "exit":    _cmd_exit,
    "help":    _cmd_help,
}
