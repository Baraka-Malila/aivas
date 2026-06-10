"""Slash command registry and handlers for the AIVAS TUI."""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from .scan import (  # noqa: F401 — re-exported for tests + callers
    run_scan_pipeline,
    _bad_ip,
    _resolves,
    _run_nmap_sudo,
    _KNOWN_FLAGS,
)
from .handlers import cmd_copy, cmd_doctor, cmd_kev, cmd_config, cmd_history

_SCAN_INTENT_RE = re.compile(
    r'\b(scan|check|probe|assess|audit|find|vuln|port|service|network|host|ip)\b'
    r'|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    r'|localhost',
    re.IGNORECASE,
)

if TYPE_CHECKING:
    from .app import AIVASApp

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
    lines.append("\n[dim]Free text (no /) routes to AI if API key is configured.[/dim]")
    app.tui_print("\n".join(lines))


async def _cmd_clear(app: "AIVASApp", _args: str) -> None:
    app.query_one("#output").clear()
    app._last_scan_text = ""


async def _cmd_exit(app: "AIVASApp", _args: str) -> None:
    app.exit()


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
            "Usage: [bold]/scan <target> [--level 1-3] [--udp][/bold]"
        )
        return
    level, udp, i = 2, False, 1
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
        elif parts[i].startswith("--"):
            app.tui_print(
                f"[red]Unknown flag:[/red] {parts[i]!r}\n"
                "[dim]Valid flags: --level 1-3, --udp[/dim]"
            )
            return
        else:
            i += 1
    await run_scan_pipeline(app, target, level, udp)


async def _cmd_quick(app: "AIVASApp", args: str) -> None:
    target = args.split()[0] if args else ""
    if not target or target.startswith("-"):
        app.tui_print("[red]Usage:[/red] /quick <target>  e.g. /quick 192.168.100.253")
        return
    await run_scan_pipeline(app, target, level=1)


async def _cmd_deep(app: "AIVASApp", args: str) -> None:
    parts = args.split()
    if not parts or parts[0].startswith("-"):
        app.tui_print("[red]Usage:[/red] /deep <target>  e.g. /deep 192.168.100.253")
        return
    await run_scan_pipeline(app, parts[0], level=2, udp=True)


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
        + (f" (focus: {intent['focus']})" if intent.get("focus") else "") + "[/dim]"
    )
    await run_scan_pipeline(app, target, level)


_HANDLERS: dict[str, object] = {
    "scan":    _cmd_scan,
    "quick":   _cmd_quick,
    "deep":    _cmd_deep,
    "ask":     _cmd_ask,
    "doctor":  cmd_doctor,
    "history": cmd_history,
    "kev":     cmd_kev,
    "config":  cmd_config,
    "clear":   _cmd_clear,
    "copy":    cmd_copy,
    "exit":    _cmd_exit,
    "help":    _cmd_help,
}
