"""Slash command registry and handlers for the AIVAS TUI."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .scan import (  # noqa: F401 — re-exported for tests + callers
    run_scan_pipeline,
    _bad_ip,
    _resolves,
    _run_nmap_sudo,
    _KNOWN_FLAGS,
)
from .handlers import cmd_copy, cmd_doctor, cmd_config, cmd_history

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
    "doctor":  ("/doctor",                               "Check dependencies and configuration"),
    "history": ("/history [list|show <id>]",             "View past scan results"),
    "config":  ("/config [set <key> <value>|show]",      "Manage configuration"),
    "switch":  ("/switch groq|mistral|ollama",            "Switch AI provider (fast rate-limit fix)"),
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


_HELP_GROUPS = [
    ("Scanning", ["scan", "quick", "deep"]),
    ("Results",  ["history", "copy"]),
    ("Setup",    ["config", "switch", "doctor"]),
    ("Interface",["clear", "help", "exit"]),
]

async def _cmd_help(app: "AIVASApp", args: str) -> None:
    if args and args in REGISTRY:
        usage, desc = REGISTRY[args]
        app.tui_print(f"[bold #4a9eff]{usage}[/bold #4a9eff]\n  [#888888]{desc}[/#888888]")
        return
    lines = ["[bold #e0e0e0]Commands[/bold #e0e0e0]\n"]
    for group, cmds in _HELP_GROUPS:
        lines.append(f"  [#555555]{group}[/#555555]")
        for cmd in cmds:
            usage, desc = REGISTRY[cmd]
            lines.append(f"    [#4a9eff]{usage:<38}[/#4a9eff] [#888888]{desc}[/#888888]")
        lines.append("")
    lines.append("[#555555]Free-text (no /) → AI assistant if API key is set.[/#555555]")
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
        if parts[i] == "--level":
            if i + 1 >= len(parts):
                app.tui_print("[red]--level requires a value 1–3[/red]")
                return
            try:
                level = int(parts[i + 1])
            except ValueError:
                app.tui_print("[red]--level must be 1, 2, or 3[/red]")
                return
            if level not in (1, 2, 3):
                app.tui_print("[red]--level must be 1, 2, or 3[/red]")
                return
            i += 2
        elif parts[i] == "--udp":
            udp = True
            i += 1
        elif parts[i] not in _KNOWN_FLAGS and parts[i].startswith("--"):
            app.tui_print(
                f"[red]Unknown flag:[/red] {parts[i]!r}\n"
                "[#888888]Valid flags: --level 1-3, --udp[/#888888]"
            )
            return
        else:
            i += 1
    app.run_worker(run_scan_pipeline(app, target, level, udp), exclusive=True)


async def _cmd_quick(app: "AIVASApp", args: str) -> None:
    target = args.split()[0] if args else ""
    if not target or target.startswith("-"):
        app.tui_print("[red]Usage:[/red] /quick <target>  e.g. /quick 192.168.100.253")
        return
    app.run_worker(run_scan_pipeline(app, target, level=1), exclusive=True)


async def _cmd_deep(app: "AIVASApp", args: str) -> None:
    parts = args.split()
    if not parts or parts[0].startswith("-"):
        app.tui_print("[red]Usage:[/red] /deep <target>  e.g. /deep 192.168.100.253")
        return
    app.run_worker(run_scan_pipeline(app, parts[0], level=2, udp=True), exclusive=True)


async def _cmd_switch(app: "AIVASApp", args: str) -> None:
    from aivas import config as _config
    valid = ("groq", "mistral", "ollama")
    target = args.strip().lower() if args else ""
    if target not in valid:
        cfg = _config.load()
        current = cfg.get("provider", "groq")
        app.tui_print(
            f"\n  Current provider: [bold #4a9eff]{current}[/bold #4a9eff]\n"
            f"  [#888888]Usage: [bold]/switch groq[/bold]  ·  "
            f"[bold]/switch mistral[/bold]  ·  [bold]/switch ollama[/bold][/#888888]\n"
        )
        return
    _config.save("provider", target)
    hints = {
        "groq": "Fast, free tier. Rate limit? Switch to mistral.",
        "mistral": "Reliable. Good fallback when Groq is rate-limited.",
        "ollama": "Local, private. Ensure Ollama is running: ollama serve",
    }
    app.tui_print(
        f"\n[green]✓[/green] Provider switched → [bold #4a9eff]{target}[/bold #4a9eff]\n"
        f"  [#888888]{hints[target]}[/#888888]\n"
    )


_HANDLERS: dict[str, object] = {
    "scan":    _cmd_scan,
    "quick":   _cmd_quick,
    "deep":    _cmd_deep,
    "doctor":  cmd_doctor,
    "history": cmd_history,
    "config":  cmd_config,
    "switch":  _cmd_switch,
    "clear":   _cmd_clear,
    "copy":    cmd_copy,
    "exit":    _cmd_exit,
    "help":    _cmd_help,
}
