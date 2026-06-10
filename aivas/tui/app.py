from __future__ import annotations

import asyncio
import sqlite3
import subprocess

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Input, Label, OptionList, RichLog

from . import commands as _cmds
from .input_actions import InputActionsMixin

_BANNER = (
    "[bold cyan]   █████╗ ██╗██╗   ██╗ █████╗ ███████╗[/bold cyan]\n"
    "[bold cyan]  ██╔══██╗██║██║   ██║██╔══██╗██╔════╝[/bold cyan]\n"
    "[bold cyan]  ███████║██║██║   ██║███████║███████╗[/bold cyan]\n"
    "[bold cyan]  ██╔══██║██║╚██╗ ██╔╝██╔══██║╚════██║[/bold cyan]\n"
    "[bold cyan]  ██║  ██║██║ ╚████╔╝ ██║  ██║███████║[/bold cyan]\n"
    "[bold cyan]  ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝[/bold cyan]\n"
    "[dim]  AI-Assisted Vulnerability Assessment System[/dim]\n"
    "[dim]  Type [bold]/help[/bold] for commands  "
    "·  [bold]/copy[/bold] → clipboard  "
    "·  [bold]Shift+drag[/bold] → select text[/dim]"
)

_CSS = """
Screen { layout: vertical; background: $surface; }

#output {
    height: 1fr;
    border: heavy $accent;
    padding: 1 2;
    scrollbar-gutter: stable;
}

#suggestions {
    max-height: 12;
    background: $surface-darken-1;
    display: none;
    padding: 0;
    border: none;
}

OptionList > .option-list--option-highlighted {
    background: $surface-darken-3;
    color: #4a9eff;
}

#cmd-input {
    background: $surface-darken-1;
    border-top: heavy $accent;
    border-left: none;
    border-right: none;
    border-bottom: none;
    padding: 0 2;
    width: 100%;
}

#cmd-input:focus { border-top: heavy $accent; }

#cmd-input.cmd { color: $accent; }

#scan-status {
    height: 1;
    padding: 0 2;
    background: $surface-darken-1;
    color: $warning;
    display: none;
}
"""


class AIVASApp(InputActionsMixin, App):
    """AIVAS interactive terminal interface."""

    CSS = _CSS
    TITLE = "AIVAS"
    SUB_TITLE = "AI-Assisted Vulnerability Assessment"

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("ctrl+l", "clear_output", "Clear"),
        Binding("escape", "cancel_or_blur", "Cancel", priority=True),
        Binding("up", "history_prev", "Prev", show=False),
        Binding("down", "history_next", "Next", show=False),
        Binding("tab", "accept_or_cycle", "Accept", priority=True, show=False),
    ]

    def __init__(self, conn: sqlite3.Connection) -> None:
        super().__init__()
        self.conn = conn
        self._scan_task: asyncio.Task | None = None
        self._scan_proc: subprocess.Popen | None = None
        self._last_scan_text: str = ""
        self._cmd_history: list[str] = []
        self._history_idx: int = -1
        self._suggestions: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(id="output", markup=True, highlight=True, wrap=True)
        yield OptionList(id="suggestions")
        yield Label("⟳ Scanning…  (ESC to cancel)", id="scan-status")
        yield Input(
            placeholder="/scan <target>  ·  /quick  ·  /doctor  ·  /help",
            id="cmd-input",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#output", RichLog).write(_BANNER)
        self.query_one("#cmd-input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.clear()
        self._hide_suggestions()
        if not text:
            return
        if not self._cmd_history or self._cmd_history[0] != text:
            self._cmd_history.insert(0, text)
        self._history_idx = -1
        log = self.query_one("#output", RichLog)
        log.write(f"[dim]❯ {text}[/dim]")
        try:
            await self._route(text)
        except Exception as exc:
            self.set_scan_idle()
            self._scan_task = None
            log.write(
                f"[bold red]Unexpected error:[/bold red] {type(exc).__name__}: "
                + escape(str(exc))
                + "\n[dim]This is a bug — please report it. The TUI is still running.[/dim]"
            )

    async def _route(self, text: str) -> None:
        if text.startswith("/"):
            await _cmds.handle(self, text)
        else:
            await _cmds._dispatch_ai(self, text)

    def tui_print(self, content: object) -> None:
        self.query_one("#output", RichLog).write(content)

    def set_scan_running(self, target: str = "") -> None:
        inp = self.query_one("#cmd-input", Input)
        inp.disabled = True
        self._hide_suggestions()
        lbl = self.query_one("#scan-status", Label)
        lbl.update(f"  Scanning {target}…  (ESC to cancel)")
        lbl.display = True

    def set_scan_idle(self) -> None:
        if not self.is_running:
            return
        lbl = self.query_one("#scan-status", Label)
        lbl.display = False
        inp = self.query_one("#cmd-input", Input)
        inp.disabled = False
        inp.focus()

    def store_scan_output(self, content: object) -> None:
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        c = Console(file=buf, force_terminal=False, no_color=True, width=120)
        c.print(content)
        self._last_scan_text += buf.getvalue()

    def action_clear_output(self) -> None:
        self.query_one("#output", RichLog).clear()

    def action_cancel_or_blur(self) -> None:
        if self._scan_task is not None and not self._scan_task.done():
            self._scan_task.cancel()
            if self._scan_proc is not None:
                try:
                    self._scan_proc.kill()
                except OSError:
                    pass
                self._scan_proc = None
            self.set_scan_idle()
            self.tui_print("[dim]Scan cancelled.[/dim]")
        else:
            self.query_one("#cmd-input", Input).blur()
