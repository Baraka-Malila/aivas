from __future__ import annotations

import sqlite3

from rich.console import Console
from rich.table import Table
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Input, RichLog

from . import commands as _cmds

_BANNER = (
    "[bold cyan]   █████╗ ██╗██╗   ██╗ █████╗ ███████╗[/bold cyan]\n"
    "[bold cyan]  ██╔══██╗██║██║   ██║██╔══██╗██╔════╝[/bold cyan]\n"
    "[bold cyan]  ███████║██║██║   ██║███████║███████╗[/bold cyan]\n"
    "[bold cyan]  ██╔══██║██║╚██╗ ██╔╝██╔══██║╚════██║[/bold cyan]\n"
    "[bold cyan]  ██║  ██║██║ ╚████╔╝ ██║  ██║███████║[/bold cyan]\n"
    "[bold cyan]  ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝[/bold cyan]\n"
    "[dim]  AI-Assisted Vulnerability Assessment System[/dim]\n"
    "[dim]  Type [bold]/help[/bold] for commands "
    "· free text routes to AI if API key is set[/dim]"
)

_CSS = """
Screen {
    layout: vertical;
    background: $surface;
}

#output {
    height: 1fr;
    border: heavy $accent;
    padding: 1 2;
    scrollbar-gutter: stable;
}

#input-bar {
    height: auto;
    border-top: heavy $accent;
    padding: 0 1;
    background: $surface-darken-1;
}

#cmd-input {
    background: $surface-darken-1;
    border: none;
    padding: 0 1;
    width: 100%;
}

#cmd-input:focus {
    border: none;
}
"""


class AIVASApp(App):
    """AIVAS interactive terminal interface."""

    CSS = _CSS
    TITLE = "AIVAS"
    SUB_TITLE = "AI-Assisted Vulnerability Assessment"

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("ctrl+l", "clear_output", "Clear"),
        Binding("escape", "blur_input", "Blur"),
    ]

    def __init__(self, conn: sqlite3.Connection) -> None:
        super().__init__()
        self.conn = conn

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(id="output", markup=True, highlight=True, wrap=True)
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
        if not text:
            return
        log = self.query_one("#output", RichLog)
        log.write(f"[dim]❯ {text}[/dim]")
        await self._route(text)

    async def _route(self, text: str) -> None:
        if text.startswith("/"):
            await _cmds.handle(self, text)
        else:
            await _cmds._dispatch_ai(self, text)

    def tui_print(self, content: object) -> None:
        """Write Rich-formatted text or a Rich renderable to the output pane."""
        self.query_one("#output", RichLog).write(content)

    def action_clear_output(self) -> None:
        self.query_one("#output", RichLog).clear()

    def action_blur_input(self) -> None:
        self.query_one("#cmd-input", Input).blur()
