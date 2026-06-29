from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess

from io import StringIO

from rich.console import Console
from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Footer, Header, Input, Label, OptionList, RichLog, Rule

from . import commands as _cmds
from .input_actions import InputActionsMixin
from .kev_sync import _kev_needs_sync, run_kev_background

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

_CSS = """Screen { layout: vertical; background: $surface; }
#output { height: 1fr; border: none; padding: 1 2; scrollbar-gutter: stable; }
#suggestions { max-height: 12; background: $surface-darken-1; display: none; border: none; padding: 0; }
OptionList > .option-list--option-highlighted { background: $surface-darken-3; color: #4a9eff; }
#rule-top, #rule-bottom { color: $panel; margin: 0; height: 1; }
#input-row { height: 1; background: $surface; padding: 0; }
#prompt-label { width: 3; padding: 0 0 0 1; color: #4a9eff; text-style: bold; }
#cmd-input { background: $surface; border: none; padding: 0; width: 1fr; color: $text; }
#cmd-input:focus { border: none; }
#cmd-input.cmd { color: #4a9eff; }
#scan-status { height: 1; padding: 0 2; color: #fdd835; display: none; }
"""


class AIVASApp(InputActionsMixin, App):
    """AIVAS interactive terminal interface."""

    CSS = _CSS
    TITLE = "AIVAS"
    SUB_TITLE = "AI-Assisted Vulnerability Assessment"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
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
        self._last_findings: list[dict] = []
        self._last_misconfigs: list[dict] = []
        self._last_target: str = ""
        self._scan_history: list[dict] = []
        self._spinner_timer = None
        self._current_scan_target: str = ""
        self._spinner_idx: int = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield RichLog(id="output", markup=True, highlight=True, wrap=True)
        yield OptionList(id="suggestions")
        yield Rule(id="rule-top")
        yield Horizontal(
            Label("> ", id="prompt-label"),
            Input(
                placeholder="type a command or ask me to scan something",
                id="cmd-input",
            ),
            id="input-row",
        )
        yield Rule(id="rule-bottom")
        yield Label("", id="scan-status")
        yield Footer()

    async def on_mount(self) -> None:
        self.query_one("#output", RichLog).write(_BANNER)
        self.query_one("#cmd-input", Input).focus()
        if _kev_needs_sync(self.conn):
            self.run_worker(run_kev_background(self.conn, self.tui_print), exclusive=False)
        from aivas import config as _config
        cfg = _config.load()
        if not cfg.get("api_key"):
            from .screens import SetupWizardScreen
            result = await self.push_screen_wait(SetupWizardScreen())
            if result:
                self.tui_print(f"[dim]Setup saved. Provider: {result['provider']}.[/dim]")

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
        except Exception as exc:  # last-resort: keeps TUI alive if any command raises
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
            from .ai import dispatch
            from aivas import config as _cfg
            cfg = _cfg.load()
            api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
            await dispatch(self, text, api_key=api_key)

    def tui_print(self, content: object) -> None:
        self.query_one("#output", RichLog).write(content)

    _SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def set_scan_running(self, target: str = "") -> None:
        self._current_scan_target = target
        self._spinner_idx = 0
        inp = self.query_one("#cmd-input", Input)
        inp.disabled = True
        self._hide_suggestions()
        lbl = self.query_one("#scan-status", Label)
        lbl.update(f"  ⠋ Scanning {target}…  (ESC to cancel)")
        lbl.display = True
        self._spinner_timer = self.set_interval(0.1, self._tick_spinner)

    def _tick_spinner(self) -> None:
        self._spinner_idx = (self._spinner_idx + 1) % len(self._SPIN)
        lbl = self.query_one("#scan-status", Label)
        lbl.update(f"  {self._SPIN[self._spinner_idx]} Scanning {self._current_scan_target}…  (ESC to cancel)")

    def set_scan_idle(self) -> None:
        if not self.is_running:
            return
        if self._spinner_timer is not None:
            self._spinner_timer.stop()
            self._spinner_timer = None
        lbl = self.query_one("#scan-status", Label)
        lbl.display = False
        inp = self.query_one("#cmd-input", Input)
        inp.disabled = False
        inp.focus()

    def store_scan_output(self, content: object) -> None:
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
