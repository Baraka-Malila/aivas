"""Push-screens for AIVAS: post-scan result choice and first-run setup wizard."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import RadioButton, RadioSet, Static, Input, Rule

from .colors import GRADE_COLOR


class ScanResultScreen(Screen):
    """Post-scan choice: view full report / AI narration / skip."""

    BINDINGS = [
        Binding("escape", "dismiss_skip", "Skip", show=False),
        Binding("enter",  "confirm",      "Confirm", priority=True),
    ]

    CSS = """
    ScanResultScreen {
        align: center middle;
        background: $surface;
        padding: 2 4;
    }
    #scan-summary { margin-bottom: 1; }
    #scan-choices { margin-top: 1; }
    #hint-bar { dock: bottom; color: $text-muted; }
    """

    def __init__(self, target: str, score: dict,
                 findings: list[dict], misconfigs: list[dict]) -> None:
        super().__init__()
        self._target = target
        self._score = score
        self._findings = findings
        self._misconfigs = misconfigs

    def compose(self) -> ComposeResult:
        g = self._score.get("grade", "?")
        s = self._score.get("score", 0)
        total = self._score.get("total", 0)
        gc = GRADE_COLOR(g)
        yield Rule()
        yield Static(
            f"[bold]Scan complete[/bold]  ·  {self._target}\n"
            f"Grade [{gc}]{g}[/{gc}]  ·  {s}/100  ·  [dim]{total} findings[/dim]",
            id="scan-summary",
        )
        yield Rule()
        yield Static("\nWhat would you like to do?\n")
        yield RadioSet(
            RadioButton("View full CVE report", id="report", value=True),
            RadioButton("AI narration  (top 5, English + Swahili)", id="narrate"),
            RadioButton("Save and continue", id="skip"),
            id="scan-choices",
        )
        yield Static(
            "\n[dim]↑↓ navigate  ·  Enter confirm  ·  Esc skip[/dim]",
            id="hint-bar",
        )

    def action_confirm(self) -> None:
        rs = self.query_one(RadioSet)
        choice = rs.pressed_button.id if rs.pressed_button else "skip"
        self.dismiss(choice)

    def action_dismiss_skip(self) -> None:
        self.dismiss("skip")

    def on_screen_resume(self) -> None:
        self.query_one(RadioSet).focus()


class SetupWizardScreen(Screen):
    """First-run setup: provider, API key, language."""

    BINDINGS = [
        Binding("escape", "dismiss_skip", "Skip", show=False),
        Binding("ctrl+s", "save_config",  "Save", priority=True),
    ]

    CSS = """
    SetupWizardScreen {
        background: $surface;
        padding: 2 4;
    }
    #wizard-title { margin-bottom: 1; }
    #api-key-input { margin-top: 1; width: 50; }
    #hint-bar { dock: bottom; color: $text-muted; }
    """

    def compose(self) -> ComposeResult:
        yield Rule()
        yield Static("[bold]Welcome to AIVAS — Quick Setup[/bold]\n"
                     "[dim]Set up once, scan forever.[/dim]\n",
                     id="wizard-title")
        yield Static("[bold]AI Provider:[/bold]")
        yield RadioSet(
            RadioButton("Groq  (cloud, fast, free tier)", id="groq", value=True),
            RadioButton("Ollama  (local, private)",       id="ollama"),
            id="provider-set",
        )
        yield Static("\n[bold]API Key:[/bold]")
        yield Input(placeholder="sk-... or groq API key", password=True,
                    id="api-key-input")
        yield Static("\n[bold]Output Language:[/bold]")
        yield RadioSet(
            RadioButton("English",           id="en", value=True),
            RadioButton("Swahili",           id="sw"),
            RadioButton("Both (EN + SW)",    id="both"),
            id="lang-set",
        )
        yield Rule()
        yield Static("[dim]Tab next field  ·  Ctrl+S save  ·  Esc skip[/dim]",
                     id="hint-bar")

    def action_save_config(self) -> None:
        from aivas import config as _config
        provider_rs = self.query_one("#provider-set", RadioSet)
        lang_rs = self.query_one("#lang-set", RadioSet)
        api_key = self.query_one("#api-key-input", Input).value.strip()
        provider = provider_rs.pressed_button.id if provider_rs.pressed_button else "groq"
        lang = lang_rs.pressed_button.id if lang_rs.pressed_button else "en"
        if api_key:
            _config.save("api_key", api_key)
        _config.save("provider", provider)
        _config.save("lang", lang)
        self.dismiss({"provider": provider, "lang": lang, "has_key": bool(api_key)})

    def action_dismiss_skip(self) -> None:
        self.dismiss(None)

    def on_screen_resume(self) -> None:
        self.query_one("#provider-set", RadioSet).focus()
