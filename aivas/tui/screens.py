"""Push-screens for AIVAS: first-run setup wizard and post-scan modal."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import RadioButton, RadioSet, Static, Input, Rule


class SetupWizardScreen(Screen):
    """First-run setup: provider, API key, language."""

    BINDINGS = [
        Binding("escape", "dismiss_skip", "Skip", show=False),
        Binding("ctrl+s", "save_config",  "Save", priority=True),
    ]

    CSS = """
    SetupWizardScreen {
        background: #111111;
        padding: 2 4;
    }
    #wizard-title { margin-bottom: 1; }
    #api-key-input { margin-top: 1; width: 50; }
    #hint-bar { dock: bottom; color: #888888; }
    """

    def compose(self) -> ComposeResult:
        yield Rule()
        yield Static("[bold]Welcome to AIVAS — Quick Setup[/bold]\n"
                     "[#888888]Set up once, scan forever.[/#888888]\n",
                     id="wizard-title")
        yield Static("[bold]AI Provider:[/bold]")
        yield RadioSet(
            RadioButton("Groq     (cloud, fast, free tier)", id="groq",    value=True),
            RadioButton("Mistral  (cloud, reliable)",        id="mistral"),
            RadioButton("Ollama   (local, private)",         id="ollama"),
            id="provider-set",
        )
        yield Static("\n[bold]API Key[/bold] [#888888](Groq or Mistral — leave blank for Ollama):[/#888888]")
        yield Input(placeholder="gsk_… or Mistral key", password=True,
                    id="api-key-input")
        yield Static("\n[bold]Shodan API Key[/bold] [#888888](optional — for internet exposure checks):[/#888888]")
        yield Input(placeholder="leave blank to skip", password=True,
                    id="shodan-key-input")
        yield Static("\n[bold]Output Language:[/bold]")
        yield RadioSet(
            RadioButton("English",           id="en", value=True),
            RadioButton("Swahili",           id="sw"),
            RadioButton("Both (EN + SW)",    id="both"),
            id="lang-set",
        )
        yield Rule()
        yield Static("[#888888]Tab next field  ·  Ctrl+S save  ·  Esc skip[/#888888]",
                     id="hint-bar")

    def action_save_config(self) -> None:
        from aivas import config as _config
        provider_rs = self.query_one("#provider-set", RadioSet)
        lang_rs = self.query_one("#lang-set", RadioSet)
        provider = provider_rs.pressed_button.id if provider_rs.pressed_button else "groq"
        lang = lang_rs.pressed_button.id if lang_rs.pressed_button else "en"
        api_key = self.query_one("#api-key-input", Input).value.strip()
        shodan_key = self.query_one("#shodan-key-input", Input).value.strip()
        if provider == "mistral":
            if api_key:
                _config.save("mistral_api_key", api_key)
        else:
            if api_key:
                _config.save("api_key", api_key)
        if shodan_key:
            _config.save("shodan_key", shodan_key)
        _config.save("provider", provider)
        _config.save("lang", lang)
        self.dismiss({"provider": provider, "lang": lang, "has_key": bool(api_key)})

    def action_dismiss_skip(self) -> None:
        self.dismiss(None)

    def on_screen_resume(self) -> None:
        self.query_one("#provider-set", RadioSet).focus()


class ScanResultScreen(ModalScreen):
    """Post-scan overlay: choose AI narration, full report, or skip."""

    BINDINGS = [
        Binding("escape", "dismiss_skip", "Skip",    show=False),
        Binding("enter",  "confirm",      "Confirm", priority=True),
    ]

    CSS = """
    ScanResultScreen {
        align: center bottom;
        background: #0a0a0a 60%;
    }
    #scan-panel {
        background: #141414;
        border: solid #3a3a3a;
        padding: 1 2;
        width: 70%;
        margin-bottom: 4;
        height: auto;
    }
    """

    def __init__(self, target: str, grade: str, count: int) -> None:
        super().__init__()
        self._target = target
        self._grade = grade
        self._count = count

    def compose(self) -> ComposeResult:
        grade_col = "red" if self._grade in ("D", "F") else "green"
        with Vertical(id="scan-panel"):
            yield Static(
                f"[bold]Scan complete:[/bold] {self._target}"
                f"  Grade [{grade_col}]{self._grade}[/{grade_col}]"
                f"  [#888888]{self._count} finding(s)[/#888888]"
            )
            yield RadioSet(
                RadioButton("AI narration  (Swahili + English)", id="narrate"),
                RadioButton("Full CVE report",                   id="report"),
                RadioButton("Skip",                              id="skip", value=True),
                id="choice-set",
            )
            yield Static("[#888888]Tab to select  ·  Enter confirm  ·  Esc skip[/#888888]")

    def action_confirm(self) -> None:
        rs = self.query_one("#choice-set", RadioSet)
        btn = rs.pressed_button
        self.dismiss(btn.id if btn else "skip")

    def action_dismiss_skip(self) -> None:
        self.dismiss(None)
