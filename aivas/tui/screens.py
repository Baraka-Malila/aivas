"""Push-screens for AIVAS: first-run setup wizard."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import RadioButton, RadioSet, Static, Input, Rule


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
