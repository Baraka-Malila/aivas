"""Input history and suggestion-dropdown logic for AIVASApp (mixin)."""
from __future__ import annotations

from textual.widgets import Input, OptionList

from . import commands as _cmds


class InputActionsMixin:
    """Adds command history (↑↓) and vertical suggestion dropdown to AIVASApp."""

    def on_input_changed(self, event: Input.Changed) -> None:
        text = event.value
        self.query_one("#cmd-input", Input).set_class(text.startswith("/"), "cmd")
        self._refresh_suggestions(text)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        idx = event.option_index
        if idx < len(self._suggestions):
            inp = self.query_one("#cmd-input", Input)
            inp.value = self._suggestions[idx] + " "
            inp.cursor_position = len(inp.value)
            inp.focus()
        self._hide_suggestions()

    def _refresh_suggestions(self, text: str) -> None:
        from rich.text import Text
        from aivas.tui.colors import ACCENT

        if not text.startswith("/") or (len(text) > 1 and " " in text[1:]):
            self._hide_suggestions()
            return

        typed = text[1:].lower()
        matches = [
            (name, usage, desc)
            for name, (usage, desc) in _cmds.REGISTRY.items()
            if not typed or (name.startswith(typed) and name != typed)
        ]

        ol = self.query_one("#suggestions", OptionList)
        ol.clear_options()
        self._suggestions = []

        if matches:
            from textual.widgets.option_list import Option
            for name, usage, desc in matches:
                prompt = Text()
                prompt.append(f"/{name:<12}", style=f"bold {ACCENT}")
                prompt.append(f"  {desc}", style="dim")
                ol.add_option(Option(prompt, id=name))
                self._suggestions.append(f"/{name}")
            ol.display = True
        else:
            ol.display = False

    def _accept_suggestion(self) -> bool:
        ol = self.query_one("#suggestions", OptionList)
        if not ol.display or not ol.option_count:
            return False
        idx = ol.highlighted if ol.highlighted is not None else 0
        if idx < len(self._suggestions):
            inp = self.query_one("#cmd-input", Input)
            inp.value = self._suggestions[idx] + " "
            inp.cursor_position = len(inp.value)
        self._hide_suggestions()
        self.query_one("#cmd-input", Input).focus()
        return True

    def _hide_suggestions(self) -> None:
        try:
            self.query_one("#suggestions", OptionList).display = False
        except Exception:
            pass

    def action_history_prev(self) -> None:
        inp = self.query_one("#cmd-input", Input)
        if not inp.has_focus or not self._cmd_history:
            return
        self._history_idx = min(self._history_idx + 1, len(self._cmd_history) - 1)
        inp.value = self._cmd_history[self._history_idx]
        inp.cursor_position = len(inp.value)

    def action_history_next(self) -> None:
        ol = self.query_one("#suggestions", OptionList)
        inp = self.query_one("#cmd-input", Input)
        # If suggestions visible and Down pressed, focus the list instead
        if ol.display and ol.option_count and inp.has_focus:
            ol.focus()
            return
        if not inp.has_focus:
            return
        if self._history_idx > 0:
            self._history_idx -= 1
            inp.value = self._cmd_history[self._history_idx]
            inp.cursor_position = len(inp.value)
        elif self._history_idx == 0:
            self._history_idx = -1
            inp.value = ""

    def action_accept_or_cycle(self) -> None:
        inp = self.query_one("#cmd-input", Input)
        if inp.has_focus and self._accept_suggestion():
            return
