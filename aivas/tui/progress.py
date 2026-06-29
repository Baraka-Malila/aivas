"""Step-line progress reporting for the scan pipeline."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import AIVASApp


class StepProgress:
    """Prints step start + done lines to the TUI output pane."""

    def __init__(self, app: "AIVASApp") -> None:
        self._app = app

    def step(self, name: str) -> None:
        """Print a 'starting' line for this stage."""
        self._app.tui_print(f"  [·] [dim]{name}...[/dim]")

    def done(self, name: str, detail: str = "") -> None:
        """Print a 'completed' line with optional detail."""
        detail_str = f"  [dim]{detail}[/dim]" if detail else ""
        self._app.tui_print(f"  [#4caf50]✓[/#4caf50] {name}{detail_str}")

    def fail(self, name: str, reason: str) -> None:
        """Print a 'failed' line."""
        self._app.tui_print(
            f"  [#e53935]✗[/#e53935] {name}  [dim]{reason}[/dim]"
        )
