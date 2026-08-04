"""Step-line progress reporting for the scan pipeline."""
from __future__ import annotations
import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import AIVASApp


class StepProgress:
    """Prints step start + done lines to the TUI output pane."""

    def __init__(self, app: "AIVASApp") -> None:
        self._app = app

    async def step(self, name: str) -> None:
        """Print a 'starting' line, then yield so Textual renders it."""
        self._app.tui_print(f"  [#555555]·[/#555555] [#888888]{name}…[/#888888]")
        await asyncio.sleep(0.05)

    async def done(self, name: str, detail: str = "") -> None:
        """Print a 'completed' line, then yield so Textual renders it."""
        detail_str = f"  [#888888]{detail}[/#888888]" if detail else ""
        self._app.tui_print(f"  [#4caf50]✓[/#4caf50] {name}{detail_str}")
        await asyncio.sleep(0.05)

    def fail(self, name: str, reason: str) -> None:
        self._app.tui_print(
            f"  [#e53935]✗[/#e53935] {name}  [#888888]{reason}[/#888888]"
        )
