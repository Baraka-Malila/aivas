from __future__ import annotations

from textual.suggester import Suggester

from . import commands as _cmds


class CommandSuggester(Suggester):
    """Inline tab-completion for AIVAS slash commands."""

    async def get_suggestion(self, value: str) -> str | None:
        if not value.startswith("/"):
            return None
        typed = value[1:].lower()
        for cmd in _cmds.REGISTRY:
            if cmd.startswith(typed) and cmd != typed:
                return f"/{cmd} "
        return None
