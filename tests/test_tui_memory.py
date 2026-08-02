"""Tests for TUI conversation memory (ai.py dispatch)."""
import asyncio
from unittest.mock import AsyncMock, patch


class _MockApp:
    """Minimal stand-in for AIVASApp, enough for dispatch()."""

    def __init__(self, conn):
        self.conn = conn
        self._scan_history = []
        self._chat_history = []

    def tui_print(self, text):
        pass

    def run_worker(self, coro, *, exclusive=False):
        pass

    def set_busy(self, msg):
        pass

    def set_scan_idle(self):
        pass


def test_dispatch_accumulates_history(db):
    """Second call receives first call's turns as history."""
    from aivas.tui.ai import dispatch

    app = _MockApp(db)
    turns_a = [{"role": "assistant", "content": "Hello there."}]

    with patch("aivas.tui.agent.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("Hello there.", None, turns_a)
        asyncio.run(dispatch(app, "hi", "fake_key"))

    assert app._chat_history == turns_a

    turns_b = [{"role": "assistant", "content": "Sure."}]
    with patch("aivas.tui.agent.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("Sure.", None, turns_b)
        asyncio.run(dispatch(app, "tell me more", "fake_key"))
        passed_history = mock_agent.call_args.kwargs.get("history")

    assert passed_history == turns_a


def test_dispatch_caps_history_at_12(db):
    """History is capped at 12 entries after accumulation."""
    from aivas.tui.ai import dispatch

    app = _MockApp(db)
    app._chat_history = [{"role": "assistant", "content": f"old {i}"} for i in range(12)]

    new_turns = [{"role": "assistant", "content": "newest"}]
    with patch("aivas.tui.agent.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("newest", None, new_turns)
        asyncio.run(dispatch(app, "hello", "fake_key"))

    assert len(app._chat_history) == 12
    assert app._chat_history[-1]["content"] == "newest"


def test_dispatch_starts_empty_on_fresh_app(db):
    """A brand-new app has no history and run_agent is called with empty list."""
    from aivas.tui.ai import dispatch

    app = _MockApp(db)
    del app._chat_history  # simulate attribute not set yet

    with patch("aivas.tui.agent.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("Hi", None, [])
        asyncio.run(dispatch(app, "hello", "fake_key"))
        passed_history = mock_agent.call_args.kwargs.get("history")

    assert passed_history == []
