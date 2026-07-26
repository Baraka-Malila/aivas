"""Tests for the streaming agent loop (chat_stream.py)."""
import asyncio
import json
import sqlite3
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from aivas.database.schema import create_schema


async def _collect(gen):
    return [ev async for ev in gen]


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    return db


class MockProvider:
    name = "mock"

    def generate(self, prompt, max_tokens=300):
        return "ok"

    async def stream(self, messages, max_tokens=1024):
        for word in ["Hello", " World"]:
            yield word


def _groq_resp(content="", tool_calls=None):
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls or []
    resp = MagicMock()
    resp.choices[0].message = msg
    return resp


def test_stream_simple_response(conn):
    """No tool calls — streams tokens directly from provider."""
    from aivas.server.chat_stream import stream_agent_response

    # Groq returns no tool calls → provider.stream() runs
    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = _groq_resp("Hi")
        events = asyncio.run(_collect(
            stream_agent_response(
                MockProvider(), [], "Hello", conn
            )
        ))

    types = [e["type"] for e in events]
    assert "thinking" in types
    assert "token" in types
    assert types[-1] == "done"

    tokens = [e["text"] for e in events if e["type"] == "token"]
    assert "".join(tokens) == "Hello World"


def test_stream_scan_triggered(conn):
    """AI calls scan_host → scan_triggered event emitted."""
    from aivas.server.chat_stream import stream_agent_response

    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "scan_host"
    tc.function.arguments = json.dumps({"target": "192.168.1.1", "level": "2"})

    # First call: tool call. Second call: final response (no tools).
    groq_tool_resp = _groq_resp(tool_calls=[tc])
    groq_final_resp = _groq_resp("")

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            groq_tool_resp, groq_final_resp
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "scan 192.168.1.1", conn)
        ))

    scan_ev = next((e for e in events if e["type"] == "scan_triggered"), None)
    assert scan_ev is not None
    assert scan_ev["target"] == "192.168.1.1"
    assert scan_ev["level"] == 2
    done = events[-1]
    assert done["type"] == "done"
    assert "turns" in done


def test_stream_error_on_missing_groq_key(conn, monkeypatch):
    """No GROQ_API_KEY and no config key → error event."""
    from aivas.server.chat_stream import stream_agent_response
    monkeypatch.setenv("GROQ_API_KEY", "")

    with patch("aivas.server.chat_stream._load_groq_key", return_value=None):
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "Hi", conn)
        ))
    assert events[0]["type"] == "error"
