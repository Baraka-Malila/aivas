"""Tests for the streaming agent loop (chat_stream.py)."""
import asyncio
import json
import sqlite3
from unittest.mock import patch, MagicMock

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


def test_stream_retries_without_tools_on_400(conn):
    """Groq 400/tool error → retry without tools → streams response."""
    from aivas.server.chat_stream import stream_agent_response

    err = Exception("400 Bad Request: tool_use_failed")
    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        client = MockGroq.return_value
        client.chat.completions.create.side_effect = [err, _groq_resp("fallback")]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "hi", conn)
        ))

    types = [e["type"] for e in events]
    assert "error" not in types
    assert types[-1] == "done"


def test_stream_tool_error_yields_friendly_message(conn):
    """Groq non-400 error → friendly error event, not raw traceback."""
    from aivas.server.chat_stream import stream_agent_response

    err = Exception("Connection timeout")
    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = err
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "hi", conn)
        ))

    assert events[0]["type"] == "thinking"
    err_ev = next((e for e in events if e["type"] == "error"), None)
    assert err_ev is not None
    assert "trouble" in err_ev["text"].lower()
    assert "Connection timeout" not in err_ev["text"]


def test_stream_injects_scan_context_when_scans_exist(conn):
    """System message includes recent scan context when scans exist in DB."""
    from aivas.server.chat_stream import stream_agent_response
    from aivas.history import save_scan

    save_scan(conn, "10.0.0.1", [])

    captured_messages = []

    def capture_create(**kwargs):
        captured_messages.extend(kwargs.get("messages", []))
        return _groq_resp("ok")

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = capture_create
        asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "what did we scan?", conn)
        ))

    system_content = next(
        (m["content"] for m in captured_messages if m["role"] == "system"), ""
    )
    assert "Recent scans:" in system_content
    assert "10.0.0.1" in system_content


def test_stream_emits_tool_call_event(conn):
    """tool_call event is emitted before get_last_scan executes."""
    from aivas.server.chat_stream import stream_agent_response

    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "get_last_scan"
    tc.function.arguments = "{}"

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            _groq_resp(tool_calls=[tc]), _groq_resp("")
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "summary", conn)
        ))

    ev = next((e for e in events if e["type"] == "tool_call"), None)
    assert ev is not None
    assert ev["name"] == "get_last_scan"
    assert "args" in ev


def test_stream_emits_tool_result_event(conn):
    """tool_result event has name and summary after get_last_scan executes."""
    from aivas.server.chat_stream import stream_agent_response

    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "get_last_scan"
    tc.function.arguments = "{}"

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            _groq_resp(tool_calls=[tc]), _groq_resp("")
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "summary", conn)
        ))

    ev = next((e for e in events if e["type"] == "tool_result"), None)
    assert ev is not None
    assert ev["name"] == "get_last_scan"
    assert isinstance(ev["summary"], str) and len(ev["summary"]) > 0


def test_scan_host_does_not_emit_tool_call(conn):
    """scan_host emits scan_triggered but not tool_call or tool_result."""
    from aivas.server.chat_stream import stream_agent_response

    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "scan_host"
    tc.function.arguments = json.dumps({"target": "192.168.1.1", "level": "2"})

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            _groq_resp(tool_calls=[tc]), _groq_resp("")
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "scan it", conn)
        ))

    assert not any(e["type"] == "tool_call" for e in events)
    assert not any(e["type"] == "tool_result" for e in events)
    assert any(e["type"] == "scan_triggered" for e in events)


def test_exec_tool_exception_returns_json_error(conn):
    """_exec_tool_local raising → JSON error result, no crash."""
    from aivas.server.chat_stream import stream_agent_response

    tc = MagicMock()
    tc.id = "call_x"
    tc.function.name = "get_history"
    tc.function.arguments = "{}"

    groq_tool_resp = _groq_resp(tool_calls=[tc])
    groq_final_resp = _groq_resp("")

    with patch("aivas.server.chat_stream.Groq") as MockGroq, \
         patch("aivas.server.chat_stream._exec_tool_local",
               side_effect=RuntimeError("db locked")):
        MockGroq.return_value.chat.completions.create.side_effect = [
            groq_tool_resp, groq_final_resp
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "list scans", conn)
        ))

    assert events[-1]["type"] == "done"
