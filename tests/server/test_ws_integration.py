"""Full-pipeline WebSocket integration tests for the AIVAS FastAPI server.

These tests use a real FastAPI app, real WebSocket client (via starlette
TestClient), and patched Groq — no function-in-isolation mocking.
"""
from __future__ import annotations

import json
import sqlite3
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from starlette.testclient import TestClient

import aivas.server.main as main_mod
from aivas.server.main import app
from aivas.database.schema import create_schema


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_groq_resp(content=None, tool_calls=None):
    """Build a minimal Groq chat-completion response mock."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls or []
    resp = MagicMock()
    resp.choices = [MagicMock(message=msg)]
    return resp


def make_tool_call(tc_id: str, name: str, arguments: dict):
    """Build a mock tool_call object as Groq would return."""
    tc = MagicMock()
    tc.id = tc_id
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


async def fake_stream_words(messages, max_tokens=1024):
    """Async generator that yields space-separated tokens."""
    for word in ["Hello,", " I", " am", " AIVAS."]:
        yield word


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Fresh in-memory DB wired into the FastAPI app for each test."""
    db = sqlite3.connect(str(tmp_path / "ws_int.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    monkeypatch.setattr(main_mod, "_conn", db)
    monkeypatch.setattr(main_mod, "_pending", {})
    # Use TestClient as a context manager so lifespan runs cleanly,
    # then re-apply the monkeypatched DB in case lifespan overwrote it.
    with TestClient(app, raise_server_exceptions=True) as c:
        monkeypatch.setattr(main_mod, "_conn", db)
        monkeypatch.setattr(main_mod, "_pending", {})
        yield c, db


def _new_session(client) -> str:
    """Create a chat session and return its id."""
    resp = client.post("/api/sessions")
    assert resp.status_code == 200
    return resp.json()["id"]


def _collect_ws_events(ws, stop_types=("done", "error")):
    """Receive JSON messages until a terminal type arrives."""
    events = []
    while True:
        msg = ws.receive_json()
        events.append(msg)
        if msg["type"] in stop_types:
            break
    return events


# ---------------------------------------------------------------------------
# Test 1: basic event sequence — thinking → token(s) → done
# ---------------------------------------------------------------------------

def test_chat_ws_event_sequence(client):
    """Send 'hello', assert events arrive in order: thinking, token(s), done."""
    tc, _db = client
    sid = _new_session(tc)

    groq_no_tools = make_groq_resp(content="Hello, I am AIVAS.")

    with patch("aivas.server.chat_stream.Groq") as MockGroq, \
         patch("aivas.narrator.providers.groq.AsyncGroq") as MockAsyncGroq:

        MockGroq.return_value.chat.completions.create.return_value = groq_no_tools

        # Wire the async streaming provider
        async def _stream(messages, max_tokens=1024):
            for word in ["Hello,", " I", " am", " AIVAS."]:
                yield word

        mock_async_client = MagicMock()
        MockAsyncGroq.return_value = mock_async_client
        # stream() is called on the GroqProvider instance directly
        # Patch at the provider level so we don't need to wire AsyncGroq
        with patch("aivas.narrator.providers.groq.GroqProvider.stream", side_effect=_stream):
            with tc.websocket_connect(f"/ws/chat/{sid}?provider=groq") as ws:
                ws.send_json({"type": "auth", "api_key": "test-key"})
                ws.send_json({"type": "user", "text": "hello"})
                events = _collect_ws_events(ws)

    types = [e["type"] for e in events]
    assert types[0] == "thinking", f"First event must be 'thinking', got {types}"
    assert "token" in types, "Expected at least one 'token' event"
    assert types[-1] == "done", f"Last event must be 'done', got {types}"

    token_texts = [e["text"] for e in events if e["type"] == "token"]
    full = "".join(token_texts)
    assert full == "Hello, I am AIVAS.", f"Concatenated tokens wrong: {full!r}"

    done_ev = events[-1]
    assert "text" in done_ev, "done event must have 'text' field"


# ---------------------------------------------------------------------------
# Test 2: auth message sets API key (no error about missing key)
# ---------------------------------------------------------------------------

def test_chat_ws_auth_sets_api_key(client):
    """Auth message is accepted; subsequent user message does not get an API key error."""
    tc, _db = client
    sid = _new_session(tc)

    groq_no_tools = make_groq_resp(content="Hi there.")

    async def _stream(messages, max_tokens=1024):
        yield "Hi there."

    with patch("aivas.server.chat_stream.Groq") as MockGroq, \
         patch("aivas.narrator.providers.groq.GroqProvider.stream", side_effect=_stream):

        MockGroq.return_value.chat.completions.create.return_value = groq_no_tools

        with tc.websocket_connect(f"/ws/chat/{sid}?provider=groq") as ws:
            ws.send_json({"type": "auth", "api_key": "my-real-key"})
            ws.send_json({"type": "user", "text": "ping"})
            events = _collect_ws_events(ws)

    error_events = [e for e in events if e["type"] == "error"]
    api_key_errors = [
        e for e in error_events
        if "api_key" in e.get("text", "").lower()
        or "groq" in e.get("text", "").lower()
    ]
    assert not api_key_errors, f"Unexpected API key error: {api_key_errors}"
    types = [e["type"] for e in events]
    assert "done" in types, f"Expected done event, got types: {types}"


# ---------------------------------------------------------------------------
# Test 3: scan_triggered — tool call → scan_triggered event + _pending entry
# ---------------------------------------------------------------------------

def test_chat_ws_scan_triggered(client):
    """Groq call returns scan_host tool call.

    Assert: thinking → scan_triggered (with target + scan_key) → done.
    No token events: agent exits immediately after triggering the scan so
    the Groq loop does not continue making extra calls.
    Also assert scan_key is registered in main_mod._pending.
    """
    tc, _db = client
    sid = _new_session(tc)

    scan_tc = make_tool_call("call_abc", "scan_host", {"target": "10.0.0.1", "level": "2"})
    first_resp = make_groq_resp(tool_calls=[scan_tc])

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [first_resp]

        with tc.websocket_connect(f"/ws/chat/{sid}?provider=groq") as ws:
            ws.send_json({"type": "auth", "api_key": "test-key"})
            ws.send_json({"type": "user", "text": "scan 10.0.0.1"})
            events = _collect_ws_events(ws)

    types = [e["type"] for e in events]
    assert "thinking" in types, f"Missing thinking event, got: {types}"
    assert "scan_triggered" in types, f"Missing scan_triggered event, got: {types}"
    assert "token" not in types, f"No tokens expected after scan_triggered, got: {types}"
    assert types[-1] == "done", f"Last event must be done, got: {types}"

    scan_ev = next(e for e in events if e["type"] == "scan_triggered")
    assert scan_ev["target"] == "10.0.0.1", f"Wrong target: {scan_ev}"
    assert "scan_key" in scan_ev, "scan_triggered event must include scan_key"

    scan_key = scan_ev["scan_key"]
    assert scan_key in main_mod._pending, (
        f"scan_key {scan_key!r} not found in _pending: {list(main_mod._pending.keys())}"
    )


# ---------------------------------------------------------------------------
# Test 4: unknown session_id → error event immediately
# ---------------------------------------------------------------------------

def test_chat_ws_unknown_session(client):
    """Connecting with a nonexistent session_id sends an error event."""
    tc, _db = client

    with tc.websocket_connect("/ws/chat/bad-session-id-that-does-not-exist") as ws:
        msg = ws.receive_json()

    assert msg["type"] == "error", f"Expected error event, got: {msg}"


# ---------------------------------------------------------------------------
# Test 5: scan WebSocket pipeline — events arrive in order, done is last
# ---------------------------------------------------------------------------

def test_scan_ws_pipeline(client):
    """Register a scan key manually, connect to /ws/scan/{key}, mock run_scan.

    Assert all events arrive and done is last.
    """
    tc, _db = client
    scan_key = "test-scan-key-12345"
    main_mod._pending[scan_key] = ("10.0.0.5", 2)

    async def fake_run_scan(conn, target, level, creds=None, _partial_out=None):
        yield {"type": "init", "text": "Initializing scan"}
        yield {"type": "ports", "text": "Scanning ports"}
        yield {"type": "scoring", "text": "Scoring findings"}
        yield {
            "type": "done",
            "target": target,
            "scan_id": 1,
            "score": 0,
            "grade": "A",
            "service_count": 0,
            "log": [],
            "services": [],
            "findings": [],
            "misconfigs": [],
            "credential_scan": False,
        }

    # run_scan is lazily imported inside the WS handler; patch at the source module.
    with patch("aivas.server.scan_worker.run_scan", side_effect=fake_run_scan):
        with tc.websocket_connect(f"/ws/scan/{scan_key}") as ws:
            events = _collect_ws_events(ws)

    assert len(events) >= 2, f"Expected at least 2 events, got {len(events)}"
    types = [e["type"] for e in events]
    assert types[-1] == "done", f"Last event must be done, got: {types}"
    assert "init" in types
    assert "ports" in types


# ---------------------------------------------------------------------------
# Test 6: thinking emitted exactly once — not once per tool-loop iteration
# ---------------------------------------------------------------------------

def test_chat_ws_thinking_emitted_once(client):
    """thinking is emitted exactly once even when a tool call precedes the response.

    This is the bug we fixed: the original code might emit thinking inside
    the loop instead of before it, causing multiple thinking events.
    """
    tc, _db = client
    sid = _new_session(tc)

    scan_tc = make_tool_call("call_xyz", "scan_host", {"target": "192.168.1.1", "level": "2"})
    first_resp = make_groq_resp(tool_calls=[scan_tc])
    second_resp = make_groq_resp(content="Done.")

    async def _stream(messages, max_tokens=1024):
        yield "Done."

    with patch("aivas.server.chat_stream.Groq") as MockGroq, \
         patch("aivas.narrator.providers.groq.GroqProvider.stream", side_effect=_stream):

        MockGroq.return_value.chat.completions.create.side_effect = [
            first_resp, second_resp
        ]

        with tc.websocket_connect(f"/ws/chat/{sid}?provider=groq") as ws:
            ws.send_json({"type": "auth", "api_key": "test-key"})
            ws.send_json({"type": "user", "text": "scan 192.168.1.1"})
            events = _collect_ws_events(ws)

    thinking_count = sum(1 for e in events if e["type"] == "thinking")
    assert thinking_count == 1, (
        f"Expected exactly 1 'thinking' event, got {thinking_count}. "
        f"Full event types: {[e['type'] for e in events]}"
    )
