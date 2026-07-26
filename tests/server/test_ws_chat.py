import sqlite3
import asyncio
from unittest.mock import patch, AsyncMock

import pytest
from fastapi.testclient import TestClient

import aivas.server.main as main_mod
from aivas.server.main import app
from aivas.database.schema import create_schema


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    monkeypatch.setattr(main_mod, "_conn", db)
    return TestClient(app)


def test_ws_chat_unknown_session_closes_with_error(client):
    with client.websocket_connect("/ws/chat/no-such-id") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"


def test_ws_chat_streams_tokens(client):
    """User sends a message → receives thinking, token(s), done."""
    sid = client.post("/api/sessions").json()["id"]

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        yield {"type": "thinking"}
        yield {"type": "token", "text": "Hello"}
        yield {"type": "token", "text": " back"}
        yield {"type": "done", "full_text": "Hello back", "turns": [
            {"role": "assistant", "content": "Hello back"}
        ]}

    with patch("aivas.server.ws_chat.stream_agent_response", side_effect=fake_stream):
        with client.websocket_connect(f"/ws/chat/{sid}") as ws:
            ws.send_json({"type": "user", "text": "hi"})
            msgs = [ws.receive_json() for _ in range(4)]

    types = [m["type"] for m in msgs]
    assert "thinking" in types
    assert "token" in types
    assert "done" in types
    tokens = [m["text"] for m in msgs if m["type"] == "token"]
    assert "".join(tokens) == "Hello back"


def test_ws_chat_scan_triggered_registers_key(client):
    """scan_triggered event gets a scan_key registered in _pending."""
    sid = client.post("/api/sessions").json()["id"]

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        yield {"type": "thinking"}
        yield {"type": "scan_triggered", "target": "10.0.0.1", "level": 2}
        yield {"type": "done", "full_text": "Scan started.", "turns": [
            {"role": "assistant", "content": "Scan started."}
        ]}

    with patch("aivas.server.ws_chat.stream_agent_response", side_effect=fake_stream):
        with client.websocket_connect(f"/ws/chat/{sid}") as ws:
            ws.send_json({"type": "user", "text": "scan 10.0.0.1"})
            msgs = [ws.receive_json() for _ in range(3)]

    scan_ev = next(m for m in msgs if m["type"] == "scan_triggered")
    assert scan_ev["target"] == "10.0.0.1"
    assert "scan_key" in scan_ev
    assert scan_ev["scan_key"] in main_mod._pending
