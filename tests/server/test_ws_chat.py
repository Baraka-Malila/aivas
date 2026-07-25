import sqlite3
from unittest.mock import patch

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
        ws.send_json({"type": "user", "text": "hi"})
        msg = ws.receive_json()
        assert msg["type"] == "error"


def test_ws_chat_complete_event(client):
    sid = client.post("/api/sessions").json()["id"]

    async def fake_handle(conn, session_id, text, scan_id=None):
        return ("Hello back", None)

    with patch("aivas.server.main.handle_chat", side_effect=fake_handle):
        with client.websocket_connect(f"/ws/chat/{sid}") as ws:
            ws.send_json({"type": "user", "text": "hi"})
            msg = ws.receive_json()
            assert msg["type"] == "complete"
            assert msg["text"] == "Hello back"


def test_ws_chat_scan_intent_event(client):
    sid = client.post("/api/sessions").json()["id"]

    async def fake_handle(conn, session_id, text, scan_id=None):
        return ("Scan started.", ("1.1.1.1", 2))

    with patch("aivas.server.main.handle_chat", side_effect=fake_handle):
        with client.websocket_connect(f"/ws/chat/{sid}") as ws:
            ws.send_json({"type": "user", "text": "scan 1.1.1.1"})
            msg1 = ws.receive_json()
            msg2 = ws.receive_json()
            kinds = {msg1["type"], msg2["type"]}
            assert "scan_intent" in kinds
            assert "complete" in kinds
            # scan_intent carries scan_key + target + level
            intent_msg = msg1 if msg1["type"] == "scan_intent" else msg2
            assert intent_msg["target"] == "1.1.1.1"
            assert intent_msg["level"] == 2
            assert "scan_key" in intent_msg
