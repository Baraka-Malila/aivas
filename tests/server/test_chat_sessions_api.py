import asyncio
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import aivas.server.chat_api
from aivas.server.main import app, _conn as _module_conn
import aivas.server.main as main_mod
from aivas.database.schema import create_schema
import sqlite3


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    monkeypatch.setattr(main_mod, "_conn", db)
    return TestClient(app)


def test_post_sessions_creates_returns_id(client):
    resp = client.post("/api/sessions")
    assert resp.status_code == 200
    data = resp.json()
    assert "id" in data
    assert len(data["id"]) == 36


def test_get_sessions_lists(client):
    client.post("/api/sessions")
    client.post("/api/sessions")
    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_get_session_by_id_includes_messages(client):
    sid = client.post("/api/sessions").json()["id"]
    resp = client.get(f"/api/sessions/{sid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == sid
    assert data["messages"] == []


def test_get_session_returns_404_for_missing(client):
    assert client.get("/api/sessions/nope").status_code == 404


def test_delete_session_removes(client):
    sid = client.post("/api/sessions").json()["id"]
    resp = client.delete(f"/api/sessions/{sid}")
    assert resp.status_code == 200
    assert resp.json() == {"deleted": sid}
    assert client.get(f"/api/sessions/{sid}").status_code == 404


def test_delete_missing_session_404(client):
    assert client.delete("/api/sessions/nope").status_code == 404


def test_post_chat_creates_session_when_missing(client):
    async def fake_handle(conn, pending, session_id, text):
        from aivas.server.chat_memory import create_session
        sid = session_id or create_session(conn)
        return {"response": "hello reply", "scan_id": None, "session_id": sid}
    with patch("aivas.server.chat_api.handle_chat_rest", side_effect=fake_handle):
        resp = client.post("/api/chat", json={"text": "hi"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == "hello reply"
    assert "session_id" in data and len(data["session_id"]) == 36


def test_post_chat_uses_existing_session(client):
    sid = client.post("/api/sessions").json()["id"]
    async def fake_handle(conn, pending, session_id, text):
        assert session_id == sid
        return {"response": "ok", "scan_id": None, "session_id": sid}
    with patch("aivas.server.chat_api.handle_chat_rest", side_effect=fake_handle):
        resp = client.post(
            "/api/chat", json={"text": "hi", "session_id": sid},
        )
    assert resp.status_code == 200
    assert resp.json()["session_id"] == sid
