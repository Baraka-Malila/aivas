import asyncio
import sqlite3
from unittest.mock import patch

import pytest

from aivas.database.schema import create_schema
from aivas.server import chat_api
from aivas.server.chat_memory import create_session, load_history


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_handle_chat_signature_takes_session_id():
    import inspect
    sig = inspect.signature(chat_api.handle_chat)
    params = list(sig.parameters)
    # conn, session_id, text, ...
    assert params[1] == "session_id"


def test_handle_chat_persists_user_and_assistant(conn):
    sid = create_session(conn)
    fake_resp = ("Hello back", None, [{"role": "assistant", "content": "Hello back"}])

    async def fake_run(*args, **kwargs):
        return fake_resp

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.tui.agent.run_agent", side_effect=fake_run):
            response, scan_intent = asyncio.run(
                chat_api.handle_chat(conn, sid, "hi")
            )
    assert response == "Hello back"
    assert scan_intent is None
    history = load_history(conn, sid)
    assert history == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "Hello back"},
    ]


def test_handle_chat_persists_tool_call_turns(conn):
    sid = create_session(conn)
    tc = [{"id": "c1", "type": "function",
           "function": {"name": "scan_host", "arguments": '{"target":"1.1.1.1"}'}}]
    fake_resp = (
        "Scan started.", ("1.1.1.1", 2),
        [
            {"role": "assistant", "content": "", "tool_calls": tc},
            {"role": "tool", "tool_call_id": "c1",
             "content": '{"status":"initiated"}'},
            {"role": "assistant", "content": "Scan started."},
        ],
    )

    async def fake_run(*args, **kwargs):
        return fake_resp

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.tui.agent.run_agent", side_effect=fake_run):
            response, intent = asyncio.run(
                chat_api.handle_chat(conn, sid, "scan 1.1.1.1")
            )
    assert intent == ("1.1.1.1", 2)
    history = load_history(conn, sid)
    roles = [m["role"] for m in history]
    assert roles == ["user", "assistant", "tool", "assistant"]


def test_handle_chat_sets_title_from_first_message(conn):
    sid = create_session(conn)

    async def fake_run(*args, **kwargs):
        return ("ok", None, [{"role": "assistant", "content": "ok"}])

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.tui.agent.run_agent", side_effect=fake_run):
            asyncio.run(chat_api.handle_chat(conn, sid, "What is on my router?"))
    row = conn.execute(
        "SELECT title FROM chat_sessions WHERE id=?", (sid,)
    ).fetchone()
    assert row["title"] == "What is on my router?"


def test_handle_chat_loads_history_into_run_agent(conn):
    sid = create_session(conn)
    # Seed prior turn
    conn.execute(
        "INSERT INTO chat_messages(session_id, role, content) VALUES (?, 'user', 'first')",
        (sid,),
    )
    conn.execute(
        "INSERT INTO chat_messages(session_id, role, content) VALUES (?, 'assistant', 'first reply')",
        (sid,),
    )
    conn.commit()

    captured = {}

    async def fake_run(app, text, api_key, context="", history=None):
        captured["history"] = history
        return ("ok", None, [{"role": "assistant", "content": "ok"}])

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.tui.agent.run_agent", side_effect=fake_run):
            asyncio.run(chat_api.handle_chat(conn, sid, "second"))

    assert captured["history"] == [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "first reply"},
    ]


def test_handle_chat_no_api_key_returns_clear_message(conn):
    sid = create_session(conn)
    with patch.object(chat_api._config, "load", return_value={}):
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("GROQ_API_KEY", None)
            response, intent = asyncio.run(chat_api.handle_chat(conn, sid, "hi"))
    assert "No AI key" in response
    assert intent is None
