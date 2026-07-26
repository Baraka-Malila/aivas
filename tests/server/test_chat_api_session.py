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


def test_handle_chat_rest_signature_takes_session_id():
    import inspect
    sig = inspect.signature(chat_api.handle_chat_rest)
    params = list(sig.parameters)
    # conn, pending, session_id, text
    assert params[2] == "session_id"


def test_handle_chat_rest_persists_user_and_assistant(conn):
    sid = create_session(conn)
    pending: dict = {}

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        yield {"type": "thinking"}
        yield {"type": "token", "text": "Hello back"}
        yield {"type": "done", "full_text": "Hello back", "turns": [
            {"role": "assistant", "content": "Hello back"}
        ]}

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.server.chat_api.stream_agent_response", side_effect=fake_stream):
            result = asyncio.run(chat_api.handle_chat_rest(conn, pending, sid, "hi"))

    assert result["response"] == "Hello back"
    assert result["scan_id"] is None
    history = load_history(conn, sid)
    assert history == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "Hello back"},
    ]


def test_handle_chat_rest_persists_tool_call_turns(conn):
    sid = create_session(conn)
    pending: dict = {}
    tc = [{"id": "c1", "type": "function",
           "function": {"name": "scan_host", "arguments": '{"target":"1.1.1.1"}'}}]

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        yield {"type": "scan_triggered", "target": "1.1.1.1", "level": 2}
        yield {"type": "done", "full_text": "Scan started.", "turns": [
            {"role": "assistant", "content": "", "tool_calls": tc},
            {"role": "tool", "tool_call_id": "c1", "content": '{"status":"initiated"}'},
            {"role": "assistant", "content": "Scan started."},
        ]}

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.server.chat_api.stream_agent_response", side_effect=fake_stream):
            result = asyncio.run(chat_api.handle_chat_rest(conn, pending, sid, "scan 1.1.1.1"))

    assert result["scan_id"] is not None
    assert pending  # scan was registered
    history = load_history(conn, sid)
    roles = [m["role"] for m in history]
    assert roles == ["user", "assistant", "tool", "assistant"]


def test_handle_chat_rest_sets_title_from_first_message(conn):
    sid = create_session(conn)
    pending: dict = {}

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        yield {"type": "token", "text": "ok"}
        yield {"type": "done", "full_text": "ok", "turns": [
            {"role": "assistant", "content": "ok"}
        ]}

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.server.chat_api.stream_agent_response", side_effect=fake_stream):
            asyncio.run(chat_api.handle_chat_rest(conn, pending, sid, "What is on my router?"))

    row = conn.execute(
        "SELECT title FROM chat_sessions WHERE id=?", (sid,)
    ).fetchone()
    assert row["title"] == "What is on my router?"


def test_handle_chat_rest_loads_history(conn):
    sid = create_session(conn)
    pending: dict = {}
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

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        captured["history"] = history
        yield {"type": "token", "text": "ok"}
        yield {"type": "done", "full_text": "ok", "turns": [
            {"role": "assistant", "content": "ok"}
        ]}

    with patch.object(chat_api._config, "load", return_value={"api_key": "k"}):
        with patch("aivas.server.chat_api.stream_agent_response", side_effect=fake_stream):
            asyncio.run(chat_api.handle_chat_rest(conn, pending, sid, "second"))

    assert captured["history"] == [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "first reply"},
    ]


def test_handle_chat_rest_no_api_key_returns_clear_message(conn):
    sid = create_session(conn)
    pending: dict = {}
    with patch.object(chat_api._config, "load", return_value={}):
        with patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("GROQ_API_KEY", None)
            result = asyncio.run(chat_api.handle_chat_rest(conn, pending, sid, "hi"))
    # get_provider raises ValueError when no key; handle_chat_rest returns it as response
    assert result["response"]  # some error message is returned
    assert result["session_id"] == sid
