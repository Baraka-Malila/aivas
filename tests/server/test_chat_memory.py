import sqlite3

import pytest

from aivas.database.schema import create_schema
from aivas.server.chat_memory import (
    create_session, get_session, list_sessions, delete_session,
    load_history, save_user, save_assistant, save_tool_result,
    update_title_if_unset, touch_session,
)


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_create_returns_uuid_like_string(conn):
    sid = create_session(conn)
    assert isinstance(sid, str)
    assert len(sid) == 36  # uuid4 string length


def test_get_session_returns_none_if_missing(conn):
    assert get_session(conn, "nope") is None


def test_get_session_returns_dict_after_create(conn):
    sid = create_session(conn, title="My chat")
    s = get_session(conn, sid)
    assert s["id"] == sid
    assert s["title"] == "My chat"


def test_list_sessions_orders_by_updated_desc(conn):
    s1 = create_session(conn, title="first")
    create_session(conn, title="second")
    touch_session(conn, s1)
    rows = list_sessions(conn)
    assert rows[0]["id"] == s1


def test_delete_session_returns_true_and_cascades(conn):
    sid = create_session(conn)
    save_user(conn, sid, "hi")
    assert delete_session(conn, sid) is True
    assert get_session(conn, sid) is None
    cnt = conn.execute(
        "SELECT COUNT(*) c FROM chat_messages WHERE session_id=?", (sid,)
    ).fetchone()["c"]
    assert cnt == 0


def test_delete_missing_session_returns_false(conn):
    assert delete_session(conn, "nope") is False


def test_save_user_and_assistant_roundtrip(conn):
    sid = create_session(conn)
    save_user(conn, sid, "hello")
    save_assistant(conn, sid, "hi there")
    history = load_history(conn, sid)
    assert history == [
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "hi there"},
    ]


def test_save_assistant_with_tool_calls(conn):
    sid = create_session(conn)
    save_user(conn, sid, "scan it")
    tc = [{"id": "call_1", "type": "function",
           "function": {"name": "scan_host", "arguments": '{"target":"1.1.1.1"}'}}]
    save_assistant(conn, sid, "", tool_calls=tc)
    save_tool_result(conn, sid, "call_1", '{"status":"initiated"}')
    save_assistant(conn, sid, "Scan started.")
    history = load_history(conn, sid)
    assert history[0]["role"] == "user"
    assert history[1]["role"] == "assistant"
    assert history[1]["tool_calls"] == tc
    assert history[2]["role"] == "tool"
    assert history[2]["tool_call_id"] == "call_1"
    assert history[3]["role"] == "assistant"


def test_load_history_truncates_to_max_turns(conn):
    sid = create_session(conn)
    for i in range(10):
        save_user(conn, sid, f"u{i}")
        save_assistant(conn, sid, f"a{i}")
    history = load_history(conn, sid, max_turns=3)
    assert len(history) == 6  # 3 turns × 2 messages
    assert history[0]["role"] == "user"
    assert history[0]["content"] == "u7"
    assert history[-1]["content"] == "a9"


def test_load_history_keeps_tool_pairs_intact_when_truncating(conn):
    sid = create_session(conn)
    save_user(conn, sid, "u0")
    save_assistant(conn, sid, "a0")
    save_user(conn, sid, "u1")
    save_assistant(conn, sid, "", tool_calls=[{"id":"c1","type":"function",
        "function":{"name":"x","arguments":"{}"}}])
    save_tool_result(conn, sid, "c1", "ok")
    save_assistant(conn, sid, "a1")
    save_user(conn, sid, "u2")
    save_assistant(conn, sid, "a2")
    history = load_history(conn, sid, max_turns=2)
    roles = [m["role"] for m in history]
    # Must start with user (no orphan tool/assistant) and end with assistant
    assert roles[0] == "user"
    assert roles[-1] == "assistant"
    # No "tool" message can appear without its preceding assistant tool_call
    for i, m in enumerate(history):
        if m["role"] == "tool":
            assert i > 0
            assert history[i-1]["role"] == "assistant"
            assert history[i-1].get("tool_calls")


def test_load_history_empty_session(conn):
    sid = create_session(conn)
    assert load_history(conn, sid) == []


def test_update_title_if_unset_sets_first_60_chars(conn):
    sid = create_session(conn)
    text = "Scan my router at 192.168.1.1 and tell me what's vulnerable on it please"
    update_title_if_unset(conn, sid, text)
    s = get_session(conn, sid)
    assert s["title"] == text[:60]


def test_update_title_if_unset_does_not_overwrite_existing(conn):
    sid = create_session(conn, title="kept")
    update_title_if_unset(conn, sid, "new text")
    s = get_session(conn, sid)
    assert s["title"] == "kept"


def test_touch_bumps_updated_at(conn):
    import time
    sid = create_session(conn)
    before = get_session(conn, sid)["updated_at"]
    time.sleep(1.1)
    touch_session(conn, sid)
    after = get_session(conn, sid)["updated_at"]
    assert after > before
