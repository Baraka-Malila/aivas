"""Persistent chat sessions + messages — backs multi-turn conversation."""
from __future__ import annotations

import json
import sqlite3
import uuid


_TITLE_MAX = 60


def create_session(conn: sqlite3.Connection, title: str | None = None) -> str:
    sid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO chat_sessions(id, title) VALUES (?, ?)",
        (sid, title),
    )
    conn.commit()
    return sid


def get_session(conn: sqlite3.Connection, session_id: str) -> dict | None:
    row = conn.execute(
        "SELECT id, title, created_at, updated_at FROM chat_sessions WHERE id=?",
        (session_id,),
    ).fetchone()
    return dict(row) if row else None


def list_sessions(conn: sqlite3.Connection, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        "SELECT id, title, created_at, updated_at "
        "FROM chat_sessions ORDER BY updated_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def delete_session(conn: sqlite3.Connection, session_id: str) -> bool:
    cur = conn.execute("DELETE FROM chat_sessions WHERE id=?", (session_id,))
    conn.commit()
    return cur.rowcount > 0


def save_user(conn: sqlite3.Connection, session_id: str, text: str) -> None:
    conn.execute(
        "INSERT INTO chat_messages(session_id, role, content) VALUES (?, 'user', ?)",
        (session_id, text),
    )
    conn.commit()
    touch_session(conn, session_id)


def save_assistant(
    conn: sqlite3.Connection, session_id: str,
    text: str, tool_calls: list | None = None,
) -> None:
    tc_json = json.dumps(tool_calls) if tool_calls else None
    conn.execute(
        "INSERT INTO chat_messages(session_id, role, content, tool_calls) "
        "VALUES (?, 'assistant', ?, ?)",
        (session_id, text, tc_json),
    )
    conn.commit()
    touch_session(conn, session_id)


def save_tool_result(
    conn: sqlite3.Connection, session_id: str,
    tool_call_id: str, result: str,
) -> None:
    conn.execute(
        "INSERT INTO chat_messages(session_id, role, content, tool_call_id) "
        "VALUES (?, 'tool', ?, ?)",
        (session_id, result, tool_call_id),
    )
    conn.commit()
    touch_session(conn, session_id)


def update_title_if_unset(
    conn: sqlite3.Connection, session_id: str, first_user_text: str,
) -> None:
    row = conn.execute(
        "SELECT title FROM chat_sessions WHERE id=?", (session_id,),
    ).fetchone()
    if row is None or row["title"]:
        return
    title = (first_user_text or "").strip()[:_TITLE_MAX]
    conn.execute(
        "UPDATE chat_sessions SET title=? WHERE id=?",
        (title, session_id),
    )
    conn.commit()


def touch_session(conn: sqlite3.Connection, session_id: str) -> None:
    conn.execute(
        "UPDATE chat_sessions SET updated_at=CURRENT_TIMESTAMP WHERE id=?",
        (session_id,),
    )
    conn.commit()


def load_history(
    conn: sqlite3.Connection, session_id: str, max_turns: int = 6,
) -> list[dict]:
    """Return Groq-format message list, last `max_turns` user-assistant turns.

    A turn starts at a user message and ends at the next assistant message that
    has no pending tool_calls. Tool calls + tool results inside an assistant
    response stay grouped with that assistant turn.
    """
    rows = conn.execute(
        "SELECT role, content, tool_calls, tool_call_id "
        "FROM chat_messages WHERE session_id=? "
        "ORDER BY created_at ASC, id ASC",
        (session_id,),
    ).fetchall()
    msgs: list[dict] = []
    for r in rows:
        m: dict = {"role": r["role"]}
        if r["content"] is not None:
            m["content"] = r["content"]
        else:
            m["content"] = ""
        if r["tool_calls"]:
            try:
                m["tool_calls"] = json.loads(r["tool_calls"])
            except json.JSONDecodeError:
                m["tool_calls"] = []
        if r["tool_call_id"]:
            m["tool_call_id"] = r["tool_call_id"]
        msgs.append(m)
    return _trim_to_turns(msgs, max_turns)


def _trim_to_turns(msgs: list[dict], max_turns: int) -> list[dict]:
    """Walk backwards counting user-message boundaries; cut at the Nth boundary."""
    if not msgs:
        return msgs
    boundaries = [i for i, m in enumerate(msgs) if m["role"] == "user"]
    if len(boundaries) <= max_turns:
        return msgs
    start = boundaries[-max_turns]
    return msgs[start:]
