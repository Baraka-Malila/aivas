import sqlite3
from pathlib import Path

import pytest

from aivas.database.schema import create_schema


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "test.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def _tables(conn):
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r["name"] for r in rows}


def test_chat_sessions_table_exists(conn):
    assert "chat_sessions" in _tables(conn)


def test_chat_messages_table_exists(conn):
    assert "chat_messages" in _tables(conn)


def test_cve_advice_table_exists(conn):
    assert "cve_advice" in _tables(conn)


def test_chat_sessions_insert(conn):
    conn.execute(
        "INSERT INTO chat_sessions(id, title) VALUES (?, ?)",
        ("sid-1", "Hello"),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM chat_sessions WHERE id=?", ("sid-1",)).fetchone()
    assert row["title"] == "Hello"
    assert row["created_at"] is not None


def test_chat_messages_cascade_delete(conn):
    conn.execute("INSERT INTO chat_sessions(id) VALUES (?)", ("sid-2",))
    conn.execute(
        "INSERT INTO chat_messages(session_id, role, content) VALUES (?, ?, ?)",
        ("sid-2", "user", "hi"),
    )
    conn.commit()
    conn.execute("DELETE FROM chat_sessions WHERE id=?", ("sid-2",))
    conn.commit()
    cnt = conn.execute(
        "SELECT COUNT(*) c FROM chat_messages WHERE session_id=?", ("sid-2",)
    ).fetchone()["c"]
    assert cnt == 0


def test_chat_messages_role_check_rejects_bad(conn):
    conn.execute("INSERT INTO chat_sessions(id) VALUES (?)", ("sid-3",))
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO chat_messages(session_id, role, content) VALUES (?, ?, ?)",
            ("sid-3", "system", "should fail"),
        )


def test_cve_advice_insert(conn):
    conn.execute(
        "INSERT INTO cve_advice(cve_id, advice_en, advice_sw, model) "
        "VALUES (?, ?, ?, ?)",
        ("CVE-2021-44228", "Update Log4j", "Sasisha Log4j", "test-model"),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM cve_advice WHERE cve_id=?", ("CVE-2021-44228",)
    ).fetchone()
    assert row["advice_en"] == "Update Log4j"
    assert row["advice_sw"] == "Sasisha Log4j"


def test_chat_messages_index_exists(conn):
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'"
    ).fetchall()
    names = {r["name"] for r in rows}
    assert "idx_chat_messages_session_time" in names
