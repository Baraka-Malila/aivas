import json
import sqlite3

import pytest

from aivas.database.schema import create_schema
from aivas.tui.agent import _as_int, _as_str, _exec_tool


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_as_int_valid():
    assert _as_int("42") == 42
    assert _as_int(42) == 42
    assert _as_int(" 7 ") == 7


def test_as_int_invalid_returns_default():
    assert _as_int("full", default=2) == 2
    assert _as_int(None, default=2) == 2
    assert _as_int("", default=2) == 2
    assert _as_int("3.14", default=2) == 2


def test_as_str_strips_and_handles_none():
    assert _as_str("  hi  ") == "hi"
    assert _as_str(None) == ""
    assert _as_str(None, default="x") == "x"
    assert _as_str(123) == "123"


def test_exec_tool_bad_level_uses_default(conn):
    result, intent = _exec_tool(
        "scan_host", {"target": "1.2.3.4", "level": "full"}, conn,
    )
    data = json.loads(result)
    assert data.get("status") == "initiated"
    assert intent == ("1.2.3.4", 2)


def test_exec_tool_bad_scan_id_returns_error(conn):
    result, intent = _exec_tool(
        "get_findings", {"scan_id": "latest"}, conn,
    )
    data = json.loads(result)
    assert "error" in data
    assert intent is None


def test_exec_tool_missing_target_returns_error(conn):
    result, intent = _exec_tool("scan_host", {}, conn)
    data = json.loads(result)
    assert "error" in data
    assert intent is None


def test_exec_tool_unknown_tool_returns_error(conn):
    result, intent = _exec_tool("delete_database", {}, conn)
    data = json.loads(result)
    assert "error" in data
    assert intent is None


def test_exec_tool_explain_cve_missing_id_returns_error(conn):
    result, intent = _exec_tool("explain_cve", {}, conn)
    assert "error" in json.loads(result)


def test_exec_tool_get_history_bad_limit_uses_default(conn):
    result, intent = _exec_tool(
        "get_history", {"limit": "not_a_number"}, conn,
    )
    data = json.loads(result)
    assert isinstance(data, list)  # default 5 returns whatever's in DB (empty list)
