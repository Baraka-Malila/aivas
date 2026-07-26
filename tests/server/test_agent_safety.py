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


def test_system_prompt_contains_language_mirror_instruction():
    from aivas.tui.agent import _SYSTEM
    text = _SYSTEM.lower()
    assert "language" in text
    assert "same language" in text or "user wrote" in text or "user's language" in text


def test_system_prompt_protects_identifiers():
    from aivas.tui.agent import _SYSTEM
    assert "CVE" in _SYSTEM or "identifier" in _SYSTEM.lower()


def test_detect_lang_is_removed():
    import aivas.tui.agent as a
    assert not hasattr(a, "_detect_lang")
    assert not hasattr(a, "_SWAHILI_HINTS")
    assert not hasattr(a, "_lang_instruction")


import inspect


def test_run_agent_has_history_param():
    from aivas.tui.agent import run_agent
    sig = inspect.signature(run_agent)
    assert "history" in sig.parameters
    assert sig.parameters["history"].default is None


def test_system_prompt_is_not_rigid():
    from aivas.tui.agent_prompts import SYSTEM
    # Old rigid structure must be gone
    assert "EXECUTIVE SUMMARY" not in SYSTEM
    assert "SEVERITY BREAKDOWN" not in SYSTEM
    assert "TOP FINDINGS" not in SYSTEM
    assert "REMEDIATION" not in SYSTEM


def test_system_prompt_has_persona():
    from aivas.tui.agent_prompts import SYSTEM
    assert "AIVAS" in SYSTEM
    assert "Tanzania" in SYSTEM


def test_tools_include_shodan():
    from aivas.tui.agent_prompts import TOOLS
    names = [t["function"]["name"] for t in TOOLS]
    assert "query_shodan" in names


def test_exec_tool_query_shodan_no_key():
    import sqlite3
    from aivas.tui.agent import _exec_tool
    conn = sqlite3.connect(":memory:")
    result, intent = _exec_tool("query_shodan", {"ip": "1.1.1.1"}, conn, shodan_key=None)
    data = json.loads(result)
    assert "error" in data


def test_exec_tool_unknown_returns_error():
    import sqlite3
    from aivas.tui.agent import _exec_tool
    conn = sqlite3.connect(":memory:")
    result, intent = _exec_tool("nonexistent_tool", {}, conn)
    assert "error" in json.loads(result)
