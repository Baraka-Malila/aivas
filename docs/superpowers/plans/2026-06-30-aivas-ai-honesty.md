# AIVAS AI Honesty + Conversational Backend — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AIVAS's AI claims true at the backend before any frontend redo: real multi-turn chat with persistent memory, web scans that produce bilingual narration parity with the CLI, per-CVE LLM-cached remediation, KEV findings that actually move the grade, demo-safe tool argument validation, and probers that distinguish unreachable from clean.

**Architecture:** Three new SQLite tables (`chat_sessions`, `chat_messages`, `cve_advice`) live alongside the existing scans/findings DB. A new `aivas/server/chat_memory.py` module owns session + message persistence. `agent.run_agent` accepts a `history` list and returns the assistant turns produced this call so the caller persists them. `chat_api.handle_chat` is rewritten to load history before each LLM call and save the response after. `scan_worker` calls `narrator.narrate` + a new `cve_advice.warm_cache` between scoring and `save_scan`. `scorer.py` adds a KEV multiplier + hard grade cap. The HTTP prober's three checks each return a `{status, findings}` dict. New `WS /ws/chat/{session_id}` plus REST session endpoints live in `main.py`.

**Tech Stack:** Python 3.11+, FastAPI, SQLite (`sqlite3` stdlib), Groq SDK (existing `groq` package), pytest, no new runtime dependencies.

## Global Constraints

- No Python file may exceed 200 lines of code (CLAUDE.md project rule).
- One module = one responsibility. Splitting a file that grows past 200 lines is in scope for that task.
- All git commits use author `Baraka Malila <bmalila87@gmail.com>` — never "Claude" or auto-attribution.
- All commits in this plan land on the existing branch `feat/web-ui` (current branch).
- Frontend code is OUT OF SCOPE for this plan. Phase 2 will handle the chat UI.
- Existing 267 backend tests must stay green at the end of every task.
- New SQLite tables are added inside `database/schema.create_schema` so they are created idempotently on every server startup. No separate migration runner.
- KEV CVSS penalty multiplier: `1.5×`. Hard grade cap when any KEV finding exists: `score ≤ 75`, grade `≤ C` (i.e. A or B → C; D and F unchanged).
- Conversation memory trim depth: last 6 turns (12 raw rows max), preserving tool-call/tool-result pairs whole.
- Multilingual: LLM mirrors user's input language natively. The 23-word Swahili keyword heuristic (`_detect_lang`, `_SWAHILI_HINTS`) is deleted.
- Spec source of truth: `docs/superpowers/specs/2026-06-30-aivas-ai-honesty-design.md`.

---

## File Structure

### New files

| Path | Responsibility | Approx lines |
|---|---|---|
| `aivas/server/chat_memory.py` | Session + message CRUD; history loader with trim rules | ~120 |
| `aivas/server/cve_advice.py` | LLM-cached per-CVE remediation generation + storage | ~140 |
| `tests/server/test_chat_memory.py` | Unit tests for chat_memory CRUD + trim | ~150 |
| `tests/server/test_cve_advice.py` | Unit tests for cache hit/miss + warm_cache | ~120 |
| `tests/server/test_agent_safety.py` | Tool-arg safety + history threading | ~100 |
| `tests/server/test_chat_sessions_api.py` | REST + WS session endpoints | ~140 |
| `tests/server/test_kev_scoring.py` | KEV multiplier + grade cap | ~80 |
| `tests/server/test_prober_status.py` | Status-dict probers | ~90 |

### Modified files

| Path | Change |
|---|---|
| `aivas/database/schema.py` | Add three CREATE TABLE statements + new index |
| `aivas/tui/agent.py` | Drop `_detect_lang`/`_SWAHILI_HINTS`/`_lang_instruction`; update `_SYSTEM`; add `_as_int`/`_as_str`; harden `_exec_tool`; signature `run_agent(..., history=None) -> (text, scan_intent, assistant_turns)` |
| `aivas/server/chat_api.py` | Rewrite `handle_chat` to take `session_id`, load history, save assistant turns; keep `handle_narrate` |
| `aivas/server/main.py` | Add `WS /ws/chat/{session_id}`, REST `/api/sessions` family, accept `session_id` query on `POST /api/chat` |
| `aivas/server/scan_worker.py` | Add `AI NARRATION` and `AI REMEDIATION` phases; call narrator + warm_cache before `save_scan` |
| `aivas/server/report_helpers.py` | `cve_fix(f, conn=None, lang="en")` consults cache before legacy template; rename current body to `_legacy_template_fix` |
| `aivas/server/report_gen.py` | Pass `conn` to `cve_fix` callers; render KEV pill on findings; KEV warning in executive summary |
| `aivas/scorer.py` | Per-finding penalty respects KEV multiplier; hard grade cap if any KEV finding |
| `aivas/history.py` | `list_scans` returns `kev_count` per scan; `save_scan` writes `narration_en/sw`, `fix_en/sw` from finding fields |
| `aivas/prober/headers.py` | Return `{"status": "...", "findings": [...]}` |
| `aivas/prober/endpoints.py` | Return `{"status": "...", "findings": [...]}` |
| `aivas/prober/methods.py` | Return `{"status": "...", "findings": [...]}` |
| `aivas/prober/__init__.py` (or wherever `probe_http_service` lives) | Aggregate the three sub-checks into a single result dict |
| `aivas/server/scan_helpers.py` | `http_probe_events` handles new status field |
| `aivas/templates/report.html.j2` | KEV pill on rows, sort KEV findings to top of severity group, executive summary KEV prepend |
| `tests/server/test_scan_worker.py` | Update for new phase events; verify narration populated |
| `tests/test_scorer.py` (if exists) or new | Cover KEV multiplier + cap |

---

## Tasks Overview

| # | Task | Depends on |
|---|---|---|
| 1 | Database schema additions | — |
| 2 | `chat_memory` module | Task 1 |
| 3 | Tool-arg safety helpers in agent | — |
| 4 | Drop `_detect_lang`; multilingual via system prompt | — |
| 5 | `run_agent` accepts `history`, returns `assistant_turns` | Tasks 3, 4 |
| 6 | `chat_api.handle_chat` session-aware | Tasks 2, 5 |
| 7 | `cve_advice` module | Task 1 |
| 8 | `cve_fix` three-tier fallback | Task 7 |
| 9 | KEV scoring + grade cap | — |
| 10 | KEV rendering in reports + history | Task 9 |
| 11 | HTTP prober returns `{status, findings}` | — |
| 12 | Scan worker: narration + advice warmup wiring | Tasks 7, 8, 11 |
| 13 | Session REST endpoints + `POST /api/chat` session_id | Tasks 2, 6 |
| 14 | `WS /ws/chat/{session_id}` | Tasks 6, 13 |

---

## Task 1: Database schema additions

Add `chat_sessions`, `chat_messages`, `cve_advice` tables inside `create_schema`.

**Files:**
- Modify: `aivas/database/schema.py`
- Test: `tests/database/test_schema_additions.py`

**Interfaces:**
- Produces: tables `chat_sessions(id TEXT PK, title, created_at, updated_at)`, `chat_messages(id INTEGER PK, session_id TEXT FK, role, content, tool_calls, tool_call_id, created_at)`, `cve_advice(cve_id TEXT PK, advice_en, advice_sw, model, created_at)`. Index `idx_chat_messages_session_time` on `(session_id, created_at)`.

- [ ] **Step 1: Write the failing test**

Create `tests/database/test_schema_additions.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/database/test_schema_additions.py -v
```

Expected: All tests FAIL with "no such table: chat_sessions" or similar.

- [ ] **Step 3: Add the three tables to `create_schema`**

In `aivas/database/schema.py`, inside the `conn.executescript(""" … """)` block, append the following BEFORE the closing `""")` (i.e. after the `CREATE INDEX IF NOT EXISTS idx_findings_cve` line):

```sql

CREATE TABLE IF NOT EXISTS chat_sessions (
    id          TEXT PRIMARY KEY,
    title       TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK(role IN ('user','assistant','tool')),
    content      TEXT,
    tool_calls   TEXT,
    tool_call_id TEXT,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_time
    ON chat_messages(session_id, created_at);

CREATE TABLE IF NOT EXISTS cve_advice (
    cve_id      TEXT PRIMARY KEY,
    advice_en   TEXT NOT NULL,
    advice_sw   TEXT NOT NULL,
    model       TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/database/test_schema_additions.py -v
```

Expected: All 8 tests PASS.

- [ ] **Step 5: Run full backend test suite to confirm no regressions**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 275 passed (267 existing + 8 new).

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/database/schema.py tests/database/test_schema_additions.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(db): add chat_sessions, chat_messages, cve_advice tables"
```

---

## Task 2: `chat_memory` module

CRUD operations for sessions + messages, with a `load_history` that returns Groq-shaped message list and respects turn-pair preservation.

**Files:**
- Create: `aivas/server/chat_memory.py`
- Test: `tests/server/test_chat_memory.py`

**Interfaces:**
- Consumes: tables from Task 1.
- Produces:
  - `create_session(conn, title: str | None = None) -> str` (returns new UUID v4)
  - `get_session(conn, session_id) -> dict | None`
  - `list_sessions(conn, limit: int = 20) -> list[dict]`
  - `delete_session(conn, session_id) -> bool`
  - `load_history(conn, session_id, max_turns: int = 6) -> list[dict]` (Groq-format)
  - `save_user(conn, session_id, text) -> None`
  - `save_assistant(conn, session_id, text, tool_calls: list | None = None) -> None`
  - `save_tool_result(conn, session_id, tool_call_id, result) -> None`
  - `update_title_if_unset(conn, session_id, first_user_text) -> None`
  - `touch_session(conn, session_id) -> None`

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_chat_memory.py`:

```python
import json
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
    s2 = create_session(conn, title="second")
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_chat_memory.py -v
```

Expected: All tests FAIL with `ModuleNotFoundError: No module named 'aivas.server.chat_memory'`.

- [ ] **Step 3: Implement `chat_memory.py`**

Create `aivas/server/chat_memory.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_chat_memory.py -v
```

Expected: All 13 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 288 passed.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/chat_memory.py tests/server/test_chat_memory.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(chat): chat_memory module — sessions, messages, history trim"
```

---

## Task 3: Tool-arg safety helpers in agent

Add `_as_int` / `_as_str` to `agent.py`; apply them in `_exec_tool` so a hallucinated `level="full"` or `scan_id="latest"` returns a JSON error instead of raising.

**Files:**
- Modify: `aivas/tui/agent.py`
- Test: `tests/server/test_agent_safety.py`

**Interfaces:**
- Produces:
  - `_as_int(v, default=None) -> int | None`
  - `_as_str(v, default="") -> str`
  - Hardened `_exec_tool(name, args, conn) -> tuple[str, tuple | None]` — never raises on bad LLM args.

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_agent_safety.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_agent_safety.py -v
```

Expected: `_as_int`, `_as_str` tests FAIL with `ImportError`. `_exec_tool` tests FAIL with `ValueError` from bare `int()`.

- [ ] **Step 3: Add helpers and harden `_exec_tool` in `aivas/tui/agent.py`**

Just above `_exec_tool` (around the existing `_TOOLS = [...]` line), add:

```python
def _as_int(v, default: int | None = None) -> int | None:
    if v is None:
        return default
    s = str(v).strip()
    if not s:
        return default
    try:
        return int(s)
    except ValueError:
        return default


def _as_str(v, default: str = "") -> str:
    if v is None:
        return default
    return str(v).strip()
```

Replace the body of `_exec_tool` with:

```python
def _exec_tool(name: str, args: dict, conn: sqlite3.Connection) -> tuple[str, tuple | None]:
    """Execute a tool call. Returns (result_json, scan_intent) or (error_json, None)."""
    from aivas.history import list_scans, get_scan_findings

    if name == "scan_host":
        target = _as_str(args.get("target"))
        level = _as_int(args.get("level"), default=2) or 2
        if not target:
            return json.dumps({"error": "No target specified."}), None
        msg = f"Scan initiated for {target} (level {level}). Results will appear below."
        return json.dumps({"status": "initiated", "message": msg}), (target, level)

    if name == "get_history":
        limit = _as_int(args.get("limit"), default=5) or 5
        scans = list_scans(conn, limit=limit)
        return json.dumps(scans), None

    if name == "get_last_scan":
        scans = list_scans(conn, limit=1)
        if not scans:
            return json.dumps({"error": "No scans in history yet."}), None
        findings = get_scan_findings(conn, scans[0]["id"])
        return json.dumps({"scan": scans[0], "findings": findings[:10]}), None

    if name == "get_findings":
        scan_id = _as_int(args.get("scan_id"))
        if scan_id is None:
            return json.dumps({"error": "scan_id must be an integer."}), None
        findings = get_scan_findings(conn, scan_id)
        return json.dumps(findings[:15]), None

    if name == "explain_cve":
        cve_id = _as_str(args.get("cve_id"))
        if not cve_id:
            return json.dumps({"error": "cve_id is required."}), None
        row = conn.execute(
            "SELECT cve_id, cvss_score, cvss_severity, description FROM cves WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        if not row:
            return json.dumps({"error": f"{cve_id} not found in local database."}), None
        return json.dumps(dict(row)), None

    return json.dumps({"error": f"Unknown tool: {name}"}), None
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_agent_safety.py -v
```

Expected: All 9 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 297 passed.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/agent.py tests/server/test_agent_safety.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(agent): harden tool-arg parsing — returns JSON error on bad LLM input"
```

---

## Task 4: Multilingual via LLM-native handling

Delete the 23-word Swahili keyword heuristic. Replace with a system-prompt instruction that tells the LLM to mirror the user's language.

**Files:**
- Modify: `aivas/tui/agent.py`
- Test: `tests/server/test_agent_safety.py` (extend)

**Interfaces:**
- Removed: `_detect_lang`, `_SWAHILI_HINTS`, `_lang_instruction`.
- Modified `_SYSTEM` includes a LANGUAGE block.

- [ ] **Step 1: Add a test that captures the desired system prompt content**

Append to `tests/server/test_agent_safety.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_agent_safety.py -v
```

Expected: The three new tests FAIL.

- [ ] **Step 3: Update `aivas/tui/agent.py`**

Delete these symbols (currently between approximately line 67 and line 86):

- `_SWAHILI_HINTS = frozenset({...})`
- `def _detect_lang(text: str) -> str:`
- `def _lang_instruction(lang: str) -> str:`

Update `_SYSTEM` (currently a triple-quoted block starting around line 15) by appending a LANGUAGE paragraph. The full replacement `_SYSTEM`:

```python
_SYSTEM = """\
You are AIVAS, a network security analyst for small and medium businesses in Tanzania.

Rules:
- When asked to narrate, summarize, or explain findings: call get_findings FIRST to retrieve actual CVE data, then produce a full assessment.
- Structure every narration in exactly this order:
  1. EXECUTIVE SUMMARY — 2-3 sentences: what was scanned, total finding count, overall risk level.
  2. SEVERITY BREAKDOWN — count per level (CRITICAL / HIGH / MEDIUM / LOW) and what that means in plain language.
  3. TOP FINDINGS — list the 3-5 most dangerous CVEs with ID, CVSS score, and one sentence on what an attacker can do with each.
  4. REMEDIATION — concrete steps: name the specific software/service and version to update, any config changes needed.
- Never fabricate CVE details — only use data returned by the tools.
- When asked to scan: call scan_host. After initiating, confirm the scan has started.
- Be direct. No filler phrases. No generic "update software" advice — name the exact products.

LANGUAGE:
- Respond in the same language the user wrote in. If the user mixes languages, prefer the one they wrote more of. Default to English when unclear.
- Always keep CVE IDs (e.g. CVE-2021-44228), IP addresses, port numbers, product names, and version numbers in their original Latin form. Do NOT translate identifiers.\
"""
```

Update `run_agent` (around line 134) — remove the `lang` and `_lang_instruction` references so the system message is just the `_SYSTEM` constant plus optional `context`:

```python
async def run_agent(
    app: "AIVASApp", text: str, api_key: str, context: str = ""
) -> tuple[str, tuple | None]:
    """Run Groq tool-calling loop. Returns (response_text, scan_intent|None)."""
    from groq import Groq

    system = "\n\n".join(filter(None, [_SYSTEM, context or ""]))
    client = Groq(api_key=api_key)
    orig_messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
    ]
    # ... rest of function unchanged ...
```

(NOTE — Task 5 changes the signature again. This task keeps backward compatibility intact; Task 5 adds `history` and the third return value.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_agent_safety.py -v
```

Expected: All 12 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 297 passed (no regression — `_detect_lang` was not referenced outside `agent.py`).

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/agent.py tests/server/test_agent_safety.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(agent): drop 23-word Swahili heuristic; LLM mirrors user language"
```

---

## Task 5: `run_agent` accepts `history`, returns `assistant_turns`

Change the agent signature so a caller can pass prior conversation history and receive back the new turns to persist.

**Files:**
- Modify: `aivas/tui/agent.py`
- Modify: any TUI call site that unpacks `run_agent` return value (search `aivas/tui/`)
- Test: extend `tests/server/test_agent_safety.py`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `async run_agent(app, text, api_key, context="", history=None) -> tuple[str, tuple | None, list[dict]]`
  - `assistant_turns` shape — list of dicts in Groq message format that the caller should persist via `chat_memory`.

- [ ] **Step 1: Find TUI call sites for `run_agent`**

```bash
cd /home/cyberpunk/aivas
grep -n "run_agent" aivas/tui/ -r
```

Expected: matches in TUI handlers (e.g. `aivas/tui/handlers.py`) plus the `server/chat_api.py` (already known).

- [ ] **Step 2: Add tests for new signature**

Append to `tests/server/test_agent_safety.py`:

```python
import inspect


def test_run_agent_has_history_param():
    from aivas.tui.agent import run_agent
    sig = inspect.signature(run_agent)
    assert "history" in sig.parameters
    assert sig.parameters["history"].default is None
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_agent_safety.py::test_run_agent_has_history_param -v
```

Expected: FAIL with "history not in parameters".

- [ ] **Step 4: Modify `run_agent` in `aivas/tui/agent.py`**

Replace the existing `async def run_agent(...)` body with:

```python
async def run_agent(
    app: "AIVASApp", text: str, api_key: str,
    context: str = "", history: list[dict] | None = None,
) -> tuple[str, tuple | None, list[dict]]:
    """Run Groq tool-calling loop with optional prior history.

    Returns:
        (final_text, scan_intent | None, assistant_turns)
        - final_text: the assistant's last natural-language reply
        - scan_intent: (target, level) if any scan_host tool call was made, else None
        - assistant_turns: the new messages produced this call, ready to persist:
            [{"role":"assistant","content":..., "tool_calls":[...]?},
             {"role":"tool","tool_call_id":..., "content":...}, ...]
    """
    from groq import Groq

    system = "\n\n".join(filter(None, [_SYSTEM, context or ""]))
    client = Groq(api_key=api_key)
    messages: list[dict] = [{"role": "system", "content": system}]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": text})
    scan_intent: tuple | None = None
    turns_to_persist: list[dict] = []

    def _call(msgs: list[dict], tools) -> object:
        kwargs: dict = {
            "model": "llama-3.3-70b-versatile",
            "messages": msgs,
            "max_tokens": 1000,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        return client.chat.completions.create(**kwargs)

    for _step in range(_MAX_STEPS):
        try:
            resp = await asyncio.to_thread(_call, messages, _TOOLS)
        except Exception as exc:
            s = str(exc)
            if "400" in s or "tool" in s.lower():
                # Retry without tools
                orig = [
                    {"role": "system", "content": system},
                    {"role": "user", "content": text},
                ]
                resp = await asyncio.to_thread(_call, orig, None)
                content = _XML_CALL_RE.sub("", resp.choices[0].message.content or "").strip()
                turns_to_persist.append({"role": "assistant", "content": content})
                return content, scan_intent, turns_to_persist
            raise
        msg = resp.choices[0].message

        if not msg.tool_calls:
            content = _XML_CALL_RE.sub("", msg.content or "").strip()
            turns_to_persist.append({"role": "assistant", "content": content})
            return content, scan_intent, turns_to_persist

        # Build assistant turn with tool_calls
        tool_calls_payload = [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in msg.tool_calls
        ]
        assistant_turn = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": tool_calls_payload,
        }
        messages.append(assistant_turn)
        turns_to_persist.append(assistant_turn)

        # Execute each tool, record both the in-flight message and the persisted turn
        for tc in msg.tool_calls:
            raw = tc.function.arguments or "{}"
            try:
                args = json.loads(raw) or {}
            except (json.JSONDecodeError, TypeError):
                args = {}
            result, si = _exec_tool(tc.function.name, args, app.conn)
            if si:
                scan_intent = si
            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)

    final = await asyncio.to_thread(_call, messages, None)
    content = _XML_CALL_RE.sub("", final.choices[0].message.content or "").strip()
    turns_to_persist.append({"role": "assistant", "content": content})
    return content, scan_intent, turns_to_persist
```

- [ ] **Step 5: Update TUI call sites to ignore the third return**

The TUI calls `response, scan_intent = await run_agent(...)`. Update each to:

```python
response, scan_intent, _ = await run_agent(holder, text, api_key, context=context)
```

Search for matches and update each one. Likely one or two sites in `aivas/tui/handlers.py` (or `aivas/tui/app.py`). Use:

```bash
cd /home/cyberpunk/aivas
grep -rn "await run_agent" aivas/
```

For each match (excluding `server/chat_api.py`, which Task 6 rewrites), change the tuple unpacking to add `_` at position 3.

- [ ] **Step 6: Run tests to verify pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_agent_safety.py -v
```

Expected: All tests PASS.

- [ ] **Step 7: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 298 passed.

- [ ] **Step 8: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/agent.py aivas/tui/ tests/server/test_agent_safety.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(agent): accept history; return assistant_turns for persistence"
```

---

## Task 6: `chat_api.handle_chat` becomes session-aware

Rewrite `handle_chat` to load history before the LLM call and persist user + assistant turns after.

**Files:**
- Modify: `aivas/server/chat_api.py`
- Test: `tests/server/test_chat_api_session.py`

**Interfaces:**
- Consumes: `chat_memory` (Task 2), new `run_agent` (Task 5).
- Produces:
  - `async handle_chat(conn, session_id, text, scan_id=None) -> tuple[str, tuple | None]` — `scan_id` here is the optional **scan reference** (which scan's findings to inject as context), not a session id.

- [ ] **Step 1: Write the failing test**

Create `tests/server/test_chat_api_session.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_chat_api_session.py -v
```

Expected: FAILs because `handle_chat` doesn't yet take `session_id`.

- [ ] **Step 3: Rewrite `aivas/server/chat_api.py`**

Replace the file content with:

```python
"""Wraps the Groq agent for HTTP context — no TUI runtime dependency.

Session-aware: loads prior conversation history per session_id and persists
new turns after the LLM call.
"""
from __future__ import annotations

import os
import sqlite3
import types

from aivas import config as _config
from aivas.history import list_scans, get_scan_findings
from aivas.server.chat_memory import (
    load_history, save_user, save_assistant, save_tool_result,
    update_title_if_unset, touch_session,
)


_HISTORY_TURNS = 6


def _build_context(conn: sqlite3.Connection, scan_id: int | None = None) -> str:
    lines: list[str] = []
    scans = list_scans(conn, limit=3)
    if not scans:
        return "No scans performed yet."

    lines.append("Recent scans:")
    for s in scans:
        grade = (s.get("grade") or "").replace("Grade ", "")
        lines.append(f"  · Scan #{s['id']}: {s['target']} — Grade {grade} "
                     f"({s['risk_score']}/100) on {str(s['started_at'])[:10]}")

    target_id = scan_id or scans[0]["id"]
    findings = get_scan_findings(conn, target_id)
    if findings:
        scan_ref = next((s for s in scans if s["id"] == target_id), scans[0])
        grade = (scan_ref.get("grade") or "").replace("Grade ", "")
        lines.append(
            f"\nFindings from scan #{target_id} ({scan_ref['target']}, Grade {grade}):"
        )
        by_sev: dict[str, list] = {}
        for f in findings:
            sev = f.get("cvss_severity") or "UNKNOWN"
            by_sev.setdefault(sev, []).append(f)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev not in by_sev:
                continue
            lines.append(f"  {sev} ({len(by_sev[sev])}):")
            for f in by_sev[sev][:6]:
                desc = (f.get("description") or "")[:100]
                lines.append(
                    f"    - {f['cve_id']} (CVSS {f.get('cvss_score','N/A')}): {desc}"
                )

    return "\n".join(lines)


async def handle_chat(
    conn: sqlite3.Connection,
    session_id: str,
    text: str,
    scan_id: int | None = None,
) -> tuple[str, tuple[str, int] | None]:
    """Multi-turn chat. Loads history, calls LLM, persists user + assistant turns."""
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return (
            "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY",
            None,
        )

    # 1. Load history
    history = load_history(conn, session_id, max_turns=_HISTORY_TURNS)

    # 2. Build context (scan summary) — separate from history
    context = _build_context(conn, scan_id=scan_id)

    # 3. Persist the user message BEFORE the LLM call so it survives errors
    save_user(conn, session_id, text)
    update_title_if_unset(conn, session_id, text)

    # 4. Call the agent with full history
    from aivas.tui.agent import run_agent
    holder = types.SimpleNamespace(conn=conn)
    try:
        response, scan_intent, assistant_turns = await run_agent(
            holder, text, api_key, context=context, history=history,
        )
    except Exception as exc:
        s = str(exc)
        if "401" in s or "invalid_api_key" in s.lower():
            return "API key rejected by Groq. Update: aivas config set api_key KEY", None
        return f"AI error: {exc}", None

    # 5. Persist new turns
    for turn in assistant_turns:
        role = turn.get("role")
        if role == "assistant":
            save_assistant(
                conn, session_id, turn.get("content", ""),
                tool_calls=turn.get("tool_calls"),
            )
        elif role == "tool":
            save_tool_result(
                conn, session_id, turn["tool_call_id"], turn.get("content", ""),
            )

    touch_session(conn, session_id)
    return response or "", scan_intent


async def handle_narrate(conn: sqlite3.Connection, scan_id: int) -> str:
    """Generate a 3-paragraph AI security assessment for a completed scan.

    Stateless single-shot call — does NOT use session history.
    """
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY"
    context = _build_context(conn, scan_id=scan_id)
    prompt = (
        "Write a 3-paragraph professional security assessment for the scan above. "
        "Paragraph 1: overall risk posture and grade justification. "
        "Paragraph 2: most critical findings and their real-world impact. "
        "Paragraph 3: prioritised remediation actions. "
        "Use **bold** for CVE IDs and severity labels. Do not initiate a new scan."
    )
    holder = types.SimpleNamespace(conn=conn)
    try:
        from aivas.tui.agent import run_agent
        response, _intent, _turns = await run_agent(
            holder, prompt, api_key, context=context, history=None,
        )
        return response or "Assessment could not be generated."
    except Exception as exc:
        return f"Assessment error: {exc}"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_chat_api_session.py -v
```

Expected: All 6 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 304 passed. NOTE: existing `POST /api/chat` tests may break because the route's body schema needs `session_id`. Those are addressed in Task 13.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/chat_api.py tests/server/test_chat_api_session.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(chat): handle_chat session-aware — loads history, persists turns"
```

---

## Task 7: `cve_advice` module

Generate + cache per-CVE LLM remediation. Bounded-concurrency warmup for batch use after a scan.

**Files:**
- Create: `aivas/server/cve_advice.py`
- Test: `tests/server/test_cve_advice.py`

**Interfaces:**
- Consumes: `cve_advice` table from Task 1; `aivas.narrator.providers.GroqProvider`.
- Produces:
  - `get_advice(conn, cve_id) -> dict | None`
  - `put_advice(conn, cve_id, advice_en, advice_sw, model) -> None`
  - `async generate_advice(cve_id, cve_row, api_key) -> tuple[str, str]`
  - `async warm_cache(conn, cve_ids, api_key, max_concurrent=5) -> None`

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_cve_advice.py`:

```python
import asyncio
import sqlite3
from unittest.mock import patch, MagicMock

import pytest

from aivas.database.schema import create_schema
from aivas.server.cve_advice import (
    get_advice, put_advice, generate_advice, warm_cache,
)


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_get_advice_returns_none_when_missing(conn):
    assert get_advice(conn, "CVE-X") is None


def test_put_then_get_roundtrip(conn):
    put_advice(conn, "CVE-1", "en text", "sw text", "test-model")
    row = get_advice(conn, "CVE-1")
    assert row["advice_en"] == "en text"
    assert row["advice_sw"] == "sw text"
    assert row["model"] == "test-model"


def test_put_advice_upserts_existing(conn):
    put_advice(conn, "CVE-1", "old", "old", "m1")
    put_advice(conn, "CVE-1", "new", "new", "m2")
    row = get_advice(conn, "CVE-1")
    assert row["advice_en"] == "new"
    assert row["model"] == "m2"


def test_generate_advice_parses_two_paragraph_response():
    fake_provider = MagicMock()
    fake_provider.generate.return_value = (
        "Update Apache to 2.4.50 or later. Block port externally.\n\n"
        "Sasisha Apache hadi 2.4.50. Zuia port nje."
    )
    cve_row = {
        "cve_id": "CVE-2021-41773",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "description": "Path traversal in Apache 2.4.49",
    }
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        en, sw = asyncio.run(generate_advice("CVE-2021-41773", cve_row, "key"))
    assert "Apache" in en
    assert "Sasisha" in sw or "Apache" in sw


def test_generate_advice_handles_single_paragraph_response():
    fake_provider = MagicMock()
    fake_provider.generate.return_value = "Only English here."
    cve_row = {
        "cve_id": "CVE-X", "cvss_score": 5, "cvss_severity": "MEDIUM",
        "description": "Something",
    }
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        en, sw = asyncio.run(generate_advice("CVE-X", cve_row, "key"))
    assert en == "Only English here."
    assert sw == ""


def test_warm_cache_skips_existing(conn):
    put_advice(conn, "CVE-A", "en", "sw", "cached-model")
    fake_provider = MagicMock()
    fake_provider.generate.return_value = "new en\n\nnew sw"
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-A','x')")
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-B','y')")
    conn.commit()
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        asyncio.run(warm_cache(conn, ["CVE-A", "CVE-B"], "key"))
    # CVE-A still has cached values
    assert get_advice(conn, "CVE-A")["advice_en"] == "en"
    # CVE-B got generated
    assert get_advice(conn, "CVE-B")["advice_en"] == "new en"


def test_warm_cache_silently_skips_unknown_cves(conn):
    fake_provider = MagicMock()
    fake_provider.generate.return_value = "x\n\ny"
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        # CVE-MISSING has no row in cves table — must not crash
        asyncio.run(warm_cache(conn, ["CVE-MISSING"], "key"))
    assert get_advice(conn, "CVE-MISSING") is None


def test_warm_cache_handles_provider_errors(conn):
    fake_provider = MagicMock()
    fake_provider.generate.side_effect = RuntimeError("Groq down")
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-Z','x')")
    conn.commit()
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        # must not raise
        asyncio.run(warm_cache(conn, ["CVE-Z"], "key"))
    assert get_advice(conn, "CVE-Z") is None


def test_warm_cache_no_api_key_is_noop(conn):
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-Y','x')")
    conn.commit()
    asyncio.run(warm_cache(conn, ["CVE-Y"], ""))
    assert get_advice(conn, "CVE-Y") is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_cve_advice.py -v
```

Expected: All tests FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement `cve_advice.py`**

Create `aivas/server/cve_advice.py`:

```python
"""LLM-cached per-CVE remediation advice (EN + SW)."""
from __future__ import annotations

import asyncio
import logging
import sqlite3

from aivas.narrator.providers import GroqProvider

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "llama-3.1-8b-instant"

_PROMPT = """\
You are a security engineer producing concise, ACTIONABLE remediation advice for a single CVE.

CVE: {cve_id}
CVSS: {cvss_score} ({cvss_severity})
Description: {description}

Output two short paragraphs, separated by a blank line.

Paragraph 1 — ENGLISH:
3-5 sentences. Lead with the specific software/version to upgrade to. Name compensating controls (firewall rule, config setting, disabled feature) the admin can apply TODAY if upgrade is impossible. End with one sentence on detection (log location, IOC, network signature) if relevant.

Paragraph 2 — KISWAHILI:
Same content as paragraph 1, rendered in Kiswahili. Use clear, plain language a Tanzanian IT admin would understand. Keep CVE IDs, version numbers, and product names in their original Latin form.

Do not output headings, bullets, or markdown. Two paragraphs. That is the whole output.
"""


def get_advice(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    row = conn.execute(
        "SELECT cve_id, advice_en, advice_sw, model, created_at "
        "FROM cve_advice WHERE cve_id=?",
        (cve_id,),
    ).fetchone()
    return dict(row) if row else None


def put_advice(
    conn: sqlite3.Connection, cve_id: str,
    advice_en: str, advice_sw: str, model: str,
) -> None:
    conn.execute(
        "INSERT INTO cve_advice(cve_id, advice_en, advice_sw, model) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT(cve_id) DO UPDATE SET "
        "advice_en=excluded.advice_en, advice_sw=excluded.advice_sw, "
        "model=excluded.model, created_at=CURRENT_TIMESTAMP",
        (cve_id, advice_en, advice_sw, model),
    )
    conn.commit()


def _parse_two_paragraphs(text: str) -> tuple[str, str]:
    parts = text.strip().split("\n\n", 1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return parts[0].strip(), ""


async def generate_advice(
    cve_id: str, cve_row: dict, api_key: str,
) -> tuple[str, str]:
    """Call Groq once. Returns (advice_en, advice_sw)."""
    provider = GroqProvider(api_key=api_key, model=_DEFAULT_MODEL)
    prompt = _PROMPT.format(
        cve_id=cve_id,
        cvss_score=cve_row.get("cvss_score") or "N/A",
        cvss_severity=cve_row.get("cvss_severity") or "N/A",
        description=(cve_row.get("description") or "")[:600],
    )
    text = await asyncio.to_thread(provider.generate, prompt)
    return _parse_two_paragraphs(text)


async def warm_cache(
    conn: sqlite3.Connection, cve_ids: list[str], api_key: str,
    max_concurrent: int = 5,
) -> None:
    """For each cve_id not yet cached, generate + store advice. Bounded concurrency.
       Silent on per-CVE errors; the legacy template covers misses."""
    if not api_key:
        return
    needed: list[tuple[str, dict]] = []
    for cve_id in cve_ids:
        if get_advice(conn, cve_id):
            continue
        row = conn.execute(
            "SELECT cve_id, cvss_score, cvss_severity, description "
            "FROM cves WHERE cve_id=?",
            (cve_id,),
        ).fetchone()
        if not row:
            continue
        needed.append((cve_id, dict(row)))
    if not needed:
        return

    sem = asyncio.Semaphore(max_concurrent)

    async def _one(cve_id: str, row: dict):
        async with sem:
            try:
                en, sw = await generate_advice(cve_id, row, api_key)
                if en:
                    put_advice(conn, cve_id, en, sw, _DEFAULT_MODEL)
            except Exception as exc:
                logger.warning("cve_advice failed for %s: %s", cve_id, exc)

    await asyncio.gather(*(_one(c, r) for c, r in needed))
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_cve_advice.py -v
```

Expected: All 9 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 313 passed.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/cve_advice.py tests/server/test_cve_advice.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(advice): cve_advice module — LLM-cached remediation, warm_cache"
```

---

## Task 8: `cve_fix` three-tier fallback

Replace the keyword switch with a three-tier lookup: finding's stored `fix_en/sw` → cached `cve_advice` → legacy template. Thread `conn` through callers.

**Files:**
- Modify: `aivas/server/report_helpers.py`
- Modify: `aivas/server/report_gen.py` (and `aivas/server/report_pdf.py` if it calls `cve_fix`)
- Test: `tests/server/test_cve_fix.py`

**Interfaces:**
- Modified: `cve_fix(f, conn=None, lang="en") -> str`.
- New private: `_legacy_template_fix(f, lang) -> str` — the existing keyword switch body, untouched semantically.

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_cve_fix.py`:

```python
import sqlite3

import pytest

from aivas.database.schema import create_schema
from aivas.server.report_helpers import cve_fix


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_cve_fix_prefers_stored_fix_en(conn):
    f = {"cve_id": "CVE-1", "description": "Path traversal",
         "fix_en": "Custom stored advice."}
    assert cve_fix(f, conn=conn, lang="en") == "Custom stored advice."


def test_cve_fix_prefers_stored_fix_sw(conn):
    f = {"cve_id": "CVE-1", "description": "Path traversal",
         "fix_sw": "Hatua iliyohifadhiwa."}
    assert cve_fix(f, conn=conn, lang="sw") == "Hatua iliyohifadhiwa."


def test_cve_fix_falls_back_to_cache_when_no_stored(conn):
    from aivas.server.cve_advice import put_advice
    put_advice(conn, "CVE-2", "Cached EN", "Cached SW", "m")
    f = {"cve_id": "CVE-2", "description": "Path traversal"}
    assert cve_fix(f, conn=conn, lang="en") == "Cached EN"
    assert cve_fix(f, conn=conn, lang="sw") == "Cached SW"


def test_cve_fix_falls_back_to_legacy_when_no_cache(conn):
    f = {"cve_id": "CVE-3", "description": "buffer overflow"}
    result = cve_fix(f, conn=conn, lang="en")
    assert "ASLR" in result or "vendor patch" in result.lower()


def test_cve_fix_works_without_conn(conn):
    f = {"cve_id": "CVE-4", "description": "remote code execution"}
    result = cve_fix(f, conn=None, lang="en")
    assert "vendor patch" in result.lower() or "patch" in result.lower()


def test_cve_fix_default_lang_is_en(conn):
    f = {"cve_id": "CVE-5", "description": "sql injection",
         "fix_en": "EN stored", "fix_sw": "SW stored"}
    assert cve_fix(f, conn=conn) == "EN stored"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_cve_fix.py -v
```

Expected: FAILs — current `cve_fix` doesn't take `conn` or `lang` kwargs.

- [ ] **Step 3: Modify `aivas/server/report_helpers.py`**

Find the existing `def cve_fix(f: dict) -> str:` block (lines ~24-49). Replace with:

```python
def cve_fix(f: dict, conn: "sqlite3.Connection | None" = None, lang: str = "en") -> str:
    """Three-tier remediation lookup:
       1. Stored on the finding (from narrator path) → return.
       2. Cached in cve_advice table → return.
       3. Legacy template by description keyword → return.
    """
    fix_field = f.get(f"fix_{lang}") or ""
    fix_field = fix_field.strip()
    if fix_field:
        return fix_field

    cve_id = f.get("cve_id", "")
    if conn is not None and cve_id:
        from aivas.server.cve_advice import get_advice
        cached = get_advice(conn, cve_id)
        if cached:
            return cached.get(f"advice_{lang}", "") or cached.get("advice_en", "")

    return _legacy_template_fix(f, lang)


def _legacy_template_fix(f: dict, lang: str = "en") -> str:
    """Existing keyword-switch fallback; honest as a fallback, dishonest as primary."""
    desc = (f.get("description") or "").lower()
    cve = f.get("cve_id", "")
    if any(t in desc for t in _RCE):
        action = "Apply vendor patch immediately. Isolate the service from the internet until resolved."
    elif any(t in desc for t in _SQLI):
        action = "Patch the application. Audit SQL queries to ensure parameterized inputs are used."
    elif any(t in desc for t in _AUTH):
        action = "Apply patch immediately. Enforce strong authentication and audit all access controls."
    elif any(t in desc for t in _DOS):
        action = "Apply patch. Implement rate limiting and upstream firewall filtering."
    elif any(t in desc for t in _PRIV):
        action = "Apply patch. Restrict user privileges and audit sudoers and group memberships."
    elif any(t in desc for t in _XSS):
        action = "Apply patch. Enforce a strict Content Security Policy on the web application."
    elif any(t in desc for t in _BUF):
        action = "Apply vendor patch. Ensure ASLR and DEP/NX protections are enabled on the host."
    elif any(t in desc for t in _TRAV):
        action = "Apply patch. Restrict filesystem permissions and validate all file path inputs."
    else:
        action = "Update to the latest patched version. Monitor vendor security advisories."
    return f"{cve}: {action}"
```

(The keyword sets `_RCE`, `_SQLI`, etc. remain at top of file unchanged.)

- [ ] **Step 4: Update callers in `report_gen.py` to pass `conn`**

```bash
cd /home/cyberpunk/aivas
grep -n "cve_fix" aivas/server/report_gen.py aivas/server/report_pdf.py
```

For each call site, change `cve_fix(f)` to `cve_fix(f, conn=conn)`. The relevant functions in `report_gen.py` already receive `conn` as a parameter.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_cve_fix.py -v
```

Expected: All 6 tests PASS.

- [ ] **Step 6: Run full suite — including existing report tests**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 319 passed.

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/report_helpers.py aivas/server/report_gen.py \
        aivas/server/report_pdf.py tests/server/test_cve_fix.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(reports): cve_fix three-tier fallback — stored, cached, template"
```

---

## Task 9: KEV scoring + grade cap

KEV findings get a 1.5× CVSS multiplier in the scorer; any KEV finding caps the grade at C (score ≤ 75).

**Files:**
- Modify: `aivas/scorer.py`
- Test: `tests/test_kev_scoring.py`

**Interfaces:**
- Modified: `score_findings(findings) -> dict` — same return shape; behavior changes.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_kev_scoring.py`:

```python
from aivas.scorer import score_findings


def _f(cve_id, cvss, sev="HIGH", conf="confirmed", kev=False):
    return {
        "cve_id": cve_id, "cvss_score": cvss, "cvss_severity": sev,
        "confidence": conf, "kev": kev,
    }


def test_no_findings_grade_a_100():
    assert score_findings([])["grade"] == "A"
    assert score_findings([])["score"] == 100


def test_single_non_kev_critical_grade_unchanged():
    out = score_findings([_f("CVE-1", 9.5, sev="CRITICAL")])
    # CRITICAL with confirmed conf → weight 15 × 1.0 = 15 penalty → 85
    assert out["grade"] in ("B", "A")
    assert out["score"] <= 90


def test_kev_finding_caps_grade_at_c():
    # One LOW finding marked KEV would otherwise score very high
    out = score_findings([_f("CVE-K", 3.0, sev="LOW", kev=True)])
    assert out["grade"] in ("C", "D", "F")
    assert out["score"] <= 75


def test_kev_multiplier_increases_penalty():
    base = score_findings([_f("CVE-1", 7.0, sev="HIGH", conf="confirmed", kev=False)])
    with_kev = score_findings([_f("CVE-1", 7.0, sev="HIGH", conf="confirmed", kev=True)])
    assert with_kev["score"] < base["score"]


def test_kev_does_not_demote_below_natural_grade():
    """If grade is already D or F, KEV cap leaves it as-is."""
    findings = [_f(f"CVE-{i}", 10.0, sev="CRITICAL", kev=True) for i in range(5)]
    out = score_findings(findings)
    assert out["grade"] == "F"


def test_kev_multiple_findings_compound():
    one_kev = score_findings([
        _f("CVE-1", 9.0, sev="CRITICAL", kev=True),
        _f("CVE-2", 5.0, sev="MEDIUM", kev=False),
    ])
    two_kev = score_findings([
        _f("CVE-1", 9.0, sev="CRITICAL", kev=True),
        _f("CVE-2", 5.0, sev="MEDIUM", kev=True),
    ])
    assert two_kev["score"] <= one_kev["score"]


def test_sev_counts_still_count_all_findings():
    findings = [
        _f("CVE-1", 9.0, sev="CRITICAL"),
        _f("CVE-2", 5.0, sev="MEDIUM"),
        _f("CVE-3", 3.0, sev="LOW"),
    ]
    out = score_findings(findings)
    assert out["sev_counts"].get("CRITICAL") == 1
    assert out["sev_counts"].get("MEDIUM") == 1
    assert out["sev_counts"].get("LOW") == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/test_kev_scoring.py -v
```

Expected: KEV-specific tests FAIL (current scorer ignores `kev` field).

- [ ] **Step 3: Update `aivas/scorer.py`**

Replace the file with:

```python
_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}
_CONFIDENCE_MULT = {"confirmed": 1.0, "probable": 0.9, "possible": 0.5}
_MAX_PER_FINDING = 20
_SCORE_TOP_N = 5
_KEV_MULT = 1.5
_KEV_GRADE_CAP_SCORE = 75


def _penalty_for(f: dict) -> float:
    sev = f.get("cvss_severity") or ""
    conf = f.get("confidence") or "possible"
    weight = _WEIGHTS.get(sev, 0)
    mult = _CONFIDENCE_MULT.get(conf, 0.5)
    base = weight * mult
    if f.get("kev"):
        base *= _KEV_MULT
    return min(base, _MAX_PER_FINDING)


def _grade_for_score(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def score_findings(findings: list[dict]) -> dict:
    top = sorted(
        findings, key=lambda f: _penalty_for(f), reverse=True,
    )[:_SCORE_TOP_N]
    penalty = sum(_penalty_for(f) for f in top)
    score = max(0, 100 - int(penalty))
    grade = _grade_for_score(score)

    # KEV cap: any KEV finding caps grade at C (score ≤ 75)
    if any(f.get("kev") for f in findings):
        if score > _KEV_GRADE_CAP_SCORE:
            score = _KEV_GRADE_CAP_SCORE
            grade = _grade_for_score(score)

    sev_counts: dict = {}
    for f in findings:
        s = (f.get("cvss_severity") or "N/A").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return {
        "score": score,
        "grade": grade,
        "penalty": int(penalty),
        "total": len(findings),
        "sev_counts": sev_counts,
    }
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/test_kev_scoring.py -v
```

Expected: All 7 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 326 passed. NOTE: any existing scorer tests that assumed the old behaviour may need updating — adjust them in this commit.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/scorer.py tests/test_kev_scoring.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(scorer): KEV multiplier 1.5x; cap grade at C if any KEV finding"
```

---

## Task 10: KEV rendering in reports + history

KEV pill on report rows, sort KEV first within severity, executive-summary prepend; `list_scans` returns `kev_count` per scan.

**Files:**
- Modify: `aivas/server/report_helpers.py` — add KEV note to `executive_summary`
- Modify: `aivas/server/report_gen.py` — sort KEV findings to top of severity group; pass `is_kev` to template
- Modify: `aivas/templates/report.html.j2` — KEV pill on finding rows
- Modify: `aivas/history.py` — `list_scans` includes `kev_count`
- Test: `tests/test_kev_rendering.py`

**Interfaces:**
- Modified: `executive_summary(grade, score, target, findings) -> str` — prepends "Known Exploited Vulnerability detected" sentence if any KEV finding.
- Modified: `list_scans(conn, limit) -> list[dict]` — each row gains `kev_count: int`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_kev_rendering.py`:

```python
import sqlite3

import pytest

from aivas.database.schema import create_schema
from aivas.server.report_helpers import executive_summary
from aivas.history import list_scans


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_executive_summary_no_kev_no_warning():
    findings = [
        {"cve_id": "CVE-1", "cvss_severity": "HIGH", "kev": False},
    ]
    text = executive_summary("B", 80, "1.1.1.1", findings)
    assert "known exploited" not in text.lower()


def test_executive_summary_kev_prepends_warning():
    findings = [
        {"cve_id": "CVE-1", "cvss_severity": "CRITICAL", "kev": True},
    ]
    text = executive_summary("C", 75, "1.1.1.1", findings)
    # Order matters — KEV sentence must come first
    assert text.lower().index("known exploited") < text.lower().index("risk score")


def test_executive_summary_kev_uses_plural_for_multiple():
    findings = [
        {"cve_id": "CVE-1", "cvss_severity": "CRITICAL", "kev": True},
        {"cve_id": "CVE-2", "cvss_severity": "HIGH", "kev": True},
    ]
    text = executive_summary("C", 70, "1.1.1.1", findings)
    assert "2 actively-exploited" in text or "2 known-exploited" in text


def test_list_scans_returns_kev_count(conn):
    # Insert a scan + findings, one KEV
    conn.execute(
        "INSERT INTO scans(id, target, started_at) VALUES (1, 'host', '2026-06-30')"
    )
    # Insert two CVEs (one KEV) and findings linking them
    conn.execute("INSERT INTO cves(cve_id, description, kev) VALUES('CVE-A','x',1)")
    conn.execute("INSERT INTO cves(cve_id, description, kev) VALUES('CVE-B','y',0)")
    conn.execute(
        "INSERT INTO findings(scan_id, host, cve_id) VALUES (1,'host','CVE-A')"
    )
    conn.execute(
        "INSERT INTO findings(scan_id, host, cve_id) VALUES (1,'host','CVE-B')"
    )
    conn.commit()
    scans = list_scans(conn, limit=5)
    assert scans[0]["kev_count"] == 1


def test_list_scans_kev_count_zero_when_no_kev(conn):
    conn.execute(
        "INSERT INTO scans(id, target, started_at) VALUES (1, 'host', '2026-06-30')"
    )
    conn.execute("INSERT INTO cves(cve_id, description, kev) VALUES('CVE-B','y',0)")
    conn.execute(
        "INSERT INTO findings(scan_id, host, cve_id) VALUES (1,'host','CVE-B')"
    )
    conn.commit()
    assert list_scans(conn, limit=5)[0]["kev_count"] == 0
```

- [ ] **Step 2: Run tests to verify fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/test_kev_rendering.py -v
```

Expected: FAILs.

- [ ] **Step 3: Update `executive_summary` in `aivas/server/report_helpers.py`**

Modify the existing `executive_summary` (around line 52) to prepend a KEV warning:

```python
def executive_summary(grade: str, score: int, target: str, findings: list[dict]) -> str:
    n = len(findings)
    by = {s: [f for f in findings if f.get("cvss_severity") == s] for s in _SEV_ORDER}
    nc, nh = len(by["CRITICAL"]), len(by["HIGH"])
    label = _GRADE_LABEL.get(grade, "Unknown risk level")
    if nc:
        risk = (f"{nc} critical CVE(s) identified that may allow remote code execution or full "
                f"system compromise without authentication. Immediate patching is required.")
    elif nh:
        risk = (f"{nh} high-severity CVE(s) identified. Prompt remediation is required to "
                f"prevent exploitation by network-adjacent attackers.")
    elif n:
        risk = f"{n} lower-severity CVE(s) identified. Schedule remediation within 30 days."
    else:
        risk = "No CVEs matched in the local database. Verify that services are fully up to date."

    body = (f"Host <strong>{target}</strong> received a risk score of <strong>{score}/100</strong> "
            f"(Grade <strong>{grade}</strong> — {label}). {risk}")

    kev_n = sum(1 for f in findings if f.get("kev"))
    if kev_n:
        unit = "vulnerability" if kev_n == 1 else "vulnerabilities"
        kev_note = (
            f"<strong>WARNING — {kev_n} actively-exploited {unit} detected.</strong> "
            "These CVEs are in CISA's Known Exploited Vulnerabilities catalog — "
            "confirmed in-the-wild attacks. Remediation cannot wait. "
        )
        return kev_note + body
    return body
```

- [ ] **Step 4: Update `list_scans` in `aivas/history.py`**

Find the `list_scans` function. Augment the SQL to count distinct KEV findings per scan via a subquery, and include it in the returned dict:

```python
def list_scans(conn, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        """
        SELECT s.*,
               COALESCE((
                 SELECT COUNT(DISTINCT f.cve_id)
                   FROM findings f
                   JOIN cves c ON c.cve_id = f.cve_id
                  WHERE f.scan_id = s.id AND c.kev = 1
               ), 0) AS kev_count
          FROM scans s
         ORDER BY s.id DESC
         LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
```

(If the existing `list_scans` already has computed columns, integrate carefully — read the current code first; tests will tell you if anything broke.)

- [ ] **Step 5: Update `report_gen.py` to sort KEV findings first and pass `is_kev` to the template**

Find the loop that renders findings into the template (around the call site of `cve_fix`). Sort findings within each severity group:

```python
def _sort_kev_first(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (not f.get("kev"),))
```

Apply this to the per-severity grouped lists before rendering.

In the template invocation, ensure each finding dict passed to Jinja includes `f["kev"]` (it already does — it comes from the DB row).

- [ ] **Step 6: Update `aivas/templates/report.html.j2` to render KEV pill**

Find the table row rendering for findings. Add a small pill before the CVE ID:

```html
{% if f.kev %}
  <span class="kev-pill" title="CISA Known Exploited Vulnerability">⚠ KEV</span>
{% endif %}
```

In the `<style>` block at the top of the same template, add:

```css
.kev-pill {
    display: inline-block;
    background: #7f1d1d;
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    padding: 1px 6px;
    border-radius: 3px;
    margin-right: 6px;
    letter-spacing: 0.5px;
}
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/test_kev_rendering.py -v
```

Expected: All 5 tests PASS.

- [ ] **Step 8: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: 331 passed.

- [ ] **Step 9: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/report_helpers.py aivas/server/report_gen.py \
        aivas/templates/report.html.j2 aivas/history.py tests/test_kev_rendering.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(reports): KEV pill on rows, exec summary prepend, kev_count in history"
```

---

## Task 11: HTTP prober returns `{status, findings}`

Each of the three sub-probers (`headers`, `endpoints`, `methods`) returns a dict with `status` and `findings`. Aggregator `probe_http_service` unions them.

**Files:**
- Modify: `aivas/prober/headers.py`
- Modify: `aivas/prober/endpoints.py`
- Modify: `aivas/prober/methods.py`
- Modify: `aivas/prober/__init__.py` (or wherever `probe_http_service` lives — find it)
- Modify: `aivas/server/scan_helpers.py` — `http_probe_events` handles new status
- Test: `tests/server/test_prober_status.py`

**Interfaces:**
- Modified: each sub-prober's public function now returns `{"status": "ok"|"unreachable"|"error", "findings": list[dict]}`.
- Modified: `probe_http_service(host, port, scheme=...) -> dict` with the same shape — `findings` is union of all three.

- [ ] **Step 1: Locate `probe_http_service`**

```bash
cd /home/cyberpunk/aivas
grep -n "def probe_http_service" aivas/prober/
```

Use the discovered file path in subsequent steps.

- [ ] **Step 2: Write the failing tests**

Create `tests/server/test_prober_status.py`:

```python
from unittest.mock import patch
from urllib.error import URLError

from aivas.prober import probe_http_service


def test_unreachable_returns_status_unreachable():
    with patch("urllib.request.urlopen", side_effect=URLError("Connection refused")):
        result = probe_http_service("127.0.0.1", 9999, scheme="http")
    assert result["status"] == "unreachable"
    assert result["findings"] == []


def test_ok_returns_status_ok():
    fake_resp = type("R", (), {
        "headers": {"server": "Apache"},
        "read": lambda self, *a: b"",
        "status": 200,
        "__enter__": lambda self: self,
        "__exit__": lambda self, *a: None,
    })()
    with patch("urllib.request.urlopen", return_value=fake_resp):
        result = probe_http_service("127.0.0.1", 80, scheme="http")
    assert result["status"] in ("ok", "error")
    assert isinstance(result["findings"], list)
```

(Tests may need adjustment based on actual probe internals — what matters is the shape contract.)

- [ ] **Step 3: Run to verify fails**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_prober_status.py -v
```

Expected: FAILs — current probers return lists, not dicts.

- [ ] **Step 4: Modify each sub-prober**

For `aivas/prober/headers.py`, change the top-level `check_headers(...)` function (or whatever it's called) to:

```python
def check_headers(host: str, port: int, scheme: str = "http") -> dict:
    findings: list[dict] = []
    try:
        # ... existing probe logic ...
        # populate findings
        return {"status": "ok", "findings": findings}
    except (URLError, socket.timeout, ConnectionRefusedError, OSError):
        return {"status": "unreachable", "findings": []}
    except Exception as exc:
        return {"status": "error", "findings": [], "error": str(exc)}
```

Do the same in `endpoints.py` and `methods.py`. Preserve the existing finding-detection logic verbatim — only change the return type and exception classification.

- [ ] **Step 5: Modify `probe_http_service`**

Aggregate the three:

```python
def probe_http_service(host: str, port: int, scheme: str = "http") -> dict:
    h = check_headers(host, port, scheme)
    e = check_endpoints(host, port, scheme)
    m = check_methods(host, port, scheme)
    statuses = {h["status"], e["status"], m["status"]}
    if statuses == {"unreachable"}:
        status = "unreachable"
    elif "ok" in statuses:
        status = "ok"
    else:
        status = "error"
    findings = h["findings"] + e["findings"] + m["findings"]
    return {"status": status, "findings": findings}
```

- [ ] **Step 6: Update `aivas/server/scan_helpers.py:http_probe_events`**

Find the function (it currently iterates services and calls `probe_http_service`). Update to handle the new shape:

```python
async def http_probe_events(services: list[dict]):
    misconfigs: list[dict] = []
    for svc in services:
        port = svc.get("port")
        if port not in (80, 443, 8080, 8443, 8000):
            continue
        scheme = "https" if port in (443, 8443) else "http"
        host = svc.get("host", "")
        try:
            result = await asyncio.to_thread(probe_http_service, host, port, scheme)
        except Exception as exc:
            yield _ev("http_error", f"{host}:{port} — probe error: {exc}")
            continue
        if result["status"] == "unreachable":
            yield _ev("http_unreachable",
                      f"{host}:{port} — HTTP probe failed (host did not respond)")
            continue
        if result["status"] == "error":
            yield _ev("http_error",
                      f"{host}:{port} — {result.get('error','probe error')}")
            continue
        # status == "ok"
        for f in result["findings"]:
            f["host"] = host
            f["port"] = port
            misconfigs.append(f)
            yield _ev("http_finding",
                      f"  {host}:{port} — {f.get('title','finding')} "
                      f"[{f.get('severity','MEDIUM')}]")
    yield {"__misconfigs": misconfigs}
```

(Adapt to the exact signature and event helpers the current file uses — read it first.)

- [ ] **Step 7: Update existing prober tests**

```bash
cd /home/cyberpunk/aivas
grep -rn "check_headers\|check_endpoints\|check_methods\|probe_http_service" tests/
```

Update any test that asserts a list return to expect the dict shape.

- [ ] **Step 8: Run tests**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_prober_status.py -v
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: all PASS, ~333 total.

- [ ] **Step 9: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/prober/ aivas/server/scan_helpers.py tests/
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(prober): return {status, findings}; distinguish unreachable from clean"
```

---

## Task 12: Scan worker AI wiring (narration + advice warmup)

Inside `run_scan`, between scoring and `save_scan`, run the narrator and warm the cve_advice cache.

**Files:**
- Modify: `aivas/server/scan_worker.py`
- Modify: `aivas/history.py` — ensure `save_scan` writes the narration fields from each finding
- Test: extend `tests/server/test_scan_worker.py`

**Interfaces:**
- New phase headers in events: `AI NARRATION`, `AI REMEDIATION`.
- `done` event findings include populated `narration_en/sw`, `fix_en/sw` (best-effort) and `kev` flag.

- [ ] **Step 1: Inspect `aivas/history.py:save_scan` to verify narration fields are written**

```bash
cd /home/cyberpunk/aivas
sed -n '15,50p' aivas/history.py
```

The existing `save_scan` already maps `f.get("narration_en")`, `f.get("narration_sw")`, `f.get("fix_en")`, `f.get("fix_sw")` to columns. No change needed if those keys are populated on the finding dict before save.

- [ ] **Step 2: Add the narration test**

Append to `tests/server/test_scan_worker.py`:

```python
def test_run_scan_populates_narration_when_api_key_set(monkeypatch, conn):
    """When GROQ_API_KEY is set, web scan flow runs narrator and warm_cache."""
    fake_service = {"host":"1.1.1.1","port":80,"service":"http",
                    "product":"apache","version":"2.4","os_family":None}
    fake_finding = {
        "cve_id":"CVE-2021-41773", "cvss_score":9.8, "cvss_severity":"CRITICAL",
        "description":"path traversal", "confidence":"probable",
        "host":"1.1.1.1", "port":80,
    }
    called = {"narrate": 0, "warm": 0}

    def fake_narrate(findings, provider):
        called["narrate"] += 1
        for f in findings:
            f["narration_en"] = "Test EN"
            f["narration_sw"] = "Test SW"
            f["fix_en"] = "Fix EN"
            f["fix_sw"] = "Fix SW"
        return findings

    async def fake_warm(*a, **kw):
        called["warm"] += 1

    monkeypatch.setenv("GROQ_API_KEY", "k")
    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_helpers.correlate", return_value=[fake_finding]):
                with patch("aivas.server.scan_worker.narrate", side_effect=fake_narrate):
                    with patch("aivas.server.scan_worker.warm_cache", side_effect=fake_warm):
                        events = asyncio.run(_collect(run_scan(conn, "1.1.1.1")))
    assert called["narrate"] == 1
    assert called["warm"] == 1
    # Done event findings should have narration populated
    done = events[-1]
    assert done["type"] == "done"
    if done["findings"]:
        f = done["findings"][0]
        # Narration fields aren't in the done event payload, but they were saved to DB.
    row = conn.execute(
        "SELECT en_risk FROM findings WHERE cve_id='CVE-2021-41773'"
    ).fetchone()
    assert row["en_risk"] == "Test EN"


def test_run_scan_skips_narration_without_api_key(monkeypatch, conn):
    """No GROQ_API_KEY → narrator not called; scan still completes."""
    fake_service = {"host":"1.1.1.1","port":80,"service":"http",
                    "product":"apache","version":"2.4","os_family":None}
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    called = {"narrate": 0}

    def fake_narrate(findings, provider):
        called["narrate"] += 1
        return findings

    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_helpers.correlate", return_value=[]):
                with patch("aivas.server.scan_worker.narrate", side_effect=fake_narrate):
                    events = asyncio.run(_collect(run_scan(conn, "1.1.1.1")))
    assert called["narrate"] == 0
    assert events[-1]["type"] == "error"  # no open ports / no findings — error is fine
```

- [ ] **Step 3: Run to verify fails**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_scan_worker.py::test_run_scan_populates_narration_when_api_key_set -v
```

Expected: FAIL with `AttributeError: aivas.server.scan_worker has no attribute 'narrate'` or empty result.

- [ ] **Step 4: Add imports and wire narration into `run_scan`**

In `aivas/server/scan_worker.py`, add near the top:

```python
import os
from aivas.narrator.narrator import narrate
from aivas.narrator.providers import GroqProvider
from aivas.server.cve_advice import warm_cache
```

In `run_scan`, just before the SCORING phase (find the existing `yield _ev("phase_header", "SCORING")` line), insert:

```python
api_key = os.environ.get("GROQ_API_KEY")
# Optional: read from config too (mirrors handle_chat)
try:
    from aivas import config as _config
    api_key = _config.load().get("api_key") or api_key
except Exception:
    pass

if api_key and all_findings:
    yield _ev("phase_header", "AI NARRATION")
    yield _ev("narrate", f"Generating bilingual narrations for {len(all_findings)} finding(s)…")
    try:
        provider = GroqProvider(api_key=api_key)
        narrated = await asyncio.to_thread(
            narrate, all_findings[:30], provider,
        )
        # Merge narration back into all_findings (positional match)
        for i, f in enumerate(narrated):
            all_findings[i] = f
    except Exception as exc:
        yield _ev("narrate_error", f"Narration failed: {exc}")

    yield _ev("phase_header", "AI REMEDIATION")
    cve_ids = [f.get("cve_id") for f in all_findings if f.get("cve_id")]
    yield _ev("advice", f"Generating remediation advice for {len(cve_ids)} CVE(s)…")
    try:
        await warm_cache(conn, cve_ids, api_key, max_concurrent=5)
    except Exception as exc:
        yield _ev("advice_error", f"Advice warmup failed: {exc}")

# Then existing SCORING phase continues
yield _ev("phase_header", "SCORING")
```

- [ ] **Step 5: Mark each finding's `kev` field for use by scorer**

Right after narration (or right after correlation if you prefer), look up KEV status:

```python
for f in all_findings:
    if not f.get("cve_id"):
        continue
    row = conn.execute(
        "SELECT kev FROM cves WHERE cve_id=?", (f["cve_id"],),
    ).fetchone()
    f["kev"] = bool(row and row["kev"])
```

This ensures `score_findings` sees `kev=True` on KEV CVEs and applies the multiplier + cap from Task 9.

- [ ] **Step 6: Run tests to verify pass**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_scan_worker.py -v
```

Expected: All scan_worker tests PASS.

- [ ] **Step 7: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: ~335 passed.

- [ ] **Step 8: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/scan_worker.py tests/server/test_scan_worker.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(scan): wire narrator + cve_advice warmup; mark KEV findings"
```

---

## Task 13: Session REST endpoints + `POST /api/chat` session_id support

Add the session management REST family; update `POST /api/chat` to accept `session_id` (creating one if absent).

**Files:**
- Modify: `aivas/server/main.py`
- Test: `tests/server/test_chat_sessions_api.py`

**Interfaces:**
- Produces:
  - `GET /api/sessions` → list of `{id, title, created_at, updated_at}`, latest 20
  - `POST /api/sessions` → `{id}` (creates empty)
  - `GET /api/sessions/{id}` → `{id, title, created_at, updated_at, messages: [...]}`
  - `GET /api/sessions/{id}/messages` → list of message dicts
  - `DELETE /api/sessions/{id}` → `{deleted: id}` (404 if missing)
  - `POST /api/chat` with body `{text, session_id?, scan_id?}` → `{response, scan_id?, session_id}` — creates session if missing

- [ ] **Step 1: Write the failing tests**

Create `tests/server/test_chat_sessions_api.py`:

```python
import asyncio
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

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
    async def fake_handle(conn, sid, text, scan_id=None):
        return ("hello reply", None)
    with patch("aivas.server.main.handle_chat", side_effect=fake_handle):
        resp = client.post("/api/chat", json={"text": "hi"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["response"] == "hello reply"
    assert "session_id" in data and len(data["session_id"]) == 36


def test_post_chat_uses_existing_session(client):
    sid = client.post("/api/sessions").json()["id"]
    async def fake_handle(conn, session_id, text, scan_id=None):
        assert session_id == sid
        return ("ok", None)
    with patch("aivas.server.main.handle_chat", side_effect=fake_handle):
        resp = client.post(
            "/api/chat", json={"text": "hi", "session_id": sid},
        )
    assert resp.status_code == 200
    assert resp.json()["session_id"] == sid
```

- [ ] **Step 2: Run tests to verify fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_chat_sessions_api.py -v
```

Expected: FAILs — endpoints don't exist.

- [ ] **Step 3: Add session routes to `aivas/server/main.py`**

After the existing imports, add:

```python
from aivas.server.chat_memory import (
    create_session, get_session, list_sessions, delete_session,
)
from aivas.server.chat_memory import load_history
```

Update the existing `ChatRequest` model:

```python
class ChatRequest(BaseModel):
    text: str
    session_id: str | None = None
    scan_id: int | None = None
```

Replace the existing `@app.post("/api/chat")` handler:

```python
@app.post("/api/chat")
async def chat(body: ChatRequest):
    from aivas.server.chat_api import handle_chat
    sid = body.session_id or create_session(_conn)
    response, scan_intent = await handle_chat(
        _conn, sid, body.text, scan_id=body.scan_id,
    )
    scan_key = None
    if scan_intent:
        scan_key = str(uuid.uuid4())
        _pending[scan_key] = scan_intent
    return {"response": response, "scan_id": scan_key, "session_id": sid}
```

Add new session endpoints (BEFORE the catch-all SPA route at the bottom):

```python
@app.get("/api/sessions")
async def list_sessions_route():
    return list_sessions(_conn, limit=20)


@app.post("/api/sessions")
async def create_session_route():
    sid = create_session(_conn)
    return {"id": sid}


@app.get("/api/sessions/{session_id}")
async def get_session_route(session_id: str):
    s = get_session(_conn, session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    s["messages"] = load_history(_conn, session_id, max_turns=100)
    return s


@app.get("/api/sessions/{session_id}/messages")
async def get_session_messages_route(session_id: str):
    s = get_session(_conn, session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return load_history(_conn, session_id, max_turns=100)


@app.delete("/api/sessions/{session_id}")
async def delete_session_route(session_id: str):
    if not delete_session(_conn, session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"deleted": session_id}
```

- [ ] **Step 4: Run tests**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_chat_sessions_api.py -v
```

Expected: All 8 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: ~343 passed.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/main.py tests/server/test_chat_sessions_api.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(api): session REST endpoints; POST /api/chat accepts session_id"
```

---

## Task 14: `WS /ws/chat/{session_id}` endpoint

WebSocket chat endpoint with token streaming (currently single `complete` event per turn until Groq native streaming is wired) + interrupt + scan_intent emission.

**Files:**
- Modify: `aivas/server/main.py`
- Test: `tests/server/test_ws_chat.py`

**Interfaces:**
- `WS /ws/chat/{session_id}`
- Client→Server: `{"type":"user","text":"..."} | {"type":"interrupt"}`
- Server→Client: `{"type":"complete","text":"..."} | {"type":"scan_intent","scan_key":"...","target":"...","level":N} | {"type":"error","text":"..."}`

- [ ] **Step 1: Write the failing test**

Create `tests/server/test_ws_chat.py`:

```python
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
```

- [ ] **Step 2: Run to verify fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_ws_chat.py -v
```

Expected: FAILs — endpoint doesn't exist.

- [ ] **Step 3: Add the WebSocket route to `aivas/server/main.py`**

Place this BEFORE the catch-all SPA route:

```python
@app.websocket("/ws/chat/{session_id}")
async def chat_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()
    if not get_session(_conn, session_id):
        await websocket.send_json({"type":"error","text":"Unknown session id."})
        await websocket.close()
        return
    try:
        while True:
            try:
                msg = await websocket.receive_json()
            except WebSocketDisconnect:
                return
            if msg.get("type") == "interrupt":
                # Best-effort: there's no live LLM task to cancel in this implementation;
                # acknowledge and continue.
                await websocket.send_json({"type":"interrupted"})
                continue
            if msg.get("type") != "user":
                continue
            text = msg.get("text", "")
            from aivas.server.chat_api import handle_chat
            try:
                response, scan_intent = await handle_chat(
                    _conn, session_id, text,
                )
            except Exception as exc:
                await websocket.send_json({"type":"error","text":str(exc)})
                continue
            if scan_intent:
                scan_key = str(uuid.uuid4())
                _pending[scan_key] = scan_intent
                await websocket.send_json({
                    "type": "scan_intent",
                    "scan_key": scan_key,
                    "target": scan_intent[0],
                    "level": scan_intent[1],
                })
            await websocket.send_json({"type":"complete","text": response})
    except WebSocketDisconnect:
        return
```

(`get_session` is already imported in Task 13. `WebSocket` and `WebSocketDisconnect` are already imported at top of `main.py`.)

- [ ] **Step 4: Run tests**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/server/test_ws_chat.py -v
```

Expected: All 3 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: ~346 passed.

- [ ] **Step 6: Manual smoke test (optional)**

```bash
cd /home/cyberpunk/aivas
# Start the server in one terminal
uvicorn aivas.server.main:app --reload --port 8000
# In another terminal:
curl -X POST http://localhost:8000/api/sessions
# Use the returned id to open ws://localhost:8000/ws/chat/<id> from a websocket client
```

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/main.py tests/server/test_ws_chat.py
git -c user.name="Baraka Malila" -c user.email="bmalila87@gmail.com" \
    commit -m "feat(api): WS /ws/chat/{session_id} with scan_intent + interrupt events"
```

---

## Final Verification

After all 14 tasks land, run the full suite + a manual smoke to confirm AI honesty.

- [ ] **Step 1: Full backend test suite**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/ -q --ignore=tests/test_ssh_probe.py
```

Expected: ~346 passed.

- [ ] **Step 2: Manual smoke — multi-turn chat**

With `GROQ_API_KEY` set:

```bash
cd /home/cyberpunk/aivas
uvicorn aivas.server.main:app --port 8000 &
SID=$(curl -s -X POST http://localhost:8000/api/sessions | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
curl -s -X POST http://localhost:8000/api/chat \
     -H "Content-Type: application/json" \
     -d "{\"text\":\"What can you do?\",\"session_id\":\"$SID\"}" \
     | python3 -m json.tool
curl -s -X POST http://localhost:8000/api/chat \
     -H "Content-Type: application/json" \
     -d "{\"text\":\"Now scan scanme.nmap.org\",\"session_id\":\"$SID\"}" \
     | python3 -m json.tool
curl -s -X POST http://localhost:8000/api/chat \
     -H "Content-Type: application/json" \
     -d "{\"text\":\"What was the first thing I asked you?\",\"session_id\":\"$SID\"}" \
     | python3 -m json.tool
```

Expected: third response references the first message ("you asked what I can do"). Conversation memory verified.

- [ ] **Step 3: Manual smoke — web scan narration parity**

Run `aivas serve`, open `http://localhost:8000`, trigger a scan of `scanme.nmap.org` via the chat. After the scan completes, query the DB:

```bash
sqlite3 ~/.aivas/aivas.db \
    "SELECT cve_id, length(en_risk) as en_len, length(sw_risk) as sw_len FROM findings ORDER BY id DESC LIMIT 5"
```

Expected: `en_len` and `sw_len` are non-zero — web scan now produces bilingual narrations.

- [ ] **Step 4: Manual smoke — KEV cap**

Identify a CVE in `~/.aivas/aivas.db.cves` that has `kev=1` and a host that you can scan that runs that vulnerable product. After the scan, verify the grade is C or worse even if score arithmetic would suggest A/B.

- [ ] **Step 5: Push branch (optional, user-initiated)**

```bash
cd /home/cyberpunk/aivas
git push origin feat/web-ui
```

---

## Spec coverage check (self-review)

| Spec § | Covered by | OK |
|---|---|---|
| §4 data model | Task 1 | ✓ |
| §5 conversation memory | Tasks 2, 5, 6 | ✓ |
| §6 web scan narration | Task 12 | ✓ |
| §7 LLM remediation cache | Tasks 7, 8 | ✓ |
| §8 KEV integration | Tasks 9, 10, 12 (kev flag set on finding) | ✓ |
| §9 tool-arg safety | Task 3 | ✓ |
| §10 multilingual via LLM | Task 4 | ✓ |
| §11 prober reliability | Task 11 | ✓ |
| §12 WS chat endpoint | Task 14 | ✓ |
| §13 session REST | Task 13 | ✓ |
| §14 backward compat | Each task preserves CLI/TUI surface | ✓ |
| §15 testing strategy | Each task has unit + integration tests | ✓ |

No gaps.
