# AI Core Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every bug that makes the AI wrong, amnesiac, or fragile — seven targeted changes across the TUI agent, web harness, tool registry, history API, and two frontend hooks.

**Architecture:** Five independent tasks, each touching a different layer: TUI memory (ai.py + app.py), web harness reliability (chat_stream.py), discover_hosts tool with async refactor (agent.py + agent_prompts.py + chat_stream.py async update), history severity counts (history.py), and two frontend patches (App.jsx + useScan.js). Tasks 1–4 are pure Python with pytest coverage; Task 5 is frontend-only (verified by build + visual check).

**Tech Stack:** Python 3, FastAPI, Textual TUI, Groq SDK, asyncio, SQLite, React, Vite

## Global Constraints

- No file exceeds 200 lines of code
- One module = one responsibility
- No new dependencies (no new pip or npm packages)
- All existing tests must continue to pass after each task
- `discover_hosts` must degrade gracefully when nmap lacks `cap_net_raw` — return IPs + hostnames only, note MAC requires root in a `note` field
- Commits must use author `Baraka Malila <bmalila87@gmail.com>`

---

## File Map

| File | Task | What changes |
|---|---|---|
| `aivas/tui/app.py` | 1 | Add `_chat_history: list[dict] = []` to `__init__`; reset it in `action_clear_output` |
| `aivas/tui/ai.py` | 1 | Pass and persist history through `dispatch()` |
| `aivas/server/chat_stream.py` | 2, 3 | Task 2: model upgrade, retry, tool errors as JSON, context injection. Task 3: make `_exec_tool_local` async |
| `aivas/tui/agent.py` | 3 | Make `_exec_tool` async; add `discover_hosts` branch; raise truncation caps; await `_exec_tool` in `run_agent` |
| `aivas/tui/agent_prompts.py` | 3 | Add `discover_hosts` schema; add ROUTING RULE and HONESTY RULE to SYSTEM |
| `aivas/history.py` | 4 | Add `critical_count` subquery to `list_scans()` |
| `frontend/src/App.jsx` | 5 | Welcome-back: use `scan.critical_count` and `scan.kev_count` from history API |
| `frontend/src/hooks/useScan.js` | 5 | `ws.onerror` must call `onDoneRef` so frozen scan card is replaced |
| `tests/test_tui_memory.py` | 1 | New: TUI memory accumulation + cap tests |
| `tests/test_agent.py` | 3 | New: discover_hosts parsing, truncation caps, schema presence |
| `tests/test_history.py` | 4 | Add: `critical_count` returned by `list_scans()` |
| `tests/server/test_chat_stream.py` | 2 | Add: retry test, tool error test, context injection test |

---

## Task 1: TUI Conversation Memory

**Files:**
- Modify: `aivas/tui/app.py:64-80` (`__init__`), `aivas/tui/app.py:185` (`action_clear_output`)
- Modify: `aivas/tui/ai.py:83` (`dispatch`)
- Create: `tests/test_tui_memory.py`

**Interfaces:**
- Consumes: `run_agent(app, text, api_key, context=..., history=...) -> (str, tuple|None, list[dict])` — already accepts `history` keyword arg
- Produces: `app._chat_history: list[dict]` — persists on the app instance between `dispatch()` calls

**Background:** `dispatch()` in `ai.py` currently throws away the third return value of `run_agent()` with `_`. Every message starts a fresh conversation. The fix stores turns on `app._chat_history`, passes them on the next call, and caps at 12 entries (6 exchange pairs).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_tui_memory.py`:

```python
"""Tests for TUI conversation memory (ai.py dispatch)."""
import asyncio
from unittest.mock import AsyncMock, patch


class _MockApp:
    """Minimal stand-in for AIVASApp, enough for dispatch()."""

    def __init__(self, conn):
        self.conn = conn
        self._scan_history = []
        self._chat_history = []

    def tui_print(self, text):
        pass

    def run_worker(self, coro, *, exclusive=False):
        pass

    def set_busy(self, msg):
        pass

    def set_scan_idle(self):
        pass


def test_dispatch_accumulates_history(db):
    """Second call receives first call's turns as history."""
    from aivas.tui.ai import dispatch

    app = _MockApp(db)
    turns_a = [{"role": "assistant", "content": "Hello there."}]

    with patch("aivas.tui.ai.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("Hello there.", None, turns_a)
        asyncio.run(dispatch(app, "hi", "fake_key"))

    assert app._chat_history == turns_a

    turns_b = [{"role": "assistant", "content": "Sure."}]
    with patch("aivas.tui.ai.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("Sure.", None, turns_b)
        asyncio.run(dispatch(app, "tell me more", "fake_key"))
        passed_history = mock_agent.call_args.kwargs.get("history")

    assert passed_history == turns_a


def test_dispatch_caps_history_at_12(db):
    """History is capped at 12 entries after accumulation."""
    from aivas.tui.ai import dispatch

    app = _MockApp(db)
    # Pre-fill with 12 entries
    app._chat_history = [{"role": "assistant", "content": f"old {i}"} for i in range(12)]

    new_turns = [{"role": "assistant", "content": "newest"}]
    with patch("aivas.tui.ai.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("newest", None, new_turns)
        asyncio.run(dispatch(app, "hello", "fake_key"))

    assert len(app._chat_history) == 12
    assert app._chat_history[-1]["content"] == "newest"


def test_dispatch_starts_empty_on_fresh_app(db):
    """A brand-new app has no history and run_agent is called with empty list."""
    from aivas.tui.ai import dispatch

    app = _MockApp(db)
    # Deliberately do NOT set _chat_history

    with patch("aivas.tui.ai.run_agent", new_callable=AsyncMock) as mock_agent:
        mock_agent.return_value = ("Hi", None, [])
        asyncio.run(dispatch(app, "hello", "fake_key"))
        passed_history = mock_agent.call_args.kwargs.get("history")

    assert passed_history == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python3 -m pytest tests/test_tui_memory.py -v
```

Expected: `FAILED — AttributeError: '_MockApp' object has no attribute '_chat_history'` (or `AssertionError` because history isn't passed)

- [ ] **Step 3: Add `_chat_history` to `AIVASApp.__init__` in `app.py`**

In `aivas/tui/app.py`, inside `__init__` after `self._scan_history: list[dict] = []` (line 76), add:

```python
self._chat_history: list[dict] = []
```

- [ ] **Step 4: Reset `_chat_history` in `action_clear_output` in `app.py`**

The current method body (line 185-186):
```python
def action_clear_output(self) -> None:
    self.query_one("#output", RichLog).clear()
```

Replace with:
```python
def action_clear_output(self) -> None:
    self.query_one("#output", RichLog).clear()
    self._chat_history = []
```

- [ ] **Step 5: Fix `dispatch()` in `ai.py` to pass and persist history**

The current block (line 83 area):
```python
        try:
            response, scan_intent, _ = await run_agent(app, text, api_key, context=context)
```

Replace with:
```python
        try:
            history = getattr(app, '_chat_history', [])
            response, scan_intent, turns = await run_agent(
                app, text, api_key, context=context, history=history
            )
            app._chat_history = (history + turns)[-12:]
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_tui_memory.py -v
```

Expected: 3 PASSED

- [ ] **Step 7: Run full suite to check for regressions**

```bash
python3 -m pytest tests/ -q --ignore=tests/test_tui_checklist.py 2>&1 | tail -10
```

Expected: all tests pass (or same failures as before this task)

- [ ] **Step 8: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/ai.py aivas/tui/app.py tests/test_tui_memory.py
git commit --author="Baraka Malila <bmalila87@gmail.com>" -m "fix(tui): persist conversation history across dispatch() calls"
```

---

## Task 2: Web Harness Reliability

**Files:**
- Modify: `aivas/server/chat_stream.py`
- Modify: `tests/server/test_chat_stream.py`

**Interfaces:**
- Consumes: `aivas.history.list_scans(conn, limit=3) -> list[dict]` — returns dicts with `id`, `target`, `grade`, `finding_count`
- Produces: no interface change — `stream_agent_response` signature is unchanged

**Four changes to `chat_stream.py`:**
1. Model: `llama-3.1-8b-instant` → `llama-3.3-70b-versatile` in Phase A Groq call
2. Retry: wrap Phase A call in try/except; on 400/tool errors retry once without tools; on retry failure or other exception yield friendly error
3. Tool errors as JSON: wrap `_exec_tool_local()` call in try/except; on exception return `{"error": "..."}` JSON so the model reads it and adapts
4. Context injection: add `_build_web_context(conn)` helper; prepend to the system message

**Background:** `chat_stream.py:87` uses `llama-3.1-8b-instant` which is less reliable at tool calling than the 70b model. Any exception from the Groq call crashes with a raw traceback. Tool execution exceptions terminate the entire response. The web harness never shows the AI what scans have happened.

- [ ] **Step 1: Write failing tests**

Add to `tests/server/test_chat_stream.py`:

```python
def test_stream_retries_without_tools_on_400(conn):
    """Groq 400/tool error → retry without tools → streams response."""
    from aivas.server.chat_stream import stream_agent_response

    # First call raises 400-like error; second call (retry) succeeds
    err = Exception("400 Bad Request: tool_use_failed")
    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        client = MockGroq.return_value
        client.chat.completions.create.side_effect = [err, _groq_resp("fallback")]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "hi", conn)
        ))

    types = [e["type"] for e in events]
    assert "error" not in types
    assert types[-1] == "done"


def test_stream_tool_error_returns_friendly_message(conn):
    """Groq non-400 error → friendly error event, not raw traceback."""
    from aivas.server.chat_stream import stream_agent_response

    err = Exception("Connection timeout")
    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = err
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "hi", conn)
        ))

    assert events[0]["type"] == "thinking"
    err_ev = next((e for e in events if e["type"] == "error"), None)
    assert err_ev is not None
    assert "trouble" in err_ev["text"].lower()
    assert "Connection timeout" not in err_ev["text"]


def test_stream_injects_scan_context_when_scans_exist(conn):
    """System message includes recent scan context when scans exist in DB."""
    from aivas.server.chat_stream import stream_agent_response
    from aivas.history import save_scan

    save_scan(conn, "10.0.0.1", [])  # insert a scan

    captured_messages = []

    def capture_create(**kwargs):
        captured_messages.extend(kwargs.get("messages", []))
        return _groq_resp("ok")

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = capture_create
        asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "what did we scan?", conn)
        ))

    system_content = next(
        (m["content"] for m in captured_messages if m["role"] == "system"), ""
    )
    assert "Recent scans:" in system_content
    assert "10.0.0.1" in system_content


def test_exec_tool_exception_returns_json_error(conn):
    """_exec_tool_local raising → JSON error result instead of crash."""
    from aivas.server.chat_stream import stream_agent_response
    import json

    tc = MagicMock()
    tc.id = "call_x"
    tc.function.name = "get_history"
    tc.function.arguments = "{}"

    groq_tool_resp = _groq_resp(tool_calls=[tc])
    groq_final_resp = _groq_resp("")

    with patch("aivas.server.chat_stream.Groq") as MockGroq, \
         patch("aivas.server.chat_stream._exec_tool_local",
               side_effect=RuntimeError("db locked")):
        MockGroq.return_value.chat.completions.create.side_effect = [
            groq_tool_resp, groq_final_resp
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "list scans", conn)
        ))

    # Should complete — not crash
    assert events[-1]["type"] == "done"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/server/test_chat_stream.py::test_stream_retries_without_tools_on_400 \
  tests/server/test_chat_stream.py::test_stream_tool_error_returns_friendly_message \
  tests/server/test_chat_stream.py::test_stream_injects_scan_context_when_scans_exist \
  tests/server/test_chat_stream.py::test_exec_tool_exception_returns_json_error -v
```

Expected: 4 FAILED

- [ ] **Step 3: Upgrade the model (line 87)**

In `chat_stream.py`, find:
```python
                    model="llama-3.1-8b-instant",
                    messages=messages,
                    tools=_TOOLS,
```

Replace with:
```python
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    tools=_TOOLS,
```

- [ ] **Step 4: Wrap Phase A Groq call with retry logic**

The current try/except block (lines 84-96):
```python
        try:
            resp = await asyncio.to_thread(
                lambda: groq.chat.completions.create(
                    model="llama-3.1-8b-instant",
                    messages=messages,
                    tools=_TOOLS,
                    tool_choice="auto",
                    max_tokens=600,
                )
            )
        except Exception as exc:
            yield {"type": "error", "text": f"AI error: {exc}"}
            return
```

Replace with:
```python
        try:
            resp = await asyncio.to_thread(
                lambda: groq.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    tools=_TOOLS,
                    tool_choice="auto",
                    max_tokens=600,
                )
            )
        except Exception as exc:
            s = str(exc)
            if "400" in s or "tool" in s.lower():
                try:
                    resp = await asyncio.to_thread(
                        lambda: groq.chat.completions.create(
                            model="llama-3.3-70b-versatile",
                            messages=messages,
                            max_tokens=600,
                        )
                    )
                except Exception:
                    yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
                    return
            else:
                yield {"type": "error", "text": "I'm having trouble processing that right now. Please try again."}
                return
```

- [ ] **Step 5: Wrap `_exec_tool_local` call with try/except**

Find the current call (around line 133):
```python
            result, scan_intent = _exec_tool_local(tc.function.name, args, conn, shodan_key)
```

Replace with:
```python
            try:
                result, scan_intent = _exec_tool_local(tc.function.name, args, conn, shodan_key)
            except Exception as exc:
                result = json.dumps({"error": f"Tool execution failed: {exc}"})
                scan_intent = None
```

- [ ] **Step 6: Add `_build_web_context` and inject into system prompt**

After the existing imports at the top of `chat_stream.py`, add:
```python
from aivas.history import list_scans as _list_scans
```

After the module-level constants (`_MAX_STEPS`, etc.), add the helper function:
```python
def _build_web_context(conn: sqlite3.Connection) -> str:
    scans = _list_scans(conn, limit=3)
    if not scans:
        return ""
    lines = ["Recent scans:"]
    for s in scans:
        lines.append(
            f"  · scan #{s['id']}: {s['target']} — Grade {s.get('grade', '?')}, "
            f"{s.get('finding_count', 0)} findings"
        )
    return "\n".join(lines)
```

In `stream_agent_response`, replace the current system message line (line 73):
```python
    messages: list[dict] = [{"role": "system", "content": _SYSTEM}]
```

With:
```python
    ctx = _build_web_context(conn)
    system = "\n\n".join(filter(None, [_SYSTEM, ctx]))
    messages: list[dict] = [{"role": "system", "content": system}]
```

- [ ] **Step 7: Run new tests to verify they pass**

```bash
python3 -m pytest tests/server/test_chat_stream.py -v
```

Expected: all PASSED (including the 3 original tests)

- [ ] **Step 8: Run full suite**

```bash
python3 -m pytest tests/ -q --ignore=tests/test_tui_checklist.py 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 9: Commit**

```bash
git add aivas/server/chat_stream.py tests/server/test_chat_stream.py
git commit --author="Baraka Malila <bmalila87@gmail.com>" -m "fix(web): upgrade model, retry on 400, tool errors recoverable, inject scan context"
```

---

## Task 3: discover_hosts Tool + Findings Truncation

**Files:**
- Modify: `aivas/tui/agent.py` — make `_exec_tool` async; add `discover_hosts` branch; raise truncation limits; add `await` to `_exec_tool` call in `run_agent`
- Modify: `aivas/tui/agent_prompts.py` — add `discover_hosts` schema; add ROUTING RULE and HONESTY RULE
- Modify: `aivas/server/chat_stream.py` — make `_exec_tool_local` async, add `await` to its call
- Create: `tests/test_agent.py`

**Interfaces:**
- Consumes: `asyncio.create_subprocess_exec` (stdlib — no new deps)
- Produces: `discover_hosts` tool returns `{"devices": [...], "count": N, "note": "..."}` where each device has `ip` (required), `hostname`, `mac`, `vendor` (all optional)

**Background:** The AI routes every "who is on my network?" question to `scan_host` because there is no alternative tool. `discover_hosts` runs `nmap -sn` (ping sweep only — no port scan) and returns IP/hostname/MAC/vendor. The truncation caps (10 and 15 findings) mean the AI sees partial data for any scan with more than 10 findings.

Because `discover_hosts` uses `asyncio.create_subprocess_exec`, `_exec_tool` must become `async def`. Both callers (`run_agent` in agent.py and `_exec_tool_local` in chat_stream.py) must `await` it.

- [ ] **Step 1: Write failing tests**

Create `tests/test_agent.py`:

```python
"""Tests for agent.py tool executor."""
import asyncio
import json
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aivas.database.schema import create_schema


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    return db


NMAP_XML_WITH_MAC = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme Corp"/>
    <hostnames><hostname name="device.local" type="PTR"/></hostnames>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.6" addrtype="ipv4"/>
  </host>
</nmaprun>"""

NMAP_XML_NO_MAC = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
  </host>
</nmaprun>"""


def _mock_proc(stdout: bytes):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    return proc


def test_discover_hosts_returns_up_devices(conn):
    """Only 'up' hosts are returned; down hosts are filtered out."""
    from aivas.tui.agent import _exec_tool

    with patch("asyncio.create_subprocess_exec", return_value=_mock_proc(NMAP_XML_WITH_MAC)):
        result_json, intent = asyncio.run(
            _exec_tool("discover_hosts", {"target": "192.168.1.0/24"}, conn)
        )

    result = json.loads(result_json)
    assert result["count"] == 1
    assert result["devices"][0]["ip"] == "192.168.1.5"
    assert result["devices"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert result["devices"][0]["vendor"] == "Acme Corp"
    assert result["devices"][0]["hostname"] == "device.local"
    assert intent is None


def test_discover_hosts_notes_missing_mac(conn):
    """When no device has a MAC, note field mentions cap_net_raw."""
    from aivas.tui.agent import _exec_tool

    with patch("asyncio.create_subprocess_exec", return_value=_mock_proc(NMAP_XML_NO_MAC)):
        result_json, _ = asyncio.run(
            _exec_tool("discover_hosts", {"target": "10.0.0.0/24"}, conn)
        )

    result = json.loads(result_json)
    assert result["count"] == 1
    assert "cap_net_raw" in result["note"]


def test_discover_hosts_requires_target(conn):
    """Missing target returns error JSON."""
    from aivas.tui.agent import _exec_tool

    result_json, intent = asyncio.run(
        _exec_tool("discover_hosts", {}, conn)
    )
    result = json.loads(result_json)
    assert "error" in result
    assert intent is None


def test_get_findings_returns_up_to_50(conn):
    """get_findings cap is 50 (was 15)."""
    from aivas.tui.agent import _exec_tool
    from aivas.history import save_scan

    findings = [
        {"cve_id": f"CVE-2021-{i:05d}", "cvss_score": 5.0,
         "cvss_severity": "MEDIUM", "confidence": "probable", "host": "1.2.3.4"}
        for i in range(60)
    ]
    save_scan(conn, "1.2.3.4", findings)

    result_json, _ = asyncio.run(_exec_tool("get_findings", {"scan_id": "1"}, conn))
    result = json.loads(result_json)
    assert len(result) == 50


def test_get_last_scan_returns_up_to_25(conn):
    """get_last_scan findings cap is 25 (was 10)."""
    from aivas.tui.agent import _exec_tool
    from aivas.history import save_scan

    findings = [
        {"cve_id": f"CVE-2021-{i:05d}", "cvss_score": 5.0,
         "cvss_severity": "MEDIUM", "confidence": "probable", "host": "1.2.3.4"}
        for i in range(30)
    ]
    save_scan(conn, "1.2.3.4", findings)

    result_json, _ = asyncio.run(_exec_tool("get_last_scan", {}, conn))
    result = json.loads(result_json)
    assert len(result["findings"]) == 25


def test_discover_hosts_schema_present():
    """discover_hosts schema exists in TOOLS list."""
    from aivas.tui.agent_prompts import TOOLS
    names = [t["function"]["name"] for t in TOOLS]
    assert "discover_hosts" in names


def test_system_prompt_has_routing_rule():
    """SYSTEM prompt contains ROUTING RULE for discover_hosts."""
    from aivas.tui.agent_prompts import SYSTEM
    assert "ROUTING RULE" in SYSTEM
    assert "discover_hosts" in SYSTEM


def test_system_prompt_has_honesty_rule():
    """SYSTEM prompt contains HONESTY RULE requiring get_findings before summaries."""
    from aivas.tui.agent_prompts import SYSTEM
    assert "HONESTY RULE" in SYSTEM
    assert "get_findings" in SYSTEM
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_agent.py -v
```

Expected: All FAILED (discover_hosts doesn't exist yet; truncation limits at 10/15; schema missing)

- [ ] **Step 3: Make `_exec_tool` async in `agent.py`**

Change the function signature from:
```python
def _exec_tool(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None = None
) -> tuple[str, tuple | None]:
```

To:
```python
async def _exec_tool(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None = None
) -> tuple[str, tuple | None]:
```

- [ ] **Step 4: Add `discover_hosts` branch to `_exec_tool` in `agent.py`**

Add the following block **before** the final `return json.dumps({"error": f"Unknown tool: {name}"}), None` at the bottom of `_exec_tool`:

```python
    if name == "discover_hosts":
        import shutil
        target = _as_str(args.get("target"))
        if not target:
            return json.dumps({"error": "target (CIDR or IP range) is required."}), None

        nmap_bin = shutil.which("nmap") or "nmap"
        cmd = [nmap_bin, "-sn", "-oX", "-", target]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        except Exception as exc:
            return json.dumps({"error": f"Host discovery failed: {exc}"}), None

        import xml.etree.ElementTree as ET
        devices = []
        try:
            root = ET.fromstring(stdout.decode())
            for host in root.findall("host"):
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue
                dev: dict = {}
                for addr in host.findall("address"):
                    atype = addr.get("addrtype", "")
                    if atype == "ipv4":
                        dev["ip"] = addr.get("addr")
                    elif atype == "mac":
                        dev["mac"] = addr.get("addr")
                        vendor = addr.get("vendor")
                        if vendor:
                            dev["vendor"] = vendor
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = (hostnames.find("hostname[@type='PTR']")
                          or hostnames.find("hostname"))
                    if hn is not None:
                        dev["hostname"] = hn.get("name")
                if dev.get("ip"):
                    devices.append(dev)
        except Exception as exc:
            return json.dumps({"error": f"Could not parse discovery output: {exc}"}), None

        note = ""
        if devices and not any(d.get("mac") for d in devices):
            note = "MAC addresses not available — nmap may need cap_net_raw capability (see /doctor)."

        return json.dumps({"devices": devices, "count": len(devices), "note": note}), None
```

- [ ] **Step 5: Raise truncation caps in `agent.py`**

Find line 69 (get_last_scan):
```python
        return json.dumps({"scan": scans[0], "findings": findings[:10]}), None
```

Replace with:
```python
        return json.dumps({"scan": scans[0], "findings": findings[:25]}), None
```

Find line 76 (get_findings):
```python
        return json.dumps(findings[:15]), None
```

Replace with:
```python
        return json.dumps(findings[:50]), None
```

- [ ] **Step 6: Update `run_agent` in `agent.py` to `await _exec_tool`**

Find the call to `_exec_tool` in `run_agent` (around line 216):
```python
            result, si = _exec_tool(tc.function.name, args, app.conn, shodan_key=shodan_key)
```

Replace with:
```python
            result, si = await _exec_tool(tc.function.name, args, app.conn, shodan_key=shodan_key)
```

- [ ] **Step 7: Make `_exec_tool_local` async in `chat_stream.py`**

Find the current function definition:
```python
def _exec_tool_local(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None
) -> tuple[str, tuple | None]:
    """Dispatch tool call. Returns (result_json, scan_intent | None)."""
    from aivas.tui.agent import _exec_tool
    return _exec_tool(name, args, conn, shodan_key=shodan_key)
```

Replace with:
```python
async def _exec_tool_local(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None
) -> tuple[str, tuple | None]:
    """Dispatch tool call. Returns (result_json, scan_intent | None)."""
    from aivas.tui.agent import _exec_tool
    return await _exec_tool(name, args, conn, shodan_key=shodan_key)
```

- [ ] **Step 8: Await `_exec_tool_local` in `stream_agent_response` in `chat_stream.py`**

Find the try/except block added in Task 2 around `_exec_tool_local`:
```python
            try:
                result, scan_intent = _exec_tool_local(tc.function.name, args, conn, shodan_key)
            except Exception as exc:
                result = json.dumps({"error": f"Tool execution failed: {exc}"})
                scan_intent = None
```

Replace with:
```python
            try:
                result, scan_intent = await _exec_tool_local(tc.function.name, args, conn, shodan_key)
            except Exception as exc:
                result = json.dumps({"error": f"Tool execution failed: {exc}"})
                scan_intent = None
```

- [ ] **Step 9: Add `discover_hosts` schema to `TOOLS` in `agent_prompts.py`**

Append the following entry to the `TOOLS` list (before the final `]`):

```python
    {"type": "function", "function": {
        "name": "discover_hosts",
        "description": (
            "List all devices on a network without scanning for vulnerabilities. "
            "Use this when the user asks how many devices are on the network, who is connected, "
            "what devices exist, or any question about network topology — without asking to scan "
            "for vulnerabilities or security issues. Returns IP, hostname, MAC, and vendor."
        ),
        "parameters": {"type": "object", "required": ["target"], "properties": {
            "target": {"type": "string", "description": "CIDR range e.g. 10.88.91.0/24"},
        }},
    }},
```

- [ ] **Step 10: Add ROUTING RULE and HONESTY RULE to SYSTEM in `agent_prompts.py`**

Append the following two rules to the `Rules:` section inside the `SYSTEM` string, before the final `\` and `"""`:

```
- ROUTING RULE: Use discover_hosts when the user asks about devices, who is connected,
  how many devices are on the network, or network topology. Only use scan_host when the
  user explicitly asks to scan for vulnerabilities, CVEs, security issues, or weaknesses.
- HONESTY RULE: Before giving any risk summary, remediation advice, or CVE analysis for
  a specific scan, you MUST call get_findings(scan_id) first. Never describe scan results
  from memory — only from tool output returned in this conversation.
```

The end of the SYSTEM string currently looks like:
```
- OUTPUT FORMAT: Never write raw tool call notation like <function>...</function>
  or <function=name>...</function> in your natural language responses. If a tool
  was called and returned results, describe those results in natural language.\
"""
```

Replace the final `\` and `"""` with:
```
- OUTPUT FORMAT: Never write raw tool call notation like <function>...</function>
  or <function=name>...</function> in your natural language responses. If a tool
  was called and returned results, describe those results in natural language.
- ROUTING RULE: Use discover_hosts when the user asks about devices, who is connected,
  how many devices are on the network, or network topology. Only use scan_host when the
  user explicitly asks to scan for vulnerabilities, CVEs, security issues, or weaknesses.
- HONESTY RULE: Before giving any risk summary, remediation advice, or CVE analysis for
  a specific scan, you MUST call get_findings(scan_id) first. Never describe scan results
  from memory — only from tool output returned in this conversation.\
"""
```

- [ ] **Step 11: Run new tests to verify they pass**

```bash
python3 -m pytest tests/test_agent.py -v
```

Expected: all 9 PASSED

- [ ] **Step 12: Run full suite**

```bash
python3 -m pytest tests/ -q --ignore=tests/test_tui_checklist.py 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 13: Commit**

```bash
git add aivas/tui/agent.py aivas/tui/agent_prompts.py aivas/server/chat_stream.py tests/test_agent.py
git commit --author="Baraka Malila <bmalila87@gmail.com>" -m "feat(agent): add discover_hosts tool, async _exec_tool, raise findings caps"
```

---

## Task 4: History Severity Counts

**Files:**
- Modify: `aivas/history.py` — add `critical_count` subquery to `list_scans()`
- Modify: `tests/test_history.py` — add two tests

**Interfaces:**
- Consumes: `cves.cvss_severity TEXT` column — exists in schema (confirmed)
- Produces: `list_scans()` dict now includes `critical_count: int` in addition to existing fields

**Background:** `list_scans()` already returns `kev_count`. It is missing `critical_count` (findings whose CVE has `cvss_severity = 'CRITICAL'`). The frontend welcome-back message reads `scan.counts?.CRITICAL` which is always `undefined` — there is no `counts` object in the history API response.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_history.py`:

```python
def test_list_scans_returns_critical_count(db):
    """list_scans includes critical_count for scans with CRITICAL findings."""
    # Insert a CVE with CRITICAL severity into the cves table
    db.execute(
        "INSERT OR IGNORE INTO cves (cve_id, cvss_score, cvss_severity, description) "
        "VALUES ('CVE-2021-41773', 9.8, 'CRITICAL', 'Apache path traversal')"
    )
    db.commit()

    findings = [
        {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
         "confidence": "probable", "host": "1.2.3.4"},
    ]
    save_scan(db, "1.2.3.4", findings)

    scans = list_scans(db)
    assert scans[0]["critical_count"] == 1


def test_list_scans_critical_count_zero_when_none(db):
    """list_scans returns critical_count=0 when no CRITICAL findings exist."""
    findings = [
        {"cve_id": "CVE-2018-15473", "cvss_score": 5.3, "cvss_severity": "MEDIUM",
         "confidence": "probable", "host": "1.2.3.4"},
    ]
    save_scan(db, "1.2.3.4", findings)

    scans = list_scans(db)
    assert scans[0]["critical_count"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest tests/test_history.py::test_list_scans_returns_critical_count \
  tests/test_history.py::test_list_scans_critical_count_zero_when_none -v
```

Expected: 2 FAILED with `KeyError: 'critical_count'`

- [ ] **Step 3: Add `critical_count` to `list_scans()` in `history.py`**

Find the current SQL in `list_scans()`:
```python
    rows = conn.execute(
        """
        SELECT s.id, s.target, s.started_at, s.finding_count, s.risk_score, s.grade,
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
```

Replace with:
```python
    rows = conn.execute(
        """
        SELECT s.id, s.target, s.started_at, s.finding_count, s.risk_score, s.grade,
               COALESCE((
                 SELECT COUNT(DISTINCT f.cve_id)
                   FROM findings f
                   JOIN cves c ON c.cve_id = f.cve_id
                  WHERE f.scan_id = s.id AND c.kev = 1
               ), 0) AS kev_count,
               COALESCE((
                 SELECT COUNT(DISTINCT f.cve_id)
                   FROM findings f
                   JOIN cves c ON c.cve_id = f.cve_id
                  WHERE f.scan_id = s.id AND c.cvss_severity = 'CRITICAL'
               ), 0) AS critical_count
          FROM scans s
         ORDER BY s.id DESC
         LIMIT ?
        """,
        (limit,),
    ).fetchall()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest tests/test_history.py -v
```

Expected: all 11 PASSED (9 original + 2 new)

- [ ] **Step 5: Run full suite**

```bash
python3 -m pytest tests/ -q --ignore=tests/test_tui_checklist.py 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add aivas/history.py tests/test_history.py
git commit --author="Baraka Malila <bmalila87@gmail.com>" -m "fix(history): add critical_count to list_scans() return"
```

---

## Task 5: Frontend Fixes

**Files:**
- Modify: `frontend/src/App.jsx` — welcome-back message uses `scan.critical_count` and `scan.kev_count`
- Modify: `frontend/src/hooks/useScan.js` — `ws.onerror` calls `onDoneRef` with friendly error

**Background:** `App.jsx:166` reads `scan.counts?.CRITICAL` which is always `undefined` — the history API returns `critical_count` (a flat field), not `counts.CRITICAL`. `useScan.js:57` `ws.onerror` only sets `isScanning(false)` but never calls `onDoneRef`, so the scan-progress card freezes forever on network errors instead of being replaced with an error message.

No pytest tests for these. Verify by building and checking the browser.

- [ ] **Step 1: Fix the welcome-back message in `App.jsx`**

Find the block around line 162-170:
```js
        if (Array.isArray(history) && history.length > 0) {
          const scan = history[0]
          const grade = (scan.grade || '').replace('Grade ', '')
          const days = daysAgo(scan.started_at)
          const critical = scan.counts?.CRITICAL ?? 0
          text =
            `Welcome back. Your last scan of ${scan.target} was ${days} days ago` +
            ` — Grade ${grade}, ${critical} critical vulnerabilities.` +
            ` Want me to rescan, or would you like a summary?`
        }
```

Replace with:
```js
        if (Array.isArray(history) && history.length > 0) {
          const scan = history[0]
          const grade = (scan.grade || '').replace('Grade ', '')
          const days = daysAgo(scan.started_at)
          const critical = scan.critical_count ?? 0
          const kev = scan.kev_count ?? 0
          text =
            `Welcome back. Your last scan of ${scan.target} was ${days} day${days !== 1 ? 's' : ''} ago` +
            ` — Grade ${grade}, ${scan.finding_count ?? 0} findings` +
            (critical > 0 ? `, ${critical} critical` : '') +
            (kev > 0 ? `, ${kev} actively exploited` : '') +
            `. Want me to rescan, or would you like a summary?`
        }
```

- [ ] **Step 2: Fix `ws.onerror` in `useScan.js`**

Find line 57:
```js
    ws.onerror = () => { ws.onerror = null; setIsScanning(false) }
```

Replace with:
```js
    ws.onerror = () => {
      ws.onerror = null
      setIsScanning(false)
      onDoneRef.current({
        type: 'error',
        text: 'Connection to scan service lost. Check that the server is running and try again.',
        log: logRef.current,
      })
    }
```

- [ ] **Step 3: Build and verify**

```bash
cd /home/cyberpunk/aivas/frontend && npm run build 2>&1 | tail -10
```

Expected: build exits 0 with no errors

- [ ] **Step 4: Verify welcome-back message (manual)**

Start the server (`python3 -m aivas serve` or `uvicorn aivas.server.main:app`) and open the frontend. If there are existing scans in the database, the welcome message should show `finding_count` findings, conditional `critical` and `kev` counts, and singular/plural "day/days". If no scans exist, the message should be the FIRST_VISIT_MSG.

- [ ] **Step 5: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/App.jsx frontend/src/hooks/useScan.js
git commit --author="Baraka Malila <bmalila87@gmail.com>" -m "fix(frontend): welcome-back uses real counts; scan onerror replaces frozen card"
```

---

## Self-Review Checklist

- Fix 1 (TUI memory) → Task 1 ✅
- Fix 2a (model upgrade) → Task 2, Step 3 ✅
- Fix 2b (retry on tool_use_failed) → Task 2, Step 4 ✅
- Fix 2c (tool errors recoverable) → Task 2, Step 5 ✅
- Fix 2d (scan context injection) → Task 2, Step 6 ✅
- Fix 3 (discover_hosts tool) → Task 3, Steps 3–4 ✅
- Fix 4 (findings truncation) → Task 3, Step 5 ✅
- Fix 5 (history critical_count) → Task 4 ✅
- Fix 6 (welcome-back message) → Task 5, Step 1 ✅
- Fix 7 (useScan onerror) → Task 5, Step 2 ✅
- `_exec_tool` async + callers updated → Task 3, Steps 3, 6, 7, 8 ✅
- `action_clear_output` resets `_chat_history` → Task 1, Step 4 ✅
- `discover_hosts` degrades gracefully (note field) → Task 3, Step 4 + test ✅
