# Phase 3 — AI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the rigid 4-part AI output with a streaming conversational agent using swappable providers (Groq / Claude / Ollama), Shodan enrichment, and a clean scan pipeline.

**Architecture:** A new `narrator/providers/` package abstracts all LLM providers behind `BaseProvider`. A new `server/chat_stream.py` runs the tool-calling loop with Phase A (Groq 8B decides what data is needed), then streams the final response with the user's chosen provider via `provider.stream()`. The WebSocket handler yields token events to the frontend, which accumulates them live.

**Tech Stack:** Python 3.10+, Groq SDK (groq ≥0.9), Anthropic SDK (anthropic ≥0.20, optional), requests, FastAPI WebSocket, React 18, Vitest

## Global Constraints

- No Python source file exceeds 200 lines.
- Default provider: `groq`, default model: `llama-3.3-70b-versatile`.
- Phase A (tool-dispatch summariser): always uses `llama-3.1-8b-instant` on Groq.
- `anthropic` SDK is an optional dependency — import it lazily inside `AnthropicProvider` methods.
- All existing tests must remain passing after each task.
- Commit after every task. Author: `Baraka Malila <bmalila87@gmail.com>`.
- `aivas/narrator/providers.py` is deleted in Task 1; `__init__.py` re-exports the same public names so existing callers (`tests/test_narrator_providers.py`, `aivas/server/scan_worker.py`) keep working until Task 6.
- Frontend tests use Vitest. Backend tests use pytest with `asyncio.run()` — no pytest-asyncio needed.

---

### Task 1: Provider package (`aivas/narrator/providers/`)

**Files:**
- Create: `aivas/narrator/providers/__init__.py`
- Create: `aivas/narrator/providers/base.py`
- Create: `aivas/narrator/providers/groq.py`
- Create: `aivas/narrator/providers/anthropic.py`
- Create: `aivas/narrator/providers/ollama.py`
- Create: `aivas/narrator/providers/factory.py`
- Delete: `aivas/narrator/providers.py` (replaced by the package)
- Modify: `tests/test_narrator_providers.py` (update import paths)

**Interfaces:**
- Produces: `BaseProvider` (abstract), `GroqProvider`, `AnthropicProvider`, `OllamaProvider`, `get_provider(name, model, api_key) -> BaseProvider`
- `BaseProvider.generate(prompt, max_tokens=300) -> str` — blocking, used by TUI + narrator
- `BaseProvider.stream(messages, max_tokens=1024) -> AsyncGenerator[str, None]` — async, used by chat_stream.py
- All existing callers import from `aivas.narrator.providers` — the package `__init__.py` re-exports the same names

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_narrator_providers.py  (full replacement)
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import pytest
import requests
from aivas.narrator.providers import GroqProvider, OllamaProvider, get_provider
from aivas.narrator.providers.base import BaseProvider


# --- factory ---

def test_get_provider_groq_raises_without_key():
    with pytest.raises(ValueError, match="Groq API key"):
        get_provider("groq", api_key=None)

def test_get_provider_groq_returns_groq_provider():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = get_provider("groq", api_key="fake-key")
    assert isinstance(p, GroqProvider)

def test_get_provider_groq_default_model():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = get_provider("groq", api_key="k")
    assert p._model == "llama-3.3-70b-versatile"

def test_get_provider_groq_custom_model():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = get_provider("groq", api_key="k", model="llama-3.1-8b-instant")
    assert p._model == "llama-3.1-8b-instant"

def test_get_provider_ollama_returns_ollama_provider():
    p = get_provider("ollama")
    assert isinstance(p, OllamaProvider)

def test_get_provider_claude_raises_without_key():
    with pytest.raises(ValueError, match="Anthropic"):
        get_provider("claude", api_key=None)

def test_get_provider_unknown_raises():
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider("openai")

# --- GroqProvider ---

def test_groq_generate_returns_string():
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "response text"
    with patch("aivas.narrator.providers.groq.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = mock_resp
        p = GroqProvider(api_key="fake-key")
        result = p.generate("prompt")
    assert result == "response text"

def test_groq_name():
    with patch("aivas.narrator.providers.groq.Groq"):
        p = GroqProvider(api_key="k")
    assert p.name == "groq"

def test_groq_stream_yields_tokens():
    async def _run():
        async def mock_aiter(self):
            for content in ["Hello", " World"]:
                chunk = MagicMock()
                chunk.choices[0].delta.content = content
                yield chunk

        mock_stream = MagicMock()
        mock_stream.__aiter__ = mock_aiter

        with patch("aivas.narrator.providers.groq.AsyncGroq") as MockAsync:
            MockAsync.return_value.chat.completions.create = AsyncMock(
                return_value=mock_stream
            )
            from aivas.narrator.providers.groq import GroqProvider
            p = GroqProvider(api_key="k")
            tokens = [t async for t in p.stream([{"role": "user", "content": "hi"}])]
        return tokens

    tokens = asyncio.run(_run())
    assert tokens == ["Hello", " World"]

# --- OllamaProvider ---

def test_ollama_generate_posts_to_api():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(
            status_code=200, json=lambda: {"response": "Ollama output"}
        )
        mock_post.return_value.raise_for_status = MagicMock()
        p = OllamaProvider()
        result = p.generate("prompt text")
    assert result == "Ollama output"
    assert "11434" in mock_post.call_args[0][0]
    assert "generate" in mock_post.call_args[0][0]

def test_ollama_name():
    p = OllamaProvider()
    assert p.name == "ollama"

def test_ollama_raises_on_http_error():
    with patch("requests.post") as mock_post:
        mock_post.return_value = MagicMock(
            raise_for_status=MagicMock(side_effect=requests.HTTPError("404"))
        )
        p = OllamaProvider()
        with pytest.raises(requests.HTTPError):
            p.generate("prompt text")

# --- BaseProvider is abstract ---

def test_base_provider_is_abstract():
    with pytest.raises(TypeError):
        BaseProvider()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
pytest tests/test_narrator_providers.py -v 2>&1 | tail -20
```
Expected: ImportError or ModuleNotFoundError (package doesn't exist yet)

- [ ] **Step 3: Create `aivas/narrator/providers/base.py`**

```python
from abc import ABC, abstractmethod


class BaseProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 300) -> str: ...

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        """Yield string tokens. Subclasses must implement as async generator."""
        raise NotImplementedError(f"{self.__class__.__name__}.stream() not implemented")
        yield  # pragma: no cover — makes this an async generator
```

- [ ] **Step 4: Create `aivas/narrator/providers/groq.py`**

```python
import re
import time
from groq import Groq, AsyncGroq
from .base import BaseProvider

_RETRY_DELAYS = (2.0, 6.0)


class GroqProvider(BaseProvider):
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self._api_key = api_key
        self._client = Groq(api_key=api_key)
        self._model = model

    @property
    def name(self) -> str:
        return "groq"

    @staticmethod
    def _retry_delay(error: Exception) -> float | None:
        m = re.search(r"try again in ([\d.]+)s", str(error), re.IGNORECASE)
        return float(m.group(1)) if m else None

    def generate(self, prompt: str, max_tokens: int = 300) -> str:
        for _attempt, backoff in enumerate(_RETRY_DELAYS + (None,)):
            try:
                resp = self._client.chat.completions.create(
                    model=self._model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                )
                return resp.choices[0].message.content
            except Exception as exc:
                is_rate = "429" in str(exc) or "rate_limit" in str(exc).lower()
                if is_rate and backoff is not None:
                    time.sleep(self._retry_delay(exc) or backoff)
                    continue
                raise

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        client = AsyncGroq(api_key=self._api_key)
        resp = await client.chat.completions.create(
            model=self._model,
            messages=messages,
            max_tokens=max_tokens,
            stream=True,
        )
        async for chunk in resp:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta
```

- [ ] **Step 5: Create `aivas/narrator/providers/anthropic.py`**

```python
from .base import BaseProvider


class AnthropicProvider(BaseProvider):
    def __init__(self, api_key: str, model: str = "claude-haiku-4-5-20251001"):
        self._api_key = api_key
        self._model = model

    @property
    def name(self) -> str:
        return "claude"

    def generate(self, prompt: str, max_tokens: int = 300) -> str:
        from anthropic import Anthropic
        client = Anthropic(api_key=self._api_key)
        resp = client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=self._api_key)
        system = next(
            (m["content"] for m in messages if m.get("role") == "system"), ""
        )
        chat_msgs = [
            m for m in messages
            if m.get("role") in ("user", "assistant") and m.get("content")
        ]
        if not chat_msgs:
            return
        async with client.messages.stream(
            model=self._model,
            max_tokens=max_tokens,
            system=system or "You are a helpful assistant.",
            messages=chat_msgs,
        ) as s:
            async for text in s.text_stream:
                yield text
```

- [ ] **Step 6: Create `aivas/narrator/providers/ollama.py`**

```python
import asyncio
import json
import requests
from .base import BaseProvider


class OllamaProvider(BaseProvider):
    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self._model = model
        self._base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return "ollama"

    def generate(self, prompt: str, max_tokens: int = 300) -> str:
        resp = requests.post(
            f"{self._base_url}/api/generate",
            json={
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["response"]

    async def stream(self, messages: list[dict], max_tokens: int = 1024):
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        chat_msgs = [
            m for m in messages if m.get("role") in ("user", "assistant", "system")
        ]

        def _run():
            try:
                resp = requests.post(
                    f"{self._base_url}/api/chat",
                    json={
                        "model": self._model,
                        "messages": chat_msgs,
                        "stream": True,
                        "options": {"num_predict": max_tokens},
                    },
                    stream=True,
                    timeout=120,
                )
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if line:
                        data = json.loads(line)
                        token = data.get("message", {}).get("content", "")
                        if token:
                            loop.call_soon_threadsafe(queue.put_nowait, token)
            except Exception as exc:
                loop.call_soon_threadsafe(queue.put_nowait, f"\n[Ollama error: {exc}]")
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        thread = loop.run_in_executor(None, _run)
        while True:
            token = await queue.get()
            if token is None:
                break
            yield token
        await thread
```

- [ ] **Step 7: Create `aivas/narrator/providers/factory.py`**

```python
from .base import BaseProvider

_DEFAULTS: dict[str, str] = {
    "groq": "llama-3.3-70b-versatile",
    "claude": "claude-haiku-4-5-20251001",
    "ollama": "llama3",
}


def get_provider(
    name: str,
    model: str | None = None,
    api_key: str | None = None,
) -> BaseProvider:
    m = model or _DEFAULTS.get(name)
    if name == "groq":
        if not api_key:
            raise ValueError(
                "Groq API key required. Set GROQ_API_KEY env var or pass api_key."
            )
        from .groq import GroqProvider
        return GroqProvider(api_key=api_key, model=m)
    if name == "claude":
        if not api_key:
            raise ValueError("Anthropic API key required for claude provider.")
        from .anthropic import AnthropicProvider
        return AnthropicProvider(api_key=api_key, model=m)
    if name == "ollama":
        from .ollama import OllamaProvider
        return OllamaProvider(model=m)
    raise ValueError(f"Unknown provider: {name!r}. Choose 'groq', 'claude', or 'ollama'.")
```

- [ ] **Step 8: Create `aivas/narrator/providers/__init__.py`** (re-export old public names)

```python
from .base import BaseProvider
from .groq import GroqProvider
from .ollama import OllamaProvider
from .factory import get_provider

__all__ = ["BaseProvider", "GroqProvider", "OllamaProvider", "get_provider"]
```

- [ ] **Step 9: Delete old `aivas/narrator/providers.py`**

```bash
rm /home/cyberpunk/aivas/aivas/narrator/providers.py
```

- [ ] **Step 10: Run tests and verify they pass**

```bash
cd /home/cyberpunk/aivas
pytest tests/test_narrator_providers.py -v
```
Expected: all tests PASS

- [ ] **Step 11: Run full test suite to check nothing broke**

```bash
pytest --tb=short -q 2>&1 | tail -20
```
Expected: same pass count as before this task (all existing tests still pass)

- [ ] **Step 12: Commit**

```bash
git add aivas/narrator/providers/ tests/test_narrator_providers.py
git rm aivas/narrator/providers.py
git commit -m "feat: extract narrator/providers into package with stream() support"
```

---

### Task 2: System prompt + Shodan client + agent updates

**Files:**
- Modify: `aivas/tui/agent_prompts.py` (new SYSTEM, add query_shodan TOOL)
- Create: `aivas/narrator/shodan_client.py`
- Modify: `aivas/tui/agent.py` (add query_shodan to `_exec_tool`, add `shodan_key` param)
- Test: `tests/test_shodan_client.py` (new)
- Test: `tests/server/test_agent_safety.py` (verify system prompt is conversational)

**Interfaces:**
- Produces: `query_shodan(ip: str, api_key: str) -> dict` in `shodan_client.py`
- Produces: updated `_exec_tool(name, args, conn, shodan_key=None)` in `agent.py`
- Produces: `SYSTEM` string and `TOOLS` list in `agent_prompts.py` (used by `agent.py` and `chat_stream.py`)

- [ ] **Step 1: Write failing tests**

```python
# tests/test_shodan_client.py
from unittest.mock import patch, MagicMock
import pytest
from aivas.narrator.shodan_client import query_shodan


def test_query_shodan_returns_dict():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "ip_str": "1.1.1.1",
        "ports": [80, 443],
        "hostnames": ["one.one.one.one"],
        "country_name": "Australia",
        "org": "Cloudflare",
        "vulns": [],
        "tags": ["cdn"],
    }
    with patch("requests.get", return_value=mock_resp):
        result = query_shodan("1.1.1.1", "fake-key")
    assert result["ip"] == "1.1.1.1"
    assert result["ports"] == [80, 443]
    assert result["org"] == "Cloudflare"


def test_query_shodan_empty_key_returns_error():
    result = query_shodan("1.1.1.1", "")
    assert "error" in result
    assert "not configured" in result["error"]


def test_query_shodan_http_error_returns_error():
    import requests as _requests
    with patch("requests.get", side_effect=_requests.HTTPError("403 Forbidden")):
        result = query_shodan("1.1.1.1", "fake-key")
    assert "error" in result
```

Also add to `tests/server/test_agent_safety.py` (append these tests):

```python
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
    import json
    data = json.loads(result)
    assert "error" in data

def test_exec_tool_unknown_returns_error():
    import sqlite3, json
    from aivas.tui.agent import _exec_tool
    conn = sqlite3.connect(":memory:")
    result, intent = _exec_tool("nonexistent_tool", {}, conn)
    assert "error" in json.loads(result)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_shodan_client.py tests/server/test_agent_safety.py -v 2>&1 | tail -20
```
Expected: ImportError for `shodan_client`, and failures for the new agent_safety tests

- [ ] **Step 3: Create `aivas/narrator/shodan_client.py`**

```python
"""Shodan free-tier IP intelligence lookup."""
from __future__ import annotations
import requests

_BASE = "https://api.shodan.io/shodan/host"


def query_shodan(ip: str, api_key: str) -> dict:
    """Return threat intelligence for ip from Shodan free-tier API.

    Returns a dict with ip, ports, hostnames, country, org, vulns, tags.
    On error or missing key, returns {"ip": ip, "error": "..."}.
    """
    if not api_key:
        return {"ip": ip, "error": "Shodan key not configured."}
    try:
        resp = requests.get(
            f"{_BASE}/{ip}",
            params={"key": api_key},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "ip": data.get("ip_str", ip),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "country": data.get("country_name", ""),
            "org": data.get("org", ""),
            "vulns": list(data.get("vulns", {}).keys()),
            "tags": data.get("tags", []),
        }
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}
```

- [ ] **Step 4: Replace `aivas/tui/agent_prompts.py`**

```python
"""Prompt strings and tool schemas for the AIVAS AI agent."""
from __future__ import annotations

SYSTEM = """\
You are AIVAS, a network security analyst assistant for small businesses in Tanzania.

You help users understand their network security: scan hosts for open ports and
vulnerabilities, explain CVEs, answer questions about networking and security,
and give actionable remediation advice. Respond naturally — match the format to
what was asked. A greeting gets a greeting. A quick question gets a short answer.
A narration request gets a structured assessment.

Tools available:
- scan_host: trigger a network scan. Call this when the user asks to scan.
  Confirm you have started it, then wait for the results to appear.
- get_history: list recent scans.
- get_last_scan: get findings from the most recent scan.
- get_findings: get CVE findings for a specific scan ID.
- explain_cve: look up a CVE in the local vulnerability database.
- query_shodan: get threat intelligence for an IP from Shodan.

Rules:
- Never fabricate CVE details. Only cite CVEs returned by tools in this session.
- If you mention a CVE ID that was not returned by a tool, add a note that it
  could not be verified against local scan data.
- Match the user's language (Swahili or English). Mixed language — prefer the
  majority. Default to English when unclear.
- Keep CVE IDs (e.g. CVE-2021-44228), IP addresses, port numbers, product names,
  and version numbers in their original Latin form — never translate identifiers.\
"""

TOOLS = [
    {"type": "function", "function": {
        "name": "scan_host",
        "description": "Scan a host for open ports and vulnerabilities",
        "parameters": {"type": "object", "required": ["target"], "properties": {
            "target": {"type": "string", "description": "IP address, hostname, or CIDR"},
            "level": {"type": "string", "description": "Scan depth: 1=quick 2=full 3=deep"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_history",
        "description": "List recent scans from scan history",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "string", "description": "Number of scans to return"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_last_scan",
        "description": "Get CVE findings from the most recent scan",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_findings",
        "description": "Get CVE findings for a specific scan ID",
        "parameters": {"type": "object", "required": ["scan_id"], "properties": {
            "scan_id": {"type": "string", "description": "Scan ID from get_history"},
        }},
    }},
    {"type": "function", "function": {
        "name": "explain_cve",
        "description": "Look up a CVE in the local vulnerability database",
        "parameters": {"type": "object", "required": ["cve_id"], "properties": {
            "cve_id": {"type": "string", "description": "CVE ID e.g. CVE-2021-44228"},
        }},
    }},
    {"type": "function", "function": {
        "name": "query_shodan",
        "description": "Get threat intelligence for an IP address from Shodan",
        "parameters": {"type": "object", "required": ["ip"], "properties": {
            "ip": {"type": "string", "description": "IPv4 address to look up"},
        }},
    }},
]
```

- [ ] **Step 5: Update `aivas/tui/agent.py` — add `shodan_key` param to `_exec_tool` and add `query_shodan` case**

In `_exec_tool` (line 39), change the signature and add the new case before the final `return`:

```python
def _exec_tool(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None = None
) -> tuple[str, tuple | None]:
```

Add this case before `return json.dumps({"error": f"Unknown tool: {name}"})`:

```python
    if name == "query_shodan":
        ip = _as_str(args.get("ip"))
        if not ip:
            return json.dumps({"error": "ip is required."}), None
        from aivas.narrator.shodan_client import query_shodan
        result = query_shodan(ip, shodan_key or "")
        return json.dumps(result), None
```

- [ ] **Step 6: Run tests and verify they pass**

```bash
pytest tests/test_shodan_client.py tests/server/test_agent_safety.py -v
```
Expected: all tests PASS

- [ ] **Step 7: Run full test suite**

```bash
pytest --tb=short -q 2>&1 | tail -10
```

- [ ] **Step 8: Commit**

```bash
git add aivas/tui/agent_prompts.py aivas/tui/agent.py aivas/narrator/shodan_client.py tests/test_shodan_client.py tests/server/test_agent_safety.py
git commit -m "feat: conversational system prompt, Shodan tool, query_shodan in agent"
```

---

### Task 3: Streaming agent (`aivas/server/chat_stream.py`)

**Files:**
- Create: `aivas/server/chat_stream.py`
- Test: `tests/server/test_chat_stream.py` (new)

**Interfaces:**
- Consumes: `BaseProvider` from Task 1, `_exec_tool` from `agent.py` (Task 2), `SYSTEM` + `TOOLS` from `agent_prompts.py` (Task 2)
- Produces: `stream_agent_response(provider, session_history, user_text, conn, shodan_key=None) -> AsyncGenerator[dict, None]`
- Events yielded: `{"type":"thinking"}`, `{"type":"token","text":"..."}`, `{"type":"scan_triggered","target":"...","level":2}`, `{"type":"done","full_text":"...","turns":[...]}`, `{"type":"error","text":"..."}`

**Design:** Phase A uses Groq `llama-3.1-8b-instant` (blocking) to handle tool calls. Phase B calls `provider.stream()` for the final user-facing response. Tool results >4000 chars are compressed by a Groq summariser before continuing.

- [ ] **Step 1: Write the failing tests**

```python
# tests/server/test_chat_stream.py
import asyncio
import json
import sqlite3
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from aivas.database.schema import create_schema


async def _collect(gen):
    return [ev async for ev in gen]


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    return db


class MockProvider:
    name = "mock"
    def generate(self, prompt, max_tokens=300):
        return "ok"
    async def stream(self, messages, max_tokens=1024):
        for word in ["Hello", " World"]:
            yield word


def _groq_resp(content="", tool_calls=None):
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls or []
    resp = MagicMock()
    resp.choices[0].message = msg
    return resp


def test_stream_simple_response(conn):
    """No tool calls — streams tokens directly from provider."""
    from aivas.server.chat_stream import stream_agent_response

    # Groq returns no tool calls → provider.stream() runs
    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.return_value = _groq_resp("Hi")
        events = asyncio.run(_collect(
            stream_agent_response(
                MockProvider(), [], "Hello", conn
            )
        ))

    types = [e["type"] for e in events]
    assert "thinking" in types
    assert "token" in types
    assert types[-1] == "done"

    tokens = [e["text"] for e in events if e["type"] == "token"]
    assert "".join(tokens) == "Hello World"


def test_stream_scan_triggered(conn):
    """AI calls scan_host → scan_triggered event emitted."""
    from aivas.server.chat_stream import stream_agent_response

    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "scan_host"
    tc.function.arguments = json.dumps({"target": "192.168.1.1", "level": "2"})

    # First call: tool call. Second call: final response (no tools).
    groq_tool_resp = _groq_resp(tool_calls=[tc])
    groq_final_resp = _groq_resp("")

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            groq_tool_resp, groq_final_resp
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "scan 192.168.1.1", conn)
        ))

    scan_ev = next((e for e in events if e["type"] == "scan_triggered"), None)
    assert scan_ev is not None
    assert scan_ev["target"] == "192.168.1.1"
    assert scan_ev["level"] == 2
    done = events[-1]
    assert done["type"] == "done"
    assert "turns" in done


def test_stream_error_on_missing_groq_key(conn, monkeypatch):
    """No GROQ_API_KEY and no config key → error event."""
    from aivas.server.chat_stream import stream_agent_response
    monkeypatch.setenv("GROQ_API_KEY", "")

    with patch("aivas.server.chat_stream._load_groq_key", return_value=None):
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "Hi", conn)
        ))
    assert events[0]["type"] == "error"
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest tests/server/test_chat_stream.py -v 2>&1 | tail -10
```
Expected: ImportError — file doesn't exist yet

- [ ] **Step 3: Create `aivas/server/chat_stream.py`**

```python
"""Streaming agent loop for the web chat WebSocket."""
from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
from typing import AsyncGenerator

from aivas.narrator.providers.base import BaseProvider
from aivas.tui.agent_prompts import SYSTEM as _SYSTEM, TOOLS as _TOOLS

_MAX_STEPS = 5
_SUMMARIZE_THRESHOLD = 4000
_SUMMARIZE_TOKENS = 500
_XML_CALL_RE = re.compile(r"<function=\w[^>]*>.*?</function>", re.DOTALL)


def _load_groq_key() -> str | None:
    try:
        from aivas import config as _cfg
        key = _cfg.load().get("api_key")
        if key:
            return key
    except Exception:
        pass
    return os.environ.get("GROQ_API_KEY") or None


async def _summarize(text: str, question: str, groq_client) -> str:
    prompt = (
        f"Extract only the security-relevant facts needed to answer: {question!r}\n\n"
        f"Tool output:\n{text}"
    )
    resp = await asyncio.to_thread(
        lambda: groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=_SUMMARIZE_TOKENS,
        )
    )
    return resp.choices[0].message.content or text[:_SUMMARIZE_THRESHOLD]


def _exec_tool_local(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None
) -> tuple[str, tuple | None]:
    """Dispatch tool call. Returns (result_json, scan_intent | None)."""
    from aivas.tui.agent import _exec_tool
    return _exec_tool(name, args, conn, shodan_key=shodan_key)


async def stream_agent_response(
    provider: BaseProvider,
    session_history: list[dict],
    user_text: str,
    conn: sqlite3.Connection,
    shodan_key: str | None = None,
) -> AsyncGenerator[dict, None]:
    """Yield WebSocket events for one user turn.

    Phase A: Groq llama-3.1-8b-instant handles tool calls (blocking, fast).
    Phase B: provider.stream() delivers the final response token-by-token.
    """
    from groq import Groq

    groq_key = _load_groq_key()
    if not groq_key:
        yield {"type": "error", "text": "No Groq API key configured. Run: aivas config set api_key YOUR_KEY"}
        return

    groq = Groq(api_key=groq_key)
    messages: list[dict] = [{"role": "system", "content": _SYSTEM}]
    if session_history:
        messages.extend(session_history)
    messages.append({"role": "user", "content": user_text})

    turns_to_persist: list[dict] = []
    full_text = ""

    for _step in range(_MAX_STEPS):
        yield {"type": "thinking"}

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

        msg = resp.choices[0].message

        if not msg.tool_calls:
            # Phase B: stream the final response
            async for token in provider.stream(messages, max_tokens=1200):
                clean = _XML_CALL_RE.sub("", token)
                if clean:
                    full_text += clean
                    yield {"type": "token", "text": clean}
            turns_to_persist.append({"role": "assistant", "content": full_text})
            yield {"type": "done", "full_text": full_text, "turns": turns_to_persist}
            return

        # Handle tool calls
        tool_calls_payload = [
            {
                "id": tc.id, "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
            }
            for tc in msg.tool_calls
        ]
        assistant_turn = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": tool_calls_payload,
        }
        messages.append(assistant_turn)
        turns_to_persist.append(assistant_turn)

        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}

            result, scan_intent = _exec_tool_local(tc.function.name, args, conn, shodan_key)

            if scan_intent:
                yield {"type": "scan_triggered", "target": scan_intent[0], "level": scan_intent[1]}

            if len(result) > _SUMMARIZE_THRESHOLD:
                result = await _summarize(result, user_text, groq)

            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)

    # Exhausted steps — stream whatever the provider gives
    async for token in provider.stream(messages, max_tokens=1200):
        clean = _XML_CALL_RE.sub("", token)
        if clean:
            full_text += clean
            yield {"type": "token", "text": clean}
    turns_to_persist.append({"role": "assistant", "content": full_text})
    yield {"type": "done", "full_text": full_text, "turns": turns_to_persist}
```

- [ ] **Step 4: Run tests and verify they pass**

```bash
pytest tests/server/test_chat_stream.py -v
```
Expected: all tests PASS

- [ ] **Step 5: Run full suite**

```bash
pytest --tb=short -q 2>&1 | tail -10
```

- [ ] **Step 6: Commit**

```bash
git add aivas/server/chat_stream.py tests/server/test_chat_stream.py
git commit -m "feat: streaming agent with Phase A tool dispatch and Phase B provider stream"
```

---

### Task 4: WebSocket streaming (`aivas/server/ws_chat.py` rewrite)

**Files:**
- Modify: `aivas/server/ws_chat.py` (full rewrite — 60 lines → ~90 lines)
- Modify: `aivas/server/chat_api.py` (simplify `handle_chat`; keep `handle_narrate`)
- Modify: `tests/server/test_ws_chat.py` (update for new event protocol)

**Interfaces:**
- Consumes: `stream_agent_response()` from Task 3
- WS connect URL: `/ws/chat/{session_id}?provider=groq&model=llama-3.3-70b-versatile`
- First message after connect (optional): `{"type":"auth","api_key":"...","shodan_key":"..."}`
- Events sent to client: `{"type":"thinking"}`, `{"type":"token","text":"..."}`, `{"type":"scan_triggered","target":"...","level":2,"scan_key":"..."}`, `{"type":"done","text":"..."}`, `{"type":"error","text":"..."}`

Note: `{"type":"complete","text":"..."}` is **gone** — replaced by streaming tokens + `done`. The scan event was `scan_intent`; it is now `scan_triggered` with an added `scan_key`. Update ws_chat tests to match.

- [ ] **Step 1: Update the tests first**

```python
# tests/server/test_ws_chat.py  (full replacement)
import sqlite3
import asyncio
from unittest.mock import patch, AsyncMock

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
        msg = ws.receive_json()
        assert msg["type"] == "error"


def test_ws_chat_streams_tokens(client):
    """User sends a message → receives thinking, token(s), done."""
    sid = client.post("/api/sessions").json()["id"]

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        yield {"type": "thinking"}
        yield {"type": "token", "text": "Hello"}
        yield {"type": "token", "text": " back"}
        yield {"type": "done", "full_text": "Hello back", "turns": [
            {"role": "assistant", "content": "Hello back"}
        ]}

    with patch("aivas.server.ws_chat.stream_agent_response", side_effect=fake_stream):
        with client.websocket_connect(f"/ws/chat/{sid}") as ws:
            ws.send_json({"type": "user", "text": "hi"})
            msgs = [ws.receive_json() for _ in range(4)]

    types = [m["type"] for m in msgs]
    assert "thinking" in types
    assert "token" in types
    assert "done" in types
    tokens = [m["text"] for m in msgs if m["type"] == "token"]
    assert "".join(tokens) == "Hello back"


def test_ws_chat_scan_triggered_registers_key(client):
    """scan_triggered event gets a scan_key registered in _pending."""
    sid = client.post("/api/sessions").json()["id"]

    async def fake_stream(provider, history, text, conn, shodan_key=None):
        yield {"type": "thinking"}
        yield {"type": "scan_triggered", "target": "10.0.0.1", "level": 2}
        yield {"type": "done", "full_text": "Scan started.", "turns": [
            {"role": "assistant", "content": "Scan started."}
        ]}

    with patch("aivas.server.ws_chat.stream_agent_response", side_effect=fake_stream):
        with client.websocket_connect(f"/ws/chat/{sid}") as ws:
            ws.send_json({"type": "user", "text": "scan 10.0.0.1"})
            msgs = [ws.receive_json() for _ in range(3)]

    scan_ev = next(m for m in msgs if m["type"] == "scan_triggered")
    assert scan_ev["target"] == "10.0.0.1"
    assert "scan_key" in scan_ev
    assert scan_ev["scan_key"] in main_mod._pending
```

- [ ] **Step 2: Run to verify they fail**

```bash
pytest tests/server/test_ws_chat.py -v 2>&1 | tail -15
```
Expected: test_ws_chat_streams_tokens and test_ws_chat_scan_triggered_registers_key FAIL (old protocol)

- [ ] **Step 3: Rewrite `aivas/server/ws_chat.py`**

```python
"""WebSocket chat endpoint — streaming responses to the web UI."""
from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from aivas.server.chat_stream import stream_agent_response
from aivas.server.chat_memory import save_user, save_assistant, save_tool_result, update_title_if_unset, touch_session
from aivas.narrator.providers.factory import get_provider

router = APIRouter()

_PROVIDER_DEFAULTS = {
    "groq": "llama-3.3-70b-versatile",
    "claude": "claude-haiku-4-5-20251001",
    "ollama": "llama3",
}


@router.websocket("/ws/chat/{session_id}")
async def chat_ws(
    websocket: WebSocket,
    session_id: str,
    provider: str = "groq",
    model: str | None = None,
):
    import aivas.server.main as _main
    from aivas import config as _cfg

    await websocket.accept()
    if not _main.get_session(_main._conn, session_id):
        await websocket.send_json({"type": "error", "text": "Unknown session id."})
        await websocket.close()
        return

    cfg = _cfg.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    shodan_key: str | None = None

    try:
        while True:
            try:
                msg = await websocket.receive_json()
            except WebSocketDisconnect:
                return

            if msg.get("type") == "auth":
                api_key = msg.get("api_key") or api_key
                shodan_key = msg.get("shodan_key") or shodan_key
                continue

            if msg.get("type") != "user":
                continue

            text = msg.get("text", "").strip()
            if not text:
                continue

            save_user(_main._conn, session_id, text)
            update_title_if_unset(_main._conn, session_id, text)

            from aivas.server.chat_memory import load_history
            history = load_history(_main._conn, session_id, max_turns=6)

            try:
                chosen_model = model or _PROVIDER_DEFAULTS.get(provider, "llama-3.3-70b-versatile")
                llm = get_provider(provider, model=chosen_model, api_key=api_key)
            except ValueError as exc:
                await websocket.send_json({"type": "error", "text": str(exc)})
                continue

            async for event in stream_agent_response(
                llm, history, text, _main._conn, shodan_key=shodan_key
            ):
                if event["type"] == "scan_triggered":
                    scan_key = str(uuid.uuid4())
                    _main._pending[scan_key] = (event["target"], event["level"])
                    await websocket.send_json({**event, "scan_key": scan_key})
                elif event["type"] == "done":
                    for turn in event.get("turns", []):
                        role = turn.get("role")
                        if role == "assistant":
                            save_assistant(
                                _main._conn, session_id, turn.get("content", ""),
                                tool_calls=turn.get("tool_calls"),
                            )
                        elif role == "tool":
                            save_tool_result(
                                _main._conn, session_id,
                                turn["tool_call_id"], turn.get("content", ""),
                            )
                    touch_session(_main._conn, session_id)
                    await websocket.send_json({"type": "done", "text": event.get("full_text", "")})
                else:
                    await websocket.send_json(event)

    except WebSocketDisconnect:
        return
```

- [ ] **Step 4: Simplify `aivas/server/chat_api.py`** — remove `handle_chat` (replaced by ws_chat streaming path), keep `handle_narrate`. Also remove `_build_context` since it's no longer used.

The file becomes (replace entire content):

```python
"""Stateless narration endpoint — no TUI or session dependency."""
from __future__ import annotations

import os
import sqlite3

from aivas import config as _config
from aivas.history import get_scan_findings, list_scans


async def handle_narrate(conn: sqlite3.Connection, scan_id: int) -> str:
    """Generate a security assessment for a completed scan (stateless single-shot)."""
    cfg = _config.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "No AI key configured. Run: aivas config set api_key YOUR_GROQ_KEY"

    scans = list_scans(conn, limit=5)
    scan_ref = next((s for s in scans if s["id"] == scan_id), None)
    if not scan_ref:
        return f"Scan #{scan_id} not found."

    findings = get_scan_findings(conn, scan_id)
    if not findings:
        return f"No findings for scan #{scan_id}."

    lines = [
        f"Scan #{scan_id}: {scan_ref['target']} — Grade {scan_ref.get('grade','?')} ({scan_ref.get('risk_score','?')}/100)",
        "",
        "Findings:",
    ]
    for f in findings[:15]:
        lines.append(
            f"  {f['cve_id']} CVSS {f.get('cvss_score','N/A')} ({f.get('cvss_severity','?')}): "
            f"{(f.get('description') or '')[:120]}"
        )
    context = "\n".join(lines)

    prompt = (
        f"{context}\n\nWrite a 3-paragraph professional security assessment. "
        "Paragraph 1: overall risk and grade justification. "
        "Paragraph 2: most critical findings and real-world impact. "
        "Paragraph 3: prioritised remediation actions. "
        "Use **bold** for CVE IDs. Do not initiate a new scan."
    )

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
        )
        return resp.choices[0].message.content or "Assessment could not be generated."
    except Exception as exc:
        return f"Assessment error: {exc}"
```

- [ ] **Step 5: Update `aivas/server/main.py`** — remove the `handle_chat` import (line 18) since it's no longer used by main.py

Find line:
```python
from aivas.server.chat_api import handle_chat
```
Remove it. `handle_narrate` is still imported via the `/api/narrate/{scan_id}` route which does a lazy import.

Also update the `POST /api/chat` REST route — it still needs to work for non-WS clients. Replace the route handler to use `handle_narrate`-style direct call:

Actually, looking at main.py line 110-120, `POST /api/chat` calls `handle_chat`. Since we removed `handle_chat`, update this route to use `stream_agent_response` and return the full text:

```python
@app.post("/api/chat")
async def chat(body: ChatRequest):
    from aivas.server.chat_stream import stream_agent_response
    from aivas.narrator.providers.factory import get_provider
    from aivas import config as _cfg
    import os

    sid = body.session_id or create_session(_conn)
    cfg = _cfg.load()
    api_key = cfg.get("api_key") or os.environ.get("GROQ_API_KEY")

    try:
        provider = get_provider("groq", api_key=api_key)
    except ValueError as exc:
        return {"response": str(exc), "session_id": sid, "scan_id": None}

    from aivas.server.chat_memory import load_history
    history = load_history(_conn, sid, max_turns=6)

    full_text = ""
    scan_key = None
    async for event in stream_agent_response(provider, history, body.text, _conn):
        if event["type"] == "token":
            full_text += event["text"]
        elif event["type"] == "scan_triggered":
            scan_key = str(uuid.uuid4())
            _pending[scan_key] = (event["target"], event["level"])
        elif event["type"] == "done":
            from aivas.server.chat_memory import save_user, save_assistant, save_tool_result, update_title_if_unset, touch_session
            save_user(_conn, sid, body.text)
            update_title_if_unset(_conn, sid, body.text)
            for turn in event.get("turns", []):
                if turn.get("role") == "assistant":
                    save_assistant(_conn, sid, turn.get("content", ""), tool_calls=turn.get("tool_calls"))
                elif turn.get("role") == "tool":
                    save_tool_result(_conn, sid, turn["tool_call_id"], turn.get("content", ""))
            touch_session(_conn, sid)
    return {"response": full_text, "scan_id": scan_key, "session_id": sid}
```

Remove the old import at the top of main.py:
```python
from aivas.server.chat_api import handle_chat
```

- [ ] **Step 6: Run tests**

```bash
pytest tests/server/test_ws_chat.py tests/server/test_chat_api_session.py -v 2>&1 | tail -20
```
Expected: all PASS. Note: `test_chat_api_session.py` tests `handle_narrate` which is now simpler — verify it still passes.

- [ ] **Step 7: Run full suite**

```bash
pytest --tb=short -q 2>&1 | tail -10
```

- [ ] **Step 8: Commit**

```bash
git add aivas/server/ws_chat.py aivas/server/chat_api.py aivas/server/main.py tests/server/test_ws_chat.py
git commit -m "feat: WebSocket chat now streams tokens; scan_triggered replaces scan_intent"
```

---

### Task 5: Scan worker cleanup

**Files:**
- Modify: `aivas/server/scan_worker.py` (remove AI phases, add log accumulation)
- Modify: `tests/server/test_scan_worker.py` (verify no LLM calls, verify log field)

**Goal:** Remove lines 147–186 (AI NARRATION + AI REMEDIATION phases). The `done` event gains a `log: list[str]` field containing every phase event text from the scan.

- [ ] **Step 1: Add tests**

Append to `tests/server/test_scan_worker.py`:

```python
def test_run_scan_does_not_call_llm(conn):
    """Scan pipeline must not make any LLM calls after cleanup."""
    with patch("aivas.server.scan_worker._blocking_nmap") as mock_nmap, \
         patch("aivas.server.scan_worker.parse_nmap_xml") as mock_parse, \
         patch("aivas.server.scan_worker.score_findings") as mock_score, \
         patch("aivas.server.scan_worker.save_scan", return_value=42) as mock_save:

        mock_nmap.return_value = "<nmaprun/>"
        mock_parse.return_value = [
            {"host": "1.2.3.4", "port": 80, "protocol": "tcp",
             "service": "http", "product": "nginx", "version": "1.18"}
        ]
        mock_score.return_value = {"grade": "B", "score": 65, "total": 1, "sev_counts": {}}

        with patch("aivas.server.scan_worker.cve_events") as mock_cve, \
             patch("aivas.server.scan_worker.http_probe_events") as mock_http:

            async def _empty():
                yield {"__findings": []}
                return

            async def _empty_http():
                yield {"__misconfigs": []}
                return

            mock_cve.return_value = _empty()
            mock_http.return_value = _empty_http()

            events = asyncio.run(_collect(run_scan(conn, "1.2.3.4")))

    # No groq/narrator calls should have been made
    import sys
    for mod_name in list(sys.modules):
        if "groq" in mod_name:
            assert not hasattr(sys.modules[mod_name], '_call_count'), \
                "Groq module should not have been called"

    done = next(e for e in events if e["type"] == "done")
    assert "log" in done
    assert isinstance(done["log"], list)
    assert len(done["log"]) > 0


def test_done_event_has_log_with_phase_events(conn):
    """done event log contains phase header strings."""
    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<nmaprun/>"), \
         patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[]), \
         patch("aivas.server.scan_worker.score_findings", return_value={"grade": "A", "score": 95, "total": 0, "sev_counts": {}}):
        events = asyncio.run(_collect(run_scan(conn, "1.2.3.4")))

    # Either error (no open ports) or done — both should carry log
    last = events[-1]
    # For "no open ports" case, no done event, but we verify the error path is clean
    assert last["type"] in ("error", "done")
```

- [ ] **Step 2: Run to verify**

```bash
pytest tests/server/test_scan_worker.py -v 2>&1 | tail -15
```
New tests will fail (log field doesn't exist yet; AI phases still present)

- [ ] **Step 3: Modify `aivas/server/scan_worker.py`**

**a) Remove the AI phases.** Delete lines 147–186 (the block from `api_key = os.environ.get("GROQ_API_KEY")` through `yield _ev("advice_error", ...)`) and the trailing blank line. Also remove unused imports: line 16 `from aivas.narrator.narrator import narrate` and line 17 `from aivas.narrator.providers import GroqProvider` and line 18 `from aivas.server.cve_advice import warm_cache`.

**b) Add log accumulation.** At the top of `run_scan()`, add `_log: list[str] = []`.

After every `yield _ev(...)` call that isn't `done` or `error`, also append the text to `_log`. The cleanest way: create a helper that both appends and yields:

Replace the function signature and add a helper inside `run_scan`:

```python
async def run_scan(
    conn: sqlite3.Connection, target: str, level: int = 2
) -> AsyncGenerator[dict, None]:
    """Yield granular progress events then a single done or error event."""
    is_net = "/" in target
    scripts = scripts_for_level(level)
    _log: list[str] = []

    def _emit(ev: dict) -> dict:
        if ev.get("text"):
            _log.append(ev["text"])
        return ev
```

Then replace each `yield _ev(...)` with `yield _emit(_ev(...))` for all non-done/non-error events.

For the `done` event (currently lines 205–235), add `"log": _log` to the dict:

```python
    yield {
        "type": "done",
        "target": target,
        "scan_id": scan_id,
        "score": score,
        "grade": grade,
        "service_count": len(all_services),
        "log": _log,
        "services": [...],
        "findings": [...],
        "misconfigs": all_misconfigs,
    }
```

Also remove the `os` import if it was only used for the AI phase (`os.environ.get("GROQ_API_KEY")`). Check: `os` is still used on line 8 for the `os` import in the original file — keep it if used elsewhere, otherwise remove.

- [ ] **Step 4: Run tests**

```bash
pytest tests/server/test_scan_worker.py -v
```
Expected: all tests PASS including the two new ones

- [ ] **Step 5: Run full suite**

```bash
pytest --tb=short -q 2>&1 | tail -10
```

- [ ] **Step 6: Commit**

```bash
git add aivas/server/scan_worker.py tests/server/test_scan_worker.py
git commit -m "feat: remove AI phases from scan worker; scan is now fast; done event carries log"
```

---

### Task 6: Frontend streaming foundation

**Files:**
- Modify: `frontend/src/lib/messageReducer.js` (add `SET_STREAMING` action)
- Modify: `frontend/src/components/AiMessage.jsx` (streaming cursor ▋)
- Test: `frontend/src/lib/messageReducer.js` tests (inline in same test file if exists, or add)

**Interfaces:**
- Consumes: `message.streaming: boolean` field on AI messages
- New action: `SET_STREAMING: { type: 'SET_STREAMING', id, streaming }` — sets `message.streaming` flag
- `AiMessage` accepts `streaming` prop: when `true`, appends `▋` cursor after text

- [ ] **Step 1: Write failing tests**

Create `frontend/src/lib/messageReducer.test.js`:

```javascript
import { describe, it, expect } from 'vitest'
import { reducer, uid } from './messageReducer'

describe('reducer', () => {
  it('APPEND adds message to state', () => {
    const msg = { id: 'a', type: 'ai', text: '' }
    const state = reducer([], { type: 'APPEND', msg })
    expect(state).toHaveLength(1)
    expect(state[0]).toEqual(msg)
  })

  it('UPDATE_TEXT updates matching message text', () => {
    const initial = [{ id: 'x', type: 'ai', text: 'old' }]
    const state = reducer(initial, { type: 'UPDATE_TEXT', id: 'x', text: 'new' })
    expect(state[0].text).toBe('new')
  })

  it('SET_STREAMING sets streaming flag', () => {
    const initial = [{ id: 'x', type: 'ai', text: 'hello', streaming: true }]
    const state = reducer(initial, { type: 'SET_STREAMING', id: 'x', streaming: false })
    expect(state[0].streaming).toBe(false)
  })

  it('SET_STREAMING does not mutate other fields', () => {
    const initial = [{ id: 'x', type: 'ai', text: 'hello', streaming: true }]
    const state = reducer(initial, { type: 'SET_STREAMING', id: 'x', streaming: false })
    expect(state[0].text).toBe('hello')
    expect(state[0].type).toBe('ai')
  })

  it('REMOVE removes matching message', () => {
    const initial = [{ id: 'a' }, { id: 'b' }]
    const state = reducer(initial, { type: 'REMOVE', id: 'a' })
    expect(state).toHaveLength(1)
    expect(state[0].id).toBe('b')
  })

  it('SET_MESSAGES replaces state entirely', () => {
    const initial = [{ id: 'a' }]
    const msgs = [{ id: 'b' }, { id: 'c' }]
    const state = reducer(initial, { type: 'SET_MESSAGES', messages: msgs })
    expect(state).toEqual(msgs)
  })

  it('unknown action returns state unchanged', () => {
    const initial = [{ id: 'z' }]
    const state = reducer(initial, { type: 'BOGUS' })
    expect(state).toBe(initial)
  })
})
```

Also create `frontend/src/components/AiMessage.test.jsx`:

```javascript
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import AiMessage from './AiMessage'

describe('AiMessage', () => {
  it('renders text', () => {
    render(<AiMessage text="Hello world" />)
    expect(screen.getByText(/Hello world/)).toBeTruthy()
  })

  it('shows cursor when streaming=true', () => {
    const { container } = render(<AiMessage text="Typing" streaming={true} />)
    expect(container.textContent).toContain('▋')
  })

  it('hides cursor when streaming=false', () => {
    const { container } = render(<AiMessage text="Done" streaming={false} />)
    expect(container.textContent).not.toContain('▋')
  })

  it('hides cursor when streaming prop absent', () => {
    const { container } = render(<AiMessage text="Done" />)
    expect(container.textContent).not.toContain('▋')
  })
})
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/cyberpunk/aivas/frontend && npx vitest run src/lib/messageReducer.test.js src/components/AiMessage.test.jsx 2>&1 | tail -20
```
Expected: SET_STREAMING test fails (action doesn't exist); cursor tests fail

- [ ] **Step 3: Add SET_STREAMING to `frontend/src/lib/messageReducer.js`**

Add this case to the `switch` in `reducer()`, before `default`:

```javascript
    case 'SET_STREAMING':
      return state.map(m => m.id === action.id ? { ...m, streaming: action.streaming } : m)
```

- [ ] **Step 4: Update `frontend/src/components/AiMessage.jsx`**

```javascript
import { mdToHtml } from '../lib/mdToHtml'

export default function AiMessage({ text, streaming }) {
  return (
    <div className="py-3">
      <div style={{ color: '#4a9eff' }} className="text-xs font-medium mb-1.5 select-none">
        ✦ AIVAS
      </div>
      <div
        style={{ color: '#c8c8c8', lineHeight: 1.7 }}
        className="text-sm"
        dangerouslySetInnerHTML={{ __html: mdToHtml(text) + (streaming ? '<span class="cursor-blink">▋</span>' : '') }}
      />
    </div>
  )
}
```

- [ ] **Step 5: Run tests**

```bash
npx vitest run src/lib/messageReducer.test.js src/components/AiMessage.test.jsx 2>&1 | tail -15
```
Expected: all PASS

- [ ] **Step 6: Run full frontend test suite**

```bash
npx vitest run 2>&1 | tail -10
```
Expected: all existing tests still pass

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/lib/messageReducer.js frontend/src/lib/messageReducer.test.js frontend/src/components/AiMessage.jsx frontend/src/components/AiMessage.test.jsx
git commit -m "feat: SET_STREAMING reducer action and AiMessage streaming cursor"
```

---

### Task 7: Frontend hooks — useChat auth + useScan log

**Files:**
- Modify: `frontend/src/hooks/useChat.js`
- Modify: `frontend/src/hooks/useScan.js`
- Modify: `frontend/src/hooks/useChat.test.js` (update for new protocol)
- Modify: `frontend/src/hooks/useScan.test.js` (add log accumulation test)

**Changes:**
- `useChat` — accept `{ sessionId, onEvent, provider, model, apiKey, shodanKey }` props; send auth message on WS open; handle `token` and `done` events via `onEvent`
- `useScan` — accumulate all event texts in `logRef`; pass `log: string[]` in the `onDone` callback

- [ ] **Step 1: Read current hook tests**

```bash
cat /home/cyberpunk/aivas/frontend/src/hooks/useChat.test.js
cat /home/cyberpunk/aivas/frontend/src/hooks/useScan.test.js
```

- [ ] **Step 2: Update `frontend/src/hooks/useChat.test.js`**

Replace with:

```javascript
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useChat } from './useChat'

class FakeWS {
  constructor(url) { this.url = url; this.sent = []; this.readyState = 0 }
  send(data) { this.sent.push(JSON.parse(data)) }
  close() { this.readyState = 3 }
}

let fakeWs
beforeEach(() => {
  fakeWs = null
  vi.stubGlobal('WebSocket', function(url) {
    fakeWs = new FakeWS(url)
    return fakeWs
  })
})

describe('useChat', () => {
  it('opens WS with provider/model query params', () => {
    renderHook(() => useChat({
      sessionId: 'abc', onEvent: vi.fn(),
      provider: 'groq', model: 'llama-3.3-70b-versatile'
    }))
    expect(fakeWs.url).toContain('provider=groq')
    expect(fakeWs.url).toContain('model=llama-3.3-70b-versatile')
  })

  it('sends auth message on open with api key', () => {
    renderHook(() => useChat({
      sessionId: 'abc', onEvent: vi.fn(),
      apiKey: 'gsk_test', shodanKey: 'shodan_key_123'
    }))
    act(() => { fakeWs.onopen?.() })
    const authMsg = fakeWs.sent.find(m => m.type === 'auth')
    expect(authMsg).toBeTruthy()
    expect(authMsg.api_key).toBe('gsk_test')
    expect(authMsg.shodan_key).toBe('shodan_key_123')
  })

  it('calls onEvent for token messages', () => {
    const onEvent = vi.fn()
    renderHook(() => useChat({ sessionId: 'abc', onEvent }))
    act(() => { fakeWs.onmessage?.({ data: JSON.stringify({ type: 'token', text: 'Hi' }) }) })
    expect(onEvent).toHaveBeenCalledWith({ type: 'token', text: 'Hi' })
  })

  it('send() dispatches user message when open', () => {
    const { result } = renderHook(() => useChat({ sessionId: 'abc', onEvent: vi.fn() }))
    act(() => { fakeWs.readyState = 1; fakeWs.onopen?.() })
    act(() => result.current.send('hello') )
    const userMsg = fakeWs.sent.find(m => m.type === 'user')
    expect(userMsg?.text).toBe('hello')
  })
})
```

- [ ] **Step 3: Update `frontend/src/hooks/useScan.test.js`** — add log accumulation test

Append to the existing test file:

```javascript
it('passes log array to onDone', () => {
  const onDone = vi.fn()
  const { result } = renderHook(() => useScan(vi.fn(), onDone))

  act(() => result.current.start('key123'))

  act(() => {
    fakeWs.onmessage?.({ data: JSON.stringify({ type: 'phase_header', text: 'PORT SCANNING' }) })
    fakeWs.onmessage?.({ data: JSON.stringify({ type: 'ports', text: 'Found 3 ports' }) })
    fakeWs.onmessage?.({ data: JSON.stringify({
      type: 'done', scan_id: 1, target: '1.1.1.1',
      grade: 'B', score: 60, service_count: 3,
      findings: [], misconfigs: [], services: [],
    }) })
  })

  expect(onDone).toHaveBeenCalled()
  const doneArg = onDone.mock.calls[0][0]
  expect(doneArg.log).toBeDefined()
  expect(doneArg.log).toContain('PORT SCANNING')
  expect(doneArg.log).toContain('Found 3 ports')
})
```

- [ ] **Step 4: Run to verify failure**

```bash
cd /home/cyberpunk/aivas/frontend && npx vitest run src/hooks/useChat.test.js src/hooks/useScan.test.js 2>&1 | tail -15
```

- [ ] **Step 5: Rewrite `frontend/src/hooks/useChat.js`**

```javascript
import { useEffect, useRef, useCallback, useState } from 'react'

export function useChat({ sessionId, onEvent, provider = 'groq', model, apiKey, shodanKey }) {
  const onEventRef = useRef(onEvent)
  useEffect(() => { onEventRef.current = onEvent })

  const wsRef = useRef(null)
  const [status, setStatus] = useState('idle')

  useEffect(() => {
    if (!sessionId) return
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const params = new URLSearchParams({ provider })
    if (model) params.set('model', model)
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/chat/${sessionId}?${params}`)
    ws.onopen = () => {
      setStatus('open')
      const auth = { type: 'auth' }
      if (apiKey) auth.api_key = apiKey
      if (shodanKey) auth.shodan_key = shodanKey
      ws.send(JSON.stringify(auth))
    }
    ws.onclose = () => setStatus('closed')
    ws.onerror = () => setStatus('error')
    ws.onmessage = (e) => {
      try { onEventRef.current(JSON.parse(e.data)) } catch {}
    }
    wsRef.current = ws
    return () => {
      ws.onopen = ws.onclose = ws.onerror = ws.onmessage = null
      ws.close()
    }
  }, [sessionId, provider, model])

  const send = useCallback((text) => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: 'user', text }))
    }
  }, [])

  return { status, send }
}
```

- [ ] **Step 6: Update `frontend/src/hooks/useScan.js`** — add log accumulation

```javascript
import { useRef, useCallback, useState, useEffect } from 'react'

export function useScan(onProgress, onDone) {
  const onProgressRef = useRef(onProgress)
  const onDoneRef = useRef(onDone)
  useEffect(() => {
    onProgressRef.current = onProgress
    onDoneRef.current = onDone
  })

  const wsRef = useRef(null)
  const logRef = useRef([])
  const [isScanning, setIsScanning] = useState(false)

  const start = useCallback((scanKey) => {
    if (wsRef.current) {
      wsRef.current.onmessage = null
      wsRef.current.onerror = null
      wsRef.current.onclose = null
      wsRef.current.close()
    }
    logRef.current = []
    setIsScanning(true)
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/scan/${scanKey}`)
    ws.onmessage = (e) => {
      let msg
      try { msg = JSON.parse(e.data) } catch { return }
      if (msg.text) logRef.current = [...logRef.current, msg.text]
      if (msg.type === 'phase_header') {
        onProgressRef.current(msg.text || '')
      } else if (msg.type === 'done') {
        setIsScanning(false)
        onDoneRef.current({ ...msg, log: logRef.current })
        ws.close()
      } else if (msg.type === 'error') {
        setIsScanning(false)
        ws.close()
      }
    }
    ws.onerror = () => { wsRef.current.onerror = null; setIsScanning(false) }
    wsRef.current = ws
  }, [])

  return { isScanning, start }
}
```

- [ ] **Step 7: Update `frontend/src/App.jsx`** — useChat call signature changed

Find: `const { send, status: chatStatus } = useChat(sessionId, handleChatEvent)`

Replace with:
```javascript
const storedProvider = localStorage.getItem('aivas_provider') || 'groq'
const storedModel = localStorage.getItem('aivas_model') || undefined
const storedKey = localStorage.getItem('aivas_api_key') || undefined
const storedShodan = localStorage.getItem('aivas_shodan_key') || undefined

const { send, status: chatStatus } = useChat({
  sessionId,
  onEvent: handleChatEvent,
  provider: storedProvider,
  model: storedModel,
  apiKey: storedKey,
  shodanKey: storedShodan,
})
```

This reads from localStorage at render time. Settings changes take effect on the next session load.

- [ ] **Step 8: Update `frontend/src/App.jsx`** — handle streaming events in `handleChatEvent`

Find `handleChatEvent` in App.jsx. It currently handles `complete` events. Replace/add handling for the new protocol:

The existing handler handles: `complete`, `scan_intent`, `narrate`, `ai`, `error`. Update to handle `token`, `done`, `scan_triggered` (replacing `scan_intent`), and `thinking`.

In `handleChatEvent`, add these cases:

```javascript
// Streaming: first token → append message in streaming state
if (event.type === 'thinking') {
  const id = uid()
  thinkingIdRef.current = id
  dispatch({ type: 'APPEND', msg: { id, type: 'ai', text: '', streaming: true } })
  return
}
if (event.type === 'token') {
  if (thinkingIdRef.current) {
    // accumulate into existing streaming message
    dispatch(prev => {
      const existing = prev.find(m => m.id === thinkingIdRef.current)
      if (!existing) return prev
      return prev.map(m =>
        m.id === thinkingIdRef.current
          ? { ...m, text: (m.text || '') + event.text }
          : m
      )
    })
    // Use UPDATE_TEXT action instead:
    // Need to track accumulated text. Use a ref.
  }
  return
}
```

Actually, looking at the existing reducer, `UPDATE_TEXT` replaces the entire text, not appends. For accumulation, we need to track the running text. Use a ref:

Add `streamingTextRef` to App.jsx, then in `handleChatEvent`:

```javascript
if (event.type === 'thinking') {
  const id = uid()
  thinkingIdRef.current = id
  streamingTextRef.current = ''
  dispatch({ type: 'APPEND', msg: { id, type: 'ai', text: '', streaming: true } })
  return
}
if (event.type === 'token') {
  if (!thinkingIdRef.current) return
  streamingTextRef.current += event.text
  dispatch({ type: 'UPDATE_TEXT', id: thinkingIdRef.current, text: streamingTextRef.current })
  return
}
if (event.type === 'done') {
  if (thinkingIdRef.current) {
    dispatch({ type: 'SET_STREAMING', id: thinkingIdRef.current, streaming: false })
    thinkingIdRef.current = null
    streamingTextRef.current = ''
  }
  return
}
if (event.type === 'scan_triggered') {
  // same as old scan_intent handling — call startScanRef
  if (startScanRef.current) startScanRef.current(event.scan_key, event.target)
  return
}
```

Remove the old `complete` case handler.

- [ ] **Step 9: Run tests**

```bash
cd /home/cyberpunk/aivas/frontend && npx vitest run 2>&1 | tail -15
```
Expected: all tests PASS

- [ ] **Step 10: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/hooks/useChat.js frontend/src/hooks/useScan.js frontend/src/hooks/useChat.test.js frontend/src/hooks/useScan.test.js frontend/src/App.jsx
git commit -m "feat: useChat sends auth message + supports provider/model; useScan accumulates log"
```

---

### Task 8: ScanCard Scan Log + SettingsModal + build verification

**Files:**
- Modify: `frontend/src/components/ScanCard.jsx` (add Scan Log section)
- Modify: `frontend/src/components/SettingsModal.jsx` (provider, model, Shodan key fields)
- Modify: `frontend/src/components/ScanCard.test.jsx` (add log tests)
- Test: `frontend/src/components/SettingsModal.test.jsx` (update for new fields)

**Interfaces:**
- `ScanCard` accepts `scanData.log: string[]` — renders as collapsible section at bottom of card
- `SettingsModal` saves `aivas_provider`, `aivas_model`, `aivas_shodan_key` to localStorage; default model updates when provider changes

- [ ] **Step 1: Add ScanCard log tests**

Append to `frontend/src/components/ScanCard.test.jsx`:

```javascript
it('renders Scan Log section when log is provided', () => {
  const { container } = render(
    <ScanCard
      scanData={{ ...baseScanData, log: ['PORT SCANNING', 'Found 3 ports'] }}
      onSend={vi.fn()}
    />
  )
  expect(container.textContent).toContain('Scan Log')
})

it('log items are accessible via details element', () => {
  const { container } = render(
    <ScanCard
      scanData={{ ...baseScanData, log: ['CVE LOOKUP', 'Found 2 CVEs'] }}
      onSend={vi.fn()}
    />
  )
  const details = container.querySelector('details')
  expect(details).not.toBeNull()
  expect(details.textContent).toContain('CVE LOOKUP')
  expect(details.textContent).toContain('Found 2 CVEs')
})

it('does not render Scan Log when log is empty or absent', () => {
  const { container } = render(
    <ScanCard scanData={{ ...baseScanData }} onSend={vi.fn()} />
  )
  expect(container.textContent).not.toContain('Scan Log')
})
```

(Note: `baseScanData` must already be defined in the test file from Task 5's original tests. If it's not named that, use whatever fixture is already there.)

- [ ] **Step 2: Add SettingsModal tests**

Append to or create `frontend/src/components/SettingsModal.test.jsx`:

```javascript
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SettingsModal from './SettingsModal'

const PROVIDERS = ['Groq', 'Claude', 'Ollama']
const MODEL_DEFAULTS = {
  groq: 'llama-3.3-70b-versatile',
  claude: 'claude-haiku-4-5-20251001',
  ollama: 'llama3',
}

beforeEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
})

it('renders provider dropdown', () => {
  render(<SettingsModal open={true} onClose={vi.fn()} />)
  expect(screen.getByText('Provider')).toBeTruthy()
})

it('renders model input', () => {
  render(<SettingsModal open={true} onClose={vi.fn()} />)
  const modelInput = screen.getByDisplayValue('llama-3.3-70b-versatile')
  expect(modelInput).toBeTruthy()
})

it('renders Shodan key field', () => {
  render(<SettingsModal open={true} onClose={vi.fn()} />)
  expect(screen.getByPlaceholderText(/shodan/i)).toBeTruthy()
})

it('saves provider and model to localStorage on save', () => {
  render(<SettingsModal open={true} onClose={vi.fn()} />)
  fireEvent.click(screen.getByText('Save'))
  expect(localStorage.getItem('aivas_provider')).toBe('groq')
  expect(localStorage.getItem('aivas_model')).toBe('llama-3.3-70b-versatile')
})

it('changing provider updates model default', () => {
  render(<SettingsModal open={true} onClose={vi.fn()} />)
  const select = screen.getByRole('combobox')
  fireEvent.change(select, { target: { value: 'ollama' } })
  const modelInput = screen.getByDisplayValue('llama3')
  expect(modelInput).toBeTruthy()
})
```

- [ ] **Step 3: Run to verify failures**

```bash
cd /home/cyberpunk/aivas/frontend
npx vitest run src/components/ScanCard.test.jsx src/components/SettingsModal.test.jsx 2>&1 | tail -15
```

- [ ] **Step 4: Update `frontend/src/components/ScanCard.jsx`** — add Scan Log section

Add inside the JSX, after the action buttons div and before the closing outer div:

```javascript
      {/* Scan Log */}
      {scanData.log && scanData.log.length > 0 && (
        <details style={{ borderTop: '1px solid #1e1e1e' }}>
          <summary
            style={{ color: '#666', cursor: 'pointer', userSelect: 'none' }}
            className="px-3 py-2 text-xs hover:text-white transition-colors"
          >
            Scan Log ({scanData.log.length} events)
          </summary>
          <div
            style={{ background: '#0a0a0a', maxHeight: 200, overflowY: 'auto' }}
            className="px-3 py-2"
          >
            {scanData.log.map((entry, i) => (
              <div key={i} style={{ color: '#555', fontFamily: 'monospace' }} className="text-xs py-0.5">
                {entry}
              </div>
            ))}
          </div>
        </details>
      )}
```

Also update the destructuring at the top of `ScanCard` to accept `log` (it comes from `scanData`):
```javascript
const { scan_id, target, grade, service_count, findings, counts, log } = scanData
```

And use `log` in the Scan Log section instead of `scanData.log`.

- [ ] **Step 5: Replace `frontend/src/components/SettingsModal.jsx`**

```javascript
import { useState, useEffect } from 'react'
import { X } from 'lucide-react'

const LANGS = [
  { value: 'auto', label: 'Auto' },
  { value: 'en',   label: 'English' },
  { value: 'sw',   label: 'Swahili' },
]

const PROVIDERS = [
  { value: 'groq',   label: 'Groq (online)' },
  { value: 'claude', label: 'Claude (Anthropic)' },
  { value: 'ollama', label: 'Ollama (local)' },
]

const MODEL_DEFAULTS = {
  groq:   'llama-3.3-70b-versatile',
  claude: 'claude-haiku-4-5-20251001',
  ollama: 'llama3',
}

export default function SettingsModal({ open, onClose }) {
  const [apiKey,    setApiKey]    = useState('')
  const [shodanKey, setShodanKey] = useState('')
  const [lang,      setLang]      = useState('auto')
  const [provider,  setProvider]  = useState('groq')
  const [model,     setModel]     = useState(MODEL_DEFAULTS.groq)

  useEffect(() => {
    if (!open) return
    setApiKey(localStorage.getItem('aivas_api_key') || '')
    setShodanKey(localStorage.getItem('aivas_shodan_key') || '')
    setLang(localStorage.getItem('aivas_lang') || 'auto')
    const p = localStorage.getItem('aivas_provider') || 'groq'
    setProvider(p)
    setModel(localStorage.getItem('aivas_model') || MODEL_DEFAULTS[p] || MODEL_DEFAULTS.groq)
  }, [open])

  useEffect(() => {
    const handleKeyDown = (e) => { if (e.key === 'Escape' && open) onClose() }
    if (open) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, onClose])

  if (!open) return null

  const handleProviderChange = (e) => {
    const p = e.target.value
    setProvider(p)
    setModel(MODEL_DEFAULTS[p] || MODEL_DEFAULTS.groq)
  }

  const save = () => {
    localStorage.setItem('aivas_api_key',    apiKey)
    localStorage.setItem('aivas_shodan_key', shodanKey)
    localStorage.setItem('aivas_lang',       lang)
    localStorage.setItem('aivas_provider',   provider)
    localStorage.setItem('aivas_model',      model)
    onClose()
  }

  const inputStyle = { background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }

  return (
    <>
      <div style={{ background: 'rgba(0,0,0,0.7)' }} className="fixed inset-0 z-40" onClick={onClose} />
      <div
        data-testid="settings-modal"
        style={{ background: '#111111', border: '1px solid #1e1e1e', width: 400 }}
        className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 rounded-lg p-5"
      >
        <div className="flex items-center justify-between mb-5">
          <span style={{ color: '#e0e0e0' }} className="font-medium text-sm">Settings</span>
          <button onClick={onClose} style={{ color: '#666' }} className="p-1 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* Provider */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Provider</label>
          <select
            value={provider}
            onChange={handleProviderChange}
            style={{ ...inputStyle, width: '100%' }}
            className="rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] transition-colors"
          >
            {PROVIDERS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
        </div>

        {/* Model */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Model</label>
          <input
            type="text"
            value={model}
            onChange={e => setModel(e.target.value)}
            style={inputStyle}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] transition-colors"
          />
        </div>

        {/* API Key */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">
            API Key ({provider === 'claude' ? 'Anthropic' : provider === 'groq' ? 'Groq' : 'not needed'})
          </label>
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder={provider === 'groq' ? 'gsk_…' : provider === 'claude' ? 'sk-ant-…' : 'not required'}
            style={inputStyle}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#444] transition-colors"
          />
        </div>

        {/* Shodan Key */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Shodan API Key (optional)</label>
          <input
            type="password"
            value={shodanKey}
            onChange={e => setShodanKey(e.target.value)}
            placeholder="shodan api key…"
            style={inputStyle}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#444] transition-colors"
          />
        </div>

        {/* Language */}
        <div className="mb-5">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Language</label>
          <div className="flex gap-2">
            {LANGS.map(l => (
              <button
                key={l.value}
                onClick={() => setLang(l.value)}
                style={{
                  background: lang === l.value ? '#4a9eff' : '#161616',
                  border: `1px solid ${lang === l.value ? '#4a9eff' : '#1e1e1e'}`,
                  color: lang === l.value ? '#000' : '#e0e0e0',
                }}
                className="flex-1 py-1.5 text-xs rounded font-medium transition-all"
              >
                {l.label}
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={save}
          style={{ background: '#4a9eff' }}
          className="w-full py-2 text-sm font-semibold text-black rounded hover:opacity-90 transition-opacity"
        >
          Save
        </button>
      </div>
    </>
  )
}
```

- [ ] **Step 6: Run frontend tests**

```bash
cd /home/cyberpunk/aivas/frontend
npx vitest run 2>&1 | tail -15
```
Expected: all tests PASS

- [ ] **Step 7: Build verification**

```bash
npm run build 2>&1 | tail -20
```
Expected: Build complete, no errors

- [ ] **Step 8: Run full backend test suite**

```bash
cd /home/cyberpunk/aivas && pytest --tb=short -q 2>&1 | tail -15
```
Expected: all backend tests pass

- [ ] **Step 9: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/ScanCard.jsx frontend/src/components/ScanCard.test.jsx frontend/src/components/SettingsModal.jsx frontend/src/components/SettingsModal.test.jsx
git commit -m "feat: ScanCard Scan Log, SettingsModal provider/model/Shodan fields"
```

---

## Dependency Notes

- `anthropic` SDK is not in `pyproject.toml` — add to optional dependencies or document that users need `pip install anthropic` to use the Claude provider.
- `AsyncGroq` is in the `groq>=0.9` package already installed.
- No new Python dependencies beyond what's already installed are required for Groq and Ollama providers.
- Frontend has no new npm dependencies.
