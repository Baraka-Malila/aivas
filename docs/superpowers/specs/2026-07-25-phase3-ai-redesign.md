# Phase 3 — AI Redesign: Streaming, Providers, Conversational Agent

## Goal

Replace AIVAS's rigid 4-part AI output with a genuinely conversational security assistant: streaming word-by-word responses, swappable LLM providers (Groq / Claude / Ollama), Shodan IP enrichment, and a clean scan pipeline that no longer blocks on AI work during the scan.

## Architecture

**Layers:**

```
Frontend (React)
  └─ Settings modal  ← provider / model / API keys
  └─ Chat (WebSocket /ws/chat/{session_id})
       ├─ token events → live streaming text
       └─ scan-card   ← scan result + collapsible Scan Log

Backend (FastAPI)
  └─ chat_api.py  ← agent loop, tool dispatch, streaming
  └─ scan_worker.py  ← nmap pipeline (no AI phases)
  └─ narrator/providers/  ← BaseProvider + 3 implementations
  └─ narrator/shodan_client.py  ← Shodan free-tier lookup
```

**Tech Stack:** Python 3, FastAPI, Groq SDK, Anthropic SDK, requests (Ollama), WebSocket SSE, React 18, Vitest

---

## Global Constraints

- No Python source file exceeds 200 lines.
- One module = one responsibility.
- Default provider: `groq`, default model: `llama-3.3-70b-versatile`.
- Phase A (summariser): always uses `llama-3.1-8b-instant` on Groq regardless of user model choice.
- Frontend and TUI share the same backend WebSocket and REST endpoints.
- All existing tests must remain passing after each task.
- Commit after every task.

---

## 1. Provider Layer

### Files

```
aivas/narrator/providers/
  __init__.py       ← re-exports get_provider, BaseProvider
  base.py           ← abstract BaseProvider
  groq.py           ← GroqProvider
  anthropic.py      ← AnthropicProvider
  ollama.py         ← OllamaProvider
  factory.py        ← get_provider(name, model, api_key) -> BaseProvider
```

The existing `aivas/narrator/providers.py` is deleted; all callers updated to import from `aivas.narrator.providers`.

### BaseProvider (`base.py`)

```python
from abc import ABC, abstractmethod
from typing import AsyncGenerator

class BaseProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 300) -> str: ...

    @abstractmethod
    async def stream(self, messages: list[dict], max_tokens: int = 1024) -> AsyncGenerator[str, None]: ...
```

`generate()` is kept for TUI and batch narration (blocking).  
`stream()` takes OpenAI-style `messages` list and yields string tokens one at a time.

### GroqProvider (`groq.py`)

- Uses `groq` SDK with `client.chat.completions.create(..., stream=True)`.
- `generate()` stays identical to current implementation.
- `stream()` iterates `chunk.choices[0].delta.content` and yields non-None values.
- Default model: `llama-3.3-70b-versatile`. Constructor accepts `model` param.
- Retry logic (rate-limit 429) unchanged from current implementation.

### AnthropicProvider (`anthropic.py`)

- Uses `anthropic` SDK with `client.messages.stream(...)`.
- `generate()` uses `client.messages.create()` and returns `.content[0].text`.
- `stream()` uses `with client.messages.stream(...) as s: async for text in s.text_stream`.
- Default model: `claude-haiku-4-5-20251001` (cheapest Anthropic model).

### OllamaProvider (`ollama.py`)

- `generate()`: POST `/api/generate` with `stream: false` — unchanged.
- `stream()`: POST `/api/chat` with `stream: true`, parse NDJSON, yield `chunk["message"]["content"]`.
- Default model: `llama3`.

### Factory (`factory.py`)

```python
def get_provider(
    name: str,
    model: str | None = None,
    api_key: str | None = None,
) -> BaseProvider:
```

| `name`     | Class               | Requires          |
|------------|---------------------|-------------------|
| `"groq"`   | GroqProvider        | `api_key`         |
| `"claude"` | AnthropicProvider   | `api_key`         |
| `"ollama"` | OllamaProvider      | nothing           |

Raises `ValueError` for unknown name or missing required key.

---

## 2. Agent — System Prompt Redesign

### Current problem

`aivas/tui/agent_prompts.py` mandates a rigid 4-part structure (EXECUTIVE SUMMARY → SEVERITY BREAKDOWN → TOP FINDINGS → REMEDIATION) on every single response. Every question returns the same template regardless of what was asked.

### New system prompt

```
You are AIVAS, a network security analyst assistant for small businesses in Tanzania.

You help users understand their network security posture: scan hosts, explain
vulnerabilities, answer questions about CVEs and networking, and give actionable
remediation advice. You are direct, practical, and focused on what matters to
a non-expert business owner.

Tools available:
- scan_host(target, level): run a network scan. Call this when the user asks
  to scan a host or network. The scan runs in the background and results appear
  automatically — confirm you have started it, then wait.
- get_history(limit): list recent scans.
- get_last_scan(): get findings from the most recent scan.
- get_findings(scan_id): get CVE findings for a specific scan.
- explain_cve(cve_id): look up a CVE in the local database.
- query_shodan(ip): get threat intelligence for an IP address from Shodan.

Rules:
- Match the user's language (Swahili or English). Mixed language → prefer the majority.
  Default to English when unclear.
- Keep CVE IDs (e.g. CVE-2021-44228), IP addresses, port numbers, product names,
  and version numbers in their original Latin form — never translate identifiers.
- Never fabricate CVE details. Only cite CVEs that were returned by a tool in
  this conversation. If you don't have scan data, say so and offer to scan.
- Format your response to fit the question. A greeting gets a greeting.
  A quick question gets a short answer. A narration request gets a structured
  breakdown. Do not use the same template every time.
- When narrating findings, structure naturally: what was found, how serious it is,
  what an attacker could do, what to fix. Name exact products and versions.
```

### Tools

Six tools (same schema format as current `TOOLS` list in `agent_prompts.py`):

| Tool | Description |
|------|-------------|
| `scan_host` | Trigger a scan. AI calls this when user asks to scan. |
| `get_history` | List recent scans by date/target. |
| `get_last_scan` | Findings from the most recent scan. |
| `get_findings` | Findings for a specific scan ID. |
| `explain_cve` | Local CVE database lookup. |
| `query_shodan` | Shodan IP intelligence (optional — only called if Shodan key is configured). |

### Evidence grounding

The system prompt instructs the AI to only cite CVEs returned by tools in this session. The agent loop additionally checks: before sending the final response, scan for CVE-ID patterns (`CVE-\d{4}-\d+`) and log a warning for any that do not appear in the tool results returned this turn. On warning, append a brief note to the response: `"(Note: some CVE details could not be verified against scan data — treat with caution.)"` Do not strip or silently drop — surface the issue to the user.

---

## 3. Streaming Architecture

### Backend — `chat_api.py`

The WebSocket handler gains a streaming path alongside the existing blocking path.

**Token event format:**
```json
{"type": "token", "text": "Hello"}   // one per token
{"type": "done"}                      // stream complete
{"type": "error", "text": "..."}      // on failure
```

**Agent loop (per user message):**

```
1. Load session history from DB
2. Append user message
3. Call provider.stream(messages) → async generator of tokens
   - If model wants to call a tool:
     a. Emit {type:"thinking"} event
     b. Execute tool (scan_host, get_findings, etc.)
     c. If tool result > 4000 chars: run Phase A summariser
        (GroqProvider with llama-3.1-8b-instant, blocking, 500 token limit)
        to compress to key facts
     d. Append tool result to messages
     e. Resume stream from step 3
4. Yield tokens as they arrive: {type:"token", text:"..."}
5. On complete: {type:"done"}
6. Persist full assistant response to session history
```

**Phase A summariser** (only for large tool results):
- Model: always `llama-3.1-8b-instant` on Groq (fast, cheap).
- Prompt: `"Extract only the security-relevant facts from this tool output that are needed to answer the user's question: {question}\n\nTool output:\n{output}"`
- Max tokens: 500.
- Result replaces raw tool output in the messages list before continuing.

**scan_host tool dispatch:**  
When the AI calls `scan_host`, the backend does NOT run the scan inline. It returns a special event to the frontend:
```json
{"type": "scan_triggered", "target": "192.168.1.1", "level": 2}
```
The frontend opens the scan WebSocket (`/ws/scan/{scan_key}`) and runs the scan as it does today (progress card → scan card). The AI's streaming response for that turn ends after the trigger confirmation ("I've started scanning 192.168.1.1 — results will appear shortly."). When the scan completes, the scan card appears with "Narrate findings" and "Explain worst CVE" buttons — the user clicks one of those to trigger the AI narration as a new chat turn.

### Frontend — streaming display

`messageReducer.js` already has `UPDATE_TEXT`. Streaming requires one new action: `SET_STREAMING`.

**Streaming message lifecycle:**
1. On first `{type:"token"}`: dispatch `APPEND` with `{type:"ai", text:"", streaming:true}`
2. On each token: dispatch `UPDATE_TEXT` (accumulate)
3. On `{type:"done"}`: dispatch `SET_STREAMING` with `{id, streaming:false}`

**Cursor:** while `message.streaming === true`, append `▋` to displayed text.

**ChatInput:** already disabled while `chatStatus !== 'open'` — no change needed.

---

## 4. Scan Pipeline Cleanup

### Remove AI phases from `scan_worker.py`

Delete lines 147–186 (AI NARRATION phase and AI REMEDIATION warmup). The scan pipeline becomes:

```
init → [host discovery if CIDR] → port scan → HTTP probe → CVE lookup → scoring → done
```

Scan is now fast. All narration happens in chat on demand.

### Progress display — Scan Log

**Problem:** phase events flash by during the scan and are lost when the scan card appears.

**Fix:** the scan card gains a collapsible **Scan Log** section that persists every progress event from the scan. The log is collapsed by default after the scan completes, but the user can expand it to review every phase event in full.

**Implementation:**
- The scan WebSocket client (`useScan`) accumulates all events in a `log: []` array alongside the existing progress display.
- On `{type:"done"}`, the scan card is created with `scanData.log` containing the full event history.
- `ScanCard.jsx` renders a `<details><summary>Scan Log ({n} events)</summary>...</details>` section at the bottom.
- Each log entry is one line: `[phase_header] PORT SCANNING`, `[port_open] 80/tcp OPEN → nginx 1.18`, etc.

This means: events are readable live during the scan (the progress feed scrolls), and also permanently accessible after via the Scan Log.

---

## 5. Settings UI — Provider / Model / Shodan

### New fields in `SettingsModal.jsx`

```
Provider:  [Groq ▾]          (options: Groq, Claude, Ollama)
Model:     [llama-3.3-70b-versatile]   (text input, pre-filled on provider change)
Shodan key: [____________________]     (optional, shown as password field)
```

**Default models per provider:**

| Provider | Default model |
|----------|---------------|
| Groq | `llama-3.3-70b-versatile` |
| Claude | `claude-haiku-4-5-20251001` |
| Ollama | `llama3` |

**localStorage keys:** `aivas_provider`, `aivas_model`, `aivas_api_key` (existing), `aivas_shodan_key`

**Sending to backend:** on WebSocket connect to `/ws/chat/{session_id}`, append query params:
`?provider=groq&model=llama-3.3-70b-versatile`

API keys are NOT sent as query params (visible in logs). They are sent as the first message after connect:
```json
{"type": "auth", "api_key": "...", "shodan_key": "..."}
```
Backend reads auth message, stores keys in the session context for this connection only.

### Shodan client (`narrator/shodan_client.py`)

```python
def query_shodan(ip: str, api_key: str) -> dict:
    """Return host info from Shodan free-tier API."""
```

Returns: `{ip, ports, hostnames, country, org, vulns: [...], tags: [...]}`.  
On error or missing key: returns `{ip, error: "Shodan key not configured"}`.

---

## 6. TUI Parallel Updates

The TUI (`aivas/tui/`) shares the same provider layer and system prompt. Changes:

- `aivas/tui/agent_prompts.py` — replace `SYSTEM` with the new system prompt above. `TOOLS` gains `query_shodan`.
- `aivas/tui/scan.py` — remove the `GroqProvider` import and direct instantiation; use `get_provider()` from `factory.py` instead. Provider name/model read from `config.load()`.
- No streaming in TUI — `generate()` (blocking) is used, not `stream()`. The TUI gets the better model and conversational prompt for free.

---

## 7. Test Coverage

Each task adds tests covering its new behaviour. Existing 40 frontend tests and all backend tests must remain passing.

| Task | New tests |
|------|-----------|
| Provider layer | Unit tests for each provider's `generate()` (mocked SDK). `stream()` tested with mock async generator. Factory tests for all 3 names + error cases. |
| Agent / system prompt | Integration test: send "hello" → response does NOT match the 4-part template regex. Send "narrate scan" → response DOES contain CVE data from mocked `get_findings`. |
| Streaming | WebSocket test: connect, send message, collect all events, verify sequence: token... token... done. |
| Scan pipeline | `run_scan()` completes without calling any LLM. `done` event contains `log` array with all phase events. |
| Settings UI | SettingsModal renders provider dropdown, model field, Shodan key field. Changing provider updates model field default. localStorage keys saved correctly. |
| Shodan client | `query_shodan()` with mocked requests returns expected dict. Missing key returns error dict without raising. |
