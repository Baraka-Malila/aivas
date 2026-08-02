# Live Tool Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit `tool_call` and `tool_result` WebSocket events from the backend, then display them in the frontend as a collapsible panel inside each AI message.

**Architecture:** A new `tool_events.py` module holds the `_tool_summary` helper and `_SILENT_TOOLS` constant so `chat_stream.py` stays under 200 lines. The frontend reducer gains two new action types (`TOOL_CALL`, `TOOL_RESULT`) that append/update entries on `msg.toolCalls`. A new `ToolCallPanel` component renders above the AI prose — expanded while tools run, auto-collapsing when text starts streaming, re-expandable by click.

**Tech Stack:** Python 3 / FastAPI (backend), React 18 / Vitest + @testing-library/react (frontend)

## Global Constraints

- No Python source file may exceed 200 lines of code
- No violet in any UI element
- All git commits must use author `Baraka Malila <bmalila87@gmail.com>`
- Tool: `scan_host` must NOT emit `tool_call` or `tool_result` events (it already emits `scan_triggered`)
- `_tool_summary` must return `"done"` (not raise) on any malformed/unexpected input
- `ToolCallPanel` collapsed badge text: `▶ N tool(s) used` (plural when N ≠ 1)
- `ToolCallPanel` auto-collapses when the parent message's `text` prop becomes non-empty
- Panel background: `rgba(255,255,255,0.04)` — no other background colour

---

### Task 1: Backend — tool_events module + emit events in chat_stream

**Files:**
- Create: `aivas/server/tool_events.py`
- Modify: `aivas/server/chat_stream.py`
- Test: `tests/server/test_chat_stream.py`

**Interfaces:**
- Produces: `_tool_summary(name: str, result_json: str) -> str` (imported by chat_stream)
- Produces: `_SILENT_TOOLS: set[str]` = `{"scan_host"}`
- Produces: new WebSocket event `{"type": "tool_call", "name": str, "args": dict}` — emitted before `_exec_tool_local`
- Produces: new WebSocket event `{"type": "tool_result", "name": str, "summary": str}` — emitted after `_exec_tool_local` when `scan_intent` is None

- [ ] **Step 1: Write the failing tests**

Add to `tests/server/test_chat_stream.py` (after the existing tests):

```python
def test_stream_emits_tool_call_event(conn):
    """tool_call event is emitted before get_last_scan executes."""
    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "get_last_scan"
    tc.function.arguments = "{}"

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            _groq_resp(tool_calls=[tc]), _groq_resp("")
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "summary", conn)
        ))

    ev = next((e for e in events if e["type"] == "tool_call"), None)
    assert ev is not None
    assert ev["name"] == "get_last_scan"
    assert "args" in ev


def test_stream_emits_tool_result_event(conn):
    """tool_result event has name and summary after get_last_scan executes."""
    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "get_last_scan"
    tc.function.arguments = "{}"

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            _groq_resp(tool_calls=[tc]), _groq_resp("")
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "summary", conn)
        ))

    ev = next((e for e in events if e["type"] == "tool_result"), None)
    assert ev is not None
    assert ev["name"] == "get_last_scan"
    assert isinstance(ev["summary"], str) and len(ev["summary"]) > 0


def test_scan_host_does_not_emit_tool_call(conn):
    """scan_host emits scan_triggered but not tool_call or tool_result."""
    tc = MagicMock()
    tc.id = "call_1"
    tc.function.name = "scan_host"
    tc.function.arguments = json.dumps({"target": "192.168.1.1", "level": "2"})

    with patch("aivas.server.chat_stream.Groq") as MockGroq:
        MockGroq.return_value.chat.completions.create.side_effect = [
            _groq_resp(tool_calls=[tc]), _groq_resp("")
        ]
        events = asyncio.run(_collect(
            stream_agent_response(MockProvider(), [], "scan it", conn)
        ))

    assert not any(e["type"] == "tool_call" for e in events)
    assert not any(e["type"] == "tool_result" for e in events)
    assert any(e["type"] == "scan_triggered" for e in events)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/server/test_chat_stream.py::test_stream_emits_tool_call_event tests/server/test_chat_stream.py::test_stream_emits_tool_result_event tests/server/test_chat_stream.py::test_scan_host_does_not_emit_tool_call -v
```

Expected: 3 FAILED (events not yet emitted)

- [ ] **Step 3: Create `aivas/server/tool_events.py`**

```python
"""Tool-event helpers for the streaming chat agent."""
from __future__ import annotations
import json

_SILENT_TOOLS: set[str] = {"scan_host"}


def _tool_summary(name: str, result_json: str) -> str:
    """Return a short human-readable summary of a tool result."""
    try:
        data = json.loads(result_json)
    except (json.JSONDecodeError, ValueError):
        return "done"

    if name == "get_findings":
        count = len(data) if isinstance(data, list) else 0
        return f"{count} finding{'s' if count != 1 else ''} returned"

    if name == "get_last_scan":
        count = len(data.get("findings", [])) if isinstance(data, dict) else 0
        return f"{count} finding{'s' if count != 1 else ''} returned"

    if name == "discover_hosts":
        if isinstance(data, dict):
            count = data.get("count", 0)
            note = data.get("note", "")
            if count == 0 and note:
                return note[:80]
            return f"{count} device{'s' if count != 1 else ''} found"
        return "done"

    if name == "get_history":
        count = len(data) if isinstance(data, list) else 0
        return f"{count} scan{'s' if count != 1 else ''} in history"

    return "done"
```

- [ ] **Step 4: Modify `aivas/server/chat_stream.py`**

Add import at the top (after existing imports):

```python
from aivas.server.tool_events import _SILENT_TOOLS, _tool_summary
```

Replace the tool-call loop body (lines 157–177 in current file) — the section from `for tc in msg.tool_calls:` through the `turns_to_persist.append(tool_msg)` line — with:

```python
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}

            if tc.function.name not in _SILENT_TOOLS:
                yield {"type": "tool_call", "name": tc.function.name, "args": args}

            try:
                result, scan_intent = await _exec_tool_local(tc.function.name, args, conn, shodan_key)
            except Exception as exc:
                result = json.dumps({"error": f"Tool execution failed: {exc}"})
                scan_intent = None

            if scan_intent:
                yield {"type": "scan_triggered", "target": scan_intent[0], "level": scan_intent[1]}
            elif tc.function.name not in _SILENT_TOOLS:
                yield {"type": "tool_result", "name": tc.function.name,
                       "summary": _tool_summary(tc.function.name, result)}

            if len(result) > _SUMMARIZE_THRESHOLD:
                result = await _summarize(result, user_text, groq)

            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)
```

Verify line count stays ≤ 200: `wc -l aivas/server/chat_stream.py`

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/server/test_chat_stream.py -v
```

Expected: all tests PASS (including the 3 new ones)

- [ ] **Step 6: Commit**

```bash
git add aivas/server/tool_events.py aivas/server/chat_stream.py tests/server/test_chat_stream.py
git commit -m "feat: emit tool_call and tool_result events in chat_stream"
```

---

### Task 2: Frontend reducer — TOOL_CALL and TOOL_RESULT actions

**Files:**
- Modify: `frontend/src/lib/messageReducer.js`
- Modify: `frontend/src/lib/messageReducer.test.js`

**Interfaces:**
- Consumes: nothing from Task 1 (pure reducer logic)
- Produces:
  - `reducer(state, {type: 'TOOL_CALL', id, name, args})` → appends `{name, args, status: 'running'}` to `msg.toolCalls`
  - `reducer(state, {type: 'TOOL_RESULT', id, name, summary})` → updates last running entry matching `name` to `{status: 'done', summary}`
  - Message shape after tool calls: `{ id, type: 'ai', text, streaming, toolCalls: [{name, args, status, summary?}] }`

- [ ] **Step 1: Write the failing tests**

Add to `frontend/src/lib/messageReducer.test.js`:

```js
it('TOOL_CALL appends entry with status running', () => {
  const initial = [{ id: 'x', type: 'ai', text: '', streaming: true }]
  const state = reducer(initial, { type: 'TOOL_CALL', id: 'x', name: 'get_findings', args: { scan_id: '1' } })
  expect(state[0].toolCalls).toHaveLength(1)
  expect(state[0].toolCalls[0]).toEqual({ name: 'get_findings', args: { scan_id: '1' }, status: 'running' })
})

it('TOOL_CALL appends to existing toolCalls', () => {
  const initial = [{ id: 'x', type: 'ai', text: '', streaming: true,
    toolCalls: [{ name: 'get_last_scan', args: {}, status: 'done', summary: '3 findings returned' }] }]
  const state = reducer(initial, { type: 'TOOL_CALL', id: 'x', name: 'get_findings', args: {} })
  expect(state[0].toolCalls).toHaveLength(2)
  expect(state[0].toolCalls[1].status).toBe('running')
})

it('TOOL_RESULT updates running entry to done with summary', () => {
  const initial = [{ id: 'x', type: 'ai', text: '', streaming: true,
    toolCalls: [{ name: 'get_findings', args: {}, status: 'running' }] }]
  const state = reducer(initial, { type: 'TOOL_RESULT', id: 'x', name: 'get_findings', summary: '5 findings returned' })
  expect(state[0].toolCalls[0].status).toBe('done')
  expect(state[0].toolCalls[0].summary).toBe('5 findings returned')
})

it('TOOL_RESULT only updates last running entry matching name', () => {
  const initial = [{ id: 'x', type: 'ai', text: '', streaming: true,
    toolCalls: [
      { name: 'get_findings', args: {}, status: 'done', summary: 'old' },
      { name: 'get_findings', args: {}, status: 'running' },
    ] }]
  const state = reducer(initial, { type: 'TOOL_RESULT', id: 'x', name: 'get_findings', summary: 'new' })
  expect(state[0].toolCalls[0].summary).toBe('old')
  expect(state[0].toolCalls[1].summary).toBe('new')
  expect(state[0].toolCalls[1].status).toBe('done')
})

it('TOOL_RESULT on unknown id is a no-op', () => {
  const initial = [{ id: 'x', type: 'ai', text: '' }]
  const state = reducer(initial, { type: 'TOOL_RESULT', id: 'NOPE', name: 'get_findings', summary: 'x' })
  expect(state[0].toolCalls).toBeUndefined()
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas/frontend
npx vitest run src/lib/messageReducer.test.js
```

Expected: 5 new tests FAILED

- [ ] **Step 3: Implement the two new reducer cases**

In `frontend/src/lib/messageReducer.js`, add inside the `switch` block before `default`:

```js
    case 'TOOL_CALL':
      return state.map(m => m.id === action.id
        ? { ...m, toolCalls: [...(m.toolCalls || []), { name: action.name, args: action.args, status: 'running' }] }
        : m
      )
    case 'TOOL_RESULT': {
      return state.map(m => {
        if (m.id !== action.id) return m
        let matched = false
        const toolCalls = [...(m.toolCalls || [])].reverse().map(tc => {
          if (!matched && tc.name === action.name && tc.status === 'running') {
            matched = true
            return { ...tc, status: 'done', summary: action.summary }
          }
          return tc
        }).reverse()
        return { ...m, toolCalls }
      })
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run src/lib/messageReducer.test.js
```

Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/messageReducer.js frontend/src/lib/messageReducer.test.js
git commit -m "feat: add TOOL_CALL and TOOL_RESULT reducer actions"
```

---

### Task 3: ToolCallPanel component

**Files:**
- Create: `frontend/src/components/ToolCallPanel.jsx`
- Create: `frontend/src/components/ToolCallPanel.test.jsx`

**Interfaces:**
- Consumes: `toolCalls: Array<{name: string, args: object, status: 'running'|'done', summary?: string}>` — from Task 2's reducer output
- Consumes: `text: string` — the parent AI message's current text; when non-empty the panel auto-collapses
- Produces: `<ToolCallPanel toolCalls={...} text={...} />` — default export, imported by AiMessage in Task 4

- [ ] **Step 1: Write the failing tests**

Create `frontend/src/components/ToolCallPanel.test.jsx`:

```jsx
import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ToolCallPanel from './ToolCallPanel'

const doneCalls = [
  { name: 'get_findings', args: { scan_id: '1' }, status: 'done', summary: '5 findings returned' },
]
const runningCalls = [
  { name: 'get_last_scan', args: {}, status: 'running' },
]

describe('ToolCallPanel', () => {
  it('renders nothing when toolCalls is empty', () => {
    const { container } = render(<ToolCallPanel toolCalls={[]} text="" />)
    expect(container.firstChild).toBeNull()
  })

  it('renders nothing when toolCalls is absent', () => {
    const { container } = render(<ToolCallPanel toolCalls={null} text="" />)
    expect(container.firstChild).toBeNull()
  })

  it('shows expanded panel when text is empty', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByTestId('tool-call-panel-expanded')).toBeTruthy()
  })

  it('shows tool name in expanded panel', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByText(/get_findings/)).toBeTruthy()
  })

  it('shows summary when status is done', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByText(/5 findings returned/)).toBeTruthy()
  })

  it('auto-collapses when text becomes non-empty', () => {
    const { rerender } = render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByTestId('tool-call-panel-expanded')).toBeTruthy()
    rerender(<ToolCallPanel toolCalls={doneCalls} text="Your scan shows" />)
    expect(screen.getByTestId('tool-call-panel-collapsed')).toBeTruthy()
  })

  it('collapsed badge shows correct count', () => {
    const { rerender } = render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    rerender(<ToolCallPanel toolCalls={doneCalls} text="done" />)
    expect(screen.getByText(/1 tool used/)).toBeTruthy()
  })

  it('collapsed badge uses plural for multiple tools', () => {
    const two = [
      { name: 'get_findings', args: {}, status: 'done', summary: '3 findings returned' },
      { name: 'get_last_scan', args: {}, status: 'done', summary: '3 findings returned' },
    ]
    const { rerender } = render(<ToolCallPanel toolCalls={two} text="" />)
    rerender(<ToolCallPanel toolCalls={two} text="done" />)
    expect(screen.getByText(/2 tools used/)).toBeTruthy()
  })

  it('clicking collapsed badge re-expands', () => {
    const { rerender } = render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    rerender(<ToolCallPanel toolCalls={doneCalls} text="done" />)
    fireEvent.click(screen.getByTestId('tool-call-panel-collapsed'))
    expect(screen.getByTestId('tool-call-panel-expanded')).toBeTruthy()
  })

  it('clicking header collapses expanded panel', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    fireEvent.click(screen.getByTestId('tool-call-panel-header'))
    expect(screen.getByTestId('tool-call-panel-collapsed')).toBeTruthy()
  })

  it('shows spinner indicator for running tool', () => {
    render(<ToolCallPanel toolCalls={runningCalls} text="" />)
    expect(screen.getByText(/⟳/)).toBeTruthy()
  })

  it('shows checkmark for done tool', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByText(/✓/)).toBeTruthy()
  })

  it('clicking a row toggles args detail block', () => {
    const withArgs = [{ name: 'get_findings', args: { scan_id: '3' }, status: 'done', summary: '2 findings returned' }]
    render(<ToolCallPanel toolCalls={withArgs} text="" />)
    const row = screen.getByTestId('tool-call-row-0')
    fireEvent.click(row)
    expect(screen.getByTestId('tool-call-detail-0')).toBeTruthy()
    fireEvent.click(row)
    expect(() => screen.getByTestId('tool-call-detail-0')).toThrow()
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas/frontend
npx vitest run src/components/ToolCallPanel.test.jsx
```

Expected: all FAILED (file does not exist)

- [ ] **Step 3: Implement `ToolCallPanel.jsx`**

Create `frontend/src/components/ToolCallPanel.jsx`:

```jsx
import { useState, useEffect } from 'react'

export default function ToolCallPanel({ toolCalls, text }) {
  const [expanded, setExpanded] = useState(true)
  const [expandedRows, setExpandedRows] = useState({})

  useEffect(() => {
    if (text && text.length > 0) setExpanded(false)
  }, [text])

  if (!toolCalls || toolCalls.length === 0) return null

  const hasRunning = toolCalls.some(tc => tc.status === 'running')
  const count = toolCalls.length

  if (!expanded) {
    return (
      <div
        data-testid="tool-call-panel-collapsed"
        onClick={() => setExpanded(true)}
        style={{
          marginBottom: 8, cursor: 'pointer', userSelect: 'none',
          color: 'rgba(200,200,200,0.45)', fontSize: '0.72rem',
        }}
      >
        ▶ {count} tool{count !== 1 ? 's' : ''} used
      </div>
    )
  }

  return (
    <div
      data-testid="tool-call-panel-expanded"
      style={{
        background: 'rgba(255,255,255,0.04)',
        borderRadius: 6,
        padding: '6px 10px',
        marginBottom: 10,
        fontSize: '0.75rem',
      }}
    >
      <div
        data-testid="tool-call-panel-header"
        onClick={() => setExpanded(false)}
        style={{ color: 'rgba(200,200,200,0.5)', marginBottom: 4, cursor: 'pointer', userSelect: 'none' }}
      >
        {hasRunning ? '⟳ Running tools…' : `▼ ${count} tool${count !== 1 ? 's' : ''} used`}
      </div>
      {toolCalls.map((tc, i) => (
        <div key={i}>
          <div
            data-testid={`tool-call-row-${i}`}
            onClick={() => setExpandedRows(r => ({ ...r, [i]: !r[i] }))}
            style={{ cursor: 'pointer', color: 'rgba(200,200,200,0.6)', userSelect: 'none', marginTop: 3 }}
          >
            <span>{tc.status === 'running' ? '⟳' : '✓'}</span>{' '}
            <span style={{ fontFamily: 'monospace' }}>{tc.name}</span>
            {tc.summary && (
              <span style={{ color: 'rgba(200,200,200,0.35)', marginLeft: 8 }}>{tc.summary}</span>
            )}
          </div>
          {expandedRows[i] && tc.args && Object.keys(tc.args).length > 0 && (
            <div
              data-testid={`tool-call-detail-${i}`}
              style={{
                background: 'rgba(0,0,0,0.3)', borderRadius: 4,
                padding: '4px 8px', marginTop: 3,
                fontFamily: 'monospace', fontSize: '0.68rem',
                color: 'rgba(200,200,200,0.4)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              }}
            >
              {JSON.stringify(tc.args, null, 2)}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
npx vitest run src/components/ToolCallPanel.test.jsx
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/ToolCallPanel.jsx frontend/src/components/ToolCallPanel.test.jsx
git commit -m "feat: add ToolCallPanel component with expand/collapse/detail"
```

---

### Task 4: Wire — App.jsx + AiMessage.jsx + ChatArea.jsx + build

**Files:**
- Modify: `frontend/src/App.jsx` (lines 84–124, `handleChatEvent`)
- Modify: `frontend/src/components/AiMessage.jsx`
- Modify: `frontend/src/components/ChatArea.jsx` (line 40)
- Modify: `frontend/src/components/AiMessage.test.jsx`

**Interfaces:**
- Consumes: `TOOL_CALL` / `TOOL_RESULT` reducer actions from Task 2
- Consumes: `<ToolCallPanel>` from Task 3
- Produces: complete end-to-end tool visibility in the UI

- [ ] **Step 1: Write the failing tests**

Add to `frontend/src/components/AiMessage.test.jsx`:

```jsx
import ToolCallPanel from './ToolCallPanel'

// Add at the bottom of the describe block:
it('renders ToolCallPanel when toolCalls provided', () => {
  const toolCalls = [{ name: 'get_findings', args: {}, status: 'done', summary: '3 findings returned' }]
  const { container } = render(<AiMessage text="Here are your results." streaming={false} toolCalls={toolCalls} />)
  expect(container.querySelector('[data-testid="tool-call-panel-collapsed"]')).toBeTruthy()
})

it('does not render ToolCallPanel when toolCalls absent', () => {
  const { container } = render(<AiMessage text="Hello" streaming={false} />)
  expect(container.querySelector('[data-testid="tool-call-panel-expanded"]')).toBeNull()
  expect(container.querySelector('[data-testid="tool-call-panel-collapsed"]')).toBeNull()
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas/frontend
npx vitest run src/components/AiMessage.test.jsx
```

Expected: 2 new tests FAILED

- [ ] **Step 3: Update `AiMessage.jsx`**

Replace the entire file with:

```jsx
import { mdToHtml } from '../lib/mdToHtml'
import ToolCallPanel from './ToolCallPanel'

export default function AiMessage({ text, streaming, toolCalls }) {
  return (
    <div className="py-3" data-testid="ai-message">
      {toolCalls && toolCalls.length > 0 && (
        <ToolCallPanel toolCalls={toolCalls} text={text} />
      )}
      <div
        style={{ color: '#c8c8c8', lineHeight: 1.7 }}
        className="text-sm"
        dangerouslySetInnerHTML={{
          __html: mdToHtml(text) + (streaming ? '<span class="cursor-blink">▋</span>' : '')
        }}
      />
    </div>
  )
}
```

- [ ] **Step 4: Update `ChatArea.jsx` line 40 — pass `toolCalls` to `AiMessage`**

Replace:
```jsx
if (m.type === 'ai')            return <AiMessage     key={m.id} text={m.text} streaming={m.streaming} />
```

With:
```jsx
if (m.type === 'ai')            return <AiMessage     key={m.id} text={m.text} streaming={m.streaming} toolCalls={m.toolCalls} />
```

- [ ] **Step 5: Update `App.jsx` — add tool_call and tool_result cases to handleChatEvent**

Inside `handleChatEvent`, after the `error` block (after line 124, before the closing `}`), add:

```js
    } else if (event.type === 'tool_call') {
      if (thinkingIdRef.current) {
        dispatch({ type: 'TOOL_CALL', id: thinkingIdRef.current, name: event.name, args: event.args })
      }

    } else if (event.type === 'tool_result') {
      if (thinkingIdRef.current) {
        dispatch({ type: 'TOOL_RESULT', id: thinkingIdRef.current, name: event.name, summary: event.summary })
      }
```

- [ ] **Step 6: Run all frontend tests**

```bash
cd /home/cyberpunk/aivas/frontend
npx vitest run
```

Expected: all PASS

- [ ] **Step 7: Run all Python tests**

```bash
cd /home/cyberpunk/aivas
python -m pytest tests/ -v
```

Expected: all PASS

- [ ] **Step 8: Build the frontend**

```bash
cd /home/cyberpunk/aivas/frontend
npm run build
```

Expected: build completes with no errors

- [ ] **Step 9: Commit**

```bash
git add frontend/src/App.jsx frontend/src/components/AiMessage.jsx \
        frontend/src/components/ChatArea.jsx frontend/src/components/AiMessage.test.jsx
git commit -m "feat: wire ToolCallPanel into AiMessage and App event handler"
```
