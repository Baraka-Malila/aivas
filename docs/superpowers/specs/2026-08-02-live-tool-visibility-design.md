# Live Tool Visibility — Design Spec

**Date:** 2026-08-02
**Feature:** Spec 2 — Show tool calls and results to the user in real time

---

## Problem

When the AI calls tools (`get_findings`, `discover_hosts`, `get_last_scan`, etc.) the user sees only a static "Thinking…" indicator. There is no feedback on what the AI is doing, how long it takes, or what data it found. This creates a trust gap — the user cannot tell whether the AI is working, stuck, or hallucinating context it doesn't have.

## Goal

Show tool calls and their results in the chat UI as they happen, in a way that is informative during execution and unobtrusive once the AI starts responding.

---

## Backend Changes

### New events emitted from `chat_stream.py`

Two events are added inside the Phase A tool-call loop (after `scan_triggered` handling, before the model loop repeats):

**`tool_call`** — emitted the moment a tool is invoked:
```json
{"type": "tool_call", "name": "get_findings", "args": {"scan_id": "3"}}
```

**`tool_result`** — emitted after `_exec_tool_local` returns, before appending result to messages:
```json
{"type": "tool_result", "name": "get_findings", "summary": "12 findings returned"}
```

`summary` is a short human-readable string derived from the raw result. A helper `_tool_summary(name, result_json)` produces it:
- `get_findings` / `get_last_scan` → `"N findings returned"`
- `discover_hosts` → `"N devices found"` or the note string if count is 0
- `get_history` → `"N scans in history"`
- `scan_host` → not reached (scan_triggered fires instead); fallback: `"done"`
- Unknown tool → `"done"`

`scan_triggered` is unchanged — it still fires for `scan_host` and drives the existing scan dialog.

### No new tool schemas or prompt changes

This is purely observability. The AI's behaviour is not altered.

---

## Frontend State

### `messageReducer.js`

Two new action types handled inside the `ai` message case:

- **`tool_call`**: append `{name, args, status: "running"}` to `msg.toolCalls` (create array if absent)
- **`tool_result`**: find the last entry in `msg.toolCalls` matching `name`, set `status: "done"`, set `summary`

`toolCalls` is an array on the AI message object. It is absent on user messages and on AI messages that used no tools.

### `App.jsx` — `handleChatEvent`

Add two cases alongside existing `thinking`, `token`, `scan_triggered`, `done`, `error`:

```js
case 'tool_call':
case 'tool_result':
  dispatch({ type: ev.type, ...ev })
  break
```

---

## UI Component: `ToolCallPanel`

### Location

Rendered inside `AiMessage.jsx`, between the "Thinking…" indicator and the markdown text. Only rendered when `msg.toolCalls` exists and has at least one entry.

### States

**Expanded (default while tools are running):**
- Panel with muted background (matches existing scan-progress styling)
- One row per tool call:
  - Spinner while `status === "running"`, checkmark when `status === "done"`
  - Tool name in monospace
  - Summary string once done
  - Click row to toggle a detail block showing `args` and raw result (JSON, monospace, small text)
- Panel collapses automatically when the first `token` event arrives for the same message

**Collapsed (after AI starts streaming):**
- Single line: `▶ N tools used` — clickable to re-expand
- Positioned directly above the markdown text inside the same bubble

**Re-expanded (user clicked the badge):**
- Same as expanded state, but all entries already done (no spinners)
- Each row still clickable to view args/result detail

### Styling constraints
- Background: `rgba(255,255,255,0.04)` — dim, non-competing
- Text: `var(--muted)` colour, `0.8rem` font size
- No border radius changes — same panel shape as scan progress
- No violet (project rule)
- Collapse/expand uses a CSS height transition, no layout shift

---

## Files Changed

| File | Change |
|------|--------|
| `aivas/server/chat_stream.py` | Add `_tool_summary()` helper; emit `tool_call` and `tool_result` events in the tool loop |
| `frontend/src/reducers/messageReducer.js` | Handle `tool_call` and `tool_result` action types on the active AI message |
| `frontend/src/App.jsx` | Pass `tool_call` and `tool_result` events through `handleChatEvent` |
| `frontend/src/components/AiMessage.jsx` | Render `<ToolCallPanel>` above markdown when `msg.toolCalls` exists |
| `frontend/src/components/ToolCallPanel.jsx` | New component — expanded/collapsed/detail states |
| `tests/server/test_chat_stream.py` | Tests: `tool_call` event emitted; `tool_result` with correct summary; `scan_host` does not emit `tool_call` |

---

## Error handling

- If `_tool_summary` receives malformed JSON, it returns `"done"` rather than crashing.
- `tool_result` events for an unknown tool name (no matching `tool_call` entry) are silently ignored on the frontend — defensive `find()` returns `undefined`.

---

## Out of Scope

- TUI / terminal client: no changes. Tool visibility is web-only.
- Changing which tools exist or how they behave.
- Showing tool calls in the `done` event's `turns` payload (the model already receives tool results via the messages array; this is separate from UI display).
- Streaming partial tool results.
