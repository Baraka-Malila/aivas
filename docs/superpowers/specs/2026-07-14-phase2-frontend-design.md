# AIVAS Phase 2 — Chat-First Frontend Redesign Spec

> **Scope:** Frontend only. All backend endpoints are implemented in Phase 1. No backend changes in this phase.

**Goal:** Replace the current dashboard-style React frontend with a chat-first dark-theme UI where the AI is the primary interface. Users interact entirely through natural language; scan results appear as inline cards in the conversation thread.

---

## 1. Why

The Phase 1 backend now genuinely supports multi-turn conversation, tool-triggered scans, per-CVE LLM advice, and session persistence. The existing frontend (sidebar + scan bar + results tabs) was built before those capabilities existed and doesn't expose them. Phase 2 replaces it with a UI that matches what the backend can actually do.

---

## 2. Scope

### In scope
- Full replacement of all existing `frontend/src/` components and hooks
- Dark-theme, chat-first layout per visual design below
- `useChat` hook — WebSocket chat (`WS /ws/chat/{session_id}`)
- `useScan` hook — WebSocket scan (`WS /ws/scan/{scan_key}`)
- `useSessions` hook — REST session list
- Session history drawer (slides in from right)
- Inline scan result card (grade, severity pills, CVE list, action buttons)
- Settings modal (API key, language toggle stored in `localStorage`)
- Returning-user vs first-visit AI greeting (client-generated from history check)
- Unit tests for `ScanCard.jsx`, `useChat.js`

### Out of scope
- Backend changes
- New npm packages
- Mobile-specific layout (single column adapts naturally)
- E2E tests
- Report PDF download (link to existing `/api/report/{id}` suffices)
- Voice input / STT / TTS
- Authentication

---

## 3. Tech Stack

No changes to build tooling: React 18, Vite, Tailwind CSS, Lucide React icons. Existing `lib/` files (`severity.js`, `mdToHtml.js`, `utils.js`) unchanged.

---

## 4. File Structure

### New files (create)
```
frontend/src/
  App.jsx                    ← coordinator: session init, useChat, useScan
  hooks/
    useChat.js               ← WS /ws/chat/{session_id}
    useScan.js               ← WS /ws/scan/{scan_key}
    useSessions.js           ← GET/DELETE /api/sessions
  components/
    Header.jsx               ← logo, History button, Settings button
    ChatArea.jsx             ← scrollable message list, maps message array to components
    AiMessage.jsx            ← ✦ AIVAS label + body text
    UserMessage.jsx          ← right-aligned bubble
    ScanProgress.jsx         ← animated spinner, text updates in-place
    ScanCard.jsx             ← inline result card
    ChatInput.jsx            ← fixed-bottom input bar
    SessionDrawer.jsx        ← right-side drawer, session list
    SettingsModal.jsx        ← API key input, language toggle
  index.css                  ← rewritten for dark theme
```

### Deleted files (remove)
```
frontend/src/
  components/Sidebar.jsx
  components/ScanBar.jsx
  components/ProgressFeed.jsx
  components/ResultsTabs.jsx
  components/FindingsTable.jsx
  components/FindingsTable.test.jsx
  components/MisconfigTable.jsx
  components/AssessmentPanel.jsx
  components/ReportPanel.jsx
  components/ScanLog.jsx
  hooks/useWebSocket.js
  hooks/useWebSocket.test.jsx
  hooks/useHistory.js
```

### Unchanged files (keep as-is)
```
frontend/src/
  lib/severity.js
  lib/severity.test.js
  lib/mdToHtml.js
  lib/mdToHtml.test.js
  lib/utils.js
  main.jsx
  test-setup.js
```

---

## 5. Layout

Full viewport height. Three vertical zones:

```
┌─────────────────────────────────────────┐
│  ✦ AIVAS  Network Security    🕐  ⚙    │  ← Header (48px, fixed)
├─────────────────────────────────────────┤
│                                         │
│         (scrollable chat area)          │  ← ChatArea (fills remaining height)
│         max-width: 800px, centered      │
│                                         │
├─────────────────────────────────────────┤
│  [ Type a message… ]              Send  │  ← ChatInput (fixed bottom)
└─────────────────────────────────────────┘
```

No sidebar. No secondary panels. One column.

---

## 6. Color Palette

| Token | Value | Usage |
|---|---|---|
| `bg` | `#0a0a0a` | Page background |
| `surface` | `#111111` | Cards, drawer, modals |
| `surface-raised` | `#161616` | Inputs, buttons |
| `border` | `#1e1e1e` | All borders |
| `border-subtle` | `#141414` | Row dividers |
| `text` | `#e0e0e0` | Primary text |
| `text-muted` | `#666666` | Labels, hints |
| `accent` | `#4a9eff` | Logo, links, primary actions |
| `critical` | `#ef5350` | Grade F, CRITICAL severity |
| `high` | `#ff7043` | HIGH severity |
| `medium` | `#fdd835` | MEDIUM severity |
| `low` | `#66bb6a` | LOW severity, Grade A |

Grade badge colors: A=`#66bb6a`, B=`#aed581`, C=`#fdd835`, D=`#ff7043`, F=`#ef5350`.

No violet. No light backgrounds.

---

## 7. Typography

- **UI / body:** `system-ui, -apple-system, sans-serif` — no custom font load
- **CVE IDs, IPs, CVSS scores, code:** `'Fira Code', 'SF Mono', 'Courier New', monospace`
- **Font sizes:** 14px body, 12px card metadata, 11px CVE rows, 10px labels/pills

---

## 8. Message Model

All UI state is a flat `messages` array held in `App` state:

```js
{
  id: string,           // uuid
  type: "user" | "ai" | "scan-progress" | "scan-card",
  text: string,         // for user/ai/scan-progress
  scanData: object,     // for scan-card: {scan_id, target, grade, score, findings, counts}
}
```

`ChatArea` maps this array: `user` → `UserMessage`, `ai` → `AiMessage`, `scan-progress` → `ScanProgress`, `scan-card` → `ScanCard`.

---

## 9. Message Visuals

### AI message (`AiMessage`)
- No bubble background
- Label `✦ AIVAS` in `#4a9eff`, 12px, above the body
- Body text `#c8c8c8`, 14px, line-height 1.7
- Markdown rendered via existing `mdToHtml.js`

### User message (`UserMessage`)
- Right-aligned
- Bubble: `background: #0d1929`, `border: 1px solid #1a2d45`
- `border-radius: 14px 14px 4px 14px`
- Text `#90bde0`, 14px

### Scan progress (`ScanProgress`)
- Same layout as AI message (label `✦ AIVAS`)
- Animated braille spinner (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`) cycling at 120ms
- Current step text follows the spinner on the same line
- Updates in-place: same DOM node, `text` prop swaps, no new message appended

### Scan card (`ScanCard`)
Inline below the AI message that precedes it. `background: #111111`, `border: 1px solid #1e1e1e`, `border-radius: 8px`.

```
┌──────────────────────────────────────────┐
│  192.168.1.1                  Grade: F   │  ← target in monospace, grade colored
│  6 services · 30 findings                │  ← text-muted, 12px
├──────────────────────────────────────────┤
│  ● 14 CRITICAL  ● 16 HIGH  ● 0 MEDIUM   │  ← colored severity pills
├──────────────────────────────────────────┤
│  CVE-2021-44228  Apache Log4j RCE  10.0  │  ← top 5 CVEs, monospace ID + score
│  CVE-2022-0778   OpenSSL DoS       9.8   │
│  …                                       │
│  ↓ Show all 30 findings                  │  ← expand toggle; inline, no navigation
├──────────────────────────────────────────┤
│  [Narrate]  [Explain worst]  [Rescan]    │  ← action buttons
└──────────────────────────────────────────┘
```

Action buttons send a natural-language message into the chat (they call `sendMessage` directly):
- **Narrate** → `"Narrate the findings from scan {scan_id}"`
- **Explain worst** → `"Explain the worst vulnerability from scan {scan_id}"`
- **Rescan** → `"Scan {target} again"`

KEV findings: prepend `⚠ KEV` badge in `#ff7043` before the CVE ID row.

Full report link below action buttons: `View full report ↗` → opens `/api/report/{scan_id}` in new tab.

---

## 10. Header (`Header`)

- `background: #0d0d0d`, `border-bottom: 1px solid #1a1a1a`, height 48px
- Left: `✦ AIVAS` in `#4a9eff` (same star glyph as TUI), `"Network Security"` in `#666666` beside it
- Right: two 32px icon buttons — `Clock` (history drawer), `Settings` (settings modal)

---

## 11. Opening State

On mount, App calls `GET /api/history?limit=1`:
- **No history (first visit):** push one `ai` message: `"Hello. I'm AIVAS, your network security assistant. Give me an IP address or network range and I'll scan it for you. Type /help to see what I can do."`
- **History exists (returning user):** push one `ai` message: `"Welcome back. Your last scan of {target} was {N} days ago — Grade {grade}, {criticalCount} critical vulnerabilities. Want me to rescan, or would you like a summary?"`

---

## 12. Chat Flow

The server sends `scan_intent` and then `complete` in quick succession before the scan finishes. The scan result arrives later, via the scan WebSocket. The frontend must handle these as separate events with separate message slots.

```
User types → sendMessage(text)
  → append {type:"user", text} to messages
  → append {type:"scan-progress", id:"thinking", text:"Thinking…"} placeholder
  → WS sends {type:"user", text}

WS receives {type:"scan_intent", scan_key, target, level}
  → App calls useScan.start(scan_key)
  → update "thinking" placeholder text to "Starting scan on {target}…"

WS receives {type:"complete", text}
  → replace "thinking" placeholder with {type:"ai", text}  ← AI's conversational reply
  → append NEW {type:"scan-progress", id:"scanning", text:"Scanning…"}  ← scan still running

useScan.progress changes (phase_header events from scan WS)
  → update "scanning" message text in-place

useScan receives {type:"done", result}
  → replace "scanning" message with {type:"scan-card", scanData: result}
  → useScan.reset()

WS receives {type:"error", text}
  → replace "thinking" placeholder with {type:"ai", text: "Error: " + text}
  → remove "scanning" message if present
```

---

## 13. Scan Flow

`useScan` hook:

```js
// state
isScanning: bool
progress: string          // latest phase_header text
result: object | null     // set when {type:"done"} arrives

// actions
start(scan_key)           // opens WS /ws/scan/{scan_key}
reset()                   // clears result + isScanning
```

`App` watches `useScan.progress` in a `useEffect` and updates the `scan-progress` message text in the messages array whenever it changes.

Scan WebSocket event handling:
- `{type:"phase_header", text}` → update `progress`
- `{type:"done", result}` → set `result`, `isScanning = false`
- `{type:"error", text}` → set `isScanning = false`; error surfaces via chat WS `error` event

---

## 14. Session Drawer (`SessionDrawer`)

Slides in from the right. Width 320px. `background: #111111`.

Contents:
- Title `"Conversations"` in `#e0e0e0`
- `[+ New conversation]` button at top
- List of sessions from `useSessions`: each row shows title (first 60 chars of opening message), date, truncated to one line
- Clicking a row: calls `GET /api/sessions/{id}/messages`, replays messages into `messages` array, updates `sessionId` in App, reconnects `useChat` to the new session WS
- Trash icon on hover → `DELETE /api/sessions/{id}` + refresh list
- Close on backdrop click or Escape

**History message mapping** (`GET /api/sessions/{id}/messages` → frontend messages array):
- `{role:"user", content:"..."}` → `{type:"user", text:content}`
- `{role:"assistant", content:"..."}` (non-empty content) → `{type:"ai", text:content}`
- `{role:"assistant", tool_calls:[...]}` → omit (internal tool dispatch, not shown)
- `{role:"tool", ...}` → omit (internal tool result, not shown)

Scan cards are not reconstructed on history replay — the structured findings are not stored in chat messages. The AI's narration text is present in the `assistant` messages and renders as normal AI text. This is acceptable; users can ask the AI to re-summarise or rescan.

`useSessions` hook:
```js
sessions: array           // [{id, title, updated_at}]
refresh()                 // re-fetches GET /api/sessions
deleteSession(id)         // DELETE /api/sessions/{id} then refresh
```

---

## 15. Settings Modal (`SettingsModal`)

Centered modal overlay. `background: #111111`, border `#1e1e1e`.

Two settings:
1. **API Key** — masked text input. Save stores to `localStorage` under key `aivas_api_key`. Shows `"Connected"` / `"Not configured"` status label.
2. **Language** — three-way segmented toggle: `Auto` / `English` / `Swahili`. Stored in `localStorage` under `aivas_lang`. Default: `Auto`. Passed as `X-Lang` header on chat WebSocket messages (not yet consumed by backend — stored for future use).

Close on backdrop click, Escape, or explicit close button.

---

## 16. Backend Contract

All endpoints already exist. No backend changes.

| Endpoint | Used by |
|---|---|
| `POST /api/sessions` | App mount — create session |
| `GET /api/sessions` | `useSessions` — populate drawer |
| `GET /api/sessions/{id}/messages` | Switch session — replay history |
| `DELETE /api/sessions/{id}` | Delete from drawer |
| `WS /ws/chat/{session_id}` | `useChat` — all conversation |
| `WS /ws/scan/{scan_key}` | `useScan` — triggered by scan_intent |
| `GET /api/history?limit=1` | Opening greeting |
| `GET /api/report/{scan_id}` | "View full report" link in ScanCard |

---

## 17. Settings Persistence

`localStorage` keys:
- `aivas_api_key` — Groq API key, masked in UI
- `aivas_lang` — `"auto"` | `"en"` | `"sw"`, default `"auto"`

Read on mount, written on save. Not sent to backend in this phase (backend reads key from env; stored here for future settings sync).

---

## 18. Testing

**Keep (unchanged):**
- `lib/severity.test.js`
- `lib/mdToHtml.test.js`

**Delete:**
- `components/FindingsTable.test.jsx`
- `hooks/useWebSocket.test.jsx`

**New:**
- `components/ScanCard.test.jsx` — grade badge color, severity pill render, CVE list shows top 5 then expands, KEV badge on KEV findings, action buttons call sendMessage with correct text
- `hooks/useChat.test.js` — mock WebSocket, verify: user message dispatched, scan_intent triggers onScanIntent callback, complete event triggers onComplete callback, error event triggers onError callback

---

## 19. Tailwind Config

Add custom color tokens to `tailwind.config.js` so components can use `bg-surface`, `text-accent`, `border-border` etc. rather than arbitrary hex values inline:

```js
extend: {
  colors: {
    bg: '#0a0a0a',
    surface: '#111111',
    'surface-raised': '#161616',
    border: '#1e1e1e',
    'border-subtle': '#141414',
    text: '#e0e0e0',
    'text-muted': '#666666',
    accent: '#4a9eff',
    critical: '#ef5350',
    high: '#ff7043',
    medium: '#fdd835',
    low: '#66bb6a',
  }
}
```

---

*Spec written 2026-07-14. Depends on Phase 1 backend (feat/web-ui branch, PR #3) being merged to main before implementation begins.*
