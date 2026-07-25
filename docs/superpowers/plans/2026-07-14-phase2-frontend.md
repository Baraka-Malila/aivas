# AIVAS Phase 2 — Chat-First Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the existing dashboard React frontend with a chat-first dark-theme UI where the AI is the primary interface and scan results appear as inline cards in the conversation thread.

**Architecture:** Two React hooks (`useChat`, `useScan`) managed by `App.jsx` — `useChat` owns the chat WebSocket, `useScan` owns the scan WebSocket. `App` coordinates: when `useChat` receives a `scan_intent` event it calls `useScan.start(scan_key)`, and when the scan finishes it appends a `ScanCard` to the flat messages array. All visual state is a single `messages: [{id, type, text, scanData}]` array rendered by `ChatArea`.

**Tech Stack:** React 18, Vite, Tailwind CSS 3, Lucide React, Vitest + React Testing Library. No new packages.

## Global Constraints

- No new npm packages — use only what's already in `frontend/package.json`
- No backend changes — all endpoints exist in Phase 1
- No violet, no light backgrounds
- Color palette exact values: `bg=#0a0a0a`, `surface=#111111`, `surface-raised=#161616`, `border=#1e1e1e`, `border-subtle=#141414`, `text=#e0e0e0`, `text-muted=#666666`, `accent=#4a9eff`, `critical=#ef5350`, `high=#ff7043`, `medium=#fdd835`, `low=#66bb6a`
- Grade badge colors: A=`#66bb6a`, B=`#aed581`, C=`#fdd835`, D=`#ff7043`, F=`#ef5350`
- All commands run from `frontend/` directory unless stated otherwise
- `npm run test:run` must pass before each commit (except Task 1 which has no new tests)

---

## File Map

### New (create)
- `frontend/src/hooks/useChat.js` — chat WebSocket manager
- `frontend/src/hooks/useScan.js` — scan WebSocket manager
- `frontend/src/hooks/useSessions.js` — REST session list
- `frontend/src/components/Header.jsx` — 48px top bar
- `frontend/src/components/ChatInput.jsx` — fixed bottom input
- `frontend/src/components/AiMessage.jsx` — AI reply bubble
- `frontend/src/components/UserMessage.jsx` — user bubble
- `frontend/src/components/ScanProgress.jsx` — animated spinner
- `frontend/src/components/ScanCard.jsx` — inline scan result card
- `frontend/src/components/ChatArea.jsx` — message list container
- `frontend/src/components/SessionDrawer.jsx` — right-side history drawer
- `frontend/src/components/SettingsModal.jsx` — API key + language modal
- `frontend/src/hooks/useChat.test.js` — useChat unit tests
- `frontend/src/components/ScanCard.test.jsx` — ScanCard unit tests

### Rewrite
- `frontend/src/App.jsx` — coordinator
- `frontend/src/index.css` — dark theme base
- `frontend/tailwind.config.js` — add custom color tokens

### Delete
- `frontend/src/components/Sidebar.jsx`
- `frontend/src/components/ScanBar.jsx`
- `frontend/src/components/ProgressFeed.jsx`
- `frontend/src/components/ResultsTabs.jsx`
- `frontend/src/components/FindingsTable.jsx`
- `frontend/src/components/FindingsTable.test.jsx`
- `frontend/src/components/MisconfigTable.jsx`
- `frontend/src/components/AssessmentPanel.jsx`
- `frontend/src/components/ReportPanel.jsx`
- `frontend/src/components/ScanLog.jsx`
- `frontend/src/hooks/useWebSocket.js`
- `frontend/src/hooks/useWebSocket.test.jsx`
- `frontend/src/hooks/useHistory.js`

### Keep unchanged
- `frontend/src/lib/severity.js`, `severity.test.js`
- `frontend/src/lib/mdToHtml.js`, `mdToHtml.test.js`
- `frontend/src/lib/utils.js`
- `frontend/src/main.jsx`
- `frontend/src/test-setup.js`
- All of `frontend/vite.config.js`, `postcss.config.js`, `package.json`

---

## Tasks Overview

| Task | Deliverable | Tests |
|------|-------------|-------|
| 1 | Tailwind config + dark CSS + delete old files | build passes |
| 2 | `useChat` hook | 4 unit tests |
| 3 | `useScan` + `useSessions` hooks | build passes |
| 4 | Display components: Header, ChatInput, AiMessage, UserMessage, ScanProgress | build passes |
| 5 | `ScanCard` component | 6 unit tests |
| 6 | `SessionDrawer` + `SettingsModal` | build passes |
| 7 | `ChatArea` | build passes |
| 8 | `App.jsx` coordinator + full build verification | all tests pass |

---

## Task 1: Tailwind Config + Dark Theme CSS + Delete Old Files

**Files:**
- Modify: `frontend/tailwind.config.js`
- Modify: `frontend/src/index.css`
- Delete: the 10 old component/hook files listed in the "Delete" section above

**Interfaces:**
- Produces: Tailwind color tokens `bg-surface`, `text-accent`, `border-border` etc. available to all later tasks

- [ ] **Step 1: Update tailwind.config.js with custom color tokens**

```js
// frontend/tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
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
      },
      fontFamily: {
        mono: ['"Fira Code"', '"SF Mono"', '"Courier New"', 'monospace'],
      },
    },
  },
  plugins: [],
}
```

- [ ] **Step 2: Rewrite index.css for dark theme**

```css
/* frontend/src/index.css */
@tailwind base;
@tailwind components;
@tailwind utilities;

*, *::before, *::after { box-sizing: border-box; }

html, body, #root {
  height: 100%;
  margin: 0;
  padding: 0;
}

body {
  background: #0a0a0a;
  color: #e0e0e0;
  font-family: system-ui, -apple-system, sans-serif;
  font-size: 14px;
  -webkit-font-smoothing: antialiased;
}

::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #1e1e1e; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #333; }
```

- [ ] **Step 3: Delete old files**

```bash
cd frontend && rm -f \
  src/components/Sidebar.jsx \
  src/components/ScanBar.jsx \
  src/components/ProgressFeed.jsx \
  src/components/ResultsTabs.jsx \
  src/components/FindingsTable.jsx \
  src/components/FindingsTable.test.jsx \
  src/components/MisconfigTable.jsx \
  src/components/AssessmentPanel.jsx \
  src/components/ReportPanel.jsx \
  src/components/ScanLog.jsx \
  src/hooks/useWebSocket.js \
  src/hooks/useWebSocket.test.jsx \
  src/hooks/useHistory.js
```

- [ ] **Step 4: Temporarily stub App.jsx so the build still works**

Replace the entire contents of `frontend/src/App.jsx` with this stub (Task 8 will overwrite it completely):

```jsx
// frontend/src/App.jsx  — temporary stub, replaced in Task 8
export default function App() {
  return <div style={{ background: '#0a0a0a', color: '#e0e0e0', padding: 40 }}>AIVAS loading…</div>
}
```

- [ ] **Step 5: Verify build passes**

```bash
cd frontend && npm run build
```

Expected: no errors, `dist/` updated.

- [ ] **Step 6: Commit**

```bash
cd frontend && git add -A && git commit -m "refactor(frontend): dark theme, Tailwind tokens, remove old components"
```

---

## Task 2: `useChat` Hook + Test

**Files:**
- Create: `frontend/src/hooks/useChat.js`
- Create: `frontend/src/hooks/useChat.test.js`

**Interfaces:**
- Produces: `useChat(sessionId, onEvent)` → `{ status, send }`
  - `sessionId: string | null` — when null the hook does nothing (no WS opened)
  - `onEvent: (msg: object) => void` — called for every JSON message from the server. msg.type is one of `"complete"`, `"scan_intent"`, `"error"`, `"interrupted"`.
  - `status: "idle" | "open" | "closed" | "error"`
  - `send(text: string)` — sends `{type:"user", text}` over the WS if open

- [ ] **Step 1: Write failing tests**

```js
// frontend/src/hooks/useChat.test.js
import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useChat } from './useChat'

class MockWS {
  constructor(url) {
    this.url = url
    this.readyState = 1  // OPEN
    this.sent = []
    MockWS.last = this
  }
  send(data) { this.sent.push(data) }
  close() { this.onclose?.() }
}
MockWS.last = null

beforeEach(() => { vi.stubGlobal('WebSocket', MockWS) })
afterEach(() => { vi.unstubAllGlobals() })

describe('useChat', () => {
  it('opens WebSocket with correct session URL', () => {
    renderHook(() => useChat('sess-1', vi.fn()))
    expect(MockWS.last.url).toContain('/ws/chat/sess-1')
  })

  it('does not open WebSocket when sessionId is null', () => {
    MockWS.last = null
    renderHook(() => useChat(null, vi.fn()))
    expect(MockWS.last).toBeNull()
  })

  it('send() dispatches user message over WS', () => {
    const { result } = renderHook(() => useChat('s1', vi.fn()))
    act(() => result.current.send('hello'))
    expect(JSON.parse(MockWS.last.sent[0])).toEqual({ type: 'user', text: 'hello' })
  })

  it('calls onEvent with parsed message on WS message', () => {
    const onEvent = vi.fn()
    renderHook(() => useChat('s1', onEvent))
    act(() => {
      MockWS.last.onmessage({ data: '{"type":"complete","text":"hi"}' })
    })
    expect(onEvent).toHaveBeenCalledWith({ type: 'complete', text: 'hi' })
  })
})
```

- [ ] **Step 2: Run tests — expect 4 failures**

```bash
cd frontend && npm run test:run -- src/hooks/useChat.test.js
```

Expected: 4 failures (useChat not defined).

- [ ] **Step 3: Implement useChat**

```js
// frontend/src/hooks/useChat.js
import { useEffect, useRef, useCallback, useState } from 'react'

export function useChat(sessionId, onEvent) {
  const onEventRef = useRef(onEvent)
  useEffect(() => { onEventRef.current = onEvent })

  const wsRef = useRef(null)
  const [status, setStatus] = useState('idle')

  useEffect(() => {
    if (!sessionId) return
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/chat/${sessionId}`)
    ws.onopen = () => setStatus('open')
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
  }, [sessionId])

  const send = useCallback((text) => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: 'user', text }))
    }
  }, [])

  return { status, send }
}
```

- [ ] **Step 4: Run tests — expect 4 passing**

```bash
cd frontend && npm run test:run -- src/hooks/useChat.test.js
```

Expected: 4 passed.

- [ ] **Step 5: Run full test suite**

```bash
cd frontend && npm run test:run
```

Expected: all tests pass (lib tests + new useChat tests).

- [ ] **Step 6: Commit**

```bash
cd frontend && git add src/hooks/useChat.js src/hooks/useChat.test.js && git commit -m "feat(frontend): useChat hook — chat WebSocket with session support"
```

---

## Task 3: `useScan` + `useSessions` Hooks

**Files:**
- Create: `frontend/src/hooks/useScan.js`
- Create: `frontend/src/hooks/useSessions.js`

**Interfaces:**
- Produces: `useScan(onProgress, onDone)` → `{ isScanning, start }`
  - `onProgress(text: string)` — called with each `phase_header` event text
  - `onDone(event: object)` — called with the full `{type:"done", scan_id, target, grade, score, service_count, findings, misconfigs}` event
  - `start(scanKey: string)` — opens `WS /ws/scan/{scanKey}`
  - `isScanning: bool`
- Produces: `useSessions()` → `{ sessions, refresh, deleteSession }`
  - `sessions: [{id, title, updated_at}]`
  - `refresh()` — re-fetches `GET /api/sessions`
  - `deleteSession(id)` — `DELETE /api/sessions/{id}` then removes from local state

- [ ] **Step 1: Implement useScan**

```js
// frontend/src/hooks/useScan.js
import { useRef, useCallback, useState, useEffect } from 'react'

export function useScan(onProgress, onDone) {
  const onProgressRef = useRef(onProgress)
  const onDoneRef = useRef(onDone)
  useEffect(() => {
    onProgressRef.current = onProgress
    onDoneRef.current = onDone
  })

  const wsRef = useRef(null)
  const [isScanning, setIsScanning] = useState(false)

  const start = useCallback((scanKey) => {
    if (wsRef.current) {
      wsRef.current.onmessage = null
      wsRef.current.close()
    }
    setIsScanning(true)
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/scan/${scanKey}`)
    ws.onmessage = (e) => {
      let msg
      try { msg = JSON.parse(e.data) } catch { return }
      if (msg.type === 'phase_header') {
        onProgressRef.current(msg.text || '')
      } else if (msg.type === 'done') {
        setIsScanning(false)
        onDoneRef.current(msg)
        ws.close()
      } else if (msg.type === 'error') {
        setIsScanning(false)
        ws.close()
      }
    }
    ws.onerror = () => setIsScanning(false)
    wsRef.current = ws
  }, [])

  return { isScanning, start }
}
```

- [ ] **Step 2: Implement useSessions**

```js
// frontend/src/hooks/useSessions.js
import { useState, useCallback } from 'react'

export function useSessions() {
  const [sessions, setSessions] = useState([])

  const refresh = useCallback(async () => {
    try {
      const data = await fetch('/api/sessions').then(r => r.json())
      setSessions(Array.isArray(data) ? data : [])
    } catch {}
  }, [])

  const deleteSession = useCallback(async (id) => {
    try {
      await fetch(`/api/sessions/${id}`, { method: 'DELETE' })
    } catch {}
    setSessions(prev => prev.filter(s => s.id !== id))
  }, [])

  return { sessions, refresh, deleteSession }
}
```

- [ ] **Step 3: Verify build**

```bash
cd frontend && npm run build
```

Expected: no errors.

- [ ] **Step 4: Run full test suite**

```bash
cd frontend && npm run test:run
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
cd frontend && git add src/hooks/useScan.js src/hooks/useSessions.js && git commit -m "feat(frontend): useScan + useSessions hooks"
```

---

## Task 4: Display Components — Header, ChatInput, AiMessage, UserMessage, ScanProgress

**Files:**
- Create: `frontend/src/components/Header.jsx`
- Create: `frontend/src/components/ChatInput.jsx`
- Create: `frontend/src/components/AiMessage.jsx`
- Create: `frontend/src/components/UserMessage.jsx`
- Create: `frontend/src/components/ScanProgress.jsx`

**Interfaces:**
- `<Header onHistory={fn} onSettings={fn} />` — 48px bar, logo left, icon buttons right
- `<ChatInput onSend={fn} disabled={bool} />` — fixed-bottom form, calls `onSend(text)` on submit
- `<AiMessage text={string} />` — `✦ AIVAS` label + markdown body
- `<UserMessage text={string} />` — right-aligned bubble
- `<ScanProgress text={string} />` — animated spinner + updating text

- [ ] **Step 1: Create Header.jsx**

```jsx
// frontend/src/components/Header.jsx
import { Clock, Settings } from 'lucide-react'

export default function Header({ onHistory, onSettings }) {
  return (
    <header
      style={{ background: '#0d0d0d', borderBottom: '1px solid #1a1a1a' }}
      className="h-12 flex items-center justify-between px-4 shrink-0"
    >
      <div className="flex items-center gap-2">
        <span style={{ color: '#4a9eff' }} className="font-semibold text-sm select-none">
          ✦ AIVAS
        </span>
        <span style={{ color: '#666' }} className="text-xs select-none">
          Network Security
        </span>
      </div>
      <div className="flex items-center gap-1">
        <button
          onClick={onHistory}
          style={{ color: '#666' }}
          className="p-2 rounded hover:text-white transition-colors"
          aria-label="Conversation history"
        >
          <Clock size={17} />
        </button>
        <button
          onClick={onSettings}
          style={{ color: '#666' }}
          className="p-2 rounded hover:text-white transition-colors"
          aria-label="Settings"
        >
          <Settings size={17} />
        </button>
      </div>
    </header>
  )
}
```

- [ ] **Step 2: Create ChatInput.jsx**

```jsx
// frontend/src/components/ChatInput.jsx
import { useState } from 'react'
import { Send } from 'lucide-react'

export default function ChatInput({ onSend, disabled }) {
  const [text, setText] = useState('')

  const submit = (e) => {
    e.preventDefault()
    const t = text.trim()
    if (!t || disabled) return
    onSend(t)
    setText('')
  }

  return (
    <div
      style={{ background: '#0a0a0a', borderTop: '1px solid #1e1e1e' }}
      className="px-4 py-3 shrink-0"
    >
      <form
        onSubmit={submit}
        className="mx-auto flex gap-2"
        style={{ maxWidth: 800 }}
      >
        <input
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) submit(e) }}
          placeholder="Type a message…"
          disabled={disabled}
          style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
          className="flex-1 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#666] disabled:opacity-50 transition-colors"
        />
        <button
          type="submit"
          disabled={disabled || !text.trim()}
          style={{ background: '#4a9eff' }}
          className="px-3 py-2.5 rounded-lg text-black font-medium flex items-center hover:opacity-90 disabled:opacity-40 transition-opacity"
          aria-label="Send"
        >
          <Send size={16} />
        </button>
      </form>
    </div>
  )
}
```

- [ ] **Step 3: Create AiMessage.jsx**

```jsx
// frontend/src/components/AiMessage.jsx
import { mdToHtml } from '../lib/mdToHtml'

export default function AiMessage({ text }) {
  return (
    <div className="py-3">
      <div style={{ color: '#4a9eff' }} className="text-xs font-medium mb-1.5 select-none">
        ✦ AIVAS
      </div>
      <div
        style={{ color: '#c8c8c8', lineHeight: 1.7 }}
        className="text-sm"
        dangerouslySetInnerHTML={{ __html: mdToHtml(text) }}
      />
    </div>
  )
}
```

- [ ] **Step 4: Create UserMessage.jsx**

```jsx
// frontend/src/components/UserMessage.jsx
export default function UserMessage({ text }) {
  return (
    <div className="flex justify-end py-1.5">
      <div
        style={{
          background: '#0d1929',
          border: '1px solid #1a2d45',
          borderRadius: '14px 14px 4px 14px',
          color: '#90bde0',
          maxWidth: '75%',
        }}
        className="px-4 py-2.5 text-sm whitespace-pre-wrap"
      >
        {text}
      </div>
    </div>
  )
}
```

- [ ] **Step 5: Create ScanProgress.jsx**

```jsx
// frontend/src/components/ScanProgress.jsx
import { useEffect, useRef, useState } from 'react'

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

export default function ScanProgress({ text }) {
  const [frame, setFrame] = useState(0)
  const timer = useRef(null)

  useEffect(() => {
    timer.current = setInterval(() => setFrame(f => (f + 1) % FRAMES.length), 120)
    return () => clearInterval(timer.current)
  }, [])

  return (
    <div className="py-3">
      <div style={{ color: '#4a9eff' }} className="text-xs font-medium mb-1.5 select-none">
        ✦ AIVAS
      </div>
      <div style={{ color: '#666' }} className="text-sm font-mono">
        {FRAMES[frame]} {text}
      </div>
    </div>
  )
}
```

- [ ] **Step 6: Verify build**

```bash
cd frontend && npm run build
```

Expected: no errors.

- [ ] **Step 7: Run full test suite**

```bash
cd frontend && npm run test:run
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
cd frontend && git add src/components/Header.jsx src/components/ChatInput.jsx \
  src/components/AiMessage.jsx src/components/UserMessage.jsx \
  src/components/ScanProgress.jsx && \
  git commit -m "feat(frontend): Header, ChatInput, AiMessage, UserMessage, ScanProgress"
```

---

## Task 5: ScanCard Component + Test

**Files:**
- Create: `frontend/src/components/ScanCard.jsx`
- Create: `frontend/src/components/ScanCard.test.jsx`

**Interfaces:**
- Consumes: `severity.js` — `sevClasses` not used (dark theme has its own colors); imports nothing from severity.js
- Consumes (from scan done event via App): `scanData: { scan_id: int, target: str, grade: "A"|"B"|"C"|"D"|"F", score: float, service_count: int, findings: [{cve_id, cvss_score, cvss_severity, description, kev: bool, host}], counts: {CRITICAL: int, HIGH: int, MEDIUM: int, LOW: int} }`
- Produces: `<ScanCard scanData={...} onSend={fn} />` — `onSend(text)` is called when action buttons are clicked

**Important:** `kev` field on findings comes from enriched `GET /api/scan/{id}` response (not the raw done event). ScanCard just renders whatever is in `findings[i].kev`.

- [ ] **Step 1: Write failing tests**

```jsx
// frontend/src/components/ScanCard.test.jsx
import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import ScanCard from './ScanCard'

const base = {
  scan_id: 42,
  target: '192.168.1.1',
  grade: 'F',
  score: 95,
  service_count: 3,
  findings: [
    { cve_id: 'CVE-2021-44228', cvss_score: 10.0, cvss_severity: 'CRITICAL', description: 'Log4j RCE', kev: true },
    { cve_id: 'CVE-2022-0778',  cvss_score: 9.8,  cvss_severity: 'CRITICAL', description: 'OpenSSL DoS', kev: false },
    { cve_id: 'CVE-2023-0001',  cvss_score: 7.5,  cvss_severity: 'HIGH',     description: 'Test high 1', kev: false },
    { cve_id: 'CVE-2023-0002',  cvss_score: 6.1,  cvss_severity: 'HIGH',     description: 'Test high 2', kev: false },
    { cve_id: 'CVE-2023-0003',  cvss_score: 5.0,  cvss_severity: 'MEDIUM',   description: 'Test medium', kev: false },
    { cve_id: 'CVE-2023-0004',  cvss_score: 3.1,  cvss_severity: 'LOW',      description: 'Test low',    kev: false },
  ],
  counts: { CRITICAL: 2, HIGH: 2, MEDIUM: 1, LOW: 1 },
}

describe('ScanCard', () => {
  it('displays grade F with red color', () => {
    const { container } = render(<ScanCard scanData={base} onSend={vi.fn()} />)
    const gradeEl = container.querySelector('[data-testid="grade-badge"]')
    expect(gradeEl).toBeTruthy()
    expect(gradeEl.textContent).toBe('F')
    // getAttribute returns raw style string, avoids jsdom rgb normalisation
    expect(gradeEl.getAttribute('style')).toContain('ef5350')
  })

  it('shows severity pills for non-zero counts', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    expect(screen.getByText('2 CRITICAL')).toBeTruthy()
    expect(screen.getByText('2 HIGH')).toBeTruthy()
    expect(screen.getByText('1 MEDIUM')).toBeTruthy()
  })

  it('shows top 5 CVEs by default, hides the 6th', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    expect(screen.getByText('CVE-2021-44228')).toBeTruthy()
    expect(screen.getByText('CVE-2023-0003')).toBeTruthy()
    expect(screen.queryByText('CVE-2023-0004')).toBeNull()
  })

  it('expands to all findings when toggle clicked', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    fireEvent.click(screen.getByText(/Show all 6/))
    expect(screen.getByText('CVE-2023-0004')).toBeTruthy()
  })

  it('shows KEV badge only for KEV findings', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    const kevBadges = screen.getAllByText('⚠ KEV')
    expect(kevBadges).toHaveLength(1)  // only CVE-2021-44228 has kev:true
  })

  it('action buttons call onSend with correct text', () => {
    const onSend = vi.fn()
    render(<ScanCard scanData={base} onSend={onSend} />)
    fireEvent.click(screen.getByText('Narrate'))
    expect(onSend).toHaveBeenCalledWith('Narrate the findings from scan 42')
    fireEvent.click(screen.getByText('Explain worst'))
    expect(onSend).toHaveBeenCalledWith('Explain the worst vulnerability from scan 42')
    fireEvent.click(screen.getByText('Rescan'))
    expect(onSend).toHaveBeenCalledWith('Scan 192.168.1.1 again')
  })
})
```

- [ ] **Step 2: Run tests — expect 6 failures**

```bash
cd frontend && npm run test:run -- src/components/ScanCard.test.jsx
```

Expected: 6 failures (ScanCard not defined).

- [ ] **Step 3: Implement ScanCard.jsx**

```jsx
// frontend/src/components/ScanCard.jsx
import { useState } from 'react'
import { ExternalLink } from 'lucide-react'

const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }
const SEV_TEXT   = { CRITICAL: '#ef5350', HIGH: '#ff7043', MEDIUM: '#fdd835', LOW: '#66bb6a' }
const SEV_BG     = { CRITICAL: '#1a0505', HIGH: '#1a0e05', MEDIUM: '#1a1505', LOW: '#051a05' }
const SEV_ORDER  = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function ScanCard({ scanData, onSend }) {
  const [expanded, setExpanded] = useState(false)
  const { scan_id, target, grade, service_count, findings, counts } = scanData

  const shown = expanded ? findings : findings.slice(0, 5)
  const gradeColor = GRADE_COLOR[grade] || '#e0e0e0'

  return (
    <div
      style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 8 }}
      className="mt-2 overflow-hidden text-sm"
    >
      {/* Header row */}
      <div
        style={{ borderBottom: '1px solid #1e1e1e' }}
        className="flex justify-between items-start px-3 py-2.5"
      >
        <div>
          <span style={{ color: '#e0e0e0', fontFamily: 'monospace' }} className="text-sm">
            {target}
          </span>
          <div style={{ color: '#666' }} className="text-xs mt-0.5">
            {service_count} service{service_count !== 1 ? 's' : ''} · {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </div>
        </div>
        <span
          data-testid="grade-badge"
          style={{ color: gradeColor, fontWeight: 700, fontSize: 20, lineHeight: 1 }}
        >
          {grade}
        </span>
      </div>

      {/* Severity pills */}
      <div style={{ borderBottom: '1px solid #1e1e1e' }} className="flex flex-wrap gap-2 px-3 py-2">
        {SEV_ORDER.map(sev => counts[sev] > 0 && (
          <span
            key={sev}
            style={{
              background: SEV_BG[sev],
              color: SEV_TEXT[sev],
              border: `1px solid ${SEV_TEXT[sev]}44`,
            }}
            className="text-xs px-2 py-0.5 rounded font-medium"
          >
            {counts[sev]} {sev}
          </span>
        ))}
        {Object.values(counts).every(n => n === 0) && (
          <span style={{ color: '#66bb6a' }} className="text-xs">No vulnerabilities found</span>
        )}
      </div>

      {/* CVE list */}
      {findings.length > 0 && (
        <div style={{ borderBottom: '1px solid #1e1e1e' }}>
          {shown.map((f, i) => (
            <div
              key={f.cve_id || i}
              style={{ borderBottom: '1px solid #141414' }}
              className="flex items-center gap-2 px-3 py-1.5"
            >
              {f.kev && (
                <span style={{ color: '#ff7043', fontSize: 10, fontWeight: 700 }} className="shrink-0">
                  ⚠ KEV
                </span>
              )}
              <span
                style={{ color: '#e0e0e0', fontFamily: 'monospace', fontSize: 11 }}
                className="shrink-0 w-36 truncate"
              >
                {f.cve_id}
              </span>
              <span style={{ color: '#888', fontSize: 11 }} className="flex-1 truncate">
                {f.description}
              </span>
              <span
                style={{ color: SEV_TEXT[(f.cvss_severity || 'low').toUpperCase()], fontFamily: 'monospace', fontSize: 11 }}
                className="shrink-0"
              >
                {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
              </span>
            </div>
          ))}
          {findings.length > 5 && (
            <button
              onClick={() => setExpanded(e => !e)}
              style={{ color: '#4a9eff' }}
              className="w-full text-xs px-3 py-2 text-left hover:opacity-80 transition-opacity"
            >
              {expanded ? '↑ Show less' : `↓ Show all ${findings.length} findings`}
            </button>
          )}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-2.5">
        <button
          onClick={() => onSend(`Narrate the findings from scan ${scan_id}`)}
          style={{ background: '#0d1929', border: '1px solid #1a2d45', color: '#4a9eff' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          Narrate
        </button>
        <button
          onClick={() => onSend(`Explain the worst vulnerability from scan ${scan_id}`)}
          style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          Explain worst
        </button>
        <button
          onClick={() => onSend(`Scan ${target} again`)}
          style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          Rescan
        </button>
        <a
          href={`/api/report/${scan_id}`}
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: '#666' }}
          className="ml-auto text-xs flex items-center gap-1 hover:text-white transition-colors"
        >
          View full report <ExternalLink size={10} />
        </a>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Run tests — expect 6 passing**

```bash
cd frontend && npm run test:run -- src/components/ScanCard.test.jsx
```

Expected: 6 passed.

- [ ] **Step 5: Run full test suite**

```bash
cd frontend && npm run test:run
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
cd frontend && git add src/components/ScanCard.jsx src/components/ScanCard.test.jsx && \
  git commit -m "feat(frontend): ScanCard with grade, severity pills, CVE list, KEV badge, actions"
```

---

## Task 6: SessionDrawer + SettingsModal

**Files:**
- Create: `frontend/src/components/SessionDrawer.jsx`
- Create: `frontend/src/components/SettingsModal.jsx`

**Interfaces:**
- `<SessionDrawer open={bool} sessions={[{id,title,updated_at}]} onClose={fn} onSelect={fn(session)} onDelete={fn(id)} onNew={fn} />`
- `<SettingsModal open={bool} onClose={fn} />`
  - Reads/writes `localStorage.aivas_api_key` (string) and `localStorage.aivas_lang` (`"auto"|"en"|"sw"`)

- [ ] **Step 1: Create SessionDrawer.jsx**

```jsx
// frontend/src/components/SessionDrawer.jsx
import { X, Trash2, Plus } from 'lucide-react'

export default function SessionDrawer({ open, sessions, onClose, onSelect, onDelete, onNew }) {
  if (!open) return null

  return (
    <>
      <div
        style={{ background: 'rgba(0,0,0,0.6)' }}
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      <div
        style={{ background: '#111111', borderLeft: '1px solid #1e1e1e', width: 320 }}
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col"
      >
        {/* Header */}
        <div
          style={{ borderBottom: '1px solid #1e1e1e' }}
          className="flex items-center justify-between px-4 py-3 shrink-0"
        >
          <span style={{ color: '#e0e0e0' }} className="font-medium text-sm">Conversations</span>
          <button onClick={onClose} style={{ color: '#666' }} className="p-1 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* New conversation */}
        <button
          onClick={onNew}
          style={{ borderBottom: '1px solid #1e1e1e', color: '#4a9eff' }}
          className="flex items-center gap-2 px-4 py-2.5 text-xs hover:bg-white/5 transition-colors text-left shrink-0"
        >
          <Plus size={14} /> New conversation
        </button>

        {/* Session list */}
        <div className="flex-1 overflow-y-auto">
          {sessions.length === 0 && (
            <div style={{ color: '#666' }} className="px-4 py-8 text-xs text-center">
              No conversations yet
            </div>
          )}
          {sessions.map(s => (
            <div
              key={s.id}
              style={{ borderBottom: '1px solid #141414' }}
              className="group flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors cursor-pointer"
              onClick={() => { onSelect(s); onClose() }}
            >
              <div className="flex-1 min-w-0 pr-2">
                <div style={{ color: '#e0e0e0' }} className="text-xs truncate">
                  {s.title || 'New conversation'}
                </div>
                <div style={{ color: '#666' }} className="text-xs mt-0.5">
                  {formatDate(s.updated_at)}
                </div>
              </div>
              <button
                onClick={e => { e.stopPropagation(); onDelete(s.id) }}
                style={{ color: '#444' }}
                className="opacity-0 group-hover:opacity-100 p-1 hover:text-red-400 transition-all shrink-0"
                aria-label="Delete conversation"
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}

function formatDate(isoStr) {
  if (!isoStr) return ''
  return new Date(isoStr).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}
```

- [ ] **Step 2: Create SettingsModal.jsx**

```jsx
// frontend/src/components/SettingsModal.jsx
import { useState, useEffect } from 'react'
import { X } from 'lucide-react'

const LANGS = [
  { value: 'auto', label: 'Auto' },
  { value: 'en',   label: 'English' },
  { value: 'sw',   label: 'Swahili' },
]

export default function SettingsModal({ open, onClose }) {
  const [apiKey, setApiKey] = useState('')
  const [lang, setLang] = useState('auto')

  useEffect(() => {
    if (!open) return
    setApiKey(localStorage.getItem('aivas_api_key') || '')
    setLang(localStorage.getItem('aivas_lang') || 'auto')
  }, [open])

  if (!open) return null

  const save = () => {
    localStorage.setItem('aivas_api_key', apiKey)
    localStorage.setItem('aivas_lang', lang)
    onClose()
  }

  return (
    <>
      <div
        style={{ background: 'rgba(0,0,0,0.7)' }}
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      <div
        style={{ background: '#111111', border: '1px solid #1e1e1e', width: 380 }}
        className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 rounded-lg p-5"
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <span style={{ color: '#e0e0e0' }} className="font-medium text-sm">Settings</span>
          <button onClick={onClose} style={{ color: '#666' }} className="p-1 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* API Key */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">API Key (Groq)</label>
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder="gsk_…"
            style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#444] transition-colors"
          />
          <div style={{ color: apiKey ? '#66bb6a' : '#666' }} className="text-xs mt-1">
            {apiKey ? 'Configured' : 'Not configured'}
          </div>
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

- [ ] **Step 3: Verify build**

```bash
cd frontend && npm run build
```

Expected: no errors.

- [ ] **Step 4: Run full test suite**

```bash
cd frontend && npm run test:run
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
cd frontend && git add src/components/SessionDrawer.jsx src/components/SettingsModal.jsx && \
  git commit -m "feat(frontend): SessionDrawer + SettingsModal"
```

---

## Task 7: ChatArea

**Files:**
- Create: `frontend/src/components/ChatArea.jsx`

**Interfaces:**
- Consumes: `AiMessage`, `UserMessage`, `ScanProgress`, `ScanCard` (all built in Tasks 4-5)
- Consumes: `messages: [{id, type: "user"|"ai"|"scan-progress"|"scan-card", text?, scanData?}]`
- Consumes: `onSend(text: string)` — passed through to ScanCard action buttons
- Produces: `<ChatArea messages={[...]} onSend={fn} />` — scrollable, auto-scrolls to bottom on new message

- [ ] **Step 1: Implement ChatArea.jsx**

```jsx
// frontend/src/components/ChatArea.jsx
import { useEffect, useRef } from 'react'
import AiMessage from './AiMessage'
import UserMessage from './UserMessage'
import ScanProgress from './ScanProgress'
import ScanCard from './ScanCard'

export default function ChatArea({ messages, onSend }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length])

  return (
    <div className="flex-1 overflow-y-auto px-4">
      <div className="mx-auto py-6 space-y-1" style={{ maxWidth: 800 }}>
        {messages.map(m => {
          if (m.type === 'user')         return <UserMessage   key={m.id} text={m.text} />
          if (m.type === 'ai')           return <AiMessage     key={m.id} text={m.text} />
          if (m.type === 'scan-progress') return <ScanProgress key={m.id} text={m.text} />
          if (m.type === 'scan-card')    return <ScanCard      key={m.id} scanData={m.scanData} onSend={onSend} />
          return null
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Verify build**

```bash
cd frontend && npm run build
```

Expected: no errors.

- [ ] **Step 3: Run full test suite**

```bash
cd frontend && npm run test:run
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
cd frontend && git add src/components/ChatArea.jsx && git commit -m "feat(frontend): ChatArea — scrollable message list"
```

---

## Task 8: App.jsx — Coordinator + Build Verification

**Files:**
- Rewrite: `frontend/src/App.jsx`

**Interfaces:**
- Consumes: all hooks and components from Tasks 2-7
- Backend calls:
  - `POST /api/sessions` → `{id: string}` — create new session
  - `GET /api/history?limit=1` → `[{id, target, started_at, grade, risk_score}]` — greeting data. Note: `grade` is stored as `"Grade A"` (includes the word "Grade"). `started_at` is the timestamp field.
  - `GET /api/sessions` → `[{id, title, updated_at}]` — drawer list
  - `GET /api/sessions/{id}/messages` → `[{role, content, tool_calls?}]` — session history replay
  - `GET /api/scan/{scan_id}` → `[{cve_id, cvss_score, cvss_severity, description, confidence, kev, host}]` — enriched findings after scan done

**Message roles from session history:**
- `role:"user"` with `content` string → map to `{type:"user", text:content}`
- `role:"assistant"` with non-empty `content` → map to `{type:"ai", text:content}`
- `role:"assistant"` with `tool_calls` (no content) → skip
- `role:"tool"` → skip

- [ ] **Step 1: Implement App.jsx**

```jsx
// frontend/src/App.jsx
import { useReducer, useEffect, useRef, useState, useCallback } from 'react'
import Header from './components/Header'
import ChatArea from './components/ChatArea'
import ChatInput from './components/ChatInput'
import SessionDrawer from './components/SessionDrawer'
import SettingsModal from './components/SettingsModal'
import { useChat } from './hooks/useChat'
import { useScan } from './hooks/useScan'
import { useSessions } from './hooks/useSessions'

function uid() { return Math.random().toString(36).slice(2, 9) }

function daysAgo(isoStr) {
  if (!isoStr) return 0
  return Math.floor((Date.now() - new Date(isoStr).getTime()) / 86_400_000)
}

function countSeverities(findings) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of findings) {
    const s = (f.cvss_severity || 'LOW').toUpperCase()
    if (s in c) c[s]++
  }
  return c
}

function mapHistory(msgs) {
  return (Array.isArray(msgs) ? msgs : [])
    .filter(m => (m.role === 'user' || m.role === 'assistant') && m.content)
    .map(m => ({ id: uid(), type: m.role === 'user' ? 'user' : 'ai', text: m.content }))
}

function reducer(state, action) {
  switch (action.type) {
    case 'APPEND':      return [...state, action.msg]
    case 'UPDATE_TEXT': return state.map(m => m.id === action.id ? { ...m, text: action.text } : m)
    case 'REPLACE':     return state.map(m => m.id === action.id ? action.msg : m)
    case 'SET':         return action.messages
    default:            return state
  }
}

const FIRST_VISIT_MSG =
  "Hello. I'm AIVAS, your network security assistant. Give me an IP address or network range and I'll scan it for you. Type /help to see what I can do."

export default function App() {
  const [messages, dispatch] = useReducer(reducer, [])
  const [sessionId, setSessionId] = useState(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  // Refs to avoid stale closures in callbacks
  const thinkingIdRef   = useRef(null)
  const scanningIdRef   = useRef(null)
  const scanPendingRef  = useRef(false)
  const startScanRef    = useRef(null)
  const refreshSessRef  = useRef(null)

  // --- Scan callbacks (stable, use refs) ---

  const handleScanProgress = useCallback((text) => {
    if (scanningIdRef.current) {
      dispatch({ type: 'UPDATE_TEXT', id: scanningIdRef.current, text })
    }
  }, [])

  const handleScanDone = useCallback(async (doneEvent) => {
    scanPendingRef.current = false
    let findings = doneEvent.findings || []
    try {
      const enriched = await fetch(`/api/scan/${doneEvent.scan_id}`).then(r => r.json())
      if (Array.isArray(enriched)) findings = enriched
    } catch {}

    const scanData = {
      scan_id:       doneEvent.scan_id,
      target:        doneEvent.target,
      grade:         doneEvent.grade,
      score:         doneEvent.score,
      service_count: doneEvent.service_count,
      findings,
      counts: countSeverities(findings),
    }

    if (scanningIdRef.current) {
      dispatch({
        type: 'REPLACE',
        id: scanningIdRef.current,
        msg: { id: scanningIdRef.current, type: 'scan-card', scanData },
      })
      scanningIdRef.current = null
    }
    refreshSessRef.current?.()
  }, [])

  // --- Chat event handler (stable, uses startScanRef) ---

  const handleChatEvent = useCallback((event) => {
    if (event.type === 'scan_intent') {
      scanPendingRef.current = true
      dispatch({ type: 'UPDATE_TEXT', id: thinkingIdRef.current, text: `Starting scan on ${event.target}…` })
      startScanRef.current?.(event.scan_key)

    } else if (event.type === 'complete') {
      // Replace "thinking" placeholder with AI's conversational reply
      dispatch({
        type: 'REPLACE',
        id: thinkingIdRef.current,
        msg: { id: thinkingIdRef.current, type: 'ai', text: event.text },
      })
      // If scan was triggered, append a separate scanning progress slot
      if (scanPendingRef.current) {
        const sid = uid()
        scanningIdRef.current = sid
        dispatch({ type: 'APPEND', msg: { id: sid, type: 'scan-progress', text: 'Scanning…' } })
      }

    } else if (event.type === 'error') {
      dispatch({
        type: 'REPLACE',
        id: thinkingIdRef.current,
        msg: { id: thinkingIdRef.current, type: 'ai', text: `Error: ${event.text}` },
      })
    }
  }, [])

  // --- Hooks ---

  const { send } = useChat(sessionId, handleChatEvent)
  const { start: startScan } = useScan(handleScanProgress, handleScanDone)
  const { sessions, refresh: refreshSessions, deleteSession } = useSessions()

  // Wire refs after hooks so callbacks can call hook functions without stale closures
  useEffect(() => { startScanRef.current = startScan }, [startScan])
  useEffect(() => { refreshSessRef.current = refreshSessions }, [refreshSessions])

  // --- Initialise on mount ---

  useEffect(() => {
    async function init() {
      const { id } = await fetch('/api/sessions', { method: 'POST' }).then(r => r.json())
      setSessionId(id)
      refreshSessions()

      const history = await fetch('/api/history?limit=1').then(r => r.json()).catch(() => [])
      const text = history.length > 0
        ? `Welcome back. Your last scan of ${history[0].target} was ${daysAgo(history[0].started_at)} days ago — ${history[0].grade}. Want me to rescan, or would you like a summary?`
        : FIRST_VISIT_MSG
      dispatch({ type: 'APPEND', msg: { id: uid(), type: 'ai', text } })
    }
    init()
  }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  // --- User actions ---

  const handleSend = useCallback((text) => {
    const tid = uid()
    thinkingIdRef.current = tid
    scanPendingRef.current = false
    dispatch({ type: 'APPEND', msg: { id: uid(), type: 'user', text } })
    dispatch({ type: 'APPEND', msg: { id: tid, type: 'scan-progress', text: 'Thinking…' } })
    send(text)
  }, [send])

  const handleSelectSession = useCallback(async (session) => {
    // Load the selected session's history into messages and reconnect chat WS
    const msgs = await fetch(`/api/sessions/${session.id}/messages`).then(r => r.json()).catch(() => [])
    dispatch({ type: 'SET', messages: mapHistory(msgs) })
    setSessionId(session.id)
  }, [])

  const handleNewConversation = useCallback(async () => {
    const { id } = await fetch('/api/sessions', { method: 'POST' }).then(r => r.json())
    setSessionId(id)
    dispatch({ type: 'SET', messages: [{ id: uid(), type: 'ai', text: FIRST_VISIT_MSG }] })
    refreshSessions()
  }, [refreshSessions])

  // --- Render ---

  return (
    <div style={{ background: '#0a0a0a' }} className="flex flex-col h-screen">
      <Header
        onHistory={() => { setDrawerOpen(true); refreshSessions() }}
        onSettings={() => setSettingsOpen(true)}
      />
      <ChatArea messages={messages} onSend={handleSend} />
      <ChatInput onSend={handleSend} />
      <SessionDrawer
        open={drawerOpen}
        sessions={sessions}
        onClose={() => setDrawerOpen(false)}
        onSelect={handleSelectSession}
        onDelete={deleteSession}
        onNew={() => { handleNewConversation(); setDrawerOpen(false) }}
      />
      <SettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
      />
    </div>
  )
}
```

- [ ] **Step 2: Run full test suite**

```bash
cd frontend && npm run test:run
```

Expected: all tests pass (useChat: 4, ScanCard: 6, lib tests: keep passing). If any test imports a deleted component, remove the test file too (they were already deleted in Task 1).

- [ ] **Step 3: Build production bundle**

```bash
cd frontend && npm run build
```

Expected: no errors, `dist/` updated with new bundle.

- [ ] **Step 4: Sanity check — does the server serve it?**

Start the backend (requires Groq API key in env or settings):

```bash
cd /home/cyberpunk/aivas && GROQ_API_KEY=dummy python3 -m uvicorn aivas.server.main:app --port 8000 &
sleep 2
curl -s http://localhost:8000/ | grep -o '<title>[^<]*</title>'
kill %1
```

Expected output: `<title>AIVAS</title>` (or the index.html title). No 500 errors.

- [ ] **Step 5: Commit**

```bash
cd frontend && git add src/App.jsx && git commit -m "feat(frontend): App coordinator — chat-first dark UI, session management, scan flow"
```

---

## Final Verification

After all 8 tasks:

```bash
cd frontend && npm run test:run
```

Expected output:
```
✓ src/lib/severity.test.js  (N tests)
✓ src/lib/mdToHtml.test.js  (N tests)
✓ src/hooks/useChat.test.js (4 tests)
✓ src/components/ScanCard.test.jsx (6 tests)
Test Files  4 passed
```

```bash
cd frontend && npm run build
```

Expected: exit 0, `dist/index.html` present.

---

## Spec Coverage Check (self-review)

| Spec section | Covered by |
|---|---|
| §4 File structure — new/delete/keep | Task 1 (delete), Tasks 2-8 (create) |
| §5 Layout (header, chat, input) | Task 4 (Header, ChatInput), Task 7 (ChatArea), Task 8 (App layout) |
| §6 Color palette | Task 1 (tailwind.config.js + index.css) |
| §7 Typography | Task 1 (tailwind.config.js mono font) |
| §8 Message model | Task 8 (App.jsx reducer) |
| §9 Message visuals | Tasks 4-5 (AiMessage, UserMessage, ScanProgress, ScanCard) |
| §10 Header | Task 4 |
| §11 Opening state (greeting) | Task 8 (init useEffect) |
| §12 Chat flow (dual WS timing) | Task 8 (handleChatEvent) |
| §13 Scan flow (useScan) | Task 3 |
| §14 Session drawer + history mapping | Task 6 (drawer), Task 8 (handleSelectSession) |
| §15 Settings modal | Task 6 |
| §16 Backend contract | No backend changes needed |
| §17 localStorage persistence | Task 6 (SettingsModal) |
| §18 Testing (useChat + ScanCard) | Tasks 2, 5 |
| §19 Tailwind config | Task 1 |
