import { useReducer, useEffect, useRef, useState, useCallback } from 'react'
import Header from './components/Header'
import ChatArea from './components/ChatArea'
import ChatInput from './components/ChatInput'
import SessionDrawer from './components/SessionDrawer'
import SettingsModal from './components/SettingsModal'
import { useChat } from './hooks/useChat'
import { useScan } from './hooks/useScan'
import { useSessions } from './hooks/useSessions'
import {
  uid, reducer, mapHistory, countSeverities, daysAgo, FIRST_VISIT_MSG,
} from './lib/messageReducer'

export default function App() {
  const [messages, dispatch] = useReducer(reducer, [])
  const [sessionId, setSessionId] = useState(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  // Refs to break circular dep: handleChatEvent → startScan, and onDone → refresh
  const thinkingIdRef  = useRef(null)
  const scanningIdRef  = useRef(null)
  const scanPendingRef = useRef(false)
  const startScanRef   = useRef(null)
  const refreshSessRef = useRef(null)

  // --- Scan callbacks (stable refs) ---

  const handleScanProgress = useCallback((text) => {
    if (scanningIdRef.current) {
      dispatch({ type: 'UPDATE_TEXT', id: scanningIdRef.current, text })
    }
  }, [])

  const handleScanDone = useCallback(async (doneEvent) => {
    scanPendingRef.current = false
    let findings = doneEvent.findings || []
    try {
      const res = await fetch(`/api/scan/${doneEvent.scan_id}`)
      const enriched = await res.json()
      if (Array.isArray(enriched)) findings = enriched
    } catch (_) { /* keep original findings */ }

    const scanData = {
      scan_id:       doneEvent.scan_id,
      target:        doneEvent.target,
      grade:         doneEvent.grade,
      score:         doneEvent.score,
      service_count: doneEvent.service_count,
      findings,
      counts:        countSeverities(findings),
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

  // --- Chat event handler (uses startScanRef to avoid stale closure) ---

  const handleChatEvent = useCallback((event) => {
    if (event.type === 'scan_intent') {
      scanPendingRef.current = true
      dispatch({
        type: 'UPDATE_TEXT',
        id: thinkingIdRef.current,
        text: `Starting scan on ${event.target}…`,
      })
      startScanRef.current?.(event.scan_key)

    } else if (event.type === 'complete') {
      // Replace "Thinking…" slot with the AI's conversational reply
      dispatch({
        type: 'REPLACE',
        id: thinkingIdRef.current,
        msg: { id: thinkingIdRef.current, type: 'ai', text: event.text },
      })
      // If a scan was triggered, open a second slot for scan progress
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
      if (scanningIdRef.current) {
        dispatch({ type: 'REMOVE', id: scanningIdRef.current })
        scanningIdRef.current = null
      }
    }
  }, [])

  // --- Hooks ---

  const { send, status: chatStatus } = useChat(sessionId, handleChatEvent)
  const { start: startScan } = useScan(handleScanProgress, handleScanDone)
  const { sessions, refresh: refreshSessions, deleteSession } = useSessions()

  // Wire refs after hooks resolve
  useEffect(() => { startScanRef.current = startScan }, [startScan])
  useEffect(() => { refreshSessRef.current = refreshSessions }, [refreshSessions])

  // --- Mount: create session + opening greeting ---

  useEffect(() => {
    async function init() {
      try {
        const { id } = await fetch('/api/sessions', { method: 'POST' }).then(r => r.json())
        setSessionId(id)
      } catch (_) {}
      refreshSessions()

      let text = FIRST_VISIT_MSG
      try {
        const history = await fetch('/api/history?limit=1').then(r => r.json())
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
      } catch (_) {}

      dispatch({ type: 'APPEND', msg: { id: uid(), type: 'ai', text } })
    }
    init()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // --- User actions ---

  const handleSend = useCallback((text) => {
    const tid = uid()
    thinkingIdRef.current = tid
    scanPendingRef.current = false
    dispatch({ type: 'APPEND', msg: { id: uid(), type: 'user', text } })
    dispatch({ type: 'APPEND', msg: { id: tid, type: 'scan-progress', text: 'Thinking…' } })
    send(text)
  }, [send])

  const handleSelectSession = useCallback(async (id) => {
    thinkingIdRef.current = null
    scanningIdRef.current = null
    scanPendingRef.current = false
    try {
      const msgs = await fetch(`/api/sessions/${id}/messages`).then(r => r.json())
      dispatch({ type: 'SET_MESSAGES', messages: mapHistory(msgs) })
    } catch (_) {
      dispatch({ type: 'SET_MESSAGES', messages: [] })
    }
    setSessionId(id)
  }, [])

  const handleNewConversation = useCallback(async () => {
    thinkingIdRef.current = null
    scanningIdRef.current = null
    scanPendingRef.current = false
    try {
      const { id } = await fetch('/api/sessions', { method: 'POST' }).then(r => r.json())
      setSessionId(id)
    } catch (_) {}
    dispatch({ type: 'SET_MESSAGES', messages: [{ id: uid(), type: 'ai', text: FIRST_VISIT_MSG }] })
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
      <ChatInput onSend={handleSend} disabled={chatStatus !== 'open'} />
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
