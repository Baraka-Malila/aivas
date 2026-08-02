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
  const thinkingIdRef    = useRef(null)
  const streamingTextRef = useRef('')
  const scanningIdRef    = useRef(null)
  const scanPendingRef   = useRef(false)
  const startScanRef     = useRef(null)
  const refreshSessRef   = useRef(null)

  // --- Scan callbacks (stable refs) ---

  const handleScanProgress = useCallback((entry) => {
    if (scanningIdRef.current) {
      dispatch({ type: 'UPDATE_LOG', id: scanningIdRef.current, entry })
    }
  }, [])

  const handleScanDone = useCallback(async (doneEvent) => {
    scanPendingRef.current = false

    if (doneEvent.type === 'error' || doneEvent.type === 'stopped') {
      if (scanningIdRef.current) {
        const text = doneEvent.type === 'stopped'
          ? "Scan stopped. What would you like to do — scan a different target, review the last results, or something else?"
          : `**Scan failed:** ${doneEvent.text || 'Unknown error. Check the target and try again.'}`
        dispatch({
          type: 'REPLACE',
          id: scanningIdRef.current,
          msg: { id: scanningIdRef.current, type: 'ai', text },
        })
        scanningIdRef.current = null
      }
      return
    }

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
    if (event.type === 'thinking') {
      const id = uid()
      thinkingIdRef.current = id
      streamingTextRef.current = ''
      dispatch({ type: 'APPEND', msg: { id, type: 'ai', text: '', streaming: true } })

    } else if (event.type === 'token') {
      if (!thinkingIdRef.current) return
      streamingTextRef.current += event.text
      dispatch({ type: 'UPDATE_TEXT', id: thinkingIdRef.current, text: streamingTextRef.current })

    } else if (event.type === 'done') {
      if (thinkingIdRef.current) {
        dispatch({ type: 'SET_STREAMING', id: thinkingIdRef.current, streaming: false })
        thinkingIdRef.current = null
        streamingTextRef.current = ''
      }

    } else if (event.type === 'scan_triggered') {
      scanPendingRef.current = true
      const slotId = uid()
      scanningIdRef.current = slotId
      dispatch({ type: 'APPEND', msg: { id: slotId, type: 'scan-progress', log: ['Initializing scan…'] } })
      if (startScanRef.current) startScanRef.current(event.scan_key, event.target)

    } else if (event.type === 'error') {
      if (thinkingIdRef.current) {
        dispatch({
          type: 'REPLACE',
          id: thinkingIdRef.current,
          msg: { id: thinkingIdRef.current, type: 'ai', text: `Error: ${event.text}` },
        })
        thinkingIdRef.current = null
        streamingTextRef.current = ''
      }
      if (scanningIdRef.current) {
        dispatch({ type: 'REMOVE', id: scanningIdRef.current })
        scanningIdRef.current = null
      }

    } else if (event.type === 'tool_call') {
      if (thinkingIdRef.current) {
        dispatch({ type: 'TOOL_CALL', id: thinkingIdRef.current, name: event.name, args: event.args })
      }

    } else if (event.type === 'tool_result') {
      if (thinkingIdRef.current) {
        dispatch({ type: 'TOOL_RESULT', id: thinkingIdRef.current, name: event.name, summary: event.summary })
      }
    }
  }, [])

  // --- Hooks ---

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
  const { start: startScan, stop: stopScan } = useScan(handleScanProgress, handleScanDone)
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
          const critical = scan.critical_count ?? 0
          const kev = scan.kev_count ?? 0
          text =
            `Welcome back. Your last scan of ${scan.target} was ${days} day${days !== 1 ? 's' : ''} ago` +
            ` — Grade ${grade}, ${scan.finding_count ?? 0} findings` +
            (critical > 0 ? `, ${critical} critical` : '') +
            (kev > 0 ? `, ${kev} actively exploited` : '') +
            `. Want me to rescan, or would you like a summary?`
        }
      } catch (_) {}

      dispatch({ type: 'APPEND', msg: { id: uid(), type: 'ai', text } })
    }
    init()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // --- User actions ---

  const handleSend = useCallback((text) => {
    scanPendingRef.current = false
    dispatch({ type: 'APPEND', msg: { id: uid(), type: 'user', text } })
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
      <ChatArea messages={messages} onSend={handleSend} onStopScan={stopScan} />
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
