import { useReducer, useEffect, useRef, useState, useCallback } from 'react'
import Header from './components/Header'
import ChatArea from './components/ChatArea'
import ChatInput from './components/ChatInput'
import SessionDrawer from './components/SessionDrawer'
import SettingsModal from './components/SettingsModal'
import LoginPage from './components/LoginPage'
import AdminPanel from './components/AdminPanel'
import ReportsView from './components/ReportsView'
import { useAuth } from './hooks/useAuth'
import { useChat } from './hooks/useChat'
import { useScan } from './hooks/useScan'
import { useSessions } from './hooks/useSessions'
import {
  uid, reducer, mapHistory, countSeverities, daysAgo, FIRST_VISIT_MSG,
} from './lib/messageReducer'

export default function App() {
  const { user, token, loading: authLoading, onAuth, logout } = useAuth()
  if (authLoading) return null
  if (!user) return <LoginPage onAuth={onAuth} />
  return <AuthenticatedApp user={user} token={token} logout={logout} />
}

function AuthenticatedApp({ user, token, logout }) {
  const [messages, dispatch] = useReducer(reducer, [])
  const [sessionId, setSessionId] = useState(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsSection, setSettingsSection] = useState('general')
  const [adminOpen, setAdminOpen] = useState(false)
  const [activeTab, setActiveTab] = useState('console')

  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {}
  const authFetch = (url, opts = {}) => fetch(url, {
    ...opts,
    headers: { ...(opts.headers || {}), ...authHeaders },
  })

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

    if (doneEvent.type === 'error' || (doneEvent.type === 'stopped' && !doneEvent.scan_id)) {
      if (scanningIdRef.current) {
        const status = doneEvent.type === 'stopped' ? 'stopped' : 'failed'
        const text = doneEvent.type === 'stopped'
          ? "Scan stopped. What would you like to do — scan a different target, review the last results, or something else?"
          : `**Scan failed:** ${doneEvent.text || 'Unknown error. Check the target and try again.'}`
        // Keep scan-progress visible (with log) by marking it done instead of replacing it
        dispatch({ type: 'MARK_SCAN_DONE', id: scanningIdRef.current, status })
        dispatch({ type: 'APPEND', msg: { id: uid(), type: 'ai', text } })
        scanningIdRef.current = null
      }
      return
    }

    let findings = doneEvent.findings || []
    try {
      const res = await authFetch(`/api/scan/${doneEvent.scan_id}`)
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
      log:           doneEvent.log || [],
      misconfigs:    doneEvent.misconfigs || [],
      partial:       doneEvent.type === 'partial_done',
    }

    if (scanningIdRef.current) {
      // Keep scan-progress visible (collapsed) then append the scan-card below it
      dispatch({ type: 'MARK_SCAN_DONE', id: scanningIdRef.current, status: 'complete' })
      dispatch({ type: 'APPEND', msg: { id: uid(), type: 'scan-card', scanData } })
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
        dispatch({ type: 'ERROR_MESSAGE', id: thinkingIdRef.current, text: `Error: ${event.text}` })
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
  const storedLang = localStorage.getItem('aivas_lang') || 'auto'

  const { send, status: chatStatus } = useChat({
    sessionId,
    onEvent: handleChatEvent,
    provider: storedProvider,
    model: storedModel,
    apiKey: storedKey,
    shodanKey: storedShodan,
    lang: storedLang,
  })
  const { start: startScan, stop: stopScan } = useScan(handleScanProgress, handleScanDone)
  const { sessions, refresh: refreshSessions, deleteSession, renameSession } = useSessions(token)

  // Wire refs after hooks resolve
  useEffect(() => { startScanRef.current = startScan }, [startScan])
  useEffect(() => { refreshSessRef.current = refreshSessions }, [refreshSessions])

  // --- Mount: create session + opening greeting ---

  useEffect(() => {
    async function init() {
      try {
        const { id } = await authFetch('/api/sessions', { method: 'POST' }).then(r => r.json())
        setSessionId(id)
      } catch (_) {}
      refreshSessions()

      let text = FIRST_VISIT_MSG
      try {
        const history = await authFetch('/api/history?limit=1').then(r => r.json())
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

  const handleDirectScan = useCallback(async (target, creds) => {
    try {
      const resp = await authFetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, level: 2, creds }),
      })
      const { scan_key } = await resp.json()
      scanPendingRef.current = true
      const slotId = uid()
      scanningIdRef.current = slotId
      dispatch({ type: 'APPEND', msg: { id: slotId, type: 'scan-progress', log: ['Initializing credentialed scan…'] } })
      startScan(scan_key, target)
    } catch (err) {
      dispatch({ type: 'APPEND', msg: { id: uid(), type: 'ai', text: `Failed to start scan: ${err.message}` } })
    }
  }, [startScan])

  const handleAnalysis = useCallback(async (type, scanId) => {
    const msgId = uid()
    dispatch({ type: 'APPEND', msg: { id: msgId, type: 'ai', text: '', streaming: true } })

    const provider = localStorage.getItem('aivas_provider') || 'groq'
    const model    = localStorage.getItem('aivas_model')    || undefined
    const apiKey   = localStorage.getItem('aivas_api_key')  || undefined
    const lang     = localStorage.getItem('aivas_lang')     || 'auto'

    let accText = ''
    try {
      const resp = await fetch(`/api/analyze/${scanId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, provider, model, api_key: apiKey, lang }),
      })
      if (!resp.ok) {
        dispatch({ type: 'ERROR_MESSAGE', id: msgId, text: `Analysis request failed (${resp.status})` })
        return
      }
      const reader  = resp.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop()
        for (const line of lines) {
          if (!line.trim()) continue
          try {
            const ev = JSON.parse(line)
            if (ev.type === 'tool_call') {
              dispatch({ type: 'TOOL_CALL', id: msgId, name: ev.name, args: ev.args })
            } else if (ev.type === 'tool_result') {
              dispatch({ type: 'TOOL_RESULT', id: msgId, name: ev.name, summary: ev.summary })
            } else if (ev.type === 'token') {
              accText += ev.text
              dispatch({ type: 'UPDATE_TEXT', id: msgId, text: accText })
            } else if (ev.type === 'error') {
              dispatch({ type: 'ERROR_MESSAGE', id: msgId, text: ev.text })
            }
          } catch (_) {}
        }
      }
    } catch (err) {
      dispatch({ type: 'ERROR_MESSAGE', id: msgId, text: `Analysis error: ${err.message}` })
    }
    dispatch({ type: 'SET_STREAMING', id: msgId, streaming: false })
  }, [dispatch])

  const handleSelectSession = useCallback(async (id) => {
    thinkingIdRef.current = null
    scanningIdRef.current = null
    scanPendingRef.current = false
    try {
      const msgs = await authFetch(`/api/sessions/${id}/messages`).then(r => r.json())
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
      const { id } = await authFetch('/api/sessions', { method: 'POST' }).then(r => r.json())
      setSessionId(id)
    } catch (_) {}
    dispatch({ type: 'SET_MESSAGES', messages: [{ id: uid(), type: 'ai', text: FIRST_VISIT_MSG }] })
    refreshSessions()
  }, [refreshSessions])

  // --- Render ---

  const handleTabChange = useCallback((tab) => {
    if (tab === 'history') {
      setActiveTab('history')
      setDrawerOpen(true)
      refreshSessions()
    } else if (tab === 'targets') {
      setActiveTab('targets')
      setSettingsSection('targets')
      setSettingsOpen(true)
    } else {
      setActiveTab(tab)
    }
  }, [refreshSessions])

  return (
    <div style={{ background: '#0a0a0a' }} className="flex flex-col h-screen">
      <Header
        activeTab={activeTab}
        onTabChange={handleTabChange}
        onSettings={() => setSettingsOpen(true)}
        onAdmin={() => setAdminOpen(true)}
        user={user}
        onLogout={logout}
      />
      {activeTab === 'reports' ? (
        <ReportsView token={token} />
      ) : (
        <>
          <ChatArea messages={messages} onSend={handleSend} onAnalysis={handleAnalysis} onStopScan={stopScan} />
          <ChatInput onSend={handleSend} disabled={chatStatus !== 'open'} />
        </>
      )}
      <SessionDrawer
        open={drawerOpen}
        sessions={sessions}
        onClose={() => { setDrawerOpen(false); setActiveTab('console') }}
        onSelect={handleSelectSession}
        onDelete={deleteSession}
        onRename={renameSession}
        onNew={() => { handleNewConversation(); setDrawerOpen(false); setActiveTab('console') }}
      />
      <SettingsModal
        open={settingsOpen}
        initialSection={settingsSection}
        onClose={() => { setSettingsOpen(false); if (activeTab === 'targets') setActiveTab('console') }}
        onScan={handleDirectScan}
      />
      <AdminPanel
        open={adminOpen}
        onClose={() => setAdminOpen(false)}
        token={token}
      />
    </div>
  )
}
