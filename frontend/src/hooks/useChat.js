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
