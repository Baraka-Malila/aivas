import { useEffect, useRef, useCallback, useState } from 'react'

export function useChat({ sessionId, onEvent, provider = 'groq', model, apiKey, mistralKey, shodanKey, lang }) {
  const onEventRef = useRef(onEvent)
  useEffect(() => { onEventRef.current = onEvent })

  const wsRef = useRef(null)
  const [status, setStatus] = useState('idle')

  // Keep latest auth values in a ref so the onopen closure always sends current values
  const authRef = useRef({ apiKey, mistralKey, shodanKey, lang })
  useEffect(() => { authRef.current = { apiKey, mistralKey, shodanKey, lang } }, [apiKey, mistralKey, shodanKey, lang])

  useEffect(() => {
    if (!sessionId) return
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const params = new URLSearchParams({ provider })
    if (model) params.set('model', model)
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/chat/${sessionId}?${params}`)
    ws.onopen = () => {
      setStatus('open')
      const { apiKey: ak, mistralKey: mk, shodanKey: sk, lang: lg } = authRef.current
      const auth = { type: 'auth' }
      if (ak) auth.api_key = ak
      if (mk) auth.mistral_key = mk
      if (sk) auth.shodan_key = sk
      if (lg) auth.lang = lg
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
