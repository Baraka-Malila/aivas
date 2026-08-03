import { useRef, useCallback, useState, useEffect } from 'react'

export function useScan(onProgress, onDone) {
  const onProgressRef = useRef(onProgress)
  const onDoneRef = useRef(onDone)
  useEffect(() => {
    onProgressRef.current = onProgress
    onDoneRef.current = onDone
  })

  const wsRef = useRef(null)
  const logRef = useRef([])
  const [isScanning, setIsScanning] = useState(false)

  const stop = useCallback(() => {
    if (wsRef.current) {
      const ws = wsRef.current
      wsRef.current = null
      // Send a graceful stop so the server can save partial results,
      // then wait for partial_done or close on the same socket.
      const finalize = (msg) => {
        ws.onmessage = null
        ws.onerror = null
        ws.onclose = null
        ws.close()
        setIsScanning(false)
        onDoneRef.current(msg)
      }
      try {
        ws.onmessage = (e) => {
          let msg
          try { msg = JSON.parse(e.data) } catch { return }
          if (msg.type === 'partial_done') {
            finalize({ ...msg, log: logRef.current })
          }
        }
        ws.onerror = () => finalize({ type: 'stopped', log: logRef.current })
        ws.onclose = () => finalize({ type: 'stopped', log: logRef.current })
        ws.send(JSON.stringify({ type: 'stop' }))
        // Fallback: if server doesn't respond within 3s, treat as stopped
        setTimeout(() => finalize({ type: 'stopped', log: logRef.current }), 3000)
      } catch {
        finalize({ type: 'stopped', log: logRef.current })
      }
    } else {
      setIsScanning(false)
      onDoneRef.current({ type: 'stopped', log: logRef.current })
    }
  }, [])

  const start = useCallback((scanKey) => {
    if (wsRef.current) {
      wsRef.current.onmessage = null
      wsRef.current.onerror = null
      wsRef.current.onclose = null
      wsRef.current.close()
    }
    logRef.current = []
    setIsScanning(true)
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/scan/${scanKey}`)
    ws.onmessage = (e) => {
      let msg
      try { msg = JSON.parse(e.data) } catch { return }
      if (msg.text) {
        logRef.current = [...logRef.current, msg.text]
        if (msg.type !== 'done') {
          onProgressRef.current(msg.text)
        }
      }
      if (msg.type === 'done' || msg.type === 'partial_done') {
        setIsScanning(false)
        onDoneRef.current({ ...msg, log: logRef.current })
        ws.close()
      } else if (msg.type === 'error') {
        setIsScanning(false)
        onDoneRef.current({ type: 'error', text: msg.text, log: logRef.current })
        ws.close()
      }
    }
    ws.onerror = () => {
      ws.onerror = null
      setIsScanning(false)
      onDoneRef.current({
        type: 'error',
        text: 'Connection to scan service lost. Check that the server is running and try again.',
        log: logRef.current,
      })
    }
    wsRef.current = ws
  }, [])

  return { isScanning, start, stop }
}
