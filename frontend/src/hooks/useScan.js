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
      if (msg.text) logRef.current = [...logRef.current, msg.text]
      if (msg.type === 'phase_header') {
        onProgressRef.current(msg.text || '')
      } else if (msg.type === 'done') {
        setIsScanning(false)
        onDoneRef.current({ ...msg, log: logRef.current })
        ws.close()
      } else if (msg.type === 'error') {
        setIsScanning(false)
        ws.close()
      }
    }
    ws.onerror = () => { ws.onerror = null; setIsScanning(false) }
    wsRef.current = ws
  }, [])

  return { isScanning, start }
}
