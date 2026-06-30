// frontend/src/hooks/useWebSocket.js
import { useState, useCallback, useRef } from 'react'

export function useWebSocket({ onScanComplete } = {}) {
  const [status, setStatus] = useState('idle')
  const [progressLines, setProgressLines] = useState([])
  const [result, setResult] = useState(null)
  const [errorMsg, setErrorMsg] = useState('')
  const wsRef = useRef(null)

  const startScan = useCallback(async (target, level) => {
    if (status === 'scanning') return
    setStatus('scanning')
    setProgressLines([])
    setResult(null)
    setErrorMsg('')

    let scanKey
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, level }),
      })
      scanKey = (await res.json()).scan_key
    } catch (e) {
      setStatus('error')
      setErrorMsg('Failed to start scan: ' + e.message)
      return
    }

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/ws/scan/${scanKey}`)
    wsRef.current = ws

    ws.onmessage = (e) => {
      const ev = JSON.parse(e.data)
      if (ev.type === 'done') {
        setResult(ev)
        setStatus('done')
        onScanComplete?.()
        ws.close()
      } else if (ev.type === 'error') {
        setErrorMsg(ev.text || 'Scan error')
        setStatus('error')
        ws.close()
      } else if (ev.type === 'progress') {
        setProgressLines(prev => [...prev, ev])
      }
    }
    ws.onerror = () => {
      setErrorMsg('WebSocket connection failed')
      setStatus('error')
    }
  }, [status, onScanComplete])

  const reset = useCallback(() => {
    wsRef.current?.close()
    setStatus('idle')
    setProgressLines([])
    setResult(null)
    setErrorMsg('')
  }, [])

  return {
    status,
    progressLines,
    result,
    errorMsg,
    startScan,
    reset,
    isScanning: status === 'scanning',
    isDone: status === 'done',
  }
}
