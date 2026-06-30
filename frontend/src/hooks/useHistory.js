// frontend/src/hooks/useHistory.js
import { useState, useEffect, useCallback } from 'react'

export function useHistory() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(false)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const data = await fetch('/api/history?limit=20').then(r => r.json())
      setScans(Array.isArray(data) ? data : [])
    } catch {
      setScans([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  const deleteScan = useCallback(async (id) => {
    try {
      await fetch(`/api/scan/${id}`, { method: 'DELETE' })
      setScans(prev => prev.filter(s => s.id !== id))
    } catch { /* noop */ }
  }, [])

  return { scans, loading, refresh, deleteScan }
}
