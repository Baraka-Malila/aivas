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
