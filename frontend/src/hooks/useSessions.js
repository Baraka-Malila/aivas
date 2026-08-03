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

  const renameSession = useCallback(async (id, title) => {
    try {
      await fetch(`/api/sessions/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title }),
      })
    } catch {}
    setSessions(prev => prev.map(s => s.id === id ? { ...s, title } : s))
  }, [])

  return { sessions, refresh, deleteSession, renameSession }
}
