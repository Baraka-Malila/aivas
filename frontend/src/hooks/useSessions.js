import { useState, useCallback } from 'react'

export function useSessions(token) {
  const [sessions, setSessions] = useState([])
  const authH = token ? { Authorization: `Bearer ${token}` } : {}

  const refresh = useCallback(async () => {
    try {
      const data = await fetch('/api/sessions', { headers: authH }).then(r => r.json())
      setSessions(Array.isArray(data) ? data : [])
    } catch {}
  }, [token])  // eslint-disable-line react-hooks/exhaustive-deps

  const deleteSession = useCallback(async (id) => {
    try {
      await fetch(`/api/sessions/${id}`, { method: 'DELETE', headers: authH })
    } catch {}
    setSessions(prev => prev.filter(s => s.id !== id))
  }, [token])  // eslint-disable-line react-hooks/exhaustive-deps

  const renameSession = useCallback(async (id, title) => {
    try {
      await fetch(`/api/sessions/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...authH },
        body: JSON.stringify({ title }),
      })
    } catch {}
    setSessions(prev => prev.map(s => s.id === id ? { ...s, title } : s))
  }, [token])  // eslint-disable-line react-hooks/exhaustive-deps

  return { sessions, refresh, deleteSession, renameSession }
}
