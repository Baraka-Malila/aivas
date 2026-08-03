import { useState, useCallback, useEffect } from 'react'

export function useAuth() {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(() => localStorage.getItem('aivas_token') || null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!token) { setLoading(false); return }
    fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } })
      .then(r => { if (!r.ok) throw new Error(); return r.json() })
      .then(data => { setUser(data); setLoading(false) })
      .catch(() => {
        localStorage.removeItem('aivas_token')
        setToken(null)
        setUser(null)
        setLoading(false)
      })
  }, [token])

  const onAuth = useCallback((u, t) => {
    setUser(u)
    setToken(t)
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem('aivas_token')
    setToken(null)
    setUser(null)
  }, [])

  return { user, token, loading, onAuth, logout }
}
