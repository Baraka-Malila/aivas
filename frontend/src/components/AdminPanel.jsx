import { useEffect, useState } from 'react'
import { X } from 'lucide-react'

const MONO = { fontFamily: '"Fira Code", monospace' }

export default function AdminPanel({ open, onClose, token }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) return
    setLoading(true)
    setError('')
    fetch('/api/auth/users', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(data => setUsers(data))
      .catch(() => setError('Failed to load users'))
      .finally(() => setLoading(false))
  }, [open, token])

  if (!open) return null

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 50 }}
      className="flex items-center justify-center p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div
        style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 6, width: '100%', maxWidth: 560, overflow: 'hidden' }}
      >
        {/* Header */}
        <div style={{ borderBottom: '1px solid #1e1e1e', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px' }}>
          <div>
            <div style={{ color: '#e0e0e0', fontWeight: 600, fontSize: 14 }}>User Management</div>
            <div style={{ ...MONO, color: '#555555', fontSize: 11, marginTop: 2 }}>
              {users.length} account{users.length !== 1 ? 's' : ''}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ color: '#555555', background: 'none', border: 'none', cursor: 'pointer', padding: 4, borderRadius: 3, display: 'flex' }}
            onMouseEnter={e => e.currentTarget.style.color = '#e0e0e0'}
            onMouseLeave={e => e.currentTarget.style.color = '#555555'}
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div>
          {loading && (
            <div style={{ color: '#444', fontSize: 12, textAlign: 'center', padding: '32px 0' }}>Loading…</div>
          )}
          {error && (
            <div style={{ color: '#ef5350', fontSize: 12, textAlign: 'center', padding: '32px 0' }}>{error}</div>
          )}
          {!loading && !error && users.length === 0 && (
            <div style={{ color: '#444', fontSize: 12, textAlign: 'center', padding: '32px 0' }}>No users found</div>
          )}
          {!loading && !error && users.length > 0 && (
            <>
              {/* Column headers */}
              <div style={{ display: 'flex', padding: '8px 20px', background: '#0d0d0d', borderBottom: '1px solid #1e1e1e' }}>
                <span style={{ ...MONO, fontSize: 9, color: '#444444', letterSpacing: '0.1em', flex: 1 }}>USERNAME</span>
                <span style={{ ...MONO, fontSize: 9, color: '#444444', letterSpacing: '0.1em', width: 100 }}>ROLE</span>
                <span style={{ ...MONO, fontSize: 9, color: '#444444', letterSpacing: '0.1em', width: 56, textAlign: 'right' }}>ID</span>
              </div>
              {/* Rows */}
              {users.map((u, i) => (
                <div
                  key={u.id}
                  style={{ display: 'flex', alignItems: 'center', padding: '10px 20px', borderBottom: i < users.length - 1 ? '1px solid #141414' : 'none' }}
                >
                  <span style={{ color: '#e0e0e0', fontSize: 13, flex: 1 }}>{u.username}</span>
                  <span style={{ width: 100 }}>
                    {u.role === 'admin' ? (
                      <span style={{ ...MONO, color: '#4a9eff', fontSize: 10, letterSpacing: '0.08em' }}>ADMIN</span>
                    ) : (
                      <span style={{ color: '#555555', fontSize: 12 }}>user</span>
                    )}
                  </span>
                  <span style={{ ...MONO, color: '#555555', fontSize: 11, width: 56, textAlign: 'right' }}>#{u.id}</span>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
