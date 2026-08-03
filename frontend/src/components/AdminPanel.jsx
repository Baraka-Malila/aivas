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
        style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 8, width: '100%', maxWidth: 480, overflow: 'hidden' }}
      >
        {/* Header */}
        <div style={{ borderBottom: '1px solid #1e1e1e', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px' }}>
          <div>
            <div style={{ color: '#e0e0e0', fontSize: 13, fontWeight: 600 }}>User Management</div>
            <div style={{ ...MONO, color: '#444', fontSize: 10, marginTop: 2 }}>
              {users.length} account{users.length !== 1 ? 's' : ''}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ color: '#444', background: 'none', border: 'none', cursor: 'pointer', padding: 6, borderRadius: 3 }}
            onMouseEnter={e => e.currentTarget.style.color = '#e0e0e0'}
            onMouseLeave={e => e.currentTarget.style.color = '#444'}
          >
            <X size={14} />
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
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: '#0d0d0d', borderBottom: '1px solid #1a1a1a' }}>
                  <th style={{ ...MONO, color: '#444', fontSize: 10, fontWeight: 400, letterSpacing: '0.08em', textAlign: 'left', padding: '7px 16px', textTransform: 'uppercase' }}>Username</th>
                  <th style={{ ...MONO, color: '#444', fontSize: 10, fontWeight: 400, letterSpacing: '0.08em', textAlign: 'left', padding: '7px 12px', textTransform: 'uppercase' }}>Role</th>
                  <th style={{ ...MONO, color: '#444', fontSize: 10, fontWeight: 400, letterSpacing: '0.08em', textAlign: 'right', padding: '7px 16px', textTransform: 'uppercase' }}>ID</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} style={{ borderBottom: '1px solid #141414' }}>
                    <td style={{ ...MONO, color: '#e0e0e0', fontSize: 12, padding: '10px 16px' }}>{u.username}</td>
                    <td style={{ padding: '10px 12px' }}>
                      {u.role === 'admin' ? (
                        <span style={{ ...MONO, color: '#4a9eff', fontSize: 10, letterSpacing: '0.06em' }}>ADMIN</span>
                      ) : (
                        <span style={{ ...MONO, color: '#444', fontSize: 11 }}>user</span>
                      )}
                    </td>
                    <td style={{ ...MONO, color: '#333', fontSize: 11, textAlign: 'right', padding: '10px 16px' }}>
                      #{u.id}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
