import { useEffect, useState } from 'react'
import { X } from 'lucide-react'

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
        style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 10, width: '100%', maxWidth: 520 }}
      >
        {/* Header */}
        <div
          style={{ borderBottom: '1px solid #1e1e1e' }}
          className="flex items-center justify-between px-5 py-3.5"
        >
          <div>
            <div style={{ color: '#e0e0e0', fontWeight: 600, fontSize: 14 }}>User Management</div>
            <div style={{ color: '#555', fontSize: 12, marginTop: 1 }}>{users.length} account{users.length !== 1 ? 's' : ''}</div>
          </div>
          <button
            onClick={onClose}
            style={{ color: '#666' }}
            className="p-1.5 hover:text-white transition-colors rounded"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="p-5">
          {loading && (
            <div style={{ color: '#555', fontSize: 13 }} className="text-center py-6">Loading…</div>
          )}
          {error && (
            <div style={{ color: '#ef5350', fontSize: 13 }} className="text-center py-6">{error}</div>
          )}
          {!loading && !error && users.length === 0 && (
            <div style={{ color: '#555', fontSize: 13 }} className="text-center py-6">No users found</div>
          )}
          {!loading && !error && users.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1a1a1a' }}>
                  <th style={{ color: '#555', fontSize: 11, fontWeight: 500, textAlign: 'left', padding: '0 0 8px 0' }}>Username</th>
                  <th style={{ color: '#555', fontSize: 11, fontWeight: 500, textAlign: 'left', padding: '0 0 8px 16px' }}>Role</th>
                  <th style={{ color: '#555', fontSize: 11, fontWeight: 500, textAlign: 'right', padding: '0 0 8px 0' }}>ID</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr
                    key={u.id}
                    style={{ borderBottom: '1px solid #141414' }}
                  >
                    <td style={{ color: '#e0e0e0', fontSize: 13, padding: '9px 0' }}>{u.username}</td>
                    <td style={{ padding: '9px 0 9px 16px' }}>
                      {u.role === 'admin' ? (
                        <span style={{ background: '#4a9eff18', color: '#4a9eff', borderRadius: 4, fontSize: 10, padding: '2px 6px', fontWeight: 600 }}>
                          ADMIN
                        </span>
                      ) : (
                        <span style={{ color: '#555', fontSize: 12 }}>user</span>
                      )}
                    </td>
                    <td style={{ color: '#444', fontSize: 11, fontFamily: 'monospace', textAlign: 'right', padding: '9px 0' }}>
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
