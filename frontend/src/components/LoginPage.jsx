import { useState, useEffect } from 'react'
import logo from '../assets/logo.png'

const MONO = { fontFamily: '"Fira Code", monospace' }

const inp = {
  background: '#0a0a0a',
  border: '1px solid #252525',
  color: '#e0e0e0',
  borderRadius: 4,
  width: '100%',
  padding: '9px 12px',
  fontSize: 13,
  outline: 'none',
  ...MONO,
}

const STAT_LABEL = {
  ...MONO,
  fontSize: 10,
  letterSpacing: '0.1em',
  color: '#555',
  textTransform: 'uppercase',
}

const STAT_VALUE = {
  ...MONO,
  fontSize: 13,
  color: '#e0e0e0',
}

function StatLedger({ stats, loading }) {
  const rows = [
    { label: 'CVE DATABASE', value: loading ? '—' : stats?.cve_count?.toLocaleString() ?? '—', suffix: ' entries' },
    { label: 'KEV CATALOG',  value: loading ? '—' : stats?.kev_count?.toLocaleString() ?? '—', suffix: ' CVEs' },
    { label: 'LAST SYNC',    value: loading ? '—' : stats?.last_sync ?? '—', suffix: '' },
    { label: 'ENGINE',       value: loading ? '—' : stats?.engine ?? 'Nmap · NIST NVD', suffix: '' },
  ]
  return (
    <div style={{ marginTop: 40 }}>
      {rows.map((r, i) => (
        <div
          key={r.label}
          style={{
            borderTop: i === 0 ? '1px solid #1e1e1e' : 'none',
            borderBottom: '1px solid #1e1e1e',
            padding: '10px 0',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'baseline',
            gap: 12,
          }}
        >
          <span style={STAT_LABEL}>{r.label}</span>
          <span style={STAT_VALUE}>{r.value}<span style={{ color: '#555', fontSize: 11 }}>{r.suffix}</span></span>
        </div>
      ))}
    </div>
  )
}

export default function LoginPage({ onAuth }) {
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [stats, setStats] = useState(null)
  const [statsLoading, setStatsLoading] = useState(true)

  useEffect(() => {
    fetch('/api/stats')
      .then(r => r.json())
      .then(setStats)
      .catch(() => {})
      .finally(() => setStatsLoading(false))
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const resp = await fetch(`/api/auth/${mode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      const data = await resp.json()
      if (!resp.ok) { setError(data.detail || 'Authentication failed'); return }
      localStorage.setItem('aivas_token', data.token)
      onAuth(data.user, data.token)
    } catch {
      setError('Server unreachable')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ background: '#0a0a0a', minHeight: '100vh', display: 'flex' }}>

      {/* Left brand panel */}
      <div
        style={{
          width: 420,
          flexShrink: 0,
          background: '#0d0d0d',
          borderRight: '1px solid #1e1e1e',
          display: 'flex',
          flexDirection: 'column',
          padding: '48px 40px',
        }}
        className="hidden md:flex"
      >
        {/* Logo + wordmark */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <img src={logo} alt="AIVAS" style={{ height: 36, width: 36, objectFit: 'contain' }} />
          <span style={{ color: '#e0e0e0', fontWeight: 700, fontSize: 22, letterSpacing: '-0.5px' }}>AIVAS</span>
        </div>
        <p style={{ color: '#555', fontSize: 13, marginTop: 12, lineHeight: 1.6 }}>
          AI Vulnerability Assessment System
        </p>

        <StatLedger stats={stats} loading={statsLoading} />

        <div style={{ marginTop: 'auto', paddingTop: 32 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ ...MONO, color: '#444', fontSize: 11 }}>v{stats?.version ?? '1.2.0'} · Authorized use only.</span>
            <a
              href="https://github.com/Baraka-Malila/aivas"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: '#444', display: 'flex', alignItems: 'center', marginLeft: 'auto' }}
              aria-label="GitHub"
            >
              <svg height="16" width="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
              </svg>
            </a>
          </div>
        </div>
      </div>

      {/* Right form panel */}
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <div style={{ width: '100%', maxWidth: 340 }}>

          {/* Mobile-only branding */}
          <div className="flex md:hidden items-center gap-3 mb-8">
            <img src={logo} alt="AIVAS" style={{ height: 28, width: 28 }} />
            <span style={{ color: '#e0e0e0', fontWeight: 700, fontSize: 18 }}>AIVAS</span>
          </div>

          <div style={{ marginBottom: 28 }}>
            <h2 style={{ color: '#e0e0e0', fontWeight: 600, fontSize: 18, marginBottom: 4 }}>
              {mode === 'login' ? 'Sign in' : 'Create account'}
            </h2>
            <p style={{ color: '#555', fontSize: 12 }}>
              {mode === 'login' ? 'Enter your credentials to continue' : 'Set up your AIVAS account'}
            </p>
          </div>

          <form onSubmit={submit}>
            <div style={{ marginBottom: 16 }}>
              <label style={{ ...MONO, fontSize: 10, letterSpacing: '0.1em', color: '#555', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                Username
              </label>
              <input
                style={inp}
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                autoComplete="username"
                required
              />
            </div>
            <div style={{ marginBottom: 20 }}>
              <label style={{ ...MONO, fontSize: 10, letterSpacing: '0.1em', color: '#555', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                Password
              </label>
              <input
                style={inp}
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                required
              />
            </div>

            {error && (
              <div style={{ background: '#200a0a', border: '1px solid #4a1010', color: '#ef5350', borderRadius: 4, padding: '8px 12px', fontSize: 12, marginBottom: 16 }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{ background: '#4a9eff', color: '#000', fontWeight: 600, borderRadius: 4, width: '100%', padding: '10px', fontSize: 13, border: 'none', cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.6 : 1 }}
            >
              {loading ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
            </button>
          </form>

          <div style={{ borderTop: '1px solid #1a1a1a', marginTop: 24, paddingTop: 20, textAlign: 'center' }}>
            <span style={{ color: '#555', fontSize: 12 }}>
              {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
            </span>
            <button
              onClick={() => { setMode(m => m === 'login' ? 'register' : 'login'); setError('') }}
              style={{ color: '#4a9eff', fontSize: 12, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            >
              {mode === 'login' ? 'Register' : 'Sign in'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
