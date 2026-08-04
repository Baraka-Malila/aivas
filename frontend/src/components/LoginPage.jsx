import { useState, useEffect } from 'react'
import logo from '../assets/logo.png'

const MONO = { fontFamily: '"Fira Code", monospace' }

const inp = {
  background: '#1a1a1a',
  border: '1px solid #3a3a3a',
  color: '#e0e0e0',
  borderRadius: 4,
  width: '100%',
  padding: '10px 14px',
  fontSize: 14,
  outline: 'none',
  boxSizing: 'border-box',
  fontFamily: 'inherit',
}

function StatLedger({ stats, loading }) {
  const rows = [
    { label: 'CVE DATABASE', value: loading ? '—' : (stats?.cve_count != null ? stats.cve_count.toLocaleString() + ' entries' : '—') },
    { label: 'KEV CATALOG',  value: loading ? '—' : (stats?.kev_count != null ? stats.kev_count.toLocaleString() + ' exploited' : '—') },
    { label: 'LAST NVD SYNC', value: loading ? '—' : (stats?.last_sync ?? '—') },
    { label: 'ENGINE',        value: loading ? '—' : (stats?.engine ?? 'nmap · NIST NVD') },
  ]
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {rows.map((r, i) => (
        <div
          key={r.label}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            borderTop: '1px solid #222',
            borderBottom: i === rows.length - 1 ? '1px solid #222' : 'none',
            padding: '10px 0',
          }}
        >
          <span style={{ ...MONO, fontSize: 10, color: '#888', letterSpacing: '0.08em' }}>{r.label}</span>
          <span style={{ ...MONO, fontSize: 12, color: '#a8a8a8' }}>{r.value}</span>
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
          width: 'clamp(360px, 36%, 520px)',
          flexShrink: 0,
          background: '#0d0d0d',
          borderRight: '1px solid #2a2a2a',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: 40,
        }}
        className="hidden md:flex"
      >
        {/* Top: logo + description */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <img src={logo} alt="AIVAS" style={{ height: 36, width: 36, objectFit: 'contain' }} />
            <span style={{ color: '#e0e0e0', fontWeight: 700, fontSize: 20, letterSpacing: '-0.3px' }}>AIVAS</span>
          </div>
          <p style={{ color: '#999', fontSize: 13, lineHeight: 1.6, marginTop: 14, maxWidth: 280 }}>
            AI-Assisted Network Vulnerability Assessment System
          </p>
        </div>

        {/* Middle: stat ledger */}
        <StatLedger stats={stats} loading={statsLoading} />

        {/* Bottom: version + GitHub */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ ...MONO, color: '#666', fontSize: 11 }}>v{stats?.version ?? '1.2.0'} · Authorized use only.</span>
          <a
            href="https://github.com/Baraka-Malila/aivas"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#666', display: 'flex' }}
            onMouseEnter={e => e.currentTarget.style.color = '#e0e0e0'}
            onMouseLeave={e => e.currentTarget.style.color = '#666'}
            aria-label="GitHub"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.55 0-.27-.01-1.17-.02-2.12-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.68-1.28-1.68-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.19 1.76 1.19 1.03 1.76 2.69 1.25 3.35.96.1-.75.4-1.25.72-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.78 0c2.2-1.49 3.16-1.18 3.16-1.18.63 1.59.24 2.76.12 3.05.74.81 1.18 1.83 1.18 3.09 0 4.42-2.69 5.39-5.26 5.68.41.35.78 1.05.78 2.12 0 1.53-.01 2.76-.01 3.14 0 .3.2.67.8.55A11.51 11.51 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5z"/>
            </svg>
          </a>
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

          <div style={{ marginBottom: 24 }}>
            <h2 style={{ color: '#e0e0e0', fontWeight: 600, fontSize: 18, margin: '0 0 4px 0' }}>
              {mode === 'login' ? 'Sign in' : 'Create account'}
            </h2>
            <p style={{ color: '#888', fontSize: 12, margin: 0 }}>
              {mode === 'login' ? 'Enter your credentials to continue' : 'Set up your AIVAS account'}
            </p>
          </div>

          <form onSubmit={submit}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <label style={{ color: '#999', fontSize: 11, letterSpacing: '0.06em', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                  Username
                </label>
                <input
                  style={inp}
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  autoComplete="username"
                  required
                  onFocus={e => e.target.style.borderColor = '#4a9eff'}
                  onBlur={e => e.target.style.borderColor = '#3a3a3a'}
                />
              </div>
              <div>
                <label style={{ color: '#999', fontSize: 11, letterSpacing: '0.06em', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                  Password
                </label>
                <input
                  style={inp}
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  required
                  onFocus={e => e.target.style.borderColor = '#4a9eff'}
                  onBlur={e => e.target.style.borderColor = '#3a3a3a'}
                />
              </div>
            </div>

            {error && (
              <div style={{ background: '#200a0a', border: '1px solid #4a1010', color: '#ef5350', borderRadius: 4, padding: '8px 12px', fontSize: 12, marginTop: 14 }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{ background: '#4a9eff', color: '#000000', fontWeight: 600, borderRadius: 4, width: '100%', padding: 11, fontSize: 14, border: 'none', cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.6 : 1, marginTop: 16, fontFamily: 'inherit' }}
              onMouseEnter={e => { if (!loading) e.currentTarget.style.background = '#6cb0ff' }}
              onMouseLeave={e => e.currentTarget.style.background = '#4a9eff'}
            >
              {loading ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
            </button>
          </form>

          <div style={{ borderTop: '1px solid #3a3a3a', marginTop: 24, paddingTop: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#888', fontSize: 12 }}>
              {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
            </span>
            <button
              onClick={() => { setMode(m => m === 'login' ? 'register' : 'login'); setError('') }}
              style={{ color: '#4a9eff', fontSize: 12, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
              onMouseEnter={e => e.currentTarget.style.color = '#7db8ff'}
              onMouseLeave={e => e.currentTarget.style.color = '#4a9eff'}
            >
              {mode === 'login' ? 'Register' : 'Sign in'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
