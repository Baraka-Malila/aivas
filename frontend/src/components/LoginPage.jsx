import { useState } from 'react'
import logo from '../assets/logo.png'

const inp = {
  background: '#0f0f0f', border: '1px solid #252525', color: '#e0e0e0',
  borderRadius: 6, width: '100%', padding: '10px 14px', fontSize: 14, outline: 'none',
}

export default function LoginPage({ onAuth }) {
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

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
      if (!resp.ok) {
        setError(data.detail || 'Something went wrong')
        return
      }
      localStorage.setItem('aivas_token', data.token)
      onAuth(data.user, data.token)
    } catch {
      setError('Server unreachable')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{ background: '#0a0a0a', minHeight: '100vh' }}
      className="flex items-center justify-center p-4"
    >
      <div style={{ width: '100%', maxWidth: 360 }}>
        {/* Branding */}
        <div className="flex flex-col items-center mb-8">
          <img src={logo} alt="AIVAS" style={{ height: 56, width: 56, objectFit: 'contain', marginBottom: 16 }} />
          <span style={{ color: '#e0e0e0', fontWeight: 700, fontSize: 22, letterSpacing: '-0.5px' }}>AIVAS</span>
          <span style={{ color: '#444', fontSize: 13, marginTop: 2 }}>AI Vulnerability Assessment System</span>
        </div>

        {/* Card */}
        <div
          style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 10 }}
          className="p-6"
        >
          <h2 style={{ color: '#e0e0e0', fontWeight: 600, fontSize: 16, marginBottom: 2 }}>
            {mode === 'login' ? 'Sign in' : 'Create account'}
          </h2>
          <p style={{ color: '#555', fontSize: 12, marginBottom: 20 }}>
            {mode === 'login'
              ? 'Enter your credentials to continue'
              : 'Set up your AIVAS account'}
          </p>

          <form onSubmit={submit} className="space-y-3">
            <div>
              <label style={{ color: '#777', fontSize: 12, display: 'block', marginBottom: 4 }}>Username</label>
              <input
                style={inp}
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="your username"
                autoComplete="username"
                required
              />
            </div>
            <div>
              <label style={{ color: '#777', fontSize: 12, display: 'block', marginBottom: 4 }}>Password</label>
              <input
                style={inp}
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                required
              />
            </div>

            {error && (
              <div
                style={{ background: '#200a0a', border: '1px solid #4a1010', color: '#ef5350', borderRadius: 6 }}
                className="px-3 py-2 text-xs"
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{ background: '#4a9eff', color: '#000', fontWeight: 600, borderRadius: 6, width: '100%', padding: '10px', fontSize: 14, marginTop: 4 }}
              className="hover:opacity-90 transition-opacity disabled:opacity-50"
            >
              {loading ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
            </button>
          </form>

          <div style={{ borderTop: '1px solid #1a1a1a' }} className="mt-5 pt-4 text-center">
            <span style={{ color: '#555', fontSize: 12 }}>
              {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
            </span>
            <button
              onClick={() => { setMode(m => m === 'login' ? 'register' : 'login'); setError('') }}
              style={{ color: '#4a9eff', fontSize: 12 }}
              className="hover:opacity-80 transition-opacity"
            >
              {mode === 'login' ? 'Register' : 'Sign in'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
