import { useState, useEffect } from 'react'
import { X } from 'lucide-react'

const LANGS = [
  { value: 'auto', label: 'Auto' },
  { value: 'en',   label: 'English' },
  { value: 'sw',   label: 'Swahili' },
]

const PROVIDERS = [
  { value: 'groq',   label: 'Groq (online)' },
  { value: 'claude', label: 'Claude (Anthropic)' },
  { value: 'ollama', label: 'Ollama (local)' },
]

const MODEL_DEFAULTS = {
  groq:   'llama-3.3-70b-versatile',
  claude: 'claude-haiku-4-5-20251001',
  ollama: 'llama3',
}

export default function SettingsModal({ open, onClose, onScan }) {
  const [apiKey,    setApiKey]    = useState('')
  const [shodanKey, setShodanKey] = useState('')
  const [lang,      setLang]      = useState('auto')
  const [provider,  setProvider]  = useState('groq')
  const [model,     setModel]     = useState(MODEL_DEFAULTS.groq)

  const [remoteTargets, setRemoteTargets] = useState([])
  const [newTarget, setNewTarget] = useState({ label: '', host: '', method: 'ssh', username: '', password: '', port: 22 })
  const [testResult, setTestResult] = useState(null)
  const [testing, setTesting] = useState(false)

  useEffect(() => {
    if (!open) return
    setApiKey(localStorage.getItem('aivas_api_key') || '')
    setShodanKey(localStorage.getItem('aivas_shodan_key') || '')
    setLang(localStorage.getItem('aivas_lang') || 'auto')
    const p = localStorage.getItem('aivas_provider') || 'groq'
    setProvider(p)
    setModel(localStorage.getItem('aivas_model') || MODEL_DEFAULTS[p] || MODEL_DEFAULTS.groq)
    setTestResult(null)
    fetch('/api/remote-targets')
      .then(r => r.json())
      .then(setRemoteTargets)
      .catch(() => {})
  }, [open])

  useEffect(() => {
    const handleKeyDown = (e) => { if (e.key === 'Escape' && open) onClose() }
    if (open) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, onClose])

  if (!open) return null

  const handleProviderChange = (e) => {
    const p = e.target.value
    setProvider(p)
    setModel(MODEL_DEFAULTS[p] || MODEL_DEFAULTS.groq)
  }

  const save = () => {
    localStorage.setItem('aivas_api_key',    apiKey)
    localStorage.setItem('aivas_shodan_key', shodanKey)
    localStorage.setItem('aivas_lang',       lang)
    localStorage.setItem('aivas_provider',   provider)
    localStorage.setItem('aivas_model',      model)
    onClose()
  }

  const saveTarget = async () => {
    if (!newTarget.host || !newTarget.username) return
    const label = newTarget.label || `${newTarget.username}@${newTarget.host}`
    try {
      const resp = await fetch('/api/remote-targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...newTarget, label }),
      })
      if (resp.ok) {
        const saved = await resp.json()
        setRemoteTargets(prev => [saved, ...prev])
        setNewTarget({ label: '', host: '', method: 'ssh', username: '', password: '', port: 22 })
        setTestResult(null)
      }
    } catch { /* silent */ }
  }

  const deleteTarget = async (id) => {
    try {
      await fetch(`/api/remote-targets/${id}`, { method: 'DELETE' })
      setRemoteTargets(prev => prev.filter(t => t.id !== id))
    } catch { /* silent */ }
  }

  const testConnection = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const resp = await fetch('/api/probe/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...newTarget }),
      })
      setTestResult(await resp.json())
    } catch {
      setTestResult({ ok: false, error: 'Network error' })
    }
    setTesting(false)
  }

  const inputStyle = { background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }

  return (
    <>
      <div style={{ background: 'rgba(0,0,0,0.7)' }} className="fixed inset-0 z-40" onClick={onClose} />
      <div
        data-testid="settings-modal"
        style={{ background: '#111111', border: '1px solid #1e1e1e', width: 440, maxHeight: '90vh', overflowY: 'auto' }}
        className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 rounded-lg p-5"
      >
        <div className="flex items-center justify-between mb-5">
          <span style={{ color: '#e0e0e0' }} className="font-medium text-sm">Settings</span>
          <button onClick={onClose} style={{ color: '#666' }} className="p-1 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* Provider */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Provider</label>
          <select
            value={provider}
            onChange={handleProviderChange}
            style={{ ...inputStyle, width: '100%' }}
            className="rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] transition-colors"
          >
            {PROVIDERS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
          </select>
        </div>

        {/* Model */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Model</label>
          <input
            type="text"
            value={model}
            onChange={e => setModel(e.target.value)}
            style={inputStyle}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] transition-colors"
          />
        </div>

        {/* API Key */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">
            API Key ({provider === 'claude' ? 'Anthropic' : provider === 'groq' ? 'Groq' : 'not needed'})
          </label>
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder={provider === 'groq' ? 'gsk_…' : provider === 'claude' ? 'sk-ant-…' : 'not required'}
            style={inputStyle}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#444] transition-colors"
          />
        </div>

        {/* Shodan Key */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Shodan API Key (optional)</label>
          <input
            type="password"
            value={shodanKey}
            onChange={e => setShodanKey(e.target.value)}
            placeholder="shodan api key…"
            style={inputStyle}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#444] transition-colors"
          />
        </div>

        {/* Language */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">Language</label>
          <div className="flex gap-2">
            {LANGS.map(l => (
              <button
                key={l.value}
                onClick={() => setLang(l.value)}
                style={{
                  background: lang === l.value ? '#4a9eff' : '#161616',
                  border: `1px solid ${lang === l.value ? '#4a9eff' : '#1e1e1e'}`,
                  color: lang === l.value ? '#000' : '#e0e0e0',
                }}
                className="flex-1 py-1.5 text-xs rounded font-medium transition-all"
              >
                {l.label}
              </button>
            ))}
          </div>
        </div>

        {/* Remote Targets */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-2">Remote Targets (SSH / WinRM)</label>

          {remoteTargets.map((t) => (
            <div key={t.id} style={{ background: '#161616', border: '1px solid #1e1e1e', borderRadius: 4 }}
                 className="flex items-center gap-2 px-3 py-2 mb-1.5 text-xs">
              <span style={{ color: '#4a9eff', fontFamily: 'monospace' }}>{(t.method || 'ssh').toUpperCase()}</span>
              <div className="flex flex-col min-w-0">
                <span style={{ color: '#e0e0e0' }}>{t.label || `${t.username}@${t.host}`}</span>
                <span style={{ color: '#555' }}>{t.username}@{t.host}:{t.port}</span>
              </div>
              <div className="ml-auto flex gap-3">
                {onScan && (
                  <button
                    onClick={() => { onScan(t.host, { method: t.method, username: t.username, password: t.password, port: t.port }); onClose() }}
                    style={{ color: '#4a9eff' }} className="hover:opacity-80 transition-opacity">
                    Scan
                  </button>
                )}
                <button onClick={() => deleteTarget(t.id)} style={{ color: '#555' }} className="hover:text-red-400 transition-colors">✕</button>
              </div>
            </div>
          ))}

          <div style={{ border: '1px solid #1e1e1e', borderRadius: 4 }} className="p-2.5 mt-2">
            <div className="mb-2">
              <input
                type="text"
                placeholder="Label (e.g. Kali Lab)"
                value={newTarget.label}
                onChange={e => setNewTarget(t => ({ ...t, label: e.target.value }))}
                style={{ ...inputStyle, width: '100%' }}
                className="rounded px-2 py-1.5 text-xs outline-none"
              />
            </div>
            <div className="flex gap-2 mb-2">
              <select
                value={newTarget.method}
                onChange={e => setNewTarget(t => ({ ...t, method: e.target.value, port: e.target.value === 'ssh' ? 22 : 5985 }))}
                style={{ ...inputStyle, width: 80 }}
                className="rounded px-2 py-1.5 text-xs outline-none"
              >
                <option value="ssh">SSH</option>
                <option value="winrm">WinRM</option>
              </select>
              <input
                type="text"
                placeholder="host or IP"
                value={newTarget.host}
                onChange={e => setNewTarget(t => ({ ...t, host: e.target.value }))}
                style={{ ...inputStyle, flex: 1 }}
                className="rounded px-2 py-1.5 text-xs outline-none"
              />
              <input
                type="number"
                placeholder="port"
                value={newTarget.port}
                onChange={e => setNewTarget(t => ({ ...t, port: Number(e.target.value) }))}
                style={{ ...inputStyle, width: 60 }}
                className="rounded px-2 py-1.5 text-xs outline-none"
              />
            </div>
            <div className="flex gap-2 mb-2">
              <input
                type="text"
                placeholder="username"
                value={newTarget.username}
                onChange={e => setNewTarget(t => ({ ...t, username: e.target.value }))}
                style={{ ...inputStyle, flex: 1 }}
                className="rounded px-2 py-1.5 text-xs outline-none"
              />
              <input
                type="password"
                placeholder="password"
                value={newTarget.password}
                onChange={e => setNewTarget(t => ({ ...t, password: e.target.value }))}
                style={{ ...inputStyle, flex: 1 }}
                className="rounded px-2 py-1.5 text-xs outline-none"
              />
            </div>
            <div className="flex gap-2 items-center">
              <button
                onClick={testConnection}
                disabled={testing || !newTarget.host || !newTarget.username}
                style={{ background: '#161616', border: '1px solid #1e1e1e', color: testing ? '#555' : '#e0e0e0' }}
                className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity disabled:cursor-not-allowed"
              >
                {testing ? 'Testing…' : 'Test Connection'}
              </button>
              <button
                onClick={saveTarget}
                disabled={!newTarget.host || !newTarget.username}
                style={{ background: '#161616', border: '1px solid #4a9eff', color: '#4a9eff' }}
                className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity disabled:cursor-not-allowed"
              >
                Save Target
              </button>
              {testResult && (
                <span style={{ color: testResult.ok ? '#66bb6a' : '#ef5350' }} className="text-xs">
                  {testResult.ok ? '✓ Connected' : `✗ ${testResult.error}`}
                </span>
              )}
            </div>
          </div>
        </div>

        <button
          onClick={save}
          style={{ background: '#4a9eff' }}
          className="w-full py-2 text-sm font-semibold text-black rounded hover:opacity-90 transition-opacity"
        >
          Save
        </button>
      </div>
    </>
  )
}
