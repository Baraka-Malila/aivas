import { useState, useEffect } from 'react'
import { X, Sliders, Cpu, Link, Server, Calendar, RotateCcw } from 'lucide-react'
import RemoteTargetsSection from './RemoteTargetsSection'
import ScheduleSection from './ScheduleSection'
import HistorySection from './HistorySection'

const MONO = { fontFamily: '"Fira Code", monospace' }

const LANGS = [
  { value: 'auto', label: 'Auto' },
  { value: 'en',   label: 'English' },
  { value: 'sw',   label: 'Swahili' },
]

const PROVIDERS = [
  { value: 'groq',   label: 'Groq',   sub: 'online',       letter: 'G' },
  { value: 'claude', label: 'Claude', sub: 'Anthropic',     letter: 'C' },
  { value: 'ollama', label: 'Ollama', sub: 'local · no key',letter: 'O' },
]

const MODEL_DEFAULTS = {
  groq:   'llama-3.3-70b-versatile',
  claude: 'claude-haiku-4-5-20251001',
  ollama: 'llama3',
}

const NAV = [
  { id: 'general',      label: 'General',        Icon: Sliders },
  { id: 'provider',     label: 'AI Provider',    Icon: Cpu },
  { id: 'integrations', label: 'Integrations',   Icon: Link },
  { id: 'targets',      label: 'Remote Targets', Icon: Server },
  { id: 'schedule',     label: 'Schedule',       Icon: Calendar },
  { id: 'history',      label: 'History',        Icon: RotateCcw },
]

const inp = { background: '#0f0f0f', border: '1px solid #252525', color: '#e0e0e0', borderRadius: 4, outline: 'none', boxSizing: 'border-box' }
const fieldLabel = { ...MONO, fontSize: 10, color: '#555555', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 8, display: 'block' }

export default function SettingsModal({ open, onClose, onScan, initialSection }) {
  const [apiKey,    setApiKey]    = useState('')
  const [shodanKey, setShodanKey] = useState('')
  const [lang,      setLang]      = useState('auto')
  const [provider,  setProvider]  = useState('groq')
  const [model,     setModel]     = useState(MODEL_DEFAULTS.groq)
  const [section,   setSection]   = useState('general')

  const [remoteTargets, setRemoteTargets] = useState([])
  const [newTarget,     setNewTarget]     = useState({ label: '', host: '', method: 'ssh', username: '', password: '', port: 22 })
  const [testResult,    setTestResult]    = useState(null)
  const [testing,       setTesting]       = useState(false)

  useEffect(() => {
    if (!open) return
    setApiKey(localStorage.getItem('aivas_api_key') || '')
    setShodanKey(localStorage.getItem('aivas_shodan_key') || '')
    setLang(localStorage.getItem('aivas_lang') || 'auto')
    const p = localStorage.getItem('aivas_provider') || 'groq'
    setProvider(p)
    setModel(localStorage.getItem('aivas_model') || MODEL_DEFAULTS[p] || MODEL_DEFAULTS.groq)
    setTestResult(null)
    setSection(initialSection || 'general')
    fetch('/api/remote-targets').then(r => r.json()).then(setRemoteTargets).catch(() => {})
  }, [open, initialSection])

  useEffect(() => {
    const fn = (e) => { if (e.key === 'Escape' && open) onClose() }
    if (open) { document.addEventListener('keydown', fn); return () => document.removeEventListener('keydown', fn) }
  }, [open, onClose])

  if (!open) return null

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
    const resp = await fetch('/api/remote-targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...newTarget, label }),
    }).catch(() => null)
    if (resp?.ok) {
      const saved = await resp.json()
      setRemoteTargets(prev => [saved, ...prev])
      setNewTarget({ label: '', host: '', method: 'ssh', username: '', password: '', port: 22 })
      setTestResult(null)
    }
  }

  const deleteTarget = async (id) => {
    await fetch(`/api/remote-targets/${id}`, { method: 'DELETE' }).catch(() => {})
    setRemoteTargets(prev => prev.filter(t => t.id !== id))
  }

  const testConnection = async () => {
    setTesting(true); setTestResult(null)
    try {
      const resp = await fetch('/api/probe/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newTarget),
      })
      setTestResult(await resp.json())
    } catch { setTestResult({ ok: false, error: 'Network error' }) }
    setTesting(false)
  }

  const activeLabel = NAV.find(n => n.id === section)?.label

  return (
    <>
      <div
        style={{ backdropFilter: 'blur(8px)', WebkitBackdropFilter: 'blur(8px)', background: 'rgba(0,0,0,0.55)' }}
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      <div
        data-testid="settings-modal"
        style={{ background: '#141414', border: '1px solid #222222', width: 820, maxWidth: '95vw', height: 'min(85vh, 600px)' }}
        className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 rounded-xl flex overflow-hidden"
      >
        {/* Sidebar */}
        <div style={{ width: 220, borderRight: '1px solid #222222', background: '#0f0f0f', flexShrink: 0, display: 'flex', flexDirection: 'column', padding: '16px 0', overflowY: 'auto' }}>
          <p style={{ ...MONO, color: '#444444', fontSize: 10, letterSpacing: '0.15em', textTransform: 'uppercase', padding: '0 16px', marginBottom: 10 }}>
            Settings
          </p>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {NAV.map(({ id, label, Icon }) => {
              const active = section === id
              return (
                <button
                  key={id}
                  onClick={() => setSection(id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '8px 16px',
                    fontSize: 13,
                    color: active ? '#e0e0e0' : '#666666',
                    background: active ? '#161616' : 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    textAlign: 'left',
                    width: '100%',
                    transition: 'color 0.1s',
                  }}
                  onMouseEnter={e => { if (!active) e.currentTarget.style.color = '#cccccc' }}
                  onMouseLeave={e => { if (!active) e.currentTarget.style.color = '#666666' }}
                >
                  <Icon size={15} />
                  {label}
                </button>
              )
            })}
          </div>
        </div>

        {/* Content panel */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Panel header */}
          <div style={{ borderBottom: '1px solid #1e1e1e', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 24px', flexShrink: 0 }}>
            <span style={{ color: '#e0e0e0', fontWeight: 600, fontSize: 14 }}>{activeLabel}</span>
            <button onClick={onClose} style={{ color: '#555555', background: 'none', border: 'none', cursor: 'pointer', padding: 4, display: 'flex', borderRadius: 3 }}
              onMouseEnter={e => e.currentTarget.style.color = '#e0e0e0'}
              onMouseLeave={e => e.currentTarget.style.color = '#555555'}
            >
              <X size={16} />
            </button>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
            {/* General */}
            {section === 'general' && (
              <>
                <div style={{ marginBottom: 20 }}>
                  <span style={fieldLabel}>Language</span>
                  <p style={{ color: '#555555', fontSize: 11, marginBottom: 10 }}>Language used for AI-generated reports and descriptions.</p>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {LANGS.map(l => (
                      <button key={l.value} onClick={() => setLang(l.value)}
                        style={{
                          flex: 1, padding: '6px 0', fontSize: 12, fontWeight: 500, borderRadius: 4, cursor: 'pointer',
                          background: lang === l.value ? '#4a9eff22' : 'transparent',
                          border: `1px solid ${lang === l.value ? '#4a9eff' : '#252525'}`,
                          color: lang === l.value ? '#4a9eff' : '#888888',
                          transition: 'all 0.1s',
                        }}
                      >{l.label}</button>
                    ))}
                  </div>
                </div>
                <button onClick={save} style={{ background: '#4a9eff', color: '#000000', fontWeight: 600, borderRadius: 4, padding: '9px 20px', fontSize: 13, border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#6cb0ff'}
                  onMouseLeave={e => e.currentTarget.style.background = '#4a9eff'}
                >
                  Save Changes
                </button>
              </>
            )}

            {/* AI Provider */}
            {section === 'provider' && (
              <>
                <div style={{ marginBottom: 20 }}>
                  <span style={fieldLabel}>Provider</span>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {PROVIDERS.map(p => {
                      const active = provider === p.value
                      return (
                        <div
                          key={p.value}
                          onClick={() => { setProvider(p.value); setModel(MODEL_DEFAULTS[p.value] || MODEL_DEFAULTS.groq) }}
                          style={{
                            flex: 1, border: `1px solid ${active ? '#4a9eff' : '#252525'}`, borderRadius: 4,
                            padding: '10px 12px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10,
                          }}
                          onMouseEnter={e => { if (!active) e.currentTarget.style.borderColor = '#3a3a3a' }}
                          onMouseLeave={e => { if (!active) e.currentTarget.style.borderColor = '#252525' }}
                        >
                          <span style={{ ...MONO, fontSize: 14, fontWeight: 600, color: active ? '#e0e0e0' : '#888888', width: 18, textAlign: 'center' }}>
                            {p.letter}
                          </span>
                          <div>
                            <div style={{ color: active ? '#e0e0e0' : '#aaaaaa', fontSize: 13, fontWeight: 600 }}>{p.label}</div>
                            <div style={{ color: active ? '#666666' : '#555555', fontSize: 11, marginTop: 1 }}>{p.sub}</div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                <div style={{ marginBottom: 20 }}>
                  <span style={fieldLabel}>Model</span>
                  <input type="text" value={model} onChange={e => setModel(e.target.value)}
                    style={{ ...inp, width: '100%', padding: '9px 12px', fontSize: 13, fontFamily: '"Fira Code", monospace' }}
                    onFocus={e => e.target.style.borderColor = '#4a9eff'}
                    onBlur={e => e.target.style.borderColor = '#252525'}
                  />
                </div>

                <div style={{ marginBottom: 24 }}>
                  <span style={fieldLabel}>API Key{provider === 'ollama' ? ' (not needed)' : ''}</span>
                  <p style={{ color: '#555555', fontSize: 11, marginBottom: 8 }}>
                    {provider === 'groq' ? 'Groq Cloud API key (console.groq.com)' :
                     provider === 'claude' ? 'Anthropic API key (console.anthropic.com)' :
                     'Ollama runs locally — no API key required'}
                  </p>
                  <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                    placeholder={provider === 'groq' ? 'gsk_…' : provider === 'claude' ? 'sk-ant-…' : 'not required'}
                    disabled={provider === 'ollama'}
                    style={{ ...inp, width: '100%', padding: '9px 12px', fontSize: 13, fontFamily: '"Fira Code", monospace', opacity: provider === 'ollama' ? 0.4 : 1 }}
                    onFocus={e => e.target.style.borderColor = '#4a9eff'}
                    onBlur={e => e.target.style.borderColor = '#252525'}
                  />
                </div>

                <button onClick={save} style={{ background: '#4a9eff', color: '#000000', fontWeight: 600, borderRadius: 4, padding: '9px 20px', fontSize: 13, border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#6cb0ff'}
                  onMouseLeave={e => e.currentTarget.style.background = '#4a9eff'}
                >
                  Save Changes
                </button>
              </>
            )}

            {/* Integrations */}
            {section === 'integrations' && (
              <>
                <div style={{ marginBottom: 24 }}>
                  <span style={fieldLabel}>Shodan API Key</span>
                  <p style={{ color: '#555555', fontSize: 11, marginBottom: 8 }}>
                    Optional. Enables internet exposure lookups for scanned IPs. Leave empty to skip.
                  </p>
                  <input type="password" value={shodanKey} onChange={e => setShodanKey(e.target.value)}
                    placeholder="shodan api key…"
                    style={{ ...inp, width: '100%', padding: '9px 12px', fontSize: 13, fontFamily: '"Fira Code", monospace' }}
                    onFocus={e => e.target.style.borderColor = '#4a9eff'}
                    onBlur={e => e.target.style.borderColor = '#252525'}
                  />
                </div>
                <button onClick={save} style={{ background: '#4a9eff', color: '#000000', fontWeight: 600, borderRadius: 4, padding: '9px 20px', fontSize: 13, border: 'none', cursor: 'pointer', fontFamily: 'inherit' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#6cb0ff'}
                  onMouseLeave={e => e.currentTarget.style.background = '#4a9eff'}
                >
                  Save Changes
                </button>
              </>
            )}

            {section === 'targets' && (
              <RemoteTargetsSection
                remoteTargets={remoteTargets}
                newTarget={newTarget}
                setNewTarget={setNewTarget}
                testResult={testResult}
                testing={testing}
                onSave={saveTarget}
                onDelete={deleteTarget}
                onTest={testConnection}
                onScan={onScan}
                onClose={onClose}
              />
            )}

            {section === 'schedule' && (
              <ScheduleSection remoteTargets={remoteTargets} />
            )}

            {section === 'history' && (
              <HistorySection />
            )}
          </div>
        </div>
      </div>
    </>
  )
}
