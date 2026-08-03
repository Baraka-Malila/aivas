import { useState, useEffect } from 'react'
import { X, SlidersHorizontal, Bot, Link, Server, CalendarClock } from 'lucide-react'
import RemoteTargetsSection from './RemoteTargetsSection'
import ScheduleSection from './ScheduleSection'

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

const NAV = [
  { id: 'general',      label: 'General',        Icon: SlidersHorizontal },
  { id: 'provider',     label: 'AI Provider',     Icon: Bot },
  { id: 'integrations', label: 'Integrations',   Icon: Link },
  { id: 'targets',      label: 'Remote Targets',  Icon: Server },
  { id: 'schedule',     label: 'Schedule',        Icon: CalendarClock },
]

const inp = { background: '#0f0f0f', border: '1px solid #252525', color: '#e0e0e0' }

export default function SettingsModal({ open, onClose, onScan }) {
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
    fetch('/api/remote-targets').then(r => r.json()).then(setRemoteTargets).catch(() => {})
  }, [open])

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

  return (
    <>
      <div
        style={{ backdropFilter: 'blur(8px)', WebkitBackdropFilter: 'blur(8px)', background: 'rgba(0,0,0,0.55)' }}
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      <div
        data-testid="settings-modal"
        style={{ background: '#141414', border: '1px solid #222', width: 820, maxWidth: '95vw', height: 'min(85vh, 600px)' }}
        className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 rounded-xl flex overflow-hidden"
      >
        {/* Sidebar */}
        <div style={{ width: 220, borderRight: '1px solid #222', background: '#0f0f0f', flexShrink: 0 }}
          className="flex flex-col py-4 overflow-y-auto"
        >
          <p style={{ color: '#444', fontSize: 11 }} className="px-4 mb-2 uppercase tracking-widest font-medium">
            Settings
          </p>
          {NAV.map(({ id, label, Icon }) => (
            <button
              key={id}
              onClick={() => setSection(id)}
              style={{
                background: section === id ? '#1e1e1e' : 'transparent',
                color: section === id ? '#e0e0e0' : '#666',
                borderRadius: 6,
              }}
              className="flex items-center gap-3 mx-2 px-3 py-2 text-sm text-left transition-colors hover:text-[#ccc]"
            >
              <Icon size={15} />
              {label}
            </button>
          ))}
        </div>

        {/* Content panel */}
        <div className="flex-1 flex flex-col min-w-0">
          <div style={{ borderBottom: '1px solid #1e1e1e' }} className="flex items-center justify-between px-6 py-4 shrink-0">
            <span style={{ color: '#e0e0e0' }} className="font-semibold text-sm">
              {NAV.find(n => n.id === section)?.label}
            </span>
            <button onClick={onClose} style={{ color: '#555' }} className="p-1 hover:text-white transition-colors rounded">
              <X size={16} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-6 py-5">
            {section === 'general' && (
              <>
                <div className="mb-6">
                  <p style={{ color: '#e0e0e0' }} className="text-sm font-medium mb-0.5">Language</p>
                  <p style={{ color: '#555' }} className="text-xs mb-3">Language used for AI-generated reports and descriptions.</p>
                  <div className="flex gap-2">
                    {LANGS.map(l => (
                      <button key={l.value} onClick={() => setLang(l.value)}
                        style={{
                          background: lang === l.value ? '#4a9eff22' : 'transparent',
                          border: `1px solid ${lang === l.value ? '#4a9eff' : '#252525'}`,
                          color: lang === l.value ? '#4a9eff' : '#888',
                        }}
                        className="flex-1 py-1.5 text-xs rounded font-medium transition-all"
                      >{l.label}</button>
                    ))}
                  </div>
                </div>
                <button onClick={save} style={{ background: '#4a9eff' }}
                  className="px-5 py-2 text-sm font-semibold text-black rounded hover:opacity-90 transition-opacity">
                  Save Changes
                </button>
              </>
            )}

            {section === 'provider' && (
              <>
                <div className="mb-5">
                  <p style={{ color: '#e0e0e0' }} className="text-sm font-medium mb-0.5">Provider</p>
                  <p style={{ color: '#555' }} className="text-xs mb-3">AI backend for risk analysis and Swahili translation.</p>
                  <select value={provider}
                    onChange={e => { setProvider(e.target.value); setModel(MODEL_DEFAULTS[e.target.value] || MODEL_DEFAULTS.groq) }}
                    style={{ ...inp, width: '100%' }}
                    className="rounded px-3 py-2 text-sm outline-none"
                  >
                    {PROVIDERS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                <div className="mb-5">
                  <p style={{ color: '#e0e0e0' }} className="text-sm font-medium mb-0.5">Model</p>
                  <p style={{ color: '#555' }} className="text-xs mb-3">Model ID for the selected provider.</p>
                  <input type="text" value={model} onChange={e => setModel(e.target.value)}
                    style={{ ...inp, width: '100%' }}
                    className="rounded px-3 py-2 text-sm outline-none"
                  />
                </div>
                <div className="mb-6">
                  <p style={{ color: '#e0e0e0' }} className="text-sm font-medium mb-0.5">
                    API Key{provider === 'ollama' ? ' (not needed)' : ''}
                  </p>
                  <p style={{ color: '#555' }} className="text-xs mb-3">
                    {provider === 'groq' ? 'Groq Cloud API key — get one free at console.groq.com' :
                     provider === 'claude' ? 'Anthropic API key — available at console.anthropic.com' :
                     'Ollama runs locally — no API key required'}
                  </p>
                  <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                    placeholder={provider === 'groq' ? 'gsk_…' : provider === 'claude' ? 'sk-ant-…' : 'not required'}
                    disabled={provider === 'ollama'}
                    style={{ ...inp, width: '100%', opacity: provider === 'ollama' ? 0.4 : 1 }}
                    className="rounded px-3 py-2 text-sm outline-none placeholder:text-[#444]"
                  />
                </div>
                <button onClick={save} style={{ background: '#4a9eff' }}
                  className="px-5 py-2 text-sm font-semibold text-black rounded hover:opacity-90 transition-opacity">
                  Save Changes
                </button>
              </>
            )}

            {section === 'integrations' && (
              <>
                <div className="mb-6">
                  <p style={{ color: '#e0e0e0' }} className="text-sm font-medium mb-0.5">Shodan API Key</p>
                  <p style={{ color: '#555' }} className="text-xs mb-3">
                    Optional. Enables internet exposure lookups for scanned IPs. Leave empty to skip.
                  </p>
                  <input type="password" value={shodanKey} onChange={e => setShodanKey(e.target.value)}
                    placeholder="shodan api key…"
                    style={{ ...inp, width: '100%' }}
                    className="rounded px-3 py-2 text-sm outline-none placeholder:text-[#444]"
                  />
                </div>
                <button onClick={save} style={{ background: '#4a9eff' }}
                  className="px-5 py-2 text-sm font-semibold text-black rounded hover:opacity-90 transition-opacity">
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
          </div>
        </div>
      </div>
    </>
  )
}
