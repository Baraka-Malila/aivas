import { useState, useEffect } from 'react'
import { X } from 'lucide-react'

const LANGS = [
  { value: 'auto', label: 'Auto' },
  { value: 'en',   label: 'English' },
  { value: 'sw',   label: 'Swahili' },
]

export default function SettingsModal({ open, onClose }) {
  const [apiKey, setApiKey] = useState('')
  const [lang, setLang] = useState('auto')

  useEffect(() => {
    if (!open) return
    setApiKey(localStorage.getItem('aivas_api_key') || '')
    setLang(localStorage.getItem('aivas_lang') || 'auto')
  }, [open])

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && open) {
        onClose()
      }
    }
    if (open) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, onClose])

  if (!open) return null

  const save = () => {
    localStorage.setItem('aivas_api_key', apiKey)
    localStorage.setItem('aivas_lang', lang)
    onClose()
  }

  return (
    <>
      <div
        style={{ background: 'rgba(0,0,0,0.7)' }}
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      <div
        data-testid="settings-modal"
        style={{ background: '#111111', border: '1px solid #1e1e1e', width: 380 }}
        className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 rounded-lg p-5"
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <span style={{ color: '#e0e0e0' }} className="font-medium text-sm">Settings</span>
          <button onClick={onClose} style={{ color: '#666' }} className="p-1 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* API Key */}
        <div className="mb-4">
          <label style={{ color: '#666' }} className="text-xs block mb-1.5">API Key (Groq)</label>
          <input
            type="password"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            placeholder="gsk_…"
            style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
            className="w-full rounded px-3 py-2 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#444] transition-colors"
          />
          <div style={{ color: apiKey ? '#66bb6a' : '#666' }} className="text-xs mt-1">
            {apiKey ? 'Connected' : 'Not configured'}
          </div>
        </div>

        {/* Language */}
        <div className="mb-5">
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
