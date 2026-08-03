import { useState, useEffect, useRef } from 'react'
import { Trash2, Pencil, Check, X } from 'lucide-react'

const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) }
  catch { return iso }
}

function InlineEdit({ value, onSave, onCancel }) {
  const [text, setText] = useState(value)
  const inputRef = useRef(null)
  useEffect(() => { inputRef.current?.focus() }, [])
  const commit = () => { if (text.trim()) onSave(text.trim()); else onCancel() }
  return (
    <div className="flex items-center gap-1 flex-1 min-w-0">
      <input
        ref={inputRef}
        value={text}
        onChange={e => setText(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') onCancel() }}
        style={{ background: '#0f0f0f', border: '1px solid #4a9eff', color: '#e0e0e0', borderRadius: 4 }}
        className="flex-1 min-w-0 px-2 py-0.5 text-xs outline-none"
      />
      <button onClick={commit} style={{ color: '#66bb6a' }} className="p-0.5 hover:opacity-80 shrink-0">
        <Check size={12} />
      </button>
      <button onClick={onCancel} style={{ color: '#555' }} className="p-0.5 hover:text-red-400 shrink-0">
        <X size={12} />
      </button>
    </div>
  )
}

function ScanRow({ scan, onDelete, onRename }) {
  const [editing, setEditing] = useState(false)
  const grade = (scan.grade || '').replace('Grade ', '')
  const gradeColor = GRADE_COLOR[grade] || '#888'
  const label = scan.label || `${scan.target} — ${scan.grade || '?'}`

  return (
    <div style={{ background: '#1a1a1a', border: '1px solid #252525', borderRadius: 6 }}
         className="px-3 py-2.5 text-xs group">
      <div className="flex items-center gap-2 mb-0.5">
        <span style={{ color: gradeColor, fontWeight: 700, fontSize: 13, flexShrink: 0 }}>{grade || '?'}</span>
        {editing ? (
          <InlineEdit value={label} onSave={v => { onRename(v); setEditing(false) }} onCancel={() => setEditing(false)} />
        ) : (
          <>
            <span style={{ color: '#e0e0e0' }} className="flex-1 min-w-0 truncate">{label}</span>
            <div className="ml-auto flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
              <button onClick={() => setEditing(true)} style={{ color: '#555' }} className="p-1 hover:text-[#4a9eff] transition-colors">
                <Pencil size={11} />
              </button>
              <button onClick={onDelete} style={{ color: '#555' }} className="p-1 hover:text-red-400 transition-colors">
                <Trash2 size={11} />
              </button>
            </div>
          </>
        )}
      </div>
      <div style={{ color: '#555' }} className="flex gap-x-4 flex-wrap">
        <span>Target: <span style={{ color: '#888' }}>{scan.target}</span></span>
        <span>Findings: <span style={{ color: '#888' }}>{scan.finding_count ?? 0}</span></span>
        <span>Date: <span style={{ color: '#888' }}>{fmtDate(scan.started_at)}</span></span>
      </div>
    </div>
  )
}

function SessionRow({ session, onDelete, onRename }) {
  const [editing, setEditing] = useState(false)
  const title = session.title || 'New conversation'

  return (
    <div style={{ background: '#1a1a1a', border: '1px solid #252525', borderRadius: 6 }}
         className="px-3 py-2.5 text-xs group">
      <div className="flex items-center gap-2 mb-0.5">
        {editing ? (
          <InlineEdit value={title} onSave={v => { onRename(v); setEditing(false) }} onCancel={() => setEditing(false)} />
        ) : (
          <>
            <span style={{ color: '#e0e0e0' }} className="flex-1 min-w-0 truncate">{title}</span>
            <div className="ml-auto flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
              <button onClick={() => setEditing(true)} style={{ color: '#555' }} className="p-1 hover:text-[#4a9eff] transition-colors">
                <Pencil size={11} />
              </button>
              <button onClick={onDelete} style={{ color: '#555' }} className="p-1 hover:text-red-400 transition-colors">
                <Trash2 size={11} />
              </button>
            </div>
          </>
        )}
      </div>
      <div style={{ color: '#555' }}>
        Updated: <span style={{ color: '#888' }}>{fmtDate(session.updated_at)}</span>
      </div>
    </div>
  )
}

export default function HistorySection() {
  const [scans, setScans] = useState([])
  const [sessions, setSessions] = useState([])

  useEffect(() => {
    fetch('/api/history?limit=50').then(r => r.json()).then(setScans).catch(() => {})
    fetch('/api/sessions').then(r => r.json()).then(setSessions).catch(() => {})
  }, [])

  const deleteScan = async (id) => {
    await fetch(`/api/scan/${id}`, { method: 'DELETE' }).catch(() => {})
    setScans(prev => prev.filter(s => s.id !== id))
  }

  const renameScan = async (id, label) => {
    const resp = await fetch(`/api/scan/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label }),
    }).catch(() => null)
    if (resp?.ok) {
      setScans(prev => prev.map(s => s.id === id ? { ...s, label } : s))
    }
  }

  const deleteSession = async (id) => {
    await fetch(`/api/sessions/${id}`, { method: 'DELETE' }).catch(() => {})
    setSessions(prev => prev.filter(s => s.id !== id))
  }

  const renameSession = async (id, title) => {
    const resp = await fetch(`/api/sessions/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title }),
    }).catch(() => null)
    if (resp?.ok) {
      setSessions(prev => prev.map(s => s.id === id ? { ...s, title } : s))
    }
  }

  return (
    <>
      <div className="mb-6">
        <p style={{ color: '#e0e0e0' }} className="text-sm font-medium mb-0.5">Scan History</p>
        <p style={{ color: '#555' }} className="text-xs mb-3">Hover a row to rename or delete.</p>
        <div className="space-y-2">
          {scans.length === 0 && <p style={{ color: '#444' }} className="text-xs py-2">No scans yet.</p>}
          {scans.map(s => (
            <ScanRow key={s.id} scan={s}
              onDelete={() => deleteScan(s.id)}
              onRename={label => renameScan(s.id, label)} />
          ))}
        </div>
      </div>

      <div>
        <p style={{ color: '#e0e0e0' }} className="text-sm font-medium mb-0.5">Chat Sessions</p>
        <p style={{ color: '#555' }} className="text-xs mb-3">Hover a row to rename or delete.</p>
        <div className="space-y-2">
          {sessions.length === 0 && <p style={{ color: '#444' }} className="text-xs py-2">No chat sessions yet.</p>}
          {sessions.map(s => (
            <SessionRow key={s.id} session={s}
              onDelete={() => deleteSession(s.id)}
              onRename={title => renameSession(s.id, title)} />
          ))}
        </div>
      </div>
    </>
  )
}
