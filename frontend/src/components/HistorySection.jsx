import { useState, useEffect, useRef } from 'react'
import { Check, X } from 'lucide-react'
import ContextMenu from './ContextMenu'

const MONO = { fontFamily: '"Fira Code", monospace' }
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
      <button onClick={commit} style={{ color: '#66bb6a', background: 'none', border: 'none', cursor: 'pointer', padding: 2 }}>
        <Check size={12} />
      </button>
      <button onClick={onCancel} style={{ color: '#555', background: 'none', border: 'none', cursor: 'pointer', padding: 2 }}
        onMouseEnter={e => e.currentTarget.style.color = '#ef5350'}
        onMouseLeave={e => e.currentTarget.style.color = '#555'}
      >
        <X size={12} />
      </button>
    </div>
  )
}

function ScanRow({ scan, onDelete, onRename, onContextMenu }) {
  const [editing, setEditing] = useState(false)
  const grade = (scan.grade || '').replace('Grade ', '')
  const gradeColor = GRADE_COLOR[grade] || '#888'
  const label = scan.label || `${scan.target} — ${scan.grade || '?'}`

  return (
    <div
      style={{ borderBottom: '1px solid #141414', display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', cursor: 'default' }}
      onContextMenu={e => { e.preventDefault(); onContextMenu(e, { onRename: () => setEditing(true), onDelete }) }}
    >
      <div style={{ ...MONO, color: gradeColor, fontWeight: 700, fontSize: 12, flexShrink: 0, width: 14, textAlign: 'center' }}>{grade || '?'}</div>
      <div className="flex-1 min-w-0">
        {editing ? (
          <InlineEdit value={label} onSave={v => { onRename(v); setEditing(false) }} onCancel={() => setEditing(false)} />
        ) : (
          <div style={{ color: '#c0c0c0', fontSize: 12 }} className="truncate">{label}</div>
        )}
        <div style={{ ...MONO, color: '#444', fontSize: 10, marginTop: 2 }}>
          {scan.target} · {scan.finding_count ?? 0} findings · {fmtDate(scan.started_at)}
        </div>
      </div>
    </div>
  )
}

function SessionRow({ session, onDelete, onRename, onContextMenu }) {
  const [editing, setEditing] = useState(false)
  const title = session.title || 'New conversation'

  return (
    <div
      style={{ borderBottom: '1px solid #141414', display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', cursor: 'default' }}
      onContextMenu={e => { e.preventDefault(); onContextMenu(e, { onRename: () => setEditing(true), onDelete }) }}
    >
      <div className="flex-1 min-w-0">
        {editing ? (
          <InlineEdit value={title} onSave={v => { onRename(v); setEditing(false) }} onCancel={() => setEditing(false)} />
        ) : (
          <div style={{ color: '#c0c0c0', fontSize: 12 }} className="truncate">{title}</div>
        )}
        <div style={{ ...MONO, color: '#444', fontSize: 10, marginTop: 2 }}>
          Updated {fmtDate(session.updated_at)}
        </div>
      </div>
    </div>
  )
}

export default function HistorySection() {
  const [scans, setScans] = useState([])
  const [sessions, setSessions] = useState([])
  const [ctxMenu, setCtxMenu] = useState(null)

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
    if (resp?.ok) setScans(prev => prev.map(s => s.id === id ? { ...s, label } : s))
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
    if (resp?.ok) setSessions(prev => prev.map(s => s.id === id ? { ...s, title } : s))
  }

  const handleContextMenu = (e, { onRename, onDelete }) => {
    setCtxMenu({
      x: e.clientX, y: e.clientY,
      items: [
        { label: 'Rename', onClick: onRename },
        { label: 'Delete', onClick: onDelete, danger: true },
      ],
    })
  }

  const sectionLabel = {
    ...MONO, fontSize: 10, letterSpacing: '0.1em', color: '#444',
    textTransform: 'uppercase', marginBottom: 8, display: 'block',
  }

  return (
    <>
      <div className="mb-6">
        <span style={sectionLabel}>Scan History</span>
        <p style={{ color: '#444', fontSize: 11, marginBottom: 10 }}>Right-click a row to rename or delete.</p>
        <div style={{ background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 5, overflow: 'hidden' }}>
          {scans.length === 0 && (
            <div style={{ color: '#444', fontSize: 12, padding: '12px 16px' }}>No scans yet.</div>
          )}
          {scans.map(s => (
            <ScanRow key={s.id} scan={s}
              onDelete={() => deleteScan(s.id)}
              onRename={label => renameScan(s.id, label)}
              onContextMenu={handleContextMenu}
            />
          ))}
        </div>
      </div>

      <div>
        <span style={sectionLabel}>Chat Sessions</span>
        <p style={{ color: '#444', fontSize: 11, marginBottom: 10 }}>Right-click a row to rename or delete.</p>
        <div style={{ background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 5, overflow: 'hidden' }}>
          {sessions.length === 0 && (
            <div style={{ color: '#444', fontSize: 12, padding: '12px 16px' }}>No chat sessions yet.</div>
          )}
          {sessions.map(s => (
            <SessionRow key={s.id} session={s}
              onDelete={() => deleteSession(s.id)}
              onRename={title => renameSession(s.id, title)}
              onContextMenu={handleContextMenu}
            />
          ))}
        </div>
      </div>

      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x} y={ctxMenu.y}
          items={ctxMenu.items}
          onClose={() => setCtxMenu(null)}
        />
      )}
    </>
  )
}
