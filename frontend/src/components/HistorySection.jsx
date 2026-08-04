import { useState, useEffect, useRef, useCallback } from 'react'
import { Check, X } from 'lucide-react'
import ContextMenu from './ContextMenu'

const MONO = { fontFamily: '"Fira Code", monospace' }
const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }
const PAGE = 20

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toISOString().slice(0, 10) }
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
        style={{ background: '#1a1a1a', border: '1px solid #4a9eff', color: '#e0e0e0', borderRadius: 4 }}
        className="flex-1 min-w-0 px-2 py-0.5 text-xs outline-none"
      />
      <button onClick={commit} style={{ color: '#66bb6a', background: 'none', border: 'none', cursor: 'pointer', padding: 2 }}>
        <Check size={12} />
      </button>
      <button onClick={onCancel} style={{ color: '#888', background: 'none', border: 'none', cursor: 'pointer', padding: 2 }}
        onMouseEnter={e => e.currentTarget.style.color = '#ef5350'}
        onMouseLeave={e => e.currentTarget.style.color = '#888'}
      >
        <X size={12} />
      </button>
    </div>
  )
}

function GradeBox({ grade }) {
  const color = GRADE_COLOR[grade] || '#888'
  const alpha = color + '14'
  return (
    <span style={{
      width: 24, height: 24,
      border: `1px solid ${color}`, background: alpha, color,
      borderRadius: 3,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontWeight: 700, fontSize: 13, flexShrink: 0,
      fontFamily: '"Fira Code", monospace',
    }}>
      {grade || '?'}
    </span>
  )
}

function ScanRow({ scan, onDelete, onRename, onContextMenu }) {
  const [editing, setEditing] = useState(false)
  const grade = (scan.grade || '').replace('Grade ', '')
  const label = scan.label || `${scan.target || 'unknown'} — ${fmtDate(scan.started_at)}`

  return (
    <div
      style={{ background: '#1a1a1a', border: '1px solid #333', borderRadius: 4, display: 'flex', alignItems: 'center', gap: 12, padding: '9px 12px', cursor: 'default' }}
      onContextMenu={e => { e.preventDefault(); onContextMenu(e, { onRename: () => setEditing(true), onDelete }) }}
    >
      <GradeBox grade={grade} />
      <div style={{ flex: 1, minWidth: 0 }}>
        {editing ? (
          <InlineEdit value={label} onSave={v => { onRename(v); setEditing(false) }} onCancel={() => setEditing(false)} />
        ) : (
          <div style={{ color: '#e0e0e0', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {label}
          </div>
        )}
        <div style={{ ...MONO, fontSize: 10, color: '#888', marginTop: 2 }}>
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
      style={{ background: '#1a1a1a', border: '1px solid #333', borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 12px', cursor: 'default' }}
      onContextMenu={e => { e.preventDefault(); onContextMenu(e, { onRename: () => setEditing(true), onDelete }) }}
    >
      {editing ? (
        <InlineEdit value={title} onSave={v => { onRename(v); setEditing(false) }} onCancel={() => setEditing(false)} />
      ) : (
        <>
          <span style={{ color: '#e0e0e0', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
            {title}
          </span>
          <span style={{ ...MONO, fontSize: 10, color: '#888', flexShrink: 0, marginLeft: 12 }}>
            updated {fmtDate(session.updated_at)}
          </span>
        </>
      )}
    </div>
  )
}

export default function HistorySection() {
  const [scans, setScans] = useState([])
  const [sessions, setSessions] = useState([])
  const [ctxMenu, setCtxMenu] = useState(null)
  const [hasMoreScans, setHasMoreScans] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const scanOffsetRef = useRef(0)

  const loadScans = useCallback(async (offset, replace = false) => {
    if (offset > 0) setLoadingMore(true)
    try {
      const rows = await fetch(`/api/history?limit=${PAGE}&offset=${offset}`).then(r => r.json())
      setScans(prev => replace ? rows : [...prev, ...rows])
      setHasMoreScans(rows.length === PAGE)
      scanOffsetRef.current = offset + rows.length
    } catch {}
    setLoadingMore(false)
  }, [])

  useEffect(() => {
    loadScans(0, true)
    fetch('/api/sessions').then(r => r.json()).then(setSessions).catch(() => {})
  }, [])

  const deleteScan = async (id) => {
    await fetch(`/api/scan/${id}`, { method: 'DELETE' }).catch(() => {})
    setScans(prev => prev.filter(s => s.id !== id))
    scanOffsetRef.current = Math.max(0, scanOffsetRef.current - 1)
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
    ...MONO, fontSize: 10, letterSpacing: '0.1em', color: '#888',
    textTransform: 'uppercase', marginBottom: 8, display: 'block',
  }

  return (
    <>
      <div style={{ marginBottom: 20 }}>
        <span style={sectionLabel}>SCAN HISTORY ({scans.length}{hasMoreScans ? '+' : ''})</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {scans.length === 0 && (
            <div style={{ color: '#777', fontSize: 12 }}>No scans yet.</div>
          )}
          {scans.map(s => (
            <ScanRow key={s.id} scan={s}
              onDelete={() => deleteScan(s.id)}
              onRename={label => renameScan(s.id, label)}
              onContextMenu={handleContextMenu}
            />
          ))}
        </div>
        {hasMoreScans && (
          <button
            onClick={() => loadScans(scanOffsetRef.current)}
            disabled={loadingMore}
            style={{ ...MONO, fontSize: 10, color: '#888', background: 'transparent', border: '1px solid #333', borderRadius: 3, padding: '5px 12px', cursor: 'pointer', marginTop: 8, width: '100%' }}
            onMouseEnter={e => { e.currentTarget.style.color = '#c0c0c0'; e.currentTarget.style.borderColor = '#555' }}
            onMouseLeave={e => { e.currentTarget.style.color = '#888'; e.currentTarget.style.borderColor = '#333' }}
          >
            {loadingMore ? 'Loading…' : 'Load more'}
          </button>
        )}
      </div>

      <div>
        <span style={sectionLabel}>CHAT SESSIONS ({sessions.length})</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {sessions.length === 0 && (
            <div style={{ color: '#777', fontSize: 12 }}>No chat sessions yet.</div>
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
