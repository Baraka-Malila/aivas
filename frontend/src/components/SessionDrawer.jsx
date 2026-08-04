import { useEffect, useState, useRef } from 'react'
import { X, Plus, Check } from 'lucide-react'
import ContextMenu from './ContextMenu'

const MONO = { fontFamily: '"Fira Code", monospace' }

const GRADE_COLOR   = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }
const GRADE_BORDER  = {
  A: '#1e3a24', B: '#2e3a18', C: '#3a3200', D: '#4a2015', F: '#4a1010',
}

function InlineRename({ value, onSave, onCancel }) {
  const [text, setText] = useState(value)
  const ref = useRef(null)
  useEffect(() => { ref.current?.focus() }, [])
  const commit = () => { if (text.trim()) onSave(text.trim()); else onCancel() }
  return (
    <div className="flex items-center gap-1 flex-1 min-w-0" onClick={e => e.stopPropagation()}>
      <input
        ref={ref}
        value={text}
        onChange={e => setText(e.target.value)}
        onKeyDown={e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') onCancel() }}
        style={{ background: '#1a1a1a', border: '1px solid #4a9eff', color: '#e0e0e0', borderRadius: 4 }}
        className="flex-1 min-w-0 px-2 py-0.5 text-xs outline-none"
      />
      <button onClick={commit} style={{ color: '#66bb6a' }} className="p-0.5 hover:opacity-80">
        <Check size={11} />
      </button>
    </div>
  )
}

function GradeChip({ grade }) {
  if (!grade) return null
  const color = GRADE_COLOR[grade] || '#888'
  const border = GRADE_BORDER[grade] || '#333'
  return (
    <span style={{
      ...MONO, border: `1px solid ${border}`, color,
      fontSize: 9, padding: '0 4px', borderRadius: 2, flexShrink: 0,
    }}>
      {grade}
    </span>
  )
}

function SessionItem({ session, active, onSelect, onDelete, onRename, onContextMenu }) {
  const [editing, setEditing] = useState(false)
  const grade = (session.last_grade || '').replace('Grade ', '') || null
  return (
    <div
      style={{ borderBottom: '1px solid #1e1e1e', padding: '10px 16px', cursor: 'pointer', background: active ? '#151515' : 'transparent' }}
      onClick={onSelect}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = '#151515' }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
      onContextMenu={e => { e.preventDefault(); onContextMenu(e, { onRename: () => setEditing(true), onDelete }) }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {editing ? (
          <InlineRename
            value={session.title || 'New conversation'}
            onSave={t => { onRename(t); setEditing(false) }}
            onCancel={() => setEditing(false)}
          />
        ) : (
          <span style={{ color: '#e0e0e0', fontSize: 12, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {session.title || 'New conversation'}
          </span>
        )}
        {!editing && <GradeChip grade={grade} />}
      </div>
      {!editing && (
        <div style={{ ...MONO, fontSize: 10, color: '#888', marginTop: 3 }}>
          {formatDate(session.updated_at)}
          {session.last_target ? ` · ${session.last_target}` : ''}
        </div>
      )}
    </div>
  )
}

export default function SessionDrawer({ open, sessions, activeSessionId, onClose, onSelect, onDelete, onNew, onRename }) {
  const [ctxMenu, setCtxMenu] = useState(null)

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && open) {
        if (ctxMenu) { setCtxMenu(null); return }
        onClose()
      }
    }
    if (open) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, onClose, ctxMenu])

  if (!open) return null

  const handleContextMenu = (e, { onRename: rename, onDelete: del }) => {
    setCtxMenu({
      x: e.clientX,
      y: e.clientY,
      items: [
        { label: 'Rename', onClick: rename },
        { label: 'Delete', onClick: del, danger: true },
      ],
    })
  }

  return (
    <>
      <div
        style={{ background: 'rgba(0,0,0,0.6)' }}
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      <div
        data-testid="session-drawer"
        style={{ background: '#111111', borderLeft: '1px solid #2a2a2a', width: 320 }}
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col"
      >
        {/* Header */}
        <div
          style={{ borderBottom: '1px solid #2a2a2a', flexShrink: 0 }}
          className="flex items-center justify-between px-4 py-3"
        >
          <span style={{ ...MONO, color: '#888', fontSize: 10, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
            Conversations
          </span>
          <button onClick={onClose} style={{ color: '#888', background: 'none', border: 'none', cursor: 'pointer', padding: 2, borderRadius: 3, display: 'flex' }}
            onMouseEnter={e => e.currentTarget.style.color = '#e0e0e0'}
            onMouseLeave={e => e.currentTarget.style.color = '#888'}
          >
            <X size={15} />
          </button>
        </div>

        {/* New conversation */}
        <button
          onClick={onNew}
          style={{
            color: '#4a9eff', background: 'transparent',
            border: 'none', borderBottom: '1px solid #2a2a2a',
            cursor: 'pointer', display: 'flex', alignItems: 'center',
            gap: 8, padding: '10px 16px', fontSize: 12, fontFamily: 'inherit',
            textAlign: 'left', flexShrink: 0,
          }}
          onMouseEnter={e => e.currentTarget.style.background = '#161616'}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
          <Plus size={13} /> New conversation
        </button>

        {/* Session list */}
        <div className="flex-1 overflow-y-auto">
          {sessions.length === 0 && (
            <div style={{ color: '#666', fontSize: 12 }} className="px-4 py-8 text-center">
              No conversations yet
            </div>
          )}
          {sessions.map(s => (
            <SessionItem key={s.id} session={s}
              active={s.id === activeSessionId}
              onSelect={() => { onSelect(s.id); onClose() }}
              onDelete={() => onDelete(s.id)}
              onRename={title => onRename?.(s.id, title)}
              onContextMenu={handleContextMenu}
            />
          ))}
        </div>

        {/* Footer */}
        <div style={{ borderTop: '1px solid #2a2a2a', padding: '8px 16px', flexShrink: 0 }}>
          <span style={{ ...MONO, fontSize: 10, color: '#666' }}>
            {sessions.length} conversation{sessions.length !== 1 ? 's' : ''} · right-click to rename / delete
          </span>
        </div>
      </div>

      {ctxMenu && (
        <ContextMenu
          x={ctxMenu.x}
          y={ctxMenu.y}
          items={ctxMenu.items}
          onClose={() => setCtxMenu(null)}
        />
      )}
    </>
  )
}

function formatDate(isoStr) {
  if (!isoStr) return ''
  const d = new Date(isoStr)
  return d.toISOString().slice(0, 10)
}
