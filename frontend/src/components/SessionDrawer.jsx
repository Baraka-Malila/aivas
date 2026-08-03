import { useEffect, useState, useRef } from 'react'
import { X, Plus, Check } from 'lucide-react'
import ContextMenu from './ContextMenu'

const MONO = { fontFamily: '"Fira Code", monospace' }

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

function SessionItem({ session, onSelect, onDelete, onRename, onContextMenu }) {
  const [editing, setEditing] = useState(false)
  return (
    <div
      style={{ borderBottom: '1px solid #141414' }}
      className="flex items-center px-4 py-3 hover:bg-white/5 transition-colors cursor-pointer"
      onClick={onSelect}
      onContextMenu={e => { e.preventDefault(); onContextMenu(e, { onRename: () => setEditing(true), onDelete }) }}
    >
      <div className="flex-1 min-w-0">
        {editing ? (
          <InlineRename
            value={session.title || 'New conversation'}
            onSave={t => { onRename(t); setEditing(false) }}
            onCancel={() => setEditing(false)}
          />
        ) : (
          <div style={{ color: '#e0e0e0', fontSize: 12 }} className="truncate">
            {session.title || 'New conversation'}
          </div>
        )}
        <div style={{ ...MONO, color: '#444', fontSize: 10, marginTop: 2 }}>{formatDate(session.updated_at)}</div>
      </div>
    </div>
  )
}

export default function SessionDrawer({ open, sessions, onClose, onSelect, onDelete, onNew, onRename }) {
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
        style={{ background: '#111111', borderLeft: '1px solid #1e1e1e', width: 300 }}
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col"
      >
        {/* Header */}
        <div
          style={{ borderBottom: '1px solid #1e1e1e' }}
          className="flex items-center justify-between px-4 py-3 shrink-0"
        >
          <span style={{ ...MONO, color: '#555', fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            Conversations
          </span>
          <button onClick={onClose} style={{ color: '#444', background: 'none', border: 'none', cursor: 'pointer', padding: 4, borderRadius: 3 }}
            onMouseEnter={e => e.currentTarget.style.color = '#e0e0e0'}
            onMouseLeave={e => e.currentTarget.style.color = '#444'}
          >
            <X size={14} />
          </button>
        </div>

        {/* New conversation */}
        <button
          onClick={onNew}
          style={{ borderBottom: '1px solid #1e1e1e', color: '#4a9eff', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', fontSize: 12 }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
          onMouseLeave={e => e.currentTarget.style.background = 'none'}
        >
          <Plus size={13} /> New conversation
        </button>

        {/* Session list */}
        <div className="flex-1 overflow-y-auto">
          {sessions.length === 0 && (
            <div style={{ color: '#444', fontSize: 12 }} className="px-4 py-8 text-center">
              No conversations yet
            </div>
          )}
          {sessions.map(s => (
            <SessionItem key={s.id} session={s}
              onSelect={() => { onSelect(s.id); onClose() }}
              onDelete={() => onDelete(s.id)}
              onRename={title => onRename?.(s.id, title)}
              onContextMenu={handleContextMenu}
            />
          ))}
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
  return new Date(isoStr).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}
