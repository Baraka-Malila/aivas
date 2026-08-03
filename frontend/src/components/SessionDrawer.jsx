import { useEffect, useState, useRef } from 'react'
import { X, Trash2, Plus, Pencil, Check } from 'lucide-react'

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

function SessionItem({ session, onSelect, onDelete, onRename }) {
  const [editing, setEditing] = useState(false)
  return (
    <div
      style={{ borderBottom: '1px solid #141414' }}
      className="group flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors cursor-pointer"
      onClick={onSelect}
    >
      <div className="flex-1 min-w-0 pr-2">
        {editing ? (
          <InlineRename
            value={session.title || 'New conversation'}
            onSave={t => { onRename(t); setEditing(false) }}
            onCancel={() => setEditing(false)}
          />
        ) : (
          <div style={{ color: '#e0e0e0' }} className="text-xs truncate">
            {session.title || 'New conversation'}
          </div>
        )}
        <div style={{ color: '#666' }} className="text-xs mt-0.5">{formatDate(session.updated_at)}</div>
      </div>
      {!editing && (
        <div className="opacity-0 group-hover:opacity-100 flex items-center gap-1 shrink-0 transition-opacity">
          <button
            onClick={e => { e.stopPropagation(); setEditing(true) }}
            style={{ color: '#444' }}
            className="p-1 hover:text-[#4a9eff] transition-colors"
            aria-label="Rename conversation"
          >
            <Pencil size={11} />
          </button>
          <button
            onClick={e => { e.stopPropagation(); onDelete() }}
            style={{ color: '#444' }}
            className="p-1 hover:text-red-400 transition-colors"
            aria-label="Delete conversation"
          >
            <Trash2 size={13} />
          </button>
        </div>
      )}
    </div>
  )
}

export default function SessionDrawer({ open, sessions, onClose, onSelect, onDelete, onNew, onRename }) {
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

  return (
    <>
      <div
        style={{ background: 'rgba(0,0,0,0.6)' }}
        className="fixed inset-0 z-40"
        onClick={onClose}
      />
      <div
        data-testid="session-drawer"
        style={{ background: '#111111', borderLeft: '1px solid #1e1e1e', width: 320 }}
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col"
      >
        {/* Header */}
        <div
          style={{ borderBottom: '1px solid #1e1e1e' }}
          className="flex items-center justify-between px-4 py-3 shrink-0"
        >
          <span style={{ color: '#e0e0e0' }} className="font-medium text-sm">Conversations</span>
          <button onClick={onClose} style={{ color: '#666' }} className="p-1 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>

        {/* New conversation */}
        <button
          onClick={onNew}
          style={{ borderBottom: '1px solid #1e1e1e', color: '#4a9eff' }}
          className="flex items-center gap-2 px-4 py-2.5 text-xs hover:bg-white/5 transition-colors text-left shrink-0"
        >
          <Plus size={14} /> New conversation
        </button>

        {/* Session list */}
        <div className="flex-1 overflow-y-auto">
          {sessions.length === 0 && (
            <div style={{ color: '#666' }} className="px-4 py-8 text-xs text-center">
              No conversations yet
            </div>
          )}
          {sessions.map(s => (
            <SessionItem key={s.id} session={s}
              onSelect={() => { onSelect(s.id); onClose() }}
              onDelete={() => onDelete(s.id)}
              onRename={title => onRename?.(s.id, title)}
            />
          ))}
        </div>
      </div>
    </>
  )
}

function formatDate(isoStr) {
  if (!isoStr) return ''
  return new Date(isoStr).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}
