import { useEffect } from 'react'
import { X, Trash2, Plus } from 'lucide-react'

export default function SessionDrawer({ open, sessions, onClose, onSelect, onDelete, onNew }) {
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
            <div
              key={s.id}
              style={{ borderBottom: '1px solid #141414' }}
              className="group flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors cursor-pointer"
              onClick={() => { onSelect(s); onClose() }}
            >
              <div className="flex-1 min-w-0 pr-2">
                <div style={{ color: '#e0e0e0' }} className="text-xs truncate">
                  {s.title || 'New conversation'}
                </div>
                <div style={{ color: '#666' }} className="text-xs mt-0.5">
                  {formatDate(s.updated_at)}
                </div>
              </div>
              <button
                onClick={e => { e.stopPropagation(); onDelete(s.id) }}
                style={{ color: '#444' }}
                className="opacity-0 group-hover:opacity-100 p-1 hover:text-red-400 transition-all shrink-0"
                aria-label="Delete conversation"
              >
                <Trash2 size={13} />
              </button>
            </div>
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
