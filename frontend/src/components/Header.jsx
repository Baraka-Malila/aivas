import { Clock, Settings } from 'lucide-react'

export default function Header({ onHistory, onSettings }) {
  return (
    <header
      style={{ background: '#0d0d0d', borderBottom: '1px solid #1a1a1a' }}
      className="h-12 flex items-center justify-between px-4 shrink-0"
    >
      <div className="flex items-center gap-2">
        <span style={{ color: '#4a9eff' }} className="font-semibold text-sm select-none">
          ✦ AIVAS
        </span>
        <span style={{ color: '#666' }} className="text-xs select-none">
          Network Security
        </span>
      </div>
      <div className="flex items-center gap-1">
        <button
          onClick={onHistory}
          style={{ color: '#666' }}
          className="p-2 rounded hover:text-white transition-colors"
          aria-label="Conversation history"
        >
          <Clock size={17} />
        </button>
        <button
          onClick={onSettings}
          style={{ color: '#666' }}
          className="p-2 rounded hover:text-white transition-colors"
          aria-label="Settings"
        >
          <Settings size={17} />
        </button>
      </div>
    </header>
  )
}
