import { Clock, Settings, LogOut, ShieldCheck } from 'lucide-react'

export default function Header({ onHistory, onSettings, user, onLogout }) {
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
        {user && (
          <div className="flex items-center gap-2 mr-1">
            {user.role === 'admin' && (
              <span style={{ background: '#4a9eff22', color: '#4a9eff', borderRadius: 4, fontSize: 10, padding: '1px 5px' }}>
                admin
              </span>
            )}
            <span style={{ color: '#555', fontSize: 12 }}>{user.username}</span>
          </div>
        )}
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
        {onLogout && (
          <button
            onClick={onLogout}
            style={{ color: '#666' }}
            className="p-2 rounded hover:text-red-400 transition-colors"
            aria-label="Sign out"
            title="Sign out"
          >
            <LogOut size={15} />
          </button>
        )}
      </div>
    </header>
  )
}
