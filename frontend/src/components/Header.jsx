import { Clock, Settings, LogOut, Users } from 'lucide-react'
import logo from '../assets/logo.png'

export default function Header({ onHistory, onSettings, onAdmin, user, onLogout }) {
  return (
    <header
      style={{ background: '#0d0d0d', borderBottom: '1px solid #1a1a1a' }}
      className="h-12 flex items-center justify-between px-4 shrink-0"
    >
      <div className="flex items-center gap-2.5">
        <img src={logo} alt="AIVAS" style={{ height: 22, width: 22, objectFit: 'contain' }} />
        <span style={{ color: '#e0e0e0', fontWeight: 700, fontSize: 15, letterSpacing: '-0.3px' }}>
          AIVAS
        </span>
        <span style={{ color: '#444', fontSize: 12 }} className="select-none hidden sm:block">
          Vulnerability Assessment
        </span>
      </div>

      <div className="flex items-center gap-1">
        {user && (
          <div className="flex items-center gap-2 mr-2">
            {user.role === 'admin' && (
              <span
                style={{ background: '#4a9eff18', color: '#4a9eff', borderRadius: 4, fontSize: 10, padding: '2px 6px', letterSpacing: '0.05em' }}
                className="font-medium"
              >
                ADMIN
              </span>
            )}
            <span style={{ color: '#555', fontSize: 12 }}>{user.username}</span>
          </div>
        )}

        {user?.role === 'admin' && onAdmin && (
          <button
            onClick={onAdmin}
            style={{ color: '#666' }}
            className="p-2 rounded hover:text-white transition-colors"
            aria-label="User management"
            title="User management"
          >
            <Users size={16} />
          </button>
        )}

        <button
          onClick={onHistory}
          style={{ color: '#666' }}
          className="p-2 rounded hover:text-white transition-colors"
          aria-label="Conversation history"
          title="Conversations"
        >
          <Clock size={17} />
        </button>
        <button
          onClick={onSettings}
          style={{ color: '#666' }}
          className="p-2 rounded hover:text-white transition-colors"
          aria-label="Settings"
          title="Settings"
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
