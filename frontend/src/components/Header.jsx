import { Settings, LogOut, Users } from 'lucide-react'
import logo from '../assets/logo.png'

const MONO = { fontFamily: '"Fira Code", monospace' }
const TABS = ['Console', 'History', 'Targets', 'Reports']

export default function Header({ activeTab, onTabChange, onSettings, onAdmin, user, onLogout }) {
  return (
    <header
      style={{ background: '#0d0d0d', borderBottom: '1px solid #2a2a2a', height: 48 }}
      className="flex items-center justify-between px-4 shrink-0"
    >
      {/* Left: logo + name + tabs */}
      <div className="flex items-center h-full">
        <div className="flex items-center gap-2.5 mr-5">
          <img src={logo} alt="AIVAS" style={{ height: 22, width: 22, objectFit: 'contain' }} />
          <span style={{ color: '#e0e0e0', fontWeight: 700, fontSize: 15, letterSpacing: '-0.3px' }}>AIVAS</span>
        </div>

        {/* Tab row */}
        <nav className="flex items-stretch h-full">
          {TABS.map(tab => {
            const key = tab.toLowerCase()
            const active = activeTab === key
            return (
              <button
                key={key}
                onClick={() => onTabChange(key)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  boxShadow: active ? 'inset 0 -2px 0 #4a9eff' : 'none',
                  color: active ? '#e0e0e0' : '#999',
                  fontSize: 13,
                  padding: '0 14px',
                  cursor: 'pointer',
                  height: '100%',
                  transition: 'color 0.15s',
                  whiteSpace: 'nowrap',
                  display: 'flex',
                  alignItems: 'center',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.color = '#aaaaaa' }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.color = '#999' }}
              >
                {tab}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Right: user + actions */}
      <div className="flex items-center gap-1">
        {user && (
          <div className="flex items-center gap-2 mr-2">
            {user.role === 'admin' && (
              <span style={{ ...MONO, color: '#4a9eff', fontSize: 10, letterSpacing: '0.08em' }}>
                ADMIN
              </span>
            )}
            <span style={{ ...MONO, color: '#888', fontSize: 12 }}>{user.username}</span>
          </div>
        )}

        {user?.role === 'admin' && onAdmin && (
          <button
            onClick={onAdmin}
            style={{ color: '#888', background: 'none', border: 'none', cursor: 'pointer', padding: 8, borderRadius: 4 }}
            onMouseEnter={e => { e.currentTarget.style.color = '#e0e0e0'; e.currentTarget.style.background = '#161616' }}
            onMouseLeave={e => { e.currentTarget.style.color = '#888'; e.currentTarget.style.background = 'none' }}
            aria-label="User management"
            title="User management"
          >
            <Users size={16} />
          </button>
        )}

        <button
          onClick={onSettings}
          style={{ color: '#888', background: 'none', border: 'none', cursor: 'pointer', padding: 8, borderRadius: 4 }}
          onMouseEnter={e => { e.currentTarget.style.color = '#e0e0e0'; e.currentTarget.style.background = '#161616' }}
          onMouseLeave={e => { e.currentTarget.style.color = '#888'; e.currentTarget.style.background = 'none' }}
          aria-label="Settings"
          title="Settings"
        >
          <Settings size={16} />
        </button>

        {onLogout && (
          <button
            onClick={onLogout}
            style={{ color: '#888', background: 'none', border: 'none', cursor: 'pointer', padding: 8, borderRadius: 4 }}
            onMouseEnter={e => { e.currentTarget.style.color = '#ef5350'; e.currentTarget.style.background = '#161616' }}
            onMouseLeave={e => { e.currentTarget.style.color = '#888'; e.currentTarget.style.background = 'none' }}
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
