const inp = { background: '#1a1a1a', border: '1px solid #3a3a3a', color: '#e0e0e0' }

export default function RemoteTargetsSection({
  remoteTargets, newTarget, setNewTarget,
  testResult, testing,
  onSave, onDelete, onTest, onScan, onClose,
}) {
  return (
    <>
      <div className="mb-4 space-y-1.5">
        {remoteTargets.length === 0 && (
          <p style={{ color: '#777' }} className="text-xs py-2">No saved targets yet.</p>
        )}
        {remoteTargets.map((t) => (
          <div key={t.id}
            style={{ background: '#1a1a1a', border: '1px solid #333', borderRadius: 6 }}
            className="flex items-center gap-2 px-3 py-2 text-xs"
          >
            <span style={{ color: '#4a9eff', fontFamily: 'monospace', fontSize: 10 }}>
              {(t.method || 'ssh').toUpperCase()}
            </span>
            <div className="flex flex-col min-w-0 flex-1">
              <span style={{ color: '#e0e0e0' }}>{t.label || `${t.username}@${t.host}`}</span>
              <span style={{ color: '#888' }}>{t.username}@{t.host}:{t.port}</span>
            </div>
            <div className="flex gap-3">
              {onScan && (
                <button
                  onClick={() => { onScan(t.host, { method: t.method, username: t.username, password: t.password, port: t.port }); onClose() }}
                  style={{ color: '#4a9eff' }}
                  className="hover:opacity-80 transition-opacity"
                >
                  Scan
                </button>
              )}
              <button
                onClick={() => onDelete(t.id)}
                style={{ color: '#888' }}
                className="hover:text-red-400 transition-colors"
              >✕</button>
            </div>
          </div>
        ))}
      </div>

      <div style={{ border: '1px solid #333', borderRadius: 8 }} className="p-3">
        <p style={{ color: '#888' }} className="text-xs font-medium mb-2">Add Target</p>

        <input type="text" placeholder="Label"
          value={newTarget.label}
          onChange={e => setNewTarget(t => ({ ...t, label: e.target.value }))}
          style={{ ...inp, width: '100%' }}
          className="rounded px-2 py-1.5 text-xs outline-none mb-2"
        />

        <div className="flex gap-2 mb-2">
          <select value={newTarget.method}
            onChange={e => setNewTarget(t => ({ ...t, method: e.target.value, port: e.target.value === 'ssh' ? 22 : 5985 }))}
            style={{ ...inp, width: 80 }}
            className="rounded px-2 py-1.5 text-xs outline-none"
          >
            <option value="ssh">SSH</option>
            <option value="winrm">WinRM</option>
          </select>
          <input type="text" placeholder="host or IP"
            value={newTarget.host}
            onChange={e => setNewTarget(t => ({ ...t, host: e.target.value }))}
            style={{ ...inp, flex: 1 }}
            className="rounded px-2 py-1.5 text-xs outline-none"
          />
          <input type="number" placeholder="port"
            value={newTarget.port}
            onChange={e => setNewTarget(t => ({ ...t, port: Number(e.target.value) }))}
            style={{ ...inp, width: 60 }}
            className="rounded px-2 py-1.5 text-xs outline-none"
          />
        </div>

        <div className="flex gap-2 mb-2">
          <input type="text" placeholder="username"
            value={newTarget.username}
            onChange={e => setNewTarget(t => ({ ...t, username: e.target.value }))}
            style={{ ...inp, flex: 1 }}
            className="rounded px-2 py-1.5 text-xs outline-none"
          />
          <input type="password" placeholder="password"
            value={newTarget.password}
            onChange={e => setNewTarget(t => ({ ...t, password: e.target.value }))}
            style={{ ...inp, flex: 1 }}
            className="rounded px-2 py-1.5 text-xs outline-none"
          />
        </div>

        <div className="flex gap-2 items-center">
          <button onClick={onTest}
            disabled={testing || !newTarget.host || !newTarget.username}
            style={{ background: '#1a1a1a', border: '1px solid #333', color: testing ? '#777' : '#e0e0e0' }}
            className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity disabled:cursor-not-allowed"
          >
            {testing ? 'Testing…' : 'Test'}
          </button>
          <button onClick={onSave}
            disabled={!newTarget.host || !newTarget.username}
            style={{ background: '#4a9eff', border: 'none', color: '#000000', fontWeight: 600 }}
            className="text-xs px-3 py-1.5 rounded hover:opacity-90 transition-opacity disabled:cursor-not-allowed"
          >
            Save
          </button>
          {testResult && (
            <span style={{ color: testResult.ok ? '#66bb6a' : '#ef5350' }} className="text-xs">
              {testResult.ok ? '✓ Connected' : `✗ ${testResult.error}`}
            </span>
          )}
        </div>
      </div>
    </>
  )
}
