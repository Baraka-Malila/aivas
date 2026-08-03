import { useState, useEffect } from 'react'
import { Trash2 } from 'lucide-react'

const INTERVALS = [
  { value: 'hourly', label: 'Every hour',  color: '#4a9eff' },
  { value: 'daily',  label: 'Every day',   color: '#66bb6a' },
  { value: 'weekly', label: 'Every week',  color: '#ff9800' },
]

const inp = { background: '#0f0f0f', border: '1px solid #252525', color: '#e0e0e0' }

function fmtTime(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) }
  catch { return iso }
}

function Toggle({ on, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{ width: 32, height: 18, borderRadius: 9, background: on ? '#4a9eff' : '#2a2a2a', position: 'relative', transition: 'background 0.2s', flexShrink: 0 }}
    >
      <span style={{
        position: 'absolute', top: 2,
        left: on ? 16 : 2, width: 14, height: 14, borderRadius: 7,
        background: '#fff', transition: 'left 0.2s',
      }} />
    </button>
  )
}

export default function ScheduleSection({ remoteTargets = [] }) {
  const [schedules, setSchedules] = useState([])
  const [form, setForm] = useState({ label: '', target: '', interval: 'daily', remote_target_id: '' })

  useEffect(() => {
    fetch('/api/schedules').then(r => r.json()).then(setSchedules).catch(() => {})
  }, [])

  const save = async () => {
    if (!form.target) return
    const body = {
      label: form.label || form.target,
      target: form.target,
      interval: form.interval,
      remote_target_id: form.remote_target_id ? Number(form.remote_target_id) : null,
    }
    const resp = await fetch('/api/schedules', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).catch(() => null)
    if (resp?.ok) {
      const saved = await resp.json()
      setSchedules(prev => [saved, ...prev])
      setForm({ label: '', target: '', interval: 'daily', remote_target_id: '' })
    }
  }

  const toggle = async (id, enabled) => {
    const resp = await fetch(`/api/schedules/${id}`, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !enabled }),
    }).catch(() => null)
    if (resp?.ok) {
      const updated = await resp.json()
      setSchedules(prev => prev.map(s => s.id === id ? updated : s))
    }
  }

  const del = async (id) => {
    await fetch(`/api/schedules/${id}`, { method: 'DELETE' }).catch(() => {})
    setSchedules(prev => prev.filter(s => s.id !== id))
  }

  return (
    <>
      <div className="mb-5 space-y-2">
        {schedules.length === 0 && (
          <p style={{ color: '#444' }} className="text-xs py-2">No scheduled scans yet.</p>
        )}
        {schedules.map(s => {
          const iv = INTERVALS.find(i => i.value === s.interval)
          return (
            <div key={s.id} style={{ background: '#1a1a1a', border: '1px solid #252525', borderRadius: 6 }}
                 className="px-3 py-2.5 text-xs">
              <div className="flex items-center gap-2 mb-1">
                <span style={{ color: '#e0e0e0', fontWeight: 500 }}>{s.label}</span>
                <span style={{ background: (iv?.color ?? '#888') + '22', color: iv?.color ?? '#888', borderRadius: 4, padding: '1px 6px', fontSize: 10 }}>
                  {s.interval}
                </span>
                <div className="ml-auto flex items-center gap-3">
                  <Toggle on={Boolean(s.enabled)} onClick={() => toggle(s.id, s.enabled)} />
                  <button onClick={() => del(s.id)} style={{ color: '#555' }} className="hover:text-red-400 transition-colors">
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
              <div style={{ color: '#555' }} className="flex flex-wrap gap-x-4">
                <span>Target: <span style={{ color: '#888' }}>{s.target}</span></span>
                <span>Next: <span style={{ color: '#888' }}>{fmtTime(s.next_run)}</span></span>
                {s.last_run && <span>Last: <span style={{ color: '#888' }}>{fmtTime(s.last_run)}</span></span>}
              </div>
            </div>
          )
        })}
      </div>

      <div style={{ border: '1px solid #252525', borderRadius: 8 }} className="p-3">
        <p style={{ color: '#888' }} className="text-xs font-medium mb-2">Add Schedule</p>
        <input type="text" placeholder="Label"
          value={form.label} onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
          style={{ ...inp, width: '100%' }} className="rounded px-2 py-1.5 text-xs outline-none mb-2" />
        <div className="flex gap-2 mb-2">
          <input type="text" placeholder="Target IP or CIDR"
            value={form.target} onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
            style={{ ...inp, flex: 1 }} className="rounded px-2 py-1.5 text-xs outline-none" />
          <select value={form.interval} onChange={e => setForm(f => ({ ...f, interval: e.target.value }))}
            style={{ ...inp, width: 110 }} className="rounded px-2 py-1.5 text-xs outline-none">
            {INTERVALS.map(i => <option key={i.value} value={i.value}>{i.label}</option>)}
          </select>
        </div>
        {remoteTargets.length > 0 && (
          <select value={form.remote_target_id}
            onChange={e => setForm(f => ({ ...f, remote_target_id: e.target.value }))}
            style={{ ...inp, width: '100%' }} className="rounded px-2 py-1.5 text-xs outline-none mb-2">
            <option value="">No credentials (nmap only)</option>
            {remoteTargets.map(t => (
              <option key={t.id} value={t.id}>{t.label} — {t.username}@{t.host}</option>
            ))}
          </select>
        )}
        <button onClick={save} disabled={!form.target}
          style={{ background: '#4a9eff', border: 'none', color: '#000000', fontWeight: 600 }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-90 transition-opacity disabled:cursor-not-allowed disabled:opacity-40 mt-2">
          Save Schedule
        </button>
      </div>
    </>
  )
}
