import { useEffect, useState, useCallback, useRef } from 'react'
import ContextMenu from './ContextMenu'

const MONO = { fontFamily: '"Fira Code", monospace' }
const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }

function gradeColor(g) { return GRADE_COLOR[g] || '#888' }
function gradeAlpha(g) { return (GRADE_COLOR[g] || '#888') + '14' }

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) }
  catch { return iso }
}

const PAGE = 20

export default function ReportsView({ token }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [hasMore, setHasMore] = useState(true)
  const [ctxMenu, setCtxMenu] = useState(null)
  const offsetRef = useRef(0)

  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {}

  const loadPage = useCallback(async (offset, replace = false) => {
    if (offset === 0) setLoading(true); else setLoadingMore(true)
    try {
      const rows = await fetch(`/api/history?limit=${PAGE}&offset=${offset}`, { headers: authHeaders })
        .then(r => r.json())
      setScans(prev => replace ? rows : [...prev, ...rows])
      setHasMore(rows.length === PAGE)
      offsetRef.current = offset + rows.length
    } catch {}
    setLoading(false)
    setLoadingMore(false)
  }, [])

  useEffect(() => { loadPage(0, true) }, [])

  const deleteScan = async (id) => {
    await fetch(`/api/scan/${id}`, { method: 'DELETE', headers: authHeaders }).catch(() => {})
    setScans(prev => prev.filter(s => s.id !== id))
    offsetRef.current = Math.max(0, offsetRef.current - 1)
  }

  const handleContextMenu = (e, id) => {
    e.preventDefault()
    setCtxMenu({
      x: e.clientX, y: e.clientY,
      items: [{ label: 'Delete', onClick: () => deleteScan(id), danger: true }],
    })
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', background: '#0a0a0a' }}>
      <div style={{ maxWidth: 800, margin: '0 auto', padding: '32px 24px' }}>

        <div style={{ ...MONO, fontSize: 10, letterSpacing: '0.1em', color: '#555555', textTransform: 'uppercase', marginBottom: 16 }}>
          Scan Reports ({scans.length}{hasMore ? '+' : ''})
        </div>

        {loading && (
          <div style={{ color: '#444', fontSize: 13, textAlign: 'center', paddingTop: 48 }}>Loading…</div>
        )}

        {!loading && scans.length === 0 && (
          <div style={{ color: '#444', fontSize: 13, textAlign: 'center', paddingTop: 48 }}>
            No scans yet. Run a scan from the Console tab.
          </div>
        )}

        {!loading && scans.map(scan => {
          const grade = (scan.grade || '').replace('Grade ', '')
          const gc = gradeColor(grade)
          const ga = gradeAlpha(grade)
          const label = scan.label || `${scan.target} — ${fmtDate(scan.started_at)}`
          return (
            <div
              key={scan.id}
              style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 5, marginBottom: 8, padding: '12px 16px', cursor: 'default' }}
              onContextMenu={e => handleContextMenu(e, scan.id)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 32, height: 32, flexShrink: 0,
                  border: `1px solid ${gc}`, background: ga, borderRadius: 3,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  ...MONO, color: gc, fontWeight: 700, fontSize: 14,
                }}>
                  {grade || '?'}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ ...MONO, color: '#e0e0e0', fontSize: 13, marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {label}
                  </div>
                  <div style={{ ...MONO, color: '#555555', fontSize: 11 }}>
                    {scan.target} · {scan.finding_count ?? 0} findings · {fmtDate(scan.started_at)}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                  <a
                    href={`/api/report/${scan.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ ...MONO, fontSize: 11, color: '#4a9eff', border: '1px solid #1a2d45', background: '#0d1929', borderRadius: 4, padding: '4px 10px', textDecoration: 'none' }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = '#4a9eff'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = '#1a2d45'}
                  >
                    HTML
                  </a>
                  <a
                    href={`/api/report/${scan.id}/pdf`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ ...MONO, fontSize: 11, color: '#888888', border: '1px solid #252525', borderRadius: 4, padding: '4px 10px', textDecoration: 'none' }}
                    onMouseEnter={e => { e.currentTarget.style.color = '#c0c0c0'; e.currentTarget.style.borderColor = '#333' }}
                    onMouseLeave={e => { e.currentTarget.style.color = '#888888'; e.currentTarget.style.borderColor = '#252525' }}
                  >
                    PDF
                  </a>
                </div>
              </div>
            </div>
          )
        })}

        {hasMore && !loading && (
          <button
            onClick={() => loadPage(offsetRef.current)}
            disabled={loadingMore}
            style={{ ...MONO, fontSize: 11, color: '#555555', background: 'transparent', border: '1px solid #252525', borderRadius: 4, padding: '8px 20px', cursor: 'pointer', width: '100%', marginTop: 8 }}
            onMouseEnter={e => { e.currentTarget.style.color = '#888'; e.currentTarget.style.borderColor = '#3a3a3a' }}
            onMouseLeave={e => { e.currentTarget.style.color = '#555555'; e.currentTarget.style.borderColor = '#252525' }}
          >
            {loadingMore ? 'Loading…' : 'Load more'}
          </button>
        )}
      </div>

      {ctxMenu && (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} items={ctxMenu.items} onClose={() => setCtxMenu(null)} />
      )}
    </div>
  )
}
