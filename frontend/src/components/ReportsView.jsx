import { useEffect, useState } from 'react'

const MONO = { fontFamily: '"Fira Code", monospace' }
const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }

function gradeColor(g) { return GRADE_COLOR[g] || '#888' }
function gradeAlpha(g) { return (GRADE_COLOR[g] || '#888') + '14' }

function fmtDate(iso) {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) }
  catch { return iso }
}

export default function ReportsView({ token }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  const authHeaders = token ? { Authorization: `Bearer ${token}` } : {}

  useEffect(() => {
    fetch('/api/history?limit=50', { headers: authHeaders })
      .then(r => r.json())
      .then(setScans)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return (
    <div style={{ flex: 1, overflowY: 'auto', background: '#0a0a0a' }}>
      <div style={{ maxWidth: 800, margin: '0 auto', padding: '32px 24px' }}>

        {/* Section label */}
        <div style={{ ...MONO, fontSize: 10, letterSpacing: '0.1em', color: '#555', textTransform: 'uppercase', marginBottom: 16 }}>
          Scan Reports ({scans.length})
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
          return (
            <div
              key={scan.id}
              style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 5, marginBottom: 8, padding: '12px 16px' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {/* Grade box */}
                <div style={{
                  width: 32, height: 32, flexShrink: 0,
                  border: `1px solid ${gc}`,
                  background: ga,
                  borderRadius: 3,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  ...MONO, color: gc, fontWeight: 700, fontSize: 14,
                }}>
                  {grade || '?'}
                </div>

                {/* Info */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ ...MONO, color: '#e0e0e0', fontSize: 13, marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {scan.label || scan.target}
                  </div>
                  <div style={{ ...MONO, color: '#555', fontSize: 11 }}>
                    {scan.target} · {scan.finding_count ?? 0} findings · {fmtDate(scan.started_at)}
                  </div>
                </div>

                {/* Actions */}
                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                  <a
                    href={`/api/report/${scan.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      ...MONO, fontSize: 11, color: '#4a9eff',
                      border: '1px solid #1a2d45', background: '#0d1929',
                      borderRadius: 4, padding: '4px 10px',
                      textDecoration: 'none',
                    }}
                  >
                    HTML
                  </a>
                  <a
                    href={`/api/report/${scan.id}/pdf`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      ...MONO, fontSize: 11, color: '#888',
                      border: '1px solid #252525',
                      borderRadius: 4, padding: '4px 10px',
                      textDecoration: 'none',
                    }}
                  >
                    PDF
                  </a>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
