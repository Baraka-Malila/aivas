import { useState } from 'react'
import { ExternalLink } from 'lucide-react'

const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }
const SEV_TEXT    = { CRITICAL: '#ef5350', HIGH: '#ff7043', MEDIUM: '#fdd835', LOW: '#66bb6a' }
const SEV_ORDER   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const SHOW_DEFAULT = 5

export default function ScanCard({ scanData, onSend }) {
  const { scan_id, target, grade, service_count, findings = [], counts = {}, log } = scanData
  const [showAll, setShowAll] = useState(false)

  const ranked = [...findings].sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
  const visible = showAll ? ranked : ranked.slice(0, SHOW_DEFAULT)
  const hasMore = ranked.length > SHOW_DEFAULT

  const gradeColor = GRADE_COLOR[grade] || '#e0e0e0'

  return (
    <div
      style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 8 }}
      className="mt-2 overflow-hidden text-sm"
    >
      {/* Header */}
      <div
        style={{ borderBottom: '1px solid #1e1e1e' }}
        className="flex justify-between items-start px-3 py-2.5"
      >
        <div>
          <span style={{ color: '#e0e0e0', fontFamily: 'monospace' }} className="text-sm">
            {target}
          </span>
          <div style={{ color: '#666' }} className="text-xs mt-0.5">
            {service_count} service{service_count !== 1 ? 's' : ''} · {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </div>
        </div>
        <span
          data-testid="grade-badge"
          style={{ color: gradeColor, fontWeight: 700, fontSize: 20, lineHeight: 1 }}
        >
          {grade}
        </span>
      </div>

      {/* Severity pills */}
      {SEV_ORDER.some(s => counts[s] > 0) && (
        <div style={{ borderBottom: '1px solid #1e1e1e' }} className="flex flex-wrap gap-3 px-3 py-2">
          {SEV_ORDER.filter(s => counts[s] > 0).map(s => (
            <span
              key={s}
              style={{ color: SEV_TEXT[s], fontSize: 11, fontFamily: 'monospace', fontWeight: 600 }}
            >
              {counts[s]} {s}
            </span>
          ))}
        </div>
      )}

      {/* CVE flat list */}
      {findings.length === 0 ? (
        <div style={{ borderBottom: '1px solid #1e1e1e' }} className="px-3 py-2">
          <span style={{ color: '#66bb6a' }} className="text-xs">No vulnerabilities found</span>
        </div>
      ) : (
        <div style={{ borderBottom: '1px solid #1e1e1e' }}>
          {visible.map((f, i) => {
            const sev = (f.cvss_severity || 'LOW').toUpperCase()
            return (
              <div
                key={f.cve_id || i}
                style={{ borderBottom: '1px solid #141414' }}
                className="flex items-center gap-2 px-3 py-1.5"
              >
                {f.kev && (
                  <span style={{ color: '#ff7043', fontSize: 10, fontWeight: 700 }} className="shrink-0">
                    ⚠ KEV
                  </span>
                )}
                <span
                  style={{ color: SEV_TEXT[sev] || '#e0e0e0', fontFamily: 'monospace', fontSize: 11 }}
                  className="shrink-0 w-36 truncate"
                >
                  {f.cve_id}
                </span>
                <span style={{ color: '#888', fontSize: 11 }} className="flex-1 truncate">
                  {f.description}
                </span>
                <span
                  style={{ color: SEV_TEXT[sev] || '#e0e0e0', fontFamily: 'monospace', fontSize: 11 }}
                  className="shrink-0"
                >
                  {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                </span>
              </div>
            )
          })}
          {hasMore && !showAll && (
            <button
              onClick={() => setShowAll(true)}
              style={{ background: 'transparent', border: 'none', color: '#555', width: '100%', textAlign: 'left' }}
              className="text-xs px-3 py-1.5 hover:text-white transition-colors cursor-pointer"
            >
              Show all {ranked.length}
            </button>
          )}
        </div>
      )}

      {/* Action buttons */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-2.5">
        <button
          onClick={() => onSend(`Narrate the findings from scan ${scan_id}`)}
          style={{ background: '#0d1929', border: '1px solid #1a2d45', color: '#4a9eff' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          Narrate
        </button>
        <button
          onClick={() => onSend(`Explain the worst vulnerability from scan ${scan_id}`)}
          style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          Explain worst
        </button>
        <button
          onClick={() => onSend(`Scan ${target} again`)}
          style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          Rescan
        </button>
        <div className="ml-auto flex items-center gap-3">
          <a
            href={`/api/report/${scan_id}/fix.sh`}
            download={`fix-scan-${scan_id}.sh`}
            style={{ color: '#555' }}
            className="text-xs flex items-center gap-1 hover:text-white transition-colors"
          >
            Fix Script
          </a>
          <a
            href={`/api/report/${scan_id}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#666' }}
            className="text-xs flex items-center gap-1 hover:text-white transition-colors"
          >
            View full report <ExternalLink size={10} />
          </a>
        </div>
      </div>

      {/* Scan Log */}
      {log && log.length > 0 && (
        <details style={{ borderTop: '1px solid #1e1e1e' }}>
          <summary
            style={{ color: '#666', cursor: 'pointer', userSelect: 'none' }}
            className="px-3 py-2 text-xs hover:text-white transition-colors"
          >
            Scan Log ({log.length} events)
          </summary>
          <div
            style={{ background: '#0a0a0a', maxHeight: 200, overflowY: 'auto' }}
            className="px-3 py-2"
          >
            {log.map((entry, i) => (
              <div key={i} style={{ color: '#555', fontFamily: 'monospace' }} className="text-xs py-0.5">
                {entry}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  )
}
