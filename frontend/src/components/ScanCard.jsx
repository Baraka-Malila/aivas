import { useState } from 'react'
import { ExternalLink, ChevronRight, ChevronDown, MessageSquare } from 'lucide-react'

const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }
const SEV_TEXT    = { CRITICAL: '#ef5350', HIGH: '#ff7043', MEDIUM: '#fdd835', LOW: '#66bb6a' }
const SEV_ORDER   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const MISCONFIG_SEV_TEXT = { HIGH: '#ff7043', MEDIUM: '#fdd835', LOW: '#66bb6a', INFO: '#888' }

export default function ScanCard({ scanData, onSend, onAnalysis }) {
  const { scan_id, target, grade, service_count, findings = [], misconfigs = [], log, partial } = scanData

  const hasCritical = findings.some(f => (f.cvss_severity || '').toUpperCase() === 'CRITICAL')
  const [expanded, setExpanded] = useState({
    CRITICAL: hasCritical,
    HIGH: false,
    MEDIUM: false,
    LOW: false,
  })
  const toggleGroup = (sev) => setExpanded(e => ({ ...e, [sev]: !e[sev] }))

  const grouped = SEV_ORDER.reduce((acc, sev) => {
    acc[sev] = findings
      .filter(f => (f.cvss_severity || 'LOW').toUpperCase() === sev)
      .sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
    return acc
  }, {})

  const gradeColor    = GRADE_COLOR[grade] || '#e0e0e0'
  const totalFindings = findings.length

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
            {service_count} service{service_count !== 1 ? 's' : ''} · {totalFindings} finding{totalFindings !== 1 ? 's' : ''}
          </div>
        </div>
        <span
          data-testid="grade-badge"
          style={{ color: gradeColor, fontWeight: 700, fontSize: 20, lineHeight: 1 }}
        >
          {grade}
        </span>
      </div>

      {/* Partial results banner */}
      {partial && (
        <div style={{ background: '#2a1f00', borderBottom: '1px solid #4a3800', color: '#fdd835' }}
             className="px-3 py-2 text-xs flex items-center gap-2">
          <span style={{ fontWeight: 600 }}>!</span>
          <span>Scan stopped early — results may be incomplete. Saved findings shown below.</span>
        </div>
      )}

      {/* CVE groups */}
      {totalFindings === 0 ? (
        <div style={{ borderBottom: '1px solid #1e1e1e' }} className="px-3 py-2">
          <span style={{ color: '#66bb6a' }} className="text-xs">No vulnerabilities found</span>
        </div>
      ) : (
        <div style={{ borderBottom: '1px solid #1e1e1e' }}>
          {SEV_ORDER.filter(sev => grouped[sev].length > 0).map(sev => (
            <div key={sev} style={{ borderBottom: '1px solid #1e1e1e' }}>
              <button
                data-testid={`group-header-${sev}`}
                onClick={() => toggleGroup(sev)}
                style={{ background: 'transparent', border: 'none' }}
                className="w-full flex items-center gap-2 px-3 py-2 cursor-pointer hover:opacity-80 transition-opacity"
              >
                {expanded[sev]
                  ? <ChevronDown size={12} color="#555" />
                  : <ChevronRight size={12} color="#555" />
                }
                <span style={{ color: SEV_TEXT[sev], fontFamily: 'monospace', fontSize: 11, fontWeight: 600 }}>
                  {sev}
                </span>
                <span style={{ color: '#555', fontSize: 11 }}>
                  ({grouped[sev].length})
                </span>
              </button>

              {expanded[sev] && grouped[sev].map((f, i) => (
                <div
                  key={f.cve_id || i}
                  data-testid={`cve-row-${f.cve_id}`}
                  style={{ borderTop: '1px solid #141414' }}
                  className="flex items-center gap-2 px-3 py-1.5"
                >
                  <button
                    data-testid={`ask-${f.cve_id}`}
                    onClick={() => onSend(
                      `Explain ${f.cve_id} from scan ${scan_id}. ` +
                      `What is the risk, what exact version fixes it, and what is the fastest remediation path?`
                    )}
                    style={{ background: 'transparent', border: 'none', padding: 0, cursor: 'pointer', color: '#666', lineHeight: 1 }}
                    className="shrink-0 hover:text-blue-400 transition-colors"
                    title={`Ask about ${f.cve_id}`}
                  >
                    <MessageSquare size={12} />
                  </button>
                  {f.kev && (
                    <span style={{ color: '#ff7043', fontSize: 10, fontWeight: 700, background: '#ff704318', borderRadius: 3, padding: '1px 4px' }} className="shrink-0">
                      KEV
                    </span>
                  )}
                  <span
                    style={{ color: '#e0e0e0', fontFamily: 'monospace', fontSize: 11 }}
                    className="shrink-0 w-36 truncate"
                  >
                    {f.cve_id}
                  </span>
                  <span style={{ color: '#888', fontSize: 11 }} className="flex-1 truncate">
                    {f.description}
                  </span>
                  <span
                    style={{ color: SEV_TEXT[sev], fontFamily: 'monospace', fontSize: 11 }}
                    className="shrink-0"
                  >
                    {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* Misconfigurations */}
      {misconfigs.length > 0 && (
        <details style={{ borderBottom: '1px solid #1e1e1e' }}>
          <summary
            style={{ color: '#ff7043', cursor: 'pointer', userSelect: 'none' }}
            className="px-3 py-2 text-xs hover:opacity-80 transition-opacity flex items-center gap-1"
          >
            Configuration Issues ({misconfigs.length})
          </summary>
          <div>
            {misconfigs.map((mc, i) => (
              <div
                key={i}
                style={{ borderTop: '1px solid #141414' }}
                className="px-3 py-2"
              >
                <div className="flex items-center gap-2 mb-0.5">
                  <span
                    style={{
                      color: MISCONFIG_SEV_TEXT[(mc.severity || 'INFO').toUpperCase()] || '#888',
                      fontFamily: 'monospace',
                      fontSize: 10,
                      fontWeight: 600,
                    }}
                  >
                    {(mc.severity || 'INFO').toUpperCase()}
                  </span>
                  <span style={{ color: '#e0e0e0', fontSize: 11 }}>{mc.title}</span>
                  {mc.host && (
                    <span style={{ color: '#555', fontFamily: 'monospace', fontSize: 10 }} className="ml-auto shrink-0">
                      {mc.host}{mc.port ? `:${mc.port}` : ''}
                    </span>
                  )}
                </div>
                {mc.recommendation && (
                  <div style={{ color: '#888', fontSize: 11 }} className="mt-0.5">
                    {mc.recommendation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </details>
      )}

      {/* Action buttons */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-2.5">
        <button
          onClick={() => onAnalysis('risk_summary', scan_id)}
          style={{ background: '#0d1929', border: '1px solid #1a2d45', color: '#4a9eff' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          Risk Summary
        </button>
        <button
          onClick={() => onAnalysis('remediation', scan_id)}
          style={{ background: '#161616', border: '1px solid #1e1e1e', color: '#e0e0e0' }}
          className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity"
        >
          What to do
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
            className="text-xs hover:text-white transition-colors"
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
