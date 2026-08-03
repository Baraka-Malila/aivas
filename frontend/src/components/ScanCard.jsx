import { useState } from 'react'
import { MessageSquare, ExternalLink } from 'lucide-react'

const MONO = { fontFamily: '"Fira Code", monospace' }

const GRADE_COLOR = { A: '#66bb6a', B: '#aed581', C: '#fdd835', D: '#ff7043', F: '#ef5350' }
const SEV_COLOR   = { CRITICAL: '#ef5350', HIGH: '#ff7043', MEDIUM: '#fdd835', LOW: '#66bb6a' }
const SEV_ORDER   = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function gradeAlpha(g) { return (GRADE_COLOR[g] || '#888') + '14' }

const SECTION_LABEL = {
  ...MONO,
  fontSize: 10,
  letterSpacing: '0.1em',
  color: '#555',
  textTransform: 'uppercase',
}

export default function ScanCard({ scanData, onSend, onAnalysis }) {
  const {
    scan_id, target, grade: rawGrade, score,
    service_count, findings = [], misconfigs = [], partial,
  } = scanData

  const grade = (rawGrade || '').replace('Grade ', '')
  const gc = GRADE_COLOR[grade] || '#888'
  const ga = gradeAlpha(grade)

  const grouped = SEV_ORDER.reduce((acc, sev) => {
    acc[sev] = findings
      .filter(f => (f.cvss_severity || 'LOW').toUpperCase() === sev)
      .sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
    return acc
  }, {})

  const counts = SEV_ORDER.reduce((acc, sev) => {
    acc[sev] = grouped[sev].length
    return acc
  }, {})

  const hasCritical = counts.CRITICAL > 0
  const [expanded, setExpanded] = useState({
    CRITICAL: hasCritical, HIGH: false, MEDIUM: false, LOW: false,
  })
  const toggleGroup = (sev) => setExpanded(e => ({ ...e, [sev]: !e[sev] }))

  const totalFindings = findings.length

  return (
    <div
      data-testid="scan-card"
      style={{ background: '#111111', border: '1px solid #1e1e1e', borderRadius: 5 }}
      className="mt-2 overflow-hidden"
    >
      {/* Partial banner */}
      {partial && (
        <div style={{ background: '#1a1400', borderBottom: '1px solid #3a2e00', color: '#fdd835', ...MONO, fontSize: 11 }}
             className="px-4 py-2">
          Scan stopped early — results may be incomplete.
        </div>
      )}

      {/* Card header: target + grade */}
      <div
        style={{ borderBottom: '1px solid #1e1e1e', background: '#111111' }}
        className="flex items-start justify-between px-4 py-3"
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ ...MONO, color: '#e0e0e0', fontSize: 13 }}>{target}</div>
          <div style={{ ...MONO, color: '#555', fontSize: 11, marginTop: 3 }}>
            {service_count} service{service_count !== 1 ? 's' : ''} · {totalFindings} finding{totalFindings !== 1 ? 's' : ''}
            {misconfigs.length > 0 ? ` · ${misconfigs.length} config issue${misconfigs.length !== 1 ? 's' : ''}` : ''}
          </div>
        </div>

        {/* Grade box */}
        <div style={{
          width: 48, flexShrink: 0, marginLeft: 16, textAlign: 'center',
          border: `1px solid ${gc}`, background: ga, borderRadius: 4, padding: '6px 0',
        }}>
          <div style={{ ...MONO, color: gc, fontWeight: 700, fontSize: 20, lineHeight: 1 }}>{grade || '?'}</div>
          {score != null && (
            <div style={{ ...MONO, color: '#555', fontSize: 9, marginTop: 3 }}>{score}/100</div>
          )}
        </div>
      </div>

      {/* Severity count strip */}
      <div
        style={{ borderBottom: '1px solid #1e1e1e', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)' }}
      >
        {SEV_ORDER.map(sev => (
          <div
            key={sev}
            style={{ padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 7, borderRight: sev !== 'LOW' ? '1px solid #1a1a1a' : 'none' }}
          >
            <div style={{ width: 8, height: 8, borderRadius: 1, background: SEV_COLOR[sev], flexShrink: 0 }} />
            <span style={{ ...MONO, fontSize: 10, color: '#555', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{sev}</span>
            <span style={{ ...MONO, fontSize: 12, color: counts[sev] > 0 ? SEV_COLOR[sev] : '#333', marginLeft: 'auto' }}>{counts[sev]}</span>
          </div>
        ))}
      </div>

      {/* Vulnerability findings */}
      {totalFindings > 0 && (
        <div style={{ borderBottom: '1px solid #1e1e1e' }}>
          {/* Column headers */}
          <div style={{ background: '#0d0d0d', borderBottom: '1px solid #141414', display: 'flex', gap: 0, padding: '5px 12px' }}>
            <span style={{ ...MONO, ...SECTION_LABEL, width: 150, flexShrink: 0 }}>CVE ID</span>
            <span style={{ ...MONO, ...SECTION_LABEL, width: 40, flexShrink: 0 }}>KEV</span>
            <span style={{ ...MONO, ...SECTION_LABEL, flex: 1 }}>Description</span>
            <span style={{ ...MONO, ...SECTION_LABEL, width: 48, textAlign: 'right', flexShrink: 0 }}>CVSS</span>
          </div>

          {/* Severity groups */}
          {SEV_ORDER.filter(sev => grouped[sev].length > 0).map(sev => (
            <div key={sev}>
              {/* Group header */}
              <button
                data-testid={`group-header-${sev}`}
                onClick={() => toggleGroup(sev)}
                style={{
                  width: '100%', background: 'transparent', border: 'none',
                  borderLeft: `2px solid ${SEV_COLOR[sev]}`,
                  borderBottom: '1px solid #141414',
                  padding: '5px 12px 5px 10px',
                  display: 'flex', alignItems: 'center', gap: 10,
                  cursor: 'pointer',
                }}
              >
                <span style={{ ...MONO, fontSize: 10, color: SEV_COLOR[sev], textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
                  {sev}
                </span>
                <span style={{ ...MONO, fontSize: 10, color: '#444' }}>({grouped[sev].length})</span>
                <span style={{ ...MONO, fontSize: 10, color: '#333', marginLeft: 'auto' }}>{expanded[sev] ? '▲' : '▼'}</span>
              </button>

              {/* Finding rows */}
              {expanded[sev] && grouped[sev].map((f, i) => (
                <div
                  key={f.cve_id || i}
                  data-testid={`cve-row-${f.cve_id}`}
                  style={{ display: 'flex', alignItems: 'center', gap: 0, padding: '6px 12px', borderBottom: '1px solid #0f0f0f', borderLeft: `2px solid ${SEV_COLOR[sev]}22` }}
                >
                  {/* Ask button */}
                  <button
                    data-testid={`ask-${f.cve_id}`}
                    onClick={() => onSend(
                      `Explain ${f.cve_id} from scan ${scan_id}. ` +
                      `What is the risk, what exact version fixes it, and what is the fastest remediation path?`
                    )}
                    style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: '#333', marginRight: 8, flexShrink: 0, lineHeight: 1 }}
                    title={`Ask about ${f.cve_id}`}
                    onMouseEnter={e => e.currentTarget.style.color = '#4a9eff'}
                    onMouseLeave={e => e.currentTarget.style.color = '#333'}
                  >
                    <MessageSquare size={11} />
                  </button>

                  {/* CVE ID */}
                  <span style={{ ...MONO, color: '#c0c0c0', fontSize: 11, width: 142, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.cve_id}
                  </span>

                  {/* KEV chip */}
                  <div style={{ width: 40, flexShrink: 0 }}>
                    {f.kev && (
                      <span style={{ ...MONO, color: '#ef5350', fontSize: 9, border: '1px solid #4a1010', borderRadius: 3, padding: '1px 4px', fontWeight: 600 }}>
                        KEV
                      </span>
                    )}
                  </div>

                  {/* Description */}
                  <span style={{ color: '#666', fontSize: 11, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 12 }}>
                    {f.description}
                  </span>

                  {/* CVSS */}
                  <span style={{ ...MONO, color: SEV_COLOR[sev], fontSize: 11, width: 36, textAlign: 'right', flexShrink: 0 }}>
                    {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {totalFindings === 0 && (
        <div style={{ borderBottom: '1px solid #1e1e1e', padding: '10px 12px' }}>
          <span style={{ ...MONO, color: '#66bb6a', fontSize: 11 }}>No vulnerabilities found</span>
        </div>
      )}

      {/* Configuration issues */}
      {misconfigs.length > 0 && (
        <div style={{ borderBottom: '1px solid #1e1e1e' }}>
          <div style={{ background: '#0d0d0d', borderBottom: '1px solid #141414', padding: '5px 12px' }}>
            <span style={SECTION_LABEL}>Configuration Issues ({misconfigs.length})</span>
          </div>
          {misconfigs.map((mc, i) => (
            <div
              key={i}
              style={{ display: 'flex', alignItems: 'baseline', gap: 12, padding: '7px 12px', borderBottom: i < misconfigs.length - 1 ? '1px solid #0f0f0f' : 'none' }}
            >
              <span style={{ ...MONO, fontSize: 10, color: SEV_COLOR[(mc.severity || 'INFO').toUpperCase()] || '#555', width: 60, flexShrink: 0, fontWeight: 600 }}>
                {(mc.severity || 'INFO').toUpperCase()}
              </span>
              <span style={{ color: '#c0c0c0', fontSize: 11, flex: 1 }}>{mc.title}</span>
              {mc.host && (
                <span style={{ ...MONO, color: '#444', fontSize: 10, flexShrink: 0 }}>
                  {mc.host}{mc.port ? `:${mc.port}` : ''}
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Action row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px' }}>
        <button
          onClick={() => onAnalysis('risk_summary', scan_id)}
          style={{ ...MONO, fontSize: 11, color: '#4a9eff', border: '1px solid #1a2d45', background: '#0d1929', borderRadius: 4, padding: '5px 12px', cursor: 'pointer' }}
          onMouseEnter={e => e.currentTarget.style.borderColor = '#4a9eff'}
          onMouseLeave={e => e.currentTarget.style.borderColor = '#1a2d45'}
        >
          Risk Summary
        </button>
        <button
          onClick={() => onAnalysis('remediation', scan_id)}
          style={{ ...MONO, fontSize: 11, color: '#888', border: '1px solid #252525', background: 'transparent', borderRadius: 4, padding: '5px 12px', cursor: 'pointer' }}
          onMouseEnter={e => { e.currentTarget.style.color = '#c0c0c0'; e.currentTarget.style.borderColor = '#333' }}
          onMouseLeave={e => { e.currentTarget.style.color = '#888'; e.currentTarget.style.borderColor = '#252525' }}
        >
          Remediation Plan
        </button>
        <a
          href={`/api/report/${scan_id}`}
          target="_blank"
          rel="noopener noreferrer"
          style={{ ...MONO, fontSize: 11, color: '#555', textDecoration: 'none', marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5 }}
          onMouseEnter={e => e.currentTarget.style.color = '#888'}
          onMouseLeave={e => e.currentTarget.style.color = '#555'}
        >
          Full Report <ExternalLink size={10} />
        </a>
      </div>
    </div>
  )
}
