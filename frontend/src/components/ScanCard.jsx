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
  color: '#888',
  textTransform: 'uppercase',
}

export default function ScanCard({ scanData, onSend, onAnalysis, onPdfRequest }) {
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
      style={{ background: '#111111', border: '1px solid #2a2a2a', borderRadius: 5 }}
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
        style={{ borderBottom: '1px solid #2a2a2a', background: '#111111' }}
        className="flex items-start justify-between px-4 py-3"
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ ...MONO, color: '#e0e0e0', fontSize: 14 }}>{target}</div>
          <div style={{ ...MONO, color: '#999', fontSize: 11, marginTop: 3 }}>
            {service_count} service{service_count !== 1 ? 's' : ''} · {totalFindings} finding{totalFindings !== 1 ? 's' : ''}
            {misconfigs.length > 0 ? ` · ${misconfigs.length} config issue${misconfigs.length !== 1 ? 's' : ''}` : ''}
          </div>
        </div>

        {/* Grade box + score below */}
        <div style={{ flexShrink: 0, marginLeft: 14, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
          <div style={{
            width: 38, height: 38,
            border: `1px solid ${gc}`, background: ga, borderRadius: 4,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <span style={{ ...MONO, color: gc, fontWeight: 700, fontSize: 19, lineHeight: 1 }}>{grade || '?'}</span>
          </div>
          {score != null && (
            <span style={{ ...MONO, color: '#999', fontSize: 10 }}>{score}/100</span>
          )}
        </div>
      </div>

      {/* Severity count strip */}
      <div style={{ borderBottom: '1px solid #2a2a2a', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)' }}>
        {SEV_ORDER.map(sev => (
          <div
            key={sev}
            style={{ padding: '9px 14px', display: 'flex', alignItems: 'center', gap: 8, borderRight: sev !== 'LOW' ? '1px solid #2a2a2a' : 'none' }}
          >
            <span style={{ width: 8, height: 8, background: SEV_COLOR[sev], display: 'inline-block', flexShrink: 0 }} />
            <span style={{ color: '#e0e0e0', fontSize: 14, fontWeight: 600 }}>{counts[sev]}</span>
            <span style={{ ...MONO, fontSize: 10, color: '#888', textTransform: 'uppercase' }}>{sev}</span>
          </div>
        ))}
      </div>

      {/* Vulnerability findings */}
      {totalFindings > 0 && (
        <div style={{ borderBottom: '1px solid #2a2a2a' }}>
          {/* Column headers */}
          <div style={{ background: '#0d0d0d', borderBottom: '1px solid #2a2a2a', display: 'flex', gap: 8, padding: '6px 14px' }}>
            <span style={{ ...MONO, fontSize: 9, color: '#666', letterSpacing: '0.1em', width: 150, flexShrink: 0 }}>CVE</span>
            <span style={{ ...MONO, fontSize: 9, color: '#666', letterSpacing: '0.1em', width: 34, flexShrink: 0 }}>KEV</span>
            <span style={{ ...MONO, fontSize: 9, color: '#666', letterSpacing: '0.1em', flex: 1 }}>SUMMARY</span>
            <span style={{ ...MONO, fontSize: 9, color: '#666', letterSpacing: '0.1em', flexShrink: 0 }}>CVSS</span>
          </div>

          {/* Severity groups */}
          {SEV_ORDER.filter(sev => grouped[sev].length > 0).map(sev => (
            <div key={sev}>
              {/* Group header */}
              <button
                data-testid={`group-header-${sev}`}
                onClick={() => toggleGroup(sev)}
                style={{
                  width: '100%', background: '#0d0d0d', border: 'none',
                  borderLeft: `2px solid ${SEV_COLOR[sev]}`,
                  borderBottom: '1px solid #2a2a2a',
                  padding: '7px 14px 7px 12px',
                  display: 'flex', alignItems: 'center', gap: 8,
                  cursor: 'pointer',
                }}
              >
                <span style={{ ...MONO, fontSize: 11, color: SEV_COLOR[sev], fontWeight: 600 }}>
                  {sev}
                </span>
                <span style={{ ...MONO, fontSize: 11, color: '#888' }}>({grouped[sev].length})</span>
                <span style={{ ...MONO, fontSize: 10, color: '#666', marginLeft: 'auto' }}>{expanded[sev] ? '▲' : '▼'}</span>
              </button>

              {/* Finding rows */}
              {expanded[sev] && grouped[sev].map((f, i) => (
                <div
                  key={f.cve_id || i}
                  data-testid={`cve-row-${f.cve_id}`}
                  style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 14px', borderBottom: '1px solid #1e1e1e' }}
                >
                  {/* CVE ID */}
                  <span style={{ ...MONO, color: '#e0e0e0', fontSize: 11, width: 150, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.cve_id}
                  </span>

                  {/* KEV chip */}
                  <div style={{ width: 34, flexShrink: 0 }}>
                    {f.kev && (
                      <span style={{ ...MONO, color: '#ef5350', fontSize: 9, border: '1px solid #4a1010', borderRadius: 2, padding: '1px 4px', fontWeight: 600 }}>
                        KEV
                      </span>
                    )}
                  </div>

                  {/* Description */}
                  <span style={{ color: '#bbb', fontSize: 11, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.description}
                  </span>

                  {/* CVSS */}
                  <span style={{ ...MONO, color: SEV_COLOR[sev], fontSize: 11, flexShrink: 0 }}>
                    {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {totalFindings === 0 && (
        <div style={{ borderBottom: '1px solid #2a2a2a', padding: '10px 12px' }}>
          <span style={{ ...MONO, color: '#66bb6a', fontSize: 11 }}>No vulnerabilities found</span>
        </div>
      )}

      {/* Configuration issues */}
      {misconfigs.length > 0 && (
        <div style={{ borderBottom: '1px solid #2a2a2a' }}>
          <div style={{ background: '#0d0d0d', borderBottom: '1px solid #1e1e1e', padding: '5px 12px' }}>
            <span style={SECTION_LABEL}>Configuration Issues ({misconfigs.length})</span>
          </div>
          {misconfigs.map((mc, i) => (
            <div
              key={i}
              style={{ display: 'flex', alignItems: 'baseline', gap: 12, padding: '7px 12px', borderBottom: i < misconfigs.length - 1 ? '1px solid #0f0f0f' : 'none' }}
            >
              <span style={{ ...MONO, fontSize: 10, color: SEV_COLOR[(mc.severity || 'INFO').toUpperCase()] || '#888', width: 60, flexShrink: 0, fontWeight: 600 }}>
                {(mc.severity || 'INFO').toUpperCase()}
              </span>
              <span style={{ color: '#c0c0c0', fontSize: 11, flex: 1 }}>{mc.title}</span>
              {mc.host && (
                <span style={{ ...MONO, color: '#666', fontSize: 10, flexShrink: 0 }}>
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
          style={{ ...MONO, fontSize: 11, color: '#aaa', border: '1px solid #333', background: 'transparent', borderRadius: 4, padding: '5px 12px', cursor: 'pointer' }}
          onMouseEnter={e => { e.currentTarget.style.color = '#c0c0c0'; e.currentTarget.style.borderColor = '#333' }}
          onMouseLeave={e => { e.currentTarget.style.color = '#aaa'; e.currentTarget.style.borderColor = '#333' }}
        >
          Remediation Plan
        </button>
        <button
          onClick={() => onPdfRequest?.(scan_id, target)}
          style={{
            ...MONO, fontSize: 11, color: '#888', background: 'none', border: 'none',
            marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', padding: 0,
          }}
          onMouseEnter={e => e.currentTarget.style.color = '#aaa'}
          onMouseLeave={e => e.currentTarget.style.color = '#888'}
          title="Generate PDF report"
        >
          PDF Report <ExternalLink size={10} />
        </button>
      </div>
    </div>
  )
}
