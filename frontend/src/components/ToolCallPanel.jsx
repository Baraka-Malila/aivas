import { useState, useEffect } from 'react'

const TOOL_LABEL = {
  scan_host:       'SCANNING',
  remote_scan:     'SCANNING',
  discover_hosts:  'DISCOVERING',
  get_local_info:  'PROBING',
  query_shodan:    'QUERYING',
  get_history:     'SEARCHING',
  get_last_scan:   'SEARCHING',
  get_findings:    'SEARCHING',
  explain_cve:     'LOOKING UP',
}

export default function ToolCallPanel({ toolCalls, text }) {
  const [expanded, setExpanded] = useState(true)
  const [expandedRows, setExpandedRows] = useState({})

  useEffect(() => {
    if (text && text.length > 0) setExpanded(false)
  }, [text])

  if (!toolCalls || toolCalls.length === 0) return null

  const count = toolCalls.length

  if (!expanded) {
    return (
      <div
        data-testid="tool-call-panel-collapsed"
        onClick={() => setExpanded(true)}
        style={{
          marginBottom: 8, cursor: 'pointer', userSelect: 'none',
          color: 'rgba(200,200,200,0.65)', fontSize: '0.75rem',
          fontFamily: '"Fira Code", monospace', letterSpacing: '0.05em',
        }}
      >
        ▶ {count} tool{count !== 1 ? 's' : ''} used
      </div>
    )
  }

  return (
    <div
      data-testid="tool-call-panel-expanded"
      style={{
        background: 'rgba(255,255,255,0.04)',
        borderRadius: 6,
        padding: '8px 12px',
        marginBottom: 10,
        fontSize: '0.75rem',
      }}
    >
      <div
        data-testid="tool-call-panel-header"
        onClick={() => setExpanded(false)}
        style={{ color: 'rgba(200,200,200,0.5)', marginBottom: 4, cursor: 'pointer', userSelect: 'none' }}
      >
        ▼ {count} tool{count !== 1 ? 's' : ''} used
      </div>

      {toolCalls.map((tc, i) => (
        <div key={i}>
          <div
            data-testid={`tool-call-row-${i}`}
            onClick={() => setExpandedRows(r => ({ ...r, [i]: !r[i] }))}
            style={{ cursor: 'pointer', color: 'rgba(200,200,200,0.6)', userSelect: 'none', marginTop: 3 }}
          >
            <span style={{ fontFamily: 'monospace', fontSize: '0.65rem', opacity: 0.5 }}>
              {tc.status === 'running' ? 'RUN' : 'OK'}
            </span>{' '}
            <span style={{ fontFamily: 'monospace' }}>{tc.name}</span>
            {tc.summary && (
              <span style={{ color: 'rgba(200,200,200,0.35)', marginLeft: 8 }}>{tc.summary}</span>
            )}
          </div>
          {expandedRows[i] && (
            <div
              data-testid={`tool-call-detail-${i}`}
              style={{
                background: 'rgba(0,0,0,0.3)', borderRadius: 4,
                padding: '4px 8px', marginTop: 3,
                fontFamily: 'monospace', fontSize: '0.68rem',
                color: 'rgba(200,200,200,0.4)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              }}
            >
              {tc.summary && tc.summary !== 'done' && (
                <div style={{ color: 'rgba(200,200,200,0.55)', marginBottom: 4 }}>
                  {tc.summary}
                </div>
              )}
              {tc.args && Object.keys(tc.args).length > 0
                ? JSON.stringify(tc.args, null, 2)
                : <span style={{ color: 'rgba(200,200,200,0.2)', fontStyle: 'italic' }}>no parameters</span>
              }
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
