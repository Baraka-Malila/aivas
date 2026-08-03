import { useState, useEffect } from 'react'

const LOGO_PATH = "M12 27.5 C8.5 29.8 4.5 30 3.6 28.4 C5.5 26.6 7.4 24 8.6 20.8 L18 3 L26.2 20.5 C27.6 19.4 29.6 19 30.6 19.6 C29.8 21.2 28.2 21.9 27 22 L29.3 30.2 L13.8 23.8 L26.3 18.4"

const TOOL_LABEL = {
  scan_host:       'SCANNING',
  remote_scan:     'SCANNING',
  discover_hosts:  'DISCOVERING',
  get_local_info:  'PROBING',
  get_shodan:      'QUERYING',
}

function AnimatedLogo({ label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '4px 0', marginBottom: 8 }}>
      <svg width="28" height="28" viewBox="0 0 34 34" fill="none" style={{ flexShrink: 0 }}>
        <path
          d={LOGO_PATH}
          stroke="#1e1e1e"
          strokeWidth="2.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d={LOGO_PATH}
          stroke="#4a9eff"
          strokeWidth="2.6"
          strokeLinecap="round"
          strokeLinejoin="round"
          pathLength="1"
          style={{ animation: 'aivas-logoCenter 2.2s cubic-bezier(0.2,0.7,0.4,1) infinite' }}
        />
      </svg>
      <span style={{
        fontFamily: '"Fira Code", monospace',
        fontSize: 11,
        color: '#555555',
        letterSpacing: '0.1em',
      }}>
        {label}
      </span>
    </div>
  )
}

export default function ToolCallPanel({ toolCalls, text }) {
  const [expanded, setExpanded] = useState(true)
  const [expandedRows, setExpandedRows] = useState({})

  useEffect(() => {
    if (text && text.length > 0) setExpanded(false)
  }, [text])

  if (!toolCalls || toolCalls.length === 0) return null

  const runningTool = toolCalls.find(tc => tc.status === 'running')
  const hasRunning = Boolean(runningTool)
  const label = TOOL_LABEL[runningTool?.name] || 'WORKING'
  const count = toolCalls.length

  if (!expanded) {
    return (
      <div
        data-testid="tool-call-panel-collapsed"
        onClick={() => setExpanded(true)}
        style={{
          marginBottom: 8, cursor: 'pointer', userSelect: 'none',
          color: 'rgba(200,200,200,0.45)', fontSize: '0.72rem',
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
      {hasRunning ? (
        <AnimatedLogo label={label} />
      ) : (
        <div
          data-testid="tool-call-panel-header"
          onClick={() => setExpanded(false)}
          style={{ color: 'rgba(200,200,200,0.5)', marginBottom: 4, cursor: 'pointer', userSelect: 'none' }}
        >
          ▼ {count} tool{count !== 1 ? 's' : ''} used
        </div>
      )}

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
