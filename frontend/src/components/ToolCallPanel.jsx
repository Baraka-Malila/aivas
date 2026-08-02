import { useState, useEffect } from 'react'

export default function ToolCallPanel({ toolCalls, text }) {
  const [expanded, setExpanded] = useState(true)
  const [expandedRows, setExpandedRows] = useState({})

  useEffect(() => {
    if (text && text.length > 0) setExpanded(false)
  }, [text])

  if (!toolCalls || toolCalls.length === 0) return null

  const hasRunning = toolCalls.some(tc => tc.status === 'running')
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
        padding: '6px 10px',
        marginBottom: 10,
        fontSize: '0.75rem',
      }}
    >
      <div
        data-testid="tool-call-panel-header"
        onClick={() => setExpanded(false)}
        style={{ color: 'rgba(200,200,200,0.5)', marginBottom: 4, cursor: 'pointer', userSelect: 'none' }}
      >
        {hasRunning ? '⟳ Running tools…' : `▼ ${count} tool${count !== 1 ? 's' : ''} used`}
      </div>
      {toolCalls.map((tc, i) => (
        <div key={i}>
          <div
            data-testid={`tool-call-row-${i}`}
            onClick={() => setExpandedRows(r => ({ ...r, [i]: !r[i] }))}
            style={{ cursor: 'pointer', color: 'rgba(200,200,200,0.6)', userSelect: 'none', marginTop: 3 }}
          >
            <span>{tc.status === 'running' ? '⟳' : '✓'}</span>{' '}
            <span style={{ fontFamily: 'monospace' }}>{tc.name}</span>
            {tc.summary && (
              <span style={{ color: 'rgba(200,200,200,0.35)', marginLeft: 8 }}>{tc.summary}</span>
            )}
          </div>
          {expandedRows[i] && tc.args && Object.keys(tc.args).length > 0 && (
            <div
              data-testid={`tool-call-detail-${i}`}
              style={{
                background: 'rgba(0,0,0,0.3)', borderRadius: 4,
                padding: '4px 8px', marginTop: 3,
                fontFamily: 'monospace', fontSize: '0.68rem',
                color: 'rgba(200,200,200,0.4)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              }}
            >
              {JSON.stringify(tc.args, null, 2)}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
