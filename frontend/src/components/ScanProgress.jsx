import { useEffect, useRef } from 'react'

const LOGO_PATH = "M12 27.5 C8.5 29.8 4.5 30 3.6 28.4 C5.5 26.6 7.4 24 8.6 20.8 L18 3 L26.2 20.5 C27.6 19.4 29.6 19 30.6 19.6 C29.8 21.2 28.2 21.9 27 22 L29.3 30.2 L13.8 23.8 L26.3 18.4"

const STATUS_LABEL = {
  complete: 'SCAN COMPLETE',
  stopped:  'SCAN STOPPED',
  failed:   'SCAN FAILED',
}

export default function ScanProgress({ log = [], onStop, scanStatus }) {
  const scrollRef = useRef(null)
  const isDone = !!scanStatus

  useEffect(() => {
    if (scrollRef.current && !isDone) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [log.length, isDone])

  return (
    <div className="py-3" data-testid="scan-progress">
      <div className="flex items-center justify-between mb-1.5">
        {isDone ? (
          <div style={{ color: '#555' }} className="text-xs font-medium select-none">
            {STATUS_LABEL[scanStatus] || 'SCAN DONE'}
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <svg width="28" height="28" viewBox="0 0 34 34" fill="none">
              <path d={LOGO_PATH} stroke="#1e1e1e" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
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
            <span style={{ fontFamily: '"Fira Code", monospace', fontSize: 11, color: '#555', letterSpacing: '0.1em' }}>
              SCANNING
            </span>
          </div>
        )}
        {!isDone && onStop && (
          <button
            onClick={onStop}
            style={{ color: '#666', borderColor: '#333' }}
            className="text-xs border rounded px-2 py-0.5 hover:text-red-400 hover:border-red-900 transition-colors"
          >
            Stop
          </button>
        )}
      </div>

      {isDone ? (
        <details style={{ marginTop: 4 }}>
          <summary
            style={{ color: '#444', fontSize: '0.72rem', cursor: 'pointer', userSelect: 'none' }}
          >
            ▶ {log.length} log line{log.length !== 1 ? 's' : ''}
          </summary>
          <div
            style={{
              color: '#555',
              maxHeight: '220px',
              overflowY: 'auto',
              background: '#0d0d0d',
              border: '1px solid #1a1a1a',
              borderRadius: '6px',
              padding: '8px 10px',
              marginTop: 4,
            }}
            className="text-xs font-mono"
          >
            {log.map((line, i) => (
              <div key={i} style={{ color: '#444', marginBottom: '2px' }}>{'  '}{line}</div>
            ))}
          </div>
        </details>
      ) : (
        <div
          ref={scrollRef}
          style={{
            color: '#666',
            maxHeight: '220px',
            overflowY: 'auto',
            background: '#0d0d0d',
            border: '1px solid #1a1a1a',
            borderRadius: '6px',
            padding: '8px 10px',
          }}
          className="text-xs font-mono"
        >
          {log.map((line, i) => (
            <div
              key={i}
              style={{ color: i === log.length - 1 ? '#aaa' : '#555', marginBottom: '2px' }}
            >
              {'  '}{line}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
