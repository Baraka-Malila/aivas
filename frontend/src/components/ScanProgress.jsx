import { useEffect, useRef, useState } from 'react'

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

const STATUS_LABEL = {
  complete: 'SCAN COMPLETE',
  stopped:  'SCAN STOPPED',
  failed:   'SCAN FAILED',
}

export default function ScanProgress({ log = [], onStop, scanStatus }) {
  const [frame, setFrame] = useState(0)
  const timer = useRef(null)
  const scrollRef = useRef(null)
  const isDone = !!scanStatus

  useEffect(() => {
    if (isDone) {
      clearInterval(timer.current)
      return
    }
    timer.current = setInterval(() => setFrame(f => (f + 1) % FRAMES.length), 120)
    return () => clearInterval(timer.current)
  }, [isDone])

  useEffect(() => {
    if (scrollRef.current && !isDone) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [log.length, isDone])

  const headerLabel = isDone ? (STATUS_LABEL[scanStatus] || 'SCAN DONE') : 'SCAN IN PROGRESS'
  const headerColor = isDone ? '#555' : '#4a9eff'

  return (
    <div className="py-3" data-testid="scan-progress">
      <div className="flex items-center justify-between mb-1.5">
        <div style={{ color: headerColor }} className="text-xs font-medium select-none">
          {headerLabel}
        </div>
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
          {log.map((line, i) => {
            const isLast = i === log.length - 1
            return (
              <div
                key={i}
                style={{ color: isLast ? '#aaa' : '#555', marginBottom: '2px' }}
              >
                {isLast ? `${FRAMES[frame]} ` : '  '}{line}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
