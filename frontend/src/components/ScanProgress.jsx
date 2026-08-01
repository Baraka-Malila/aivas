import { useEffect, useRef, useState } from 'react'

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

export default function ScanProgress({ log = [], onStop }) {
  const [frame, setFrame] = useState(0)
  const timer = useRef(null)
  const scrollRef = useRef(null)

  useEffect(() => {
    timer.current = setInterval(() => setFrame(f => (f + 1) % FRAMES.length), 120)
    return () => clearInterval(timer.current)
  }, [])

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [log.length])

  return (
    <div className="py-3" data-testid="scan-progress">
      <div className="flex items-center justify-between mb-1.5">
        <div style={{ color: '#4a9eff' }} className="text-xs font-medium select-none">
          SCAN IN PROGRESS
        </div>
        {onStop && (
          <button
            onClick={onStop}
            style={{ color: '#666', borderColor: '#333' }}
            className="text-xs border rounded px-2 py-0.5 hover:text-red-400 hover:border-red-900 transition-colors"
          >
            Stop
          </button>
        )}
      </div>
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
    </div>
  )
}
