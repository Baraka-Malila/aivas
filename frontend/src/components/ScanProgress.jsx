import { useEffect, useRef, useState } from 'react'

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

export default function ScanProgress({ text, onStop }) {
  const [frame, setFrame] = useState(0)
  const timer = useRef(null)

  useEffect(() => {
    timer.current = setInterval(() => setFrame(f => (f + 1) % FRAMES.length), 120)
    return () => clearInterval(timer.current)
  }, [])

  return (
    <div className="py-3" data-testid="scan-progress">
      <div className="flex items-center justify-between mb-1.5">
        <div style={{ color: '#4a9eff' }} className="text-xs font-medium select-none">
          ✦ AIVAS
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
      <div style={{ color: '#666' }} className="text-sm font-mono">
        {FRAMES[frame]} {text}
      </div>
    </div>
  )
}
