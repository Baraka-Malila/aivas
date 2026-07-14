import { useEffect, useRef, useState } from 'react'

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

export default function ScanProgress({ text }) {
  const [frame, setFrame] = useState(0)
  const timer = useRef(null)

  useEffect(() => {
    timer.current = setInterval(() => setFrame(f => (f + 1) % FRAMES.length), 120)
    return () => clearInterval(timer.current)
  }, [])

  return (
    <div className="py-3">
      <div style={{ color: '#4a9eff' }} className="text-xs font-medium mb-1.5 select-none">
        ✦ AIVAS
      </div>
      <div style={{ color: '#666' }} className="text-sm font-mono">
        {FRAMES[frame]} {text}
      </div>
    </div>
  )
}
