// frontend/src/components/ProgressFeed.jsx
import React, { useEffect, useRef, useState } from 'react'
import { sevClasses } from '../lib/severity'

const SEV_RE = /\[(CRITICAL|HIGH|MEDIUM|LOW)\]/

function PhaseHeader({ text }) {
  return (
    <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest border-b border-slate-100 pb-1 mt-4 mb-1.5 first:mt-0 select-none">
      — {text} —
    </div>
  )
}

function ProgressLine({ ev }) {
  const match = SEV_RE.exec(ev.text || '')
  const lineClass =
    ev.phase === 'cve_found'
      ? 'text-blue-700'
      : ev.phase === 'cve_none'
      ? 'text-slate-400'
      : ev.phase === 'http_finding'
      ? 'text-amber-700'
      : 'text-slate-700'
  return (
    <div className="font-mono text-sm leading-5">
      {match ? (
        <>
          <span className={lineClass}>{(ev.text || '').replace(SEV_RE, '').trimEnd()} </span>
          <span className={sevClasses(match[1])}>{match[1]}</span>
        </>
      ) : (
        <span className={lineClass}>{ev.text}</span>
      )}
    </div>
  )
}

export default function ProgressFeed({ lines }) {
  const bottomRef = useRef(null)
  const [visible, setVisible] = useState(0)

  useEffect(() => {
    if (lines.length > visible) {
      const t = setTimeout(() => setVisible(v => v + 1), 80)
      return () => clearTimeout(t)
    }
  }, [lines.length, visible])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [visible])

  if (!lines.length) return null

  return (
    <div className="p-4 space-y-0.5 min-h-[80px]">
      {lines.slice(0, visible).map((ev, i) =>
        ev.phase === 'phase_header' ? (
          <PhaseHeader key={i} text={ev.text} />
        ) : (
          <ProgressLine key={i} ev={ev} />
        )
      )}
      <div ref={bottomRef} />
    </div>
  )
}
