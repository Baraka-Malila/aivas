// frontend/src/components/ScanLog.jsx
import React, { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'

export default function ScanLog({ lines }) {
  const [open, setOpen] = useState(false)

  if (!lines?.length) return null

  return (
    <div className="border-t border-slate-100">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-5 py-2.5 text-xs text-slate-400 hover:text-slate-600 w-full text-left transition-colors"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        View scan log ({lines.length} events)
      </button>
      {open && (
        <div className="bg-slate-50 border-t border-slate-100 px-5 py-3 max-h-56 overflow-y-auto">
          {lines.map((ev, i) =>
            ev.phase === 'phase_header' ? (
              <div key={i} className="text-xs font-medium text-slate-400 uppercase tracking-widest mt-2 mb-0.5 border-b border-slate-200 pb-0.5 first:mt-0">
                {ev.text}
              </div>
            ) : (
              <div key={i} className="font-mono text-xs text-slate-500 leading-5">{ev.text}</div>
            )
          )}
        </div>
      )}
    </div>
  )
}
