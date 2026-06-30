// frontend/src/components/ScanBar.jsx
import React, { useState } from 'react'
import { Search, Zap, ChevronDown, ChevronUp, Loader2 } from 'lucide-react'

export default function ScanBar({ onScan, isScanning }) {
  const [target, setTarget] = useState('')
  const [showOptions, setShowOptions] = useState(false)

  const trigger = (level) => {
    const t = target.trim()
    if (!t || isScanning) return
    onScan(t, level)
  }

  return (
    <div className="bg-white border-b border-slate-200 sticky top-0 z-10 shadow-sm">
      <div className="flex items-center gap-2 px-4 py-3">
        <div className="flex-1 relative">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && trigger(2)}
            placeholder="Target: 192.168.1.1 or 10.0.0.0/24"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            data-form-type="other"
            className="w-full pl-8 pr-3 py-2 text-sm border border-slate-200 rounded-md font-mono bg-slate-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:opacity-60"
            disabled={isScanning}
          />
        </div>

        <button
          onClick={() => trigger(1)}
          disabled={!target.trim() || isScanning}
          className="px-3 py-2 text-sm border border-slate-200 rounded-md hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed text-slate-600 whitespace-nowrap flex items-center gap-1.5"
        >
          <Zap size={12} />
          Quick Scan
        </button>

        <button
          onClick={() => trigger(2)}
          disabled={!target.trim() || isScanning}
          className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-md font-medium whitespace-nowrap flex items-center gap-1.5"
        >
          {isScanning ? (
            <><Loader2 size={13} className="animate-spin" /> Scanning…</>
          ) : (
            'Scan'
          )}
        </button>

        <button
          onClick={() => setShowOptions(s => !s)}
          className="px-2 py-2 text-sm border border-slate-200 rounded-md hover:bg-slate-50 text-slate-400"
          aria-label="Toggle advanced options"
        >
          {showOptions ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {showOptions && (
        <div className="px-4 pb-3 flex items-center gap-6 text-sm text-slate-500 border-t border-slate-100 pt-2">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" className="rounded accent-blue-600" />
            <span>UDP scan</span>
            <span className="text-slate-400 text-xs">(requires root, slow)</span>
          </label>
          <label className="flex items-center gap-2">
            <span>NSE depth:</span>
            <select className="border border-slate-200 rounded px-2 py-1 text-xs bg-white focus:outline-none focus:ring-1 focus:ring-blue-500">
              <option value="standard">Standard</option>
              <option value="extended">Extended (shellshock, MS17-010…)</option>
            </select>
          </label>
        </div>
      )}
    </div>
  )
}
