// frontend/src/components/Sidebar.jsx
import React from 'react'
import { PlusCircle, Settings, Trash2, Shield } from 'lucide-react'
import { gradeBadgeClass } from '../lib/severity'

export default function Sidebar({ scans, onNewScan, onSelectScan, onDeleteScan, onSettings, activeScanId }) {
  return (
    <div className="w-[220px] min-h-screen bg-[#0f172a] flex flex-col text-[#cbd5e1] shrink-0">
      <div className="px-4 pt-5 pb-4 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <Shield size={18} className="text-green-400" />
          <span className="font-bold text-white text-lg tracking-tight">AIVAS</span>
        </div>
        <div className="text-xs text-slate-500 mt-1">Vulnerability Assessment</div>
      </div>

      <div className="px-3 py-3">
        <button
          onClick={onNewScan}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
        >
          <PlusCircle size={13} />
          New Scan
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-3 pb-2">
        {scans.length > 0 && (
          <div className="text-xs text-slate-500 uppercase tracking-wider px-2 mb-2 mt-1">
            Recent Scans
          </div>
        )}
        {scans.length === 0 && (
          <p className="text-slate-600 text-xs px-2 py-3">No scans yet</p>
        )}
        {scans.map(scan => {
          const grade = (scan.grade || '').replace('Grade ', '')
          const isActive = scan.id === activeScanId
          return (
            <div
              key={scan.id}
              role="button"
              tabIndex={0}
              className={`group flex items-center justify-between px-2 py-2 rounded-md cursor-pointer mb-0.5 transition-colors ${
                isActive ? 'bg-[#1e293b] border-l-2 border-blue-500 pl-1.5' : 'hover:bg-[#1e293b]'
              }`}
              onClick={() => onSelectScan(scan)}
              onKeyDown={e => e.key === 'Enter' && onSelectScan(scan)}
            >
              <div className="min-w-0 flex-1">
                <div className="text-sm text-slate-200 truncate">{scan.target}</div>
                <div className="text-xs text-slate-500">{(scan.started_at || '').slice(0, 10)}</div>
              </div>
              <div className="flex items-center gap-1 shrink-0 ml-1">
                <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${gradeBadgeClass(grade)}`}>
                  {grade || '?'}
                </span>
                <button
                  onClick={e => { e.stopPropagation(); onDeleteScan(scan.id) }}
                  className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-red-400 transition-opacity p-0.5 rounded"
                  aria-label="Delete scan"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            </div>
          )
        })}
      </div>

      <div className="px-3 py-3 border-t border-slate-700">
        <button
          onClick={onSettings}
          className="flex items-center gap-2 px-3 py-2 w-full rounded-md hover:bg-[#1e293b] text-slate-400 text-sm transition-colors"
        >
          <Settings size={13} />
          Settings
        </button>
      </div>
    </div>
  )
}
