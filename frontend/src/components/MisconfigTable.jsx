// frontend/src/components/MisconfigTable.jsx
import React from 'react'
import { sevClasses } from '../lib/severity'

export default function MisconfigTable({ misconfigs }) {
  if (!misconfigs?.length) return null

  return (
    <div className="mt-6">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 border-b border-slate-200 pb-2">
        HTTP Misconfigurations ({misconfigs.length})
      </h3>
      <div className="overflow-x-auto rounded border border-slate-200">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="bg-[#0f172a] text-slate-300 text-xs font-semibold uppercase tracking-wide">
              <th className="px-3 py-2 text-left">Host:Port</th>
              <th className="px-3 py-2 text-left">Finding</th>
              <th className="px-3 py-2 text-left">Detail</th>
              <th className="px-3 py-2 text-left">Severity</th>
            </tr>
          </thead>
          <tbody>
            {misconfigs.map((m, i) => (
              <tr key={i} className={i % 2 === 0 ? 'bg-white' : 'bg-slate-50'}>
                <td className="px-3 py-2 font-mono text-xs text-slate-600 whitespace-nowrap">
                  {m.host}:{m.port}
                </td>
                <td className="px-3 py-2 text-xs font-medium text-slate-700">{m.title}</td>
                <td className="px-3 py-2 text-xs text-slate-500 max-w-xs truncate">
                  {(m.description || '').slice(0, 90)}{(m.description || '').length > 90 ? '…' : ''}
                </td>
                <td className="px-3 py-2">
                  <span className={sevClasses(m.severity)}>{m.severity}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
