// frontend/src/components/FindingsTable.jsx
import React, { useState } from 'react'
import { ChevronUp, ChevronDown } from 'lucide-react'
import { sevClasses } from '../lib/severity'

const COLS = [
  { key: 'cvss_severity', label: 'Severity' },
  { key: 'cve_id', label: 'CVE ID' },
  { key: 'cvss_score', label: 'CVSS' },
  { key: 'host', label: 'Host' },
]

function Th({ col, sortCol, sortDir, onSort }) {
  const active = sortCol === col.key
  return (
    <th className="px-3 py-2 text-left">
      <button
        onClick={() => onSort(col.key)}
        className="flex items-center gap-1 hover:text-white text-xs font-semibold uppercase tracking-wide"
      >
        {col.label}
        {active && (sortDir === 'desc' ? <ChevronDown size={10} /> : <ChevronUp size={10} />)}
      </button>
    </th>
  )
}

export default function FindingsTable({ findings }) {
  const [sortCol, setSortCol] = useState('cvss_score')
  const [sortDir, setSortDir] = useState('desc')

  const handleSort = (col) => {
    if (sortCol === col) setSortDir(d => d === 'desc' ? 'asc' : 'desc')
    else { setSortCol(col); setSortDir('desc') }
  }

  if (!findings.length) {
    return <p className="text-slate-500 text-sm py-4">No CVE findings for this scan.</p>
  }

  const sorted = [...findings].sort((a, b) => {
    const av = a[sortCol] ?? '', bv = b[sortCol] ?? ''
    const cmp = av < bv ? -1 : av > bv ? 1 : 0
    return sortDir === 'desc' ? -cmp : cmp
  })

  return (
    <div className="overflow-x-auto rounded border border-slate-200">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="bg-[#0f172a] text-slate-300">
            <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide w-8">#</th>
            {COLS.map(col => (
              <Th key={col.key} col={col} sortCol={sortCol} sortDir={sortDir} onSort={handleSort} />
            ))}
            <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide">Description</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f, i) => (
            <tr key={i} className={i % 2 === 0 ? 'bg-white' : 'bg-slate-50'}>
              <td className="px-3 py-2 text-slate-400 text-xs text-center">{i + 1}</td>
              <td className="px-3 py-2">
                <span className={sevClasses(f.cvss_severity)}>{f.cvss_severity || '?'}</span>
              </td>
              <td className="px-3 py-2 font-mono text-xs text-blue-700 whitespace-nowrap">{f.cve_id}</td>
              <td className="px-3 py-2 text-xs text-center font-mono">{f.cvss_score ?? 'N/A'}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-500">{f.host}</td>
              <td className="px-3 py-2 text-xs text-slate-600 max-w-xs truncate">
                {(f.description || '').slice(0, 110)}{f.description?.length > 110 ? '…' : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
