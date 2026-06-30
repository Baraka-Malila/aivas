// frontend/src/components/ResultsTabs.jsx
import React, { useState } from 'react'
import FindingsTable from './FindingsTable'
import MisconfigTable from './MisconfigTable'
import AssessmentPanel from './AssessmentPanel'
import ReportPanel from './ReportPanel'
import ScanLog from './ScanLog'

const TABS = [
  { key: 'findings', label: 'Findings' },
  { key: 'assessment', label: 'Assessment' },
  { key: 'report', label: 'Report' },
]

export default function ResultsTabs({ result, progressLines }) {
  const [tab, setTab] = useState('findings')
  const { findings = [], misconfigs = [], scan_id } = result

  return (
    <div>
      <div className="flex border-b border-slate-200 px-1 bg-white">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.key
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
            }`}
          >
            {t.label}
            {t.key === 'findings' && findings.length > 0 && (
              <span className="ml-1.5 text-xs bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded-full">
                {findings.length}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="bg-white">
        {tab === 'findings' && (
          <div className="p-4">
            {findings.length === 0 && misconfigs.length === 0 ? (
              <p className="text-slate-500 text-sm py-6 text-center">No findings for this scan.</p>
            ) : (
              <>
                {findings.length > 0 && (
                  <>
                    <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 border-b border-slate-200 pb-2">
                      CVE Findings ({findings.length})
                    </h3>
                    <FindingsTable findings={findings} />
                  </>
                )}
                <MisconfigTable misconfigs={misconfigs} />
              </>
            )}
          </div>
        )}
        {tab === 'assessment' && <AssessmentPanel result={result} />}
        {tab === 'report' && <ReportPanel scanId={scan_id} />}
      </div>

      <ScanLog lines={progressLines} />
    </div>
  )
}
