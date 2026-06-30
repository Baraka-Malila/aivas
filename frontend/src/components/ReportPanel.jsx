// frontend/src/components/ReportPanel.jsx
import React from 'react'
import { FileText, Download } from 'lucide-react'

export default function ReportPanel({ scanId }) {
  return (
    <div className="p-5">
      <div className="flex gap-3 mb-5">
        <a
          href={`/api/report/${scanId}`}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-md hover:bg-slate-50 text-sm text-slate-700 transition-colors"
        >
          <FileText size={14} />
          View HTML Report
        </a>
        <a
          href={`/api/report/${scanId}/pdf`}
          download={`aivas-report-${scanId}.pdf`}
          className="flex items-center gap-2 px-4 py-2 bg-[#0f172a] hover:bg-slate-700 text-white rounded-md text-sm font-medium transition-colors"
        >
          <Download size={14} />
          Download PDF
        </a>
      </div>
      <p className="text-xs text-slate-400 leading-relaxed max-w-prose">
        Report is suitable for submission to IT managers and compliance officers.
        Generated automatically from scan data — validate with a qualified security
        professional before inclusion in official documentation or compliance submissions.
      </p>
    </div>
  )
}
