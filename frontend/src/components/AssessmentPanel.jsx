// frontend/src/components/AssessmentPanel.jsx
import React, { useState } from 'react'
import { Sparkles, Loader2 } from 'lucide-react'
import { gradeColor } from '../lib/severity'
import { mdToHtml } from '../lib/mdToHtml'

export default function AssessmentPanel({ result }) {
  const [narration, setNarration] = useState('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const generate = async () => {
    setLoading(true)
    setErr('')
    try {
      const data = await fetch(`/api/narrate/${result.scan_id}`).then(r => r.json())
      setNarration(data.response || '')
    } catch {
      setErr('Failed to connect to AI. Check your API key in Settings.')
    } finally {
      setLoading(false)
    }
  }

  const grade = (result.grade || '').replace('Grade ', '') || '?'
  const gc = gradeColor(grade)
  const cveCount = result.findings?.length ?? 0
  const miscCount = result.misconfigs?.length ?? 0

  return (
    <div className="p-5">
      <div className="flex items-center gap-5 p-4 bg-slate-50 border border-slate-200 rounded-lg mb-5">
        <div className="text-6xl font-black leading-none font-mono" style={{ color: gc }}>
          {grade}
        </div>
        <div className="w-px bg-slate-200 self-stretch" />
        <div>
          <div className="font-bold text-slate-800 text-lg">{result.score}/100 Risk Score</div>
          <div className="text-slate-500 text-sm font-mono mt-0.5">{result.target}</div>
          <div className="text-slate-400 text-xs mt-1">
            {cveCount} CVE(s) &nbsp;·&nbsp; {miscCount} misconfiguration(s)
          </div>
        </div>
      </div>

      {!narration && !loading && (
        <button
          onClick={generate}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-md text-sm font-medium"
        >
          <Sparkles size={14} />
          Generate AI Assessment
        </button>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-slate-500 text-sm">
          <Loader2 size={14} className="animate-spin" />
          AIVAS is analyzing…
        </div>
      )}

      {err && <p className="text-red-600 text-sm mt-2">{err}</p>}

      {narration && (
        <div
          className="text-slate-700 text-sm leading-relaxed mt-2 space-y-2"
          dangerouslySetInnerHTML={{ __html: mdToHtml(narration) }}
        />
      )}
    </div>
  )
}
