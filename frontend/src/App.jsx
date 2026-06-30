// frontend/src/App.jsx
import React, { useState, useCallback } from 'react'
import { Shield } from 'lucide-react'
import Sidebar from './components/Sidebar'
import ScanBar from './components/ScanBar'
import ProgressFeed from './components/ProgressFeed'
import ResultsTabs from './components/ResultsTabs'
import { useWebSocket } from './hooks/useWebSocket'
import { useHistory } from './hooks/useHistory'

function EmptyState() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-center p-10 select-none">
      <Shield size={52} className="text-slate-200 mb-4" />
      <h2 className="text-2xl font-bold text-slate-300 mb-2 tracking-tight">AIVAS</h2>
      <p className="text-slate-400 text-sm">AI-Assisted Vulnerability Assessment System</p>
      <p className="text-slate-400 text-sm mt-5">Enter a target in the bar above to begin scanning</p>
      <p className="text-slate-300 text-xs mt-1.5 font-mono">
        e.g.&nbsp; 192.168.1.1 &nbsp;or&nbsp; 10.0.0.0/24
      </p>
    </div>
  )
}

export default function App() {
  const { scans, refresh: refreshHistory, deleteScan } = useHistory()
  const [activeScanId, setActiveScanId] = useState(null)
  const [historyScan, setHistoryScan] = useState(null)

  const { status, progressLines, result, errorMsg, startScan, reset, isScanning, isDone } =
    useWebSocket({ onScanComplete: refreshHistory })

  const handleScan = useCallback((target, level) => {
    setHistoryScan(null)
    setActiveScanId(null)
    startScan(target, level)
  }, [startScan])

  const handleSelectScan = useCallback(async (scan) => {
    reset()
    setActiveScanId(scan.id)
    try {
      const findings = await fetch(`/api/scan/${scan.id}`).then(r => r.json())
      setHistoryScan({
        scan_id: scan.id,
        target: scan.target,
        score: scan.risk_score,
        grade: scan.grade,
        findings: Array.isArray(findings) ? findings : [],
        misconfigs: [],
      })
    } catch {
      setHistoryScan(null)
    }
  }, [reset])

  const handleDeleteScan = useCallback(async (id) => {
    await deleteScan(id)
    if (activeScanId === id) {
      setActiveScanId(null)
      setHistoryScan(null)
    }
  }, [deleteScan, activeScanId])

  const displayResult = isDone ? result : historyScan
  const showFeed = isScanning || status === 'error'

  return (
    <div className="flex min-h-screen bg-[#f8fafc]">
      <Sidebar
        scans={scans}
        onNewScan={() => { reset(); setHistoryScan(null); setActiveScanId(null) }}
        onSelectScan={handleSelectScan}
        onDeleteScan={handleDeleteScan}
        onSettings={() => {}}
        activeScanId={activeScanId}
      />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <ScanBar onScan={handleScan} isScanning={isScanning} />
        <div className="flex-1 overflow-y-auto">
          {showFeed && (
            <div className="mx-4 mt-4 bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
              <ProgressFeed lines={progressLines} />
              {status === 'error' && (
                <div className="px-4 pb-4 text-red-600 text-sm font-mono">{errorMsg}</div>
              )}
            </div>
          )}
          {displayResult ? (
            <div className="mx-4 mt-4 bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
              <ResultsTabs
                result={displayResult}
                progressLines={isDone ? progressLines : []}
              />
            </div>
          ) : !showFeed ? (
            <EmptyState />
          ) : null}
        </div>
      </div>
    </div>
  )
}
