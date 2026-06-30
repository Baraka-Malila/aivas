// frontend/src/lib/severity.js
export const SEV_CONFIG = {
  CRITICAL: { bg: 'bg-red-50', text: 'text-red-800', border: 'border-red-200' },
  HIGH:     { bg: 'bg-amber-50', text: 'text-amber-800', border: 'border-amber-200' },
  MEDIUM:   { bg: 'bg-yellow-50', text: 'text-yellow-800', border: 'border-yellow-200' },
  LOW:      { bg: 'bg-green-50', text: 'text-green-800', border: 'border-green-200' },
}

export function sevClasses(severity) {
  const cfg = SEV_CONFIG[(severity || '').toUpperCase()] || SEV_CONFIG.LOW
  return `${cfg.bg} ${cfg.text} font-semibold text-xs px-2 py-0.5 rounded border ${cfg.border}`
}

export function gradeColor(grade) {
  const map = { A: '#2a6e2a', B: '#3a7a3a', C: '#8a6a00', D: '#8a4000', F: '#8a0000' }
  return map[grade] || '#555'
}

export function gradeBadgeClass(grade) {
  const map = {
    A: 'bg-green-100 text-green-800',
    B: 'bg-green-50 text-green-700',
    C: 'bg-yellow-50 text-yellow-700',
    D: 'bg-orange-50 text-orange-700',
    F: 'bg-red-50 text-red-800',
  }
  return map[grade] || 'bg-slate-100 text-slate-700'
}
