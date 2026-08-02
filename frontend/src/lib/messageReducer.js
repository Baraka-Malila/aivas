// Reducer and helper functions for App.jsx message state

export function uid() {
  return Math.random().toString(36).slice(2, 9)
}

export function reducer(state, action) {
  switch (action.type) {
    case 'APPEND':
      return [...state, action.msg]
    case 'UPDATE_TEXT':
      return state.map(m => m.id === action.id ? { ...m, text: action.text } : m)
    case 'REPLACE':
      return state.map(m => m.id === action.id ? action.msg : m)
    case 'REMOVE':
      return state.filter(m => m.id !== action.id)
    case 'SET_MESSAGES':
      return action.messages
    case 'UPDATE_LOG':
      return state.map(m => m.id === action.id ? { ...m, log: action.log } : m)
    case 'SET_STREAMING':
      return state.map(m => m.id === action.id ? { ...m, streaming: action.streaming } : m)
    default:
      return state
  }
}

export function mapHistory(msgs) {
  return (Array.isArray(msgs) ? msgs : [])
    .filter(m => {
      if (m.role === 'user') return !!m.content
      if (m.role === 'assistant') return !!m.content && !m.tool_calls
      return false
    })
    .map(m => ({
      id: uid(),
      type: m.role === 'user' ? 'user' : 'ai',
      text: m.content,
    }))
}

export function countSeverities(findings) {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const f of Array.isArray(findings) ? findings : []) {
    const s = (f.cvss_severity || 'LOW').toUpperCase()
    if (s in c) c[s]++
  }
  return c
}

export function daysAgo(isoStr) {
  if (!isoStr) return 0
  return Math.round((Date.now() - new Date(isoStr).getTime()) / 86_400_000)
}

export const FIRST_VISIT_MSG =
  "Hello. I'm AIVAS, your network security assistant. Give me an IP address or " +
  "network range and I'll scan it for you. Type /help to see what I can do."
