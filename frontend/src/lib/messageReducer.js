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
      return state.map(m => m.id === action.id ? { ...m, log: [...(m.log || []), action.entry] } : m)
    case 'SET_STREAMING':
      return state.map(m => m.id === action.id ? { ...m, streaming: action.streaming } : m)
    case 'ERROR_MESSAGE':
      // Like REPLACE but preserves toolCalls so the tool panel stays visible
      return state.map(m => m.id === action.id
        ? { ...m, text: action.text, streaming: false }
        : m
      )
    case 'MARK_SCAN_DONE':
      // Mark a scan-progress message as finished (stopped/failed) without replacing it
      return state.map(m => m.id === action.id
        ? { ...m, scanStatus: action.status }
        : m
      )
    case 'TOOL_CALL':
      return state.map(m => m.id === action.id
        ? { ...m, toolCalls: [...(m.toolCalls || []), { name: action.name, args: action.args, status: 'running' }] }
        : m
      )
    case 'TOOL_RESULT': {
      return state.map(m => {
        if (m.id !== action.id) return m
        let matched = false
        const toolCalls = [...(m.toolCalls || [])].reverse().map(tc => {
          if (!matched && tc.name === action.name && tc.status === 'running') {
            matched = true
            return { ...tc, status: 'done', summary: action.summary }
          }
          return tc
        }).reverse()
        return { ...m, toolCalls }
      })
    }
    default:
      return state
  }
}

export function mapHistory(msgs) {
  const result = []
  const list = Array.isArray(msgs) ? msgs : []
  let i = 0

  while (i < list.length) {
    const m = list[i]

    if (m.role === 'user') {
      if (m.content) result.push({ id: uid(), type: 'user', text: m.content })
      i++
      continue
    }

    if (m.role === 'scan_progress') {
      result.push({ id: uid(), type: 'scan-progress', log: m.log || [], scanStatus: 'complete' })
      i++
      continue
    }

    if (m.role === 'scan') {
      result.push({ id: uid(), type: 'scan-card', scanData: m.scan_data })
      i++
      continue
    }

    if (m.role === 'assistant' && m.tool_calls && m.tool_calls.length > 0) {
      // Build tool call entries with _id for matching
      const toolCalls = m.tool_calls.map(tc => ({
        name: tc.function?.name || '?',
        args: _parseArgs(tc.function?.arguments),
        status: 'done',
        summary: 'done',
        _id: tc.id,
      }))

      let finalText = ''
      // {progress: log[]|null, scanData: {...}|null} pairs
      const scanPairs = []

      // Scan forward collecting tool results, scan progress, scan cards, optional final text
      let j = i + 1
      while (j < list.length) {
        const cur = list[j]
        if (cur.role === 'tool') {
          const idx = toolCalls.findIndex(tc => tc._id === cur.tool_call_id)
          if (idx >= 0) {
            toolCalls[idx] = {
              ...toolCalls[idx],
              summary: _histSummary(toolCalls[idx].name, cur.content || ''),
            }
          }
          j++
        } else if (cur.role === 'scan_progress') {
          // Pair with the next scan card
          const next = list[j + 1]
          if (next && next.role === 'scan') {
            scanPairs.push({ progress: cur.log || [], scanData: next.scan_data })
            j += 2
          } else {
            scanPairs.push({ progress: cur.log || [], scanData: null })
            j++
          }
        } else if (cur.role === 'scan') {
          scanPairs.push({ progress: null, scanData: cur.scan_data })
          j++
        } else if (cur.role === 'assistant' && !(cur.tool_calls && cur.tool_calls.length > 0)) {
          if (cur.content) finalText = cur.content
          j++
          break
        } else {
          break
        }
      }

      i = j
      const cleanCalls = toolCalls.map(({ _id, ...rest }) => rest)
      result.push({ id: uid(), type: 'ai', text: finalText, toolCalls: cleanCalls, streaming: false })
      for (const { progress, scanData } of scanPairs) {
        if (progress && progress.length > 0) {
          result.push({ id: uid(), type: 'scan-progress', log: progress, scanStatus: 'complete' })
        }
        if (scanData) result.push({ id: uid(), type: 'scan-card', scanData })
      }
      continue
    }

    if (m.role === 'assistant') {
      if (m.content) result.push({ id: uid(), type: 'ai', text: m.content, streaming: false })
      i++
      continue
    }

    // Skip orphaned tool messages
    i++
  }

  return result
}

function _parseArgs(argsStr) {
  try { return JSON.parse(argsStr || '{}') } catch { return {} }
}

function _histSummary(name, resultJson) {
  try {
    const data = JSON.parse(resultJson)
    if (name === 'get_local_info') {
      const ip = data.ip || data.primary_ip || data.local_ip || ''
      const host = data.hostname || ''
      return ip ? (host ? `${host} · ${ip}` : ip) : 'done'
    }
    if (name === 'get_findings') return `${Array.isArray(data) ? data.length : 0} finding(s) returned`
    if (name === 'get_last_scan') return `${data?.findings?.length || 0} finding(s) returned`
    if (name === 'discover_hosts') {
      if (data && typeof data === 'object') {
        const count = data.count || 0
        return count === 0 && data.note ? data.note.slice(0, 80) : `${count} device(s) found`
      }
    }
    if (name === 'get_history') return `${Array.isArray(data) ? data.length : 0} scan(s) in history`
    if (name === 'scan_host' || name === 'remote_scan') return 'Scan started'
    return 'done'
  } catch {
    return 'done'
  }
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
