// frontend/src/lib/mdToHtml.js
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function applyInline(line) {
  return esc(line).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
}

export function mdToHtml(md) {
  if (!md) return ''
  const lines = md.split('\n')
  const out = []
  let inList = false
  for (const raw of lines) {
    const line = raw.trim()
    if (!line) {
      if (inList) { out.push('</ul>'); inList = false }
      continue
    }
    if (line.startsWith('- ') || line.startsWith('* ')) {
      if (!inList) { out.push('<ul class="list-disc pl-5 mb-2">'); inList = true }
      out.push(`<li>${applyInline(line.slice(2))}</li>`)
    } else {
      if (inList) { out.push('</ul>'); inList = false }
      out.push(`<p class="mb-2">${applyInline(line)}</p>`)
    }
  }
  if (inList) out.push('</ul>')
  return out.join('\n')
}
