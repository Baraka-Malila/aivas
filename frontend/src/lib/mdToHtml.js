// UTF-8 smart punctuation decoded as Windows-1252 → fix back to Unicode.
// Happens when LLMs trained on CP1252-encoded data echo those byte sequences.
function fixMojibake(s) {
  return s
    .replace(/â€”/g, '—')  // â€" → em-dash
    .replace(/â€™/g, '’')  // â€™ → right single quote
    .replace(/â€˜/g, '‘')  // â€˜ → left single quote
    .replace(/â€œ/g, '“')  // â€œ → left double quote
    .replace(/â€/g, '”')  // â€\x9d → right double quote
    .replace(/â€¦/g, '…')  // â€¦ → ellipsis
}

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function applyInline(line) {
  return esc(line)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code style="background:#1a1a1a;padding:0 3px;border-radius:3px">$1</code>')
}

export function mdToHtml(md) {
  if (!md) return ''
  md = fixMojibake(md)
  const lines = md.split('\n')
  const out = []
  let inList = false
  let inOl = false

  const closeList = () => {
    if (inList) { out.push('</ul>'); inList = false }
    if (inOl) { out.push('</ol>'); inOl = false }
  }

  for (const raw of lines) {
    const line = raw.trim()

    if (!line) {
      closeList()
      continue
    }

    // ## Heading / ### Heading
    if (line.startsWith('### ')) {
      closeList()
      out.push(`<p class="mb-1 mt-2" style="font-weight:600;font-size:11px;letter-spacing:.05em;color:#aaa">${applyInline(line.slice(4))}</p>`)
      continue
    }
    if (line.startsWith('## ')) {
      closeList()
      out.push(`<p class="mb-1 mt-3" style="font-weight:700;font-size:12px;letter-spacing:.05em;color:#e0e0e0">${applyInline(line.slice(3))}</p>`)
      continue
    }
    if (line.startsWith('# ')) {
      closeList()
      out.push(`<p class="mb-1 mt-3" style="font-weight:700;font-size:13px;color:#e0e0e0">${applyInline(line.slice(2))}</p>`)
      continue
    }

    // Bullet list
    if (line.startsWith('- ') || line.startsWith('* ')) {
      if (inOl) { out.push('</ol>'); inOl = false }
      if (!inList) { out.push('<ul class="list-disc pl-5 mb-1">'); inList = true }
      out.push(`<li>${applyInline(line.slice(2))}</li>`)
      continue
    }

    // Ordered list: "1. " "2. " etc.
    const olMatch = line.match(/^\d+\.\s+(.*)/)
    if (olMatch) {
      if (inList) { out.push('</ul>'); inList = false }
      if (!inOl) { out.push('<ol class="list-decimal pl-5 mb-1">'); inOl = true }
      out.push(`<li>${applyInline(olMatch[1])}</li>`)
      continue
    }

    closeList()
    out.push(`<p class="mb-2">${applyInline(line)}</p>`)
  }

  closeList()
  return out.join('\n')
}
