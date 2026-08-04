import { useState } from 'react'
import { Send } from 'lucide-react'

export default function ChatInput({ onSend, disabled }) {
  const [text, setText] = useState('')

  const submit = (e) => {
    e.preventDefault()
    const t = text.trim()
    if (!t || disabled) return
    onSend(t)
    setText('')
  }

  return (
    <div
      style={{ background: '#0a0a0a', borderTop: '1px solid #2a2a2a' }}
      className="px-4 py-3 shrink-0"
    >
      <form
        onSubmit={submit}
        className="mx-auto flex gap-2"
        style={{ maxWidth: 800 }}
      >
        <input
          data-testid="chat-input"
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) submit(e) }}
          placeholder="Type a message…"
          disabled={disabled}
          style={{ background: '#161616', border: '1px solid #2a2a2a', color: '#e0e0e0' }}
          className="flex-1 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-[#4a9eff] placeholder:text-[#999] disabled:opacity-50 transition-colors"
        />
        <button
          type="submit"
          disabled={disabled || !text.trim()}
          style={{ background: '#4a9eff' }}
          className="px-3 py-2.5 rounded-lg text-black font-medium flex items-center hover:opacity-90 disabled:opacity-40 transition-opacity"
          aria-label="Send"
        >
          <Send size={16} />
        </button>
      </form>
    </div>
  )
}
