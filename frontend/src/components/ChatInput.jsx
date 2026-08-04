import { useState, useRef, forwardRef, useImperativeHandle } from 'react'
import { Send } from 'lucide-react'

const ChatInput = forwardRef(function ChatInput({ onSend, disabled }, ref) {
  const [text, setText] = useState('')
  const [history, setHistory] = useState([])
  const [histIdx, setHistIdx] = useState(-1)
  const inputRef = useRef(null)
  const savedTextRef = useRef('')

  useImperativeHandle(ref, () => ({
    focus: () => inputRef.current?.focus(),
  }))

  const submit = (e) => {
    e.preventDefault()
    const t = text.trim()
    if (!t || disabled) return
    setHistory(prev => [t, ...prev])
    setHistIdx(-1)
    savedTextRef.current = ''
    onSend(t)
    setText('')
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { submit(e); return }

    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (history.length === 0) return
      if (histIdx === -1) savedTextRef.current = text
      const next = Math.min(histIdx + 1, history.length - 1)
      setHistIdx(next)
      setText(history[next])
      return
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (histIdx === -1) return
      const next = histIdx - 1
      setHistIdx(next)
      setText(next === -1 ? savedTextRef.current : history[next])
    }
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
          ref={inputRef}
          data-testid="chat-input"
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={handleKeyDown}
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
})

export default ChatInput
