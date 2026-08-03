import { useEffect, useRef, useCallback } from 'react'
import AiMessage from './AiMessage'
import UserMessage from './UserMessage'
import ScanProgress from './ScanProgress'
import ScanCard from './ScanCard'

export default function ChatArea({ messages, onSend, onAnalysis, onStopScan }) {
  const containerRef = useRef(null)
  const bottomRef = useRef(null)
  const atBottomRef = useRef(true)
  const rafRef = useRef(null)

  // Track whether the user is near the bottom (within 120px)
  const onScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 120
  }, [])

  // After EVERY render: if user is at bottom, scroll to bottom.
  // RAF-debounced so rapid streaming doesn't queue dozens of animations.
  useEffect(() => {
    if (!atBottomRef.current) return
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    rafRef.current = requestAnimationFrame(() => {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    })
  })

  return (
    <div
      ref={containerRef}
      onScroll={onScroll}
      data-testid="chat-area"
      className="flex-1 overflow-y-auto"
    >
      <div className="mx-auto px-4 py-6 space-y-1" style={{ maxWidth: 800 }}>
        {messages.map(m => {
          if (m.type === 'user')          return <UserMessage   key={m.id} text={m.text} />
          if (m.type === 'ai')            return <AiMessage     key={m.id} text={m.text} streaming={m.streaming} toolCalls={m.toolCalls} />
          if (m.type === 'scan-progress') return <ScanProgress  key={m.id} log={m.log || []} onStop={onStopScan} scanStatus={m.scanStatus} />
          if (m.type === 'scan-card')     return <ScanCard      key={m.id} scanData={m.scanData} onSend={onSend} onAnalysis={onAnalysis} />
          return null
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
