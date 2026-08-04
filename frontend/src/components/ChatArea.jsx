import { useEffect, useRef, useCallback, useImperativeHandle, forwardRef } from 'react'
import AiMessage from './AiMessage'
import UserMessage from './UserMessage'
import ScanProgress from './ScanProgress'
import ScanCard from './ScanCard'

const ChatArea = forwardRef(function ChatArea({ messages, onSend, onAnalysis, onPdfRequest, onStopScan }, ref) {
  const containerRef = useRef(null)
  const bottomRef = useRef(null)
  const atBottomRef = useRef(true)
  const rafRef = useRef(null)

  useImperativeHandle(ref, () => ({
    scrollToBottom() {
      const el = containerRef.current
      if (el) el.scrollTop = el.scrollHeight
    },
  }))

  // Track whether the user is near the bottom (within 120px)
  const onScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    atBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 120
  }, [])

  // After EVERY render: if user is at bottom, scroll to absolute bottom.
  // Using scrollTop = scrollHeight directly (not scrollIntoView) so the
  // ThinkingIndicator is never clipped at the viewport edge.
  useEffect(() => {
    if (!atBottomRef.current) return
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    rafRef.current = requestAnimationFrame(() => {
      const el = containerRef.current
      if (el) el.scrollTop = el.scrollHeight
    })
  })

  return (
    <div
      ref={containerRef}
      onScroll={onScroll}
      data-testid="chat-area"
      className="flex-1 overflow-y-auto"
    >
      <div className="mx-auto px-4 pt-6 pb-20 space-y-1" style={{ maxWidth: 800 }}>
        {messages.map(m => {
          if (m.type === 'user')          return <UserMessage   key={m.id} text={m.text} />
          if (m.type === 'ai')            return <AiMessage     key={m.id} text={m.text} streaming={m.streaming} toolCalls={m.toolCalls} label={m.label} />
          if (m.type === 'scan-progress') return <ScanProgress  key={m.id} log={m.log || []} onStop={onStopScan} scanStatus={m.scanStatus} />
          if (m.type === 'scan-card')     return <ScanCard      key={m.id} scanData={m.scanData} onSend={onSend} onAnalysis={onAnalysis} onPdfRequest={onPdfRequest} />
          return null
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  )
})

export default ChatArea
