import { useEffect, useRef } from 'react'
import AiMessage from './AiMessage'
import UserMessage from './UserMessage'
import ScanProgress from './ScanProgress'
import ScanCard from './ScanCard'

export default function ChatArea({ messages, onSend, onStopScan }) {
  const bottomRef = useRef(null)
  // Scroll when list grows OR when a message changes type (e.g. scan-progress → scan-card)
  const typeKey = messages.map(m => m.type).join(',')

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length, typeKey])

  return (
    <div data-testid="chat-area" className="flex-1 overflow-y-auto">
      <div className="mx-auto px-4 py-6 space-y-1" style={{ maxWidth: 800 }}>
        {messages.map(m => {
          if (m.type === 'user')         return <UserMessage   key={m.id} text={m.text} />
          if (m.type === 'ai')           return <AiMessage     key={m.id} text={m.text} streaming={m.streaming} />
          if (m.type === 'scan-progress') return <ScanProgress key={m.id} log={m.log || []} onStop={onStopScan} />
          if (m.type === 'scan-card')    return <ScanCard      key={m.id} scanData={m.scanData} onSend={onSend} />
          return null
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
