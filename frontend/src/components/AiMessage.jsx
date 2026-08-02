import { mdToHtml } from '../lib/mdToHtml'
import ToolCallPanel from './ToolCallPanel'

export default function AiMessage({ text, streaming, toolCalls }) {
  return (
    <div className="py-3" data-testid="ai-message">
      {toolCalls && toolCalls.length > 0 && (
        <ToolCallPanel toolCalls={toolCalls} text={text} />
      )}
      <div
        style={{ color: '#c8c8c8', lineHeight: 1.7 }}
        className="text-sm"
        dangerouslySetInnerHTML={{
          __html: mdToHtml(text) + (streaming ? '<span class="cursor-blink">▋</span>' : '')
        }}
      />
    </div>
  )
}
