import { mdToHtml } from '../lib/mdToHtml'

export default function AiMessage({ text, streaming }) {
  return (
    <div className="py-3" data-testid="ai-message">
      <div style={{ color: '#4a9eff' }} className="text-xs font-medium mb-1.5 select-none">
        ✦ AIVAS
      </div>
      <div
        style={{ color: '#c8c8c8', lineHeight: 1.7 }}
        className="text-sm"
        dangerouslySetInnerHTML={{ __html: mdToHtml(text) + (streaming ? '<span class="cursor-blink">▋</span>' : '') }}
      />
    </div>
  )
}
