import { mdToHtml } from '../lib/mdToHtml'

export default function AiMessage({ text }) {
  return (
    <div className="py-3">
      <div style={{ color: '#4a9eff' }} className="text-xs font-medium mb-1.5 select-none">
        ✦ AIVAS
      </div>
      <div
        style={{ color: '#c8c8c8', lineHeight: 1.7 }}
        className="text-sm"
        dangerouslySetInnerHTML={{ __html: mdToHtml(text) }}
      />
    </div>
  )
}
