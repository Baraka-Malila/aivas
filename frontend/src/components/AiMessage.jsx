import { mdToHtml } from '../lib/mdToHtml'
import ToolCallPanel from './ToolCallPanel'

const LOGO_PATH = "M12 27.5 C8.5 29.8 4.5 30 3.6 28.4 C5.5 26.6 7.4 24 8.6 20.8 L18 3 L26.2 20.5 C27.6 19.4 29.6 19 30.6 19.6 C29.8 21.2 28.2 21.9 27 22 L29.3 30.2 L13.8 23.8 L26.3 18.4"

const TOOL_ACTIVE_LABEL = {
  get_local_info:  'PROBING',
  scan_host:       'SCANNING',
  remote_scan:     'SCANNING',
  discover_hosts:  'DISCOVERING',
  query_shodan:    'QUERYING',
  get_history:     'SEARCHING',
  get_last_scan:   'SEARCHING',
  get_findings:    'SEARCHING',
  explain_cve:     'LOOKING UP',
}

function ThinkingIndicator({ label = 'THINKING' }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '4px 0' }}>
      <svg width="30" height="30" viewBox="0 0 34 34" fill="none">
        <path
          d={LOGO_PATH}
          stroke="#1e1e1e"
          strokeWidth="2.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <path
          d={LOGO_PATH}
          stroke="#4a9eff"
          strokeWidth="2.6"
          strokeLinecap="round"
          strokeLinejoin="round"
          pathLength="1"
          style={{ animation: 'aivas-logoCenter 2.2s cubic-bezier(0.2,0.7,0.4,1) infinite' }}
        />
      </svg>
      <span style={{ fontFamily: '"Fira Code", monospace', fontSize: 11, color: '#888', letterSpacing: '0.1em' }}>
        {label}
      </span>
    </div>
  )
}

export default function AiMessage({ text, streaming, toolCalls, label }) {
  // Show the animated indicator whenever we're streaming and no response text yet.
  // It stays visible through tool calls — just changes its label.
  const showThinking = streaming && !text

  const runningTool = showThinking && toolCalls
    ? [...toolCalls].reverse().find(tc => tc.status === 'running')
    : null
  const thinkLabel = label || (runningTool && TOOL_ACTIVE_LABEL[runningTool.name]) || 'THINKING'

  return (
    <div className="py-3" data-testid="ai-message">
      {toolCalls && toolCalls.length > 0 && (
        <ToolCallPanel toolCalls={toolCalls} text={text} />
      )}
      {showThinking && <ThinkingIndicator label={thinkLabel} />}
      {text && (
        <div
          style={{ color: '#c8c8c8', lineHeight: 1.7 }}
          className="text-sm"
          dangerouslySetInnerHTML={{
            __html: mdToHtml(text) + (streaming ? '<span class="cursor-blink">▋</span>' : '')
          }}
        />
      )}
    </div>
  )
}
