export default function UserMessage({ text }) {
  return (
    <div className="flex justify-end py-1.5" data-testid="user-message">
      <div
        style={{
          background: '#0d1929',
          border: '1px solid #1a2d45',
          borderRadius: '14px 14px 4px 14px',
          color: '#90bde0',
          maxWidth: '75%',
        }}
        className="px-4 py-2.5 text-sm whitespace-pre-wrap"
      >
        {text}
      </div>
    </div>
  )
}
