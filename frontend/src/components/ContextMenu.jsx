import { useEffect, useRef } from 'react'

export default function ContextMenu({ x, y, items, onClose }) {
  const ref = useRef(null)

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    const onClick = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose() }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClick)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClick)
    }
  }, [onClose])

  // Keep menu inside viewport
  const style = {
    position: 'fixed',
    top: y,
    left: x,
    zIndex: 200,
    background: '#161616',
    border: '1px solid #252525',
    borderRadius: 5,
    minWidth: 140,
    boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
    overflow: 'hidden',
  }

  return (
    <div ref={ref} style={style}>
      {items.map((item, i) => (
        <button
          key={i}
          onClick={() => { item.onClick(); onClose() }}
          style={{
            display: 'block',
            width: '100%',
            textAlign: 'left',
            background: 'transparent',
            border: 'none',
            padding: '8px 14px',
            fontSize: 12,
            fontFamily: 'inherit',
            color: item.danger ? '#ef5350' : '#c0c0c0',
            cursor: 'pointer',
          }}
          onMouseEnter={e => { e.currentTarget.style.background = '#1e1e1e' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
        >
          {item.label}
        </button>
      ))}
    </div>
  )
}
