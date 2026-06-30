// frontend/src/hooks/useWebSocket.test.jsx
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useWebSocket } from './useWebSocket'

let mockWs
const mockOnScanComplete = vi.fn()

beforeEach(() => {
  mockWs = {
    onmessage: null,
    onerror: null,
    close: vi.fn(),
  }
  vi.stubGlobal('WebSocket', vi.fn(() => mockWs))
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ json: () => Promise.resolve({ scan_key: 'test-key-123' }) })
  ))
})

describe('useWebSocket', () => {
  it('starts in idle state', () => {
    const { result } = renderHook(() => useWebSocket({}))
    expect(result.current.status).toBe('idle')
    expect(result.current.isScanning).toBe(false)
  })

  it('transitions to scanning on startScan', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    expect(result.current.status).toBe('scanning')
    expect(result.current.isScanning).toBe(true)
  })

  it('transitions to done on done event', async () => {
    const { result } = renderHook(() => useWebSocket({ onScanComplete: mockOnScanComplete }))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => {
      mockWs.onmessage({ data: JSON.stringify({ type: 'done', scan_id: 5, score: 80, grade: 'B' }) })
    })
    expect(result.current.status).toBe('done')
    expect(result.current.isDone).toBe(true)
    expect(result.current.result.scan_id).toBe(5)
    expect(mockOnScanComplete).toHaveBeenCalled()
  })

  it('accumulates progress lines', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => {
      mockWs.onmessage({ data: JSON.stringify({ type: 'progress', phase: 'init', text: 'Starting…' }) })
      mockWs.onmessage({ data: JSON.stringify({ type: 'progress', phase: 'phase_header', text: 'PORT SCANNING' }) })
    })
    expect(result.current.progressLines).toHaveLength(2)
  })

  it('transitions to error state on error event', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => {
      mockWs.onmessage({ data: JSON.stringify({ type: 'error', text: 'nmap not found' }) })
    })
    expect(result.current.status).toBe('error')
    expect(result.current.errorMsg).toBe('nmap not found')
  })

  it('resets to idle on reset()', async () => {
    const { result } = renderHook(() => useWebSocket({}))
    await act(async () => {
      result.current.startScan('192.168.1.1', 2)
    })
    act(() => { result.current.reset() })
    expect(result.current.status).toBe('idle')
    expect(result.current.progressLines).toHaveLength(0)
  })
})
