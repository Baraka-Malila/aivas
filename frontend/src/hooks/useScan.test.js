import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useScan } from './useScan'

class MockWS {
  constructor(url) {
    this.url = url
    this.readyState = 1  // OPEN
    MockWS.last = this
  }
  close() { this.onclose?.() }
}
MockWS.last = null

beforeEach(() => {
  vi.stubGlobal('WebSocket', MockWS)
  // Mock window.location
  delete window.location
  window.location = { protocol: 'http:', host: 'localhost:3000' }
})
afterEach(() => {
  vi.unstubAllGlobals()
})

describe('useScan', () => {
  it('returns isScanning=false and start function initially', () => {
    const { result } = renderHook(() => useScan(vi.fn(), vi.fn()))
    expect(result.current.isScanning).toBe(false)
    expect(typeof result.current.start).toBe('function')
  })

  it('opens WebSocket with correct scan URL', () => {
    const { result } = renderHook(() => useScan(vi.fn(), vi.fn()))
    act(() => {
      result.current.start('scan-123')
    })
    expect(MockWS.last.url).toContain('/ws/scan/scan-123')
  })

  it('sets isScanning=true when start() is called', () => {
    const { result } = renderHook(() => useScan(vi.fn(), vi.fn()))
    expect(result.current.isScanning).toBe(false)
    act(() => {
      result.current.start('scan-1')
    })
    expect(result.current.isScanning).toBe(true)
  })

  it('calls onProgress when phase_header message is received', () => {
    const onProgress = vi.fn()
    const { result } = renderHook(() => useScan(onProgress, vi.fn()))
    act(() => {
      result.current.start('scan-1')
      MockWS.last.onmessage({ data: '{"type":"phase_header","text":"Scanning ports..."}' })
    })
    expect(onProgress).toHaveBeenCalledWith('Scanning ports...')
  })

  it('calls onDone and sets isScanning=false when done message is received', () => {
    const onDone = vi.fn()
    const { result } = renderHook(() => useScan(vi.fn(), onDone))
    act(() => {
      result.current.start('scan-1')
      const doneEvent = {
        type: 'done',
        scan_id: 's1',
        target: '192.168.1.0/24',
        grade: 'A',
        score: 85,
        service_count: 5,
        findings: [],
        misconfigs: []
      }
      MockWS.last.onmessage({ data: JSON.stringify(doneEvent) })
    })
    expect(onDone).toHaveBeenCalledWith(expect.objectContaining({ type: 'done', scan_id: 's1' }))
    expect(result.current.isScanning).toBe(false)
  })

  it('sets isScanning=false when error message is received', () => {
    const { result } = renderHook(() => useScan(vi.fn(), vi.fn()))
    act(() => {
      result.current.start('scan-1')
      MockWS.last.onmessage({ data: '{"type":"error","message":"Connection lost"}' })
    })
    expect(result.current.isScanning).toBe(false)
  })

  it('sets isScanning=false when WebSocket error occurs', () => {
    const { result } = renderHook(() => useScan(vi.fn(), vi.fn()))
    act(() => {
      result.current.start('scan-1')
      MockWS.last.onerror()
    })
    expect(result.current.isScanning).toBe(false)
  })

  it('ignores malformed JSON messages', () => {
    const onProgress = vi.fn()
    const onDone = vi.fn()
    const { result } = renderHook(() => useScan(onProgress, onDone))
    act(() => {
      result.current.start('scan-1')
      MockWS.last.onmessage({ data: 'not json' })
    })
    expect(onProgress).not.toHaveBeenCalled()
    expect(onDone).not.toHaveBeenCalled()
    expect(result.current.isScanning).toBe(true)
  })

  it('uses wss protocol when location is https', () => {
    window.location.protocol = 'https:'
    const { result } = renderHook(() => useScan(vi.fn(), vi.fn()))
    act(() => {
      result.current.start('scan-1')
    })
    expect(MockWS.last.url).toContain('wss://')
  })

  it('closes previous WebSocket when starting a new scan', () => {
    const { result } = renderHook(() => useScan(vi.fn(), vi.fn()))
    act(() => {
      result.current.start('scan-1')
    })
    const firstWS = MockWS.last
    const closeSpy = vi.spyOn(firstWS, 'close')
    act(() => {
      result.current.start('scan-2')
    })
    expect(closeSpy).toHaveBeenCalled()
  })

  it('passes log array to onDone', () => {
    const onDone = vi.fn()
    const { result } = renderHook(() => useScan(vi.fn(), onDone))

    act(() => result.current.start('key123'))

    act(() => {
      MockWS.last.onmessage?.({ data: JSON.stringify({ type: 'phase_header', text: 'PORT SCANNING' }) })
      MockWS.last.onmessage?.({ data: JSON.stringify({ type: 'ports', text: 'Found 3 ports' }) })
      MockWS.last.onmessage?.({ data: JSON.stringify({
        type: 'done', scan_id: 1, target: '1.1.1.1',
        grade: 'B', score: 60, service_count: 3,
        findings: [], misconfigs: [], services: [],
      }) })
    })

    expect(onDone).toHaveBeenCalled()
    const doneArg = onDone.mock.calls[0][0]
    expect(doneArg.log).toBeDefined()
    expect(doneArg.log).toContain('PORT SCANNING')
    expect(doneArg.log).toContain('Found 3 ports')
  })
})
