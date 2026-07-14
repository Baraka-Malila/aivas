import { renderHook, act } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useChat } from './useChat'

class MockWS {
  constructor(url) {
    this.url = url
    this.readyState = 1  // OPEN
    this.sent = []
    MockWS.last = this
  }
  send(data) { this.sent.push(data) }
  close() { this.onclose?.() }
}
MockWS.last = null

beforeEach(() => { vi.stubGlobal('WebSocket', MockWS) })
afterEach(() => { vi.unstubAllGlobals() })

describe('useChat', () => {
  it('opens WebSocket with correct session URL', () => {
    renderHook(() => useChat('sess-1', vi.fn()))
    expect(MockWS.last.url).toContain('/ws/chat/sess-1')
  })

  it('does not open WebSocket when sessionId is null', () => {
    MockWS.last = null
    renderHook(() => useChat(null, vi.fn()))
    expect(MockWS.last).toBeNull()
  })

  it('send() dispatches user message over WS', () => {
    const { result } = renderHook(() => useChat('s1', vi.fn()))
    act(() => result.current.send('hello'))
    expect(JSON.parse(MockWS.last.sent[0])).toEqual({ type: 'user', text: 'hello' })
  })

  it('calls onEvent with parsed message on WS message', () => {
    const onEvent = vi.fn()
    renderHook(() => useChat('s1', onEvent))
    act(() => {
      MockWS.last.onmessage({ data: '{"type":"complete","text":"hi"}' })
    })
    expect(onEvent).toHaveBeenCalledWith({ type: 'complete', text: 'hi' })
  })
})
