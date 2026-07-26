import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useChat } from './useChat'

class FakeWS {
  constructor(url) { this.url = url; this.sent = []; this.readyState = 0 }
  send(data) { this.sent.push(JSON.parse(data)) }
  close() { this.readyState = 3 }
}

let fakeWs
beforeEach(() => {
  fakeWs = null
  vi.stubGlobal('WebSocket', function(url) {
    fakeWs = new FakeWS(url)
    return fakeWs
  })
})

describe('useChat', () => {
  it('opens WS with provider/model query params', () => {
    renderHook(() => useChat({
      sessionId: 'abc', onEvent: vi.fn(),
      provider: 'groq', model: 'llama-3.3-70b-versatile'
    }))
    expect(fakeWs.url).toContain('provider=groq')
    expect(fakeWs.url).toContain('model=llama-3.3-70b-versatile')
  })

  it('sends auth message on open with api key', () => {
    renderHook(() => useChat({
      sessionId: 'abc', onEvent: vi.fn(),
      apiKey: 'gsk_test', shodanKey: 'shodan_key_123'
    }))
    act(() => { fakeWs.onopen?.() })
    const authMsg = fakeWs.sent.find(m => m.type === 'auth')
    expect(authMsg).toBeTruthy()
    expect(authMsg.api_key).toBe('gsk_test')
    expect(authMsg.shodan_key).toBe('shodan_key_123')
  })

  it('calls onEvent for token messages', () => {
    const onEvent = vi.fn()
    renderHook(() => useChat({ sessionId: 'abc', onEvent }))
    act(() => { fakeWs.onmessage?.({ data: JSON.stringify({ type: 'token', text: 'Hi' }) }) })
    expect(onEvent).toHaveBeenCalledWith({ type: 'token', text: 'Hi' })
  })

  it('send() dispatches user message when open', () => {
    const { result } = renderHook(() => useChat({ sessionId: 'abc', onEvent: vi.fn() }))
    act(() => { fakeWs.readyState = 1; fakeWs.onopen?.() })
    act(() => result.current.send('hello') )
    const userMsg = fakeWs.sent.find(m => m.type === 'user')
    expect(userMsg?.text).toBe('hello')
  })
})
