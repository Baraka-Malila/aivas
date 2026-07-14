import { renderHook, act, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useSessions } from './useSessions'

beforeEach(() => {
  global.fetch = vi.fn()
})

describe('useSessions', () => {
  it('returns empty sessions array initially', () => {
    const { result } = renderHook(() => useSessions())
    expect(result.current.sessions).toEqual([])
    expect(typeof result.current.refresh).toBe('function')
    expect(typeof result.current.deleteSession).toBe('function')
  })

  it('refresh() fetches sessions from /api/sessions', async () => {
    const mockSessions = [
      { id: 's1', title: 'Session 1', updated_at: '2025-01-01T00:00:00Z' },
      { id: 's2', title: 'Session 2', updated_at: '2025-01-02T00:00:00Z' }
    ]
    global.fetch.mockResolvedValueOnce({
      json: async () => mockSessions
    })

    const { result } = renderHook(() => useSessions())
    act(() => {
      result.current.refresh()
    })

    await waitFor(() => {
      expect(result.current.sessions).toEqual(mockSessions)
    })
    expect(global.fetch).toHaveBeenCalledWith('/api/sessions')
  })

  it('refresh() handles non-array responses gracefully', async () => {
    global.fetch.mockResolvedValueOnce({
      json: async () => ({ data: [] })
    })

    const { result } = renderHook(() => useSessions())
    act(() => {
      result.current.refresh()
    })

    await waitFor(() => {
      expect(result.current.sessions).toEqual([])
    })
  })

  it('refresh() handles fetch errors gracefully', async () => {
    global.fetch.mockRejectedValueOnce(new Error('Network error'))

    const { result } = renderHook(() => useSessions())
    expect(result.current.sessions).toEqual([])
    act(() => {
      result.current.refresh()
    })

    await waitFor(() => {
      expect(result.current.sessions).toEqual([])
    })
  })

  it('deleteSession() calls DELETE endpoint and removes from state', async () => {
    const mockSessions = [
      { id: 's1', title: 'Session 1', updated_at: '2025-01-01T00:00:00Z' },
      { id: 's2', title: 'Session 2', updated_at: '2025-01-02T00:00:00Z' }
    ]
    global.fetch.mockResolvedValueOnce({
      json: async () => mockSessions
    })

    const { result } = renderHook(() => useSessions())
    act(() => {
      result.current.refresh()
    })

    await waitFor(() => {
      expect(result.current.sessions).toHaveLength(2)
    })

    global.fetch.mockResolvedValueOnce({})
    act(() => {
      result.current.deleteSession('s1')
    })

    await waitFor(() => {
      expect(result.current.sessions).toEqual([
        { id: 's2', title: 'Session 2', updated_at: '2025-01-02T00:00:00Z' }
      ])
    })
    expect(global.fetch).toHaveBeenCalledWith('/api/sessions/s1', { method: 'DELETE' })
  })

  it('deleteSession() handles fetch errors gracefully', async () => {
    const mockSessions = [
      { id: 's1', title: 'Session 1', updated_at: '2025-01-01T00:00:00Z' }
    ]
    global.fetch.mockResolvedValueOnce({
      json: async () => mockSessions
    })

    const { result } = renderHook(() => useSessions())
    act(() => {
      result.current.refresh()
    })

    await waitFor(() => {
      expect(result.current.sessions).toHaveLength(1)
    })

    global.fetch.mockRejectedValueOnce(new Error('Network error'))
    act(() => {
      result.current.deleteSession('s1')
    })

    // Session should still be removed from local state despite network error
    await waitFor(() => {
      expect(result.current.sessions).toEqual([])
    })
  })

  it('deleteSession() removes only the specified session', async () => {
    const mockSessions = [
      { id: 's1', title: 'Session 1', updated_at: '2025-01-01T00:00:00Z' },
      { id: 's2', title: 'Session 2', updated_at: '2025-01-02T00:00:00Z' },
      { id: 's3', title: 'Session 3', updated_at: '2025-01-03T00:00:00Z' }
    ]
    global.fetch.mockResolvedValueOnce({
      json: async () => mockSessions
    })

    const { result } = renderHook(() => useSessions())
    act(() => {
      result.current.refresh()
    })

    await waitFor(() => {
      expect(result.current.sessions).toHaveLength(3)
    })

    global.fetch.mockResolvedValueOnce({})
    act(() => {
      result.current.deleteSession('s2')
    })

    await waitFor(() => {
      expect(result.current.sessions).toEqual([
        { id: 's1', title: 'Session 1', updated_at: '2025-01-01T00:00:00Z' },
        { id: 's3', title: 'Session 3', updated_at: '2025-01-03T00:00:00Z' }
      ])
    })
  })
})
