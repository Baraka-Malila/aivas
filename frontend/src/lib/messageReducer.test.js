import { describe, it, expect } from 'vitest'
import { reducer, uid } from './messageReducer'

describe('reducer', () => {
  it('APPEND adds message to state', () => {
    const msg = { id: 'a', type: 'ai', text: '' }
    const state = reducer([], { type: 'APPEND', msg })
    expect(state).toHaveLength(1)
    expect(state[0]).toEqual(msg)
  })

  it('UPDATE_TEXT updates matching message text', () => {
    const initial = [{ id: 'x', type: 'ai', text: 'old' }]
    const state = reducer(initial, { type: 'UPDATE_TEXT', id: 'x', text: 'new' })
    expect(state[0].text).toBe('new')
  })

  it('SET_STREAMING sets streaming flag', () => {
    const initial = [{ id: 'x', type: 'ai', text: 'hello', streaming: true }]
    const state = reducer(initial, { type: 'SET_STREAMING', id: 'x', streaming: false })
    expect(state[0].streaming).toBe(false)
  })

  it('SET_STREAMING does not mutate other fields', () => {
    const initial = [{ id: 'x', type: 'ai', text: 'hello', streaming: true }]
    const state = reducer(initial, { type: 'SET_STREAMING', id: 'x', streaming: false })
    expect(state[0].text).toBe('hello')
    expect(state[0].type).toBe('ai')
  })

  it('REMOVE removes matching message', () => {
    const initial = [{ id: 'a' }, { id: 'b' }]
    const state = reducer(initial, { type: 'REMOVE', id: 'a' })
    expect(state).toHaveLength(1)
    expect(state[0].id).toBe('b')
  })

  it('SET_MESSAGES replaces state entirely', () => {
    const initial = [{ id: 'a' }]
    const msgs = [{ id: 'b' }, { id: 'c' }]
    const state = reducer(initial, { type: 'SET_MESSAGES', messages: msgs })
    expect(state).toEqual(msgs)
  })

  it('unknown action returns state unchanged', () => {
    const initial = [{ id: 'z' }]
    const state = reducer(initial, { type: 'BOGUS' })
    expect(state).toBe(initial)
  })
})
