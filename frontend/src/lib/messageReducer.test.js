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

  it('TOOL_CALL appends entry with status running', () => {
    const initial = [{ id: 'x', type: 'ai', text: '', streaming: true }]
    const state = reducer(initial, { type: 'TOOL_CALL', id: 'x', name: 'get_findings', args: { scan_id: '1' } })
    expect(state[0].toolCalls).toHaveLength(1)
    expect(state[0].toolCalls[0]).toEqual({ name: 'get_findings', args: { scan_id: '1' }, status: 'running' })
  })

  it('TOOL_CALL appends to existing toolCalls', () => {
    const initial = [{ id: 'x', type: 'ai', text: '', streaming: true,
      toolCalls: [{ name: 'get_last_scan', args: {}, status: 'done', summary: '3 findings returned' }] }]
    const state = reducer(initial, { type: 'TOOL_CALL', id: 'x', name: 'get_findings', args: {} })
    expect(state[0].toolCalls).toHaveLength(2)
    expect(state[0].toolCalls[1].status).toBe('running')
  })

  it('TOOL_RESULT updates running entry to done with summary', () => {
    const initial = [{ id: 'x', type: 'ai', text: '', streaming: true,
      toolCalls: [{ name: 'get_findings', args: {}, status: 'running' }] }]
    const state = reducer(initial, { type: 'TOOL_RESULT', id: 'x', name: 'get_findings', summary: '5 findings returned' })
    expect(state[0].toolCalls[0].status).toBe('done')
    expect(state[0].toolCalls[0].summary).toBe('5 findings returned')
  })

  it('TOOL_RESULT only updates last running entry matching name', () => {
    const initial = [{ id: 'x', type: 'ai', text: '', streaming: true,
      toolCalls: [
        { name: 'get_findings', args: {}, status: 'done', summary: 'old' },
        { name: 'get_findings', args: {}, status: 'running' },
      ] }]
    const state = reducer(initial, { type: 'TOOL_RESULT', id: 'x', name: 'get_findings', summary: 'new' })
    expect(state[0].toolCalls[0].summary).toBe('old')
    expect(state[0].toolCalls[1].summary).toBe('new')
    expect(state[0].toolCalls[1].status).toBe('done')
  })

  it('TOOL_RESULT on unknown id is a no-op', () => {
    const initial = [{ id: 'x', type: 'ai', text: '' }]
    const state = reducer(initial, { type: 'TOOL_RESULT', id: 'NOPE', name: 'get_findings', summary: 'x' })
    expect(state[0].toolCalls).toBeUndefined()
  })
})
