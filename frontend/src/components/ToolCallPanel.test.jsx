import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ToolCallPanel from './ToolCallPanel'

const doneCalls = [
  { name: 'get_findings', args: { scan_id: '1' }, status: 'done', summary: '5 findings returned' },
]
const runningCalls = [
  { name: 'get_last_scan', args: {}, status: 'running' },
]

describe('ToolCallPanel', () => {
  it('renders nothing when toolCalls is empty', () => {
    const { container } = render(<ToolCallPanel toolCalls={[]} text="" />)
    expect(container.firstChild).toBeNull()
  })

  it('renders nothing when toolCalls is null', () => {
    const { container } = render(<ToolCallPanel toolCalls={null} text="" />)
    expect(container.firstChild).toBeNull()
  })

  it('shows expanded panel when text is empty', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByTestId('tool-call-panel-expanded')).toBeTruthy()
  })

  it('shows tool name in expanded panel', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByText(/get_findings/)).toBeTruthy()
  })

  it('shows summary when status is done', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByText(/5 findings returned/)).toBeTruthy()
  })

  it('auto-collapses when text becomes non-empty', () => {
    const { rerender } = render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByTestId('tool-call-panel-expanded')).toBeTruthy()
    rerender(<ToolCallPanel toolCalls={doneCalls} text="Your scan shows" />)
    expect(screen.getByTestId('tool-call-panel-collapsed')).toBeTruthy()
  })

  it('collapsed badge shows correct count', () => {
    const { rerender } = render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    rerender(<ToolCallPanel toolCalls={doneCalls} text="done" />)
    expect(screen.getByText(/1 tool used/)).toBeTruthy()
  })

  it('collapsed badge uses plural for multiple tools', () => {
    const two = [
      { name: 'get_findings', args: {}, status: 'done', summary: '3 findings returned' },
      { name: 'get_last_scan', args: {}, status: 'done', summary: '3 findings returned' },
    ]
    const { rerender } = render(<ToolCallPanel toolCalls={two} text="" />)
    rerender(<ToolCallPanel toolCalls={two} text="done" />)
    expect(screen.getByText(/2 tools used/)).toBeTruthy()
  })

  it('clicking collapsed badge re-expands', () => {
    const { rerender } = render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    rerender(<ToolCallPanel toolCalls={doneCalls} text="done" />)
    fireEvent.click(screen.getByTestId('tool-call-panel-collapsed'))
    expect(screen.getByTestId('tool-call-panel-expanded')).toBeTruthy()
  })

  it('clicking header collapses expanded panel', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    fireEvent.click(screen.getByTestId('tool-call-panel-header'))
    expect(screen.getByTestId('tool-call-panel-collapsed')).toBeTruthy()
  })

  it('shows spinner indicator for running tool', () => {
    render(<ToolCallPanel toolCalls={runningCalls} text="" />)
    expect(screen.getAllByText(/⟳/).length).toBeGreaterThan(0)
  })

  it('shows checkmark for done tool', () => {
    render(<ToolCallPanel toolCalls={doneCalls} text="" />)
    expect(screen.getByText(/✓/)).toBeTruthy()
  })

  it('clicking a row toggles args detail block', () => {
    const withArgs = [{ name: 'get_findings', args: { scan_id: '3' }, status: 'done', summary: '2 findings returned' }]
    render(<ToolCallPanel toolCalls={withArgs} text="" />)
    const row = screen.getByTestId('tool-call-row-0')
    fireEvent.click(row)
    expect(screen.getByTestId('tool-call-detail-0')).toBeTruthy()
    fireEvent.click(row)
    expect(() => screen.getByTestId('tool-call-detail-0')).toThrow()
  })
})
