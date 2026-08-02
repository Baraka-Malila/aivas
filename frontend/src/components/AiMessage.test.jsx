import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import AiMessage from './AiMessage'

describe('AiMessage', () => {
  it('renders text', () => {
    render(<AiMessage text="Hello world" />)
    expect(screen.getByText(/Hello world/)).toBeTruthy()
  })

  it('shows cursor when streaming=true', () => {
    const { container } = render(<AiMessage text="Typing" streaming={true} />)
    expect(container.textContent).toContain('▋')
  })

  it('hides cursor when streaming=false', () => {
    const { container } = render(<AiMessage text="Done" streaming={false} />)
    expect(container.textContent).not.toContain('▋')
  })

  it('hides cursor when streaming prop absent', () => {
    const { container } = render(<AiMessage text="Done" />)
    expect(container.textContent).not.toContain('▋')
  })

  it('renders ToolCallPanel when toolCalls provided', () => {
    const toolCalls = [{ name: 'get_findings', args: {}, status: 'done', summary: '3 findings returned' }]
    const { container } = render(<AiMessage text="Here are your results." streaming={false} toolCalls={toolCalls} />)
    expect(container.querySelector('[data-testid="tool-call-panel-collapsed"]')).toBeTruthy()
  })

  it('does not render ToolCallPanel when toolCalls absent', () => {
    const { container } = render(<AiMessage text="Hello" streaming={false} />)
    expect(container.querySelector('[data-testid="tool-call-panel-expanded"]')).toBeNull()
    expect(container.querySelector('[data-testid="tool-call-panel-collapsed"]')).toBeNull()
  })
})
