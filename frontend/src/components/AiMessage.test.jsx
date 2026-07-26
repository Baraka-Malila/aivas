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
})
