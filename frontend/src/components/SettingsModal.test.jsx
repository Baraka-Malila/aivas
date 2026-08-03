import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SettingsModal from './SettingsModal'

const PROVIDERS = ['Groq', 'Claude', 'Ollama']
const MODEL_DEFAULTS = {
  groq: 'llama-3.3-70b-versatile',
  claude: 'claude-haiku-4-5-20251001',
  ollama: 'llama3',
}

beforeEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
  // remote-targets API — return empty list so tests don't need a real server
  global.fetch = vi.fn().mockResolvedValue({ json: () => Promise.resolve([]) })
})

describe('SettingsModal', () => {
  it('renders provider dropdown', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    expect(screen.getByText('Provider')).toBeTruthy()
  })

  it('renders model input', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    const modelInput = screen.getByDisplayValue('llama-3.3-70b-versatile')
    expect(modelInput).toBeTruthy()
  })

  it('renders Shodan key field', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    expect(screen.getByPlaceholderText(/shodan/i)).toBeTruthy()
  })

  it('saves provider and model to localStorage on save', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('Save'))
    expect(localStorage.getItem('aivas_provider')).toBe('groq')
    expect(localStorage.getItem('aivas_model')).toBe('llama-3.3-70b-versatile')
  })

  it('changing provider updates model default', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    const select = screen.getAllByRole('combobox')[0]
    fireEvent.change(select, { target: { value: 'ollama' } })
    const modelInput = screen.getByDisplayValue('llama3')
    expect(modelInput).toBeTruthy()
  })
})
