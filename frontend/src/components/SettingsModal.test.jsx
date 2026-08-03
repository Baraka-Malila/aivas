import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SettingsModal from './SettingsModal'

beforeEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
  global.fetch = vi.fn().mockResolvedValue({ json: () => Promise.resolve([]) })
})

describe('SettingsModal nav', () => {
  it('opens on General section by default', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    expect(screen.getByText('Language')).toBeTruthy()
  })

  it('switches to AI Provider section', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('AI Provider'))
    expect(screen.getByText('Provider')).toBeTruthy()
    expect(screen.getByDisplayValue('llama-3.3-70b-versatile')).toBeTruthy()
  })

  it('switches to Integrations section', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('Integrations'))
    expect(screen.getByPlaceholderText(/shodan/i)).toBeTruthy()
  })

  it('switches to Remote Targets section', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('Remote Targets'))
    expect(screen.getByText('Add Target')).toBeTruthy()
  })
})

describe('SettingsModal save', () => {
  it('saves provider and model to localStorage', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('AI Provider'))
    fireEvent.click(screen.getByText('Save Changes'))
    expect(localStorage.getItem('aivas_provider')).toBe('groq')
    expect(localStorage.getItem('aivas_model')).toBe('llama-3.3-70b-versatile')
  })

  it('changing provider updates model default', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('AI Provider'))
    const select = screen.getByRole('combobox')
    fireEvent.change(select, { target: { value: 'ollama' } })
    expect(screen.getByDisplayValue('llama3')).toBeTruthy()
  })

  it('saves language selection', () => {
    render(<SettingsModal open={true} onClose={vi.fn()} />)
    fireEvent.click(screen.getByText('Swahili'))
    fireEvent.click(screen.getByText('Save Changes'))
    expect(localStorage.getItem('aivas_lang')).toBe('sw')
  })
})
