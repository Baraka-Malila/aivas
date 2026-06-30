// frontend/src/components/FindingsTable.test.jsx
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import FindingsTable from './FindingsTable'

const FINDINGS = [
  { cve_id: 'CVE-2021-41773', cvss_score: 9.8, cvss_severity: 'CRITICAL', description: 'Path traversal in Apache', host: '192.168.1.1' },
  { cve_id: 'CVE-2021-44228', cvss_score: 10.0, cvss_severity: 'CRITICAL', description: 'Log4Shell RCE', host: '192.168.1.2' },
  { cve_id: 'CVE-2020-1938', cvss_score: 9.8, cvss_severity: 'CRITICAL', description: 'Ghostcat AJP', host: '192.168.1.1' },
]

describe('FindingsTable', () => {
  it('renders all findings', () => {
    render(<FindingsTable findings={FINDINGS} />)
    expect(screen.getByText('CVE-2021-41773')).toBeInTheDocument()
    expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument()
  })

  it('shows empty state when no findings', () => {
    render(<FindingsTable findings={[]} />)
    expect(screen.getByText(/No CVE findings/)).toBeInTheDocument()
  })

  it('renders severity badges', () => {
    render(<FindingsTable findings={FINDINGS} />)
    const badges = screen.getAllByText('CRITICAL')
    expect(badges.length).toBeGreaterThanOrEqual(1)
  })

  it('renders row numbers', () => {
    render(<FindingsTable findings={FINDINGS} />)
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })
})
