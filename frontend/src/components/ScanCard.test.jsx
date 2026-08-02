import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import ScanCard from './ScanCard'

const base = {
  scan_id: 42,
  target: '192.168.1.1',
  grade: 'F',
  score: 95,
  service_count: 3,
  findings: [
    { cve_id: 'CVE-2021-44228', cvss_score: 10.0, cvss_severity: 'CRITICAL', description: 'Log4j RCE', kev: true },
    { cve_id: 'CVE-2022-0778',  cvss_score: 9.8,  cvss_severity: 'CRITICAL', description: 'OpenSSL DoS', kev: false },
    { cve_id: 'CVE-2023-0001',  cvss_score: 7.5,  cvss_severity: 'HIGH',     description: 'Test high 1', kev: false },
    { cve_id: 'CVE-2023-0002',  cvss_score: 6.1,  cvss_severity: 'HIGH',     description: 'Test high 2', kev: false },
    { cve_id: 'CVE-2023-0003',  cvss_score: 5.0,  cvss_severity: 'MEDIUM',   description: 'Test medium', kev: false },
    { cve_id: 'CVE-2023-0004',  cvss_score: 3.1,  cvss_severity: 'LOW',      description: 'Test low',    kev: false },
  ],
  counts: { CRITICAL: 2, HIGH: 2, MEDIUM: 1, LOW: 1 },
}

describe('ScanCard', () => {
  it('displays grade F with red color', () => {
    const { container } = render(<ScanCard scanData={base} onSend={vi.fn()} />)
    const gradeEl = container.querySelector('[data-testid="grade-badge"]')
    expect(gradeEl).toBeTruthy()
    expect(gradeEl.textContent).toBe('F')
    expect(gradeEl.getAttribute('style')).toContain('rgb(239, 83, 80)')
  })

  it('auto-expands CRITICAL group when CRITICAL findings exist', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    expect(screen.getByTestId('cve-row-CVE-2021-44228')).toBeTruthy()
    expect(screen.getByTestId('cve-row-CVE-2022-0778')).toBeTruthy()
  })

  it('collapses HIGH group by default', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    expect(screen.queryByTestId('cve-row-CVE-2023-0001')).toBeNull()
  })

  it('expands HIGH group when header is clicked', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    fireEvent.click(screen.getByTestId('group-header-HIGH'))
    expect(screen.getByTestId('cve-row-CVE-2023-0001')).toBeTruthy()
    expect(screen.getByTestId('cve-row-CVE-2023-0002')).toBeTruthy()
  })

  it('collapses CRITICAL group when header clicked again', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    fireEvent.click(screen.getByTestId('group-header-CRITICAL'))
    expect(screen.queryByTestId('cve-row-CVE-2021-44228')).toBeNull()
  })

  it('shows group headers for non-empty severity buckets', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    expect(screen.getByTestId('group-header-CRITICAL')).toBeTruthy()
    expect(screen.getByTestId('group-header-HIGH')).toBeTruthy()
    expect(screen.getByTestId('group-header-MEDIUM')).toBeTruthy()
    expect(screen.getByTestId('group-header-LOW')).toBeTruthy()
  })

  it('shows KEV badge only for KEV findings', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    const kevBadges = screen.getAllByText('⚠ KEV')
    expect(kevBadges).toHaveLength(1)
  })

  it('ask icon sends explain prompt for that CVE', () => {
    const onSend = vi.fn()
    render(<ScanCard scanData={base} onSend={onSend} />)
    fireEvent.click(screen.getByTestId('ask-CVE-2021-44228'))
    expect(onSend).toHaveBeenCalledWith(
      expect.stringContaining('Explain CVE-2021-44228 from scan 42')
    )
  })

  it('Risk Summary button sends summary prompt', () => {
    const onSend = vi.fn()
    render(<ScanCard scanData={base} onSend={onSend} />)
    fireEvent.click(screen.getByText('Risk Summary'))
    expect(onSend).toHaveBeenCalledWith(
      expect.stringContaining('3-sentence executive risk summary for scan 42')
    )
  })

  it('What to do button sends remediation prompt', () => {
    const onSend = vi.fn()
    render(<ScanCard scanData={base} onSend={onSend} />)
    fireEvent.click(screen.getByText('What to do'))
    expect(onSend).toHaveBeenCalledWith(
      expect.stringContaining('priority-ordered remediation plan for scan 42')
    )
  })

  it('Rescan button sends rescan prompt', () => {
    const onSend = vi.fn()
    render(<ScanCard scanData={base} onSend={onSend} />)
    fireEvent.click(screen.getByText('Rescan'))
    expect(onSend).toHaveBeenCalledWith('Scan 192.168.1.1 again')
  })

  it('has Fix Script download link', () => {
    const { container } = render(<ScanCard scanData={base} onSend={vi.fn()} />)
    const link = container.querySelector('a[href="/api/report/42/fix.sh"]')
    expect(link).toBeTruthy()
  })

  it('renders Scan Log section when log is provided', () => {
    const { container } = render(
      <ScanCard
        scanData={{ ...base, log: ['PORT SCANNING', 'Found 3 ports'] }}
        onSend={vi.fn()}
      />
    )
    expect(container.textContent).toContain('Scan Log')
  })

  it('log items are accessible via details element', () => {
    const { container } = render(
      <ScanCard
        scanData={{ ...base, log: ['CVE LOOKUP', 'Found 2 CVEs'] }}
        onSend={vi.fn()}
      />
    )
    const details = container.querySelector('details')
    expect(details).not.toBeNull()
    expect(details.textContent).toContain('CVE LOOKUP')
    expect(details.textContent).toContain('Found 2 CVEs')
  })

  it('does not render Scan Log when log is empty or absent', () => {
    const { container } = render(
      <ScanCard scanData={{ ...base }} onSend={vi.fn()} />
    )
    expect(container.textContent).not.toContain('Scan Log')
  })

  it('shows no-vulnerabilities message when findings is empty', () => {
    render(<ScanCard scanData={{ ...base, findings: [] }} onSend={vi.fn()} />)
    expect(screen.getByText('No vulnerabilities found')).toBeTruthy()
  })
})
