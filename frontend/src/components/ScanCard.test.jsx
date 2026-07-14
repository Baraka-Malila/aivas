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
    // jsdom normalizes hex to rgb; #ef5350 = rgb(239, 83, 80)
    expect(gradeEl.style.color).toBe('rgb(239, 83, 80)')
  })

  it('shows severity pills for non-zero counts', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    expect(screen.getByText('2 CRITICAL')).toBeTruthy()
    expect(screen.getByText('2 HIGH')).toBeTruthy()
    expect(screen.getByText('1 MEDIUM')).toBeTruthy()
  })

  it('shows top 5 CVEs by default, hides the 6th', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    expect(screen.getByText('CVE-2021-44228')).toBeTruthy()
    expect(screen.getByText('CVE-2023-0003')).toBeTruthy()
    expect(screen.queryByText('CVE-2023-0004')).toBeNull()
  })

  it('expands to all findings when toggle clicked', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    fireEvent.click(screen.getByText(/Show all 6/))
    expect(screen.getByText('CVE-2023-0004')).toBeTruthy()
  })

  it('shows KEV badge only for KEV findings', () => {
    render(<ScanCard scanData={base} onSend={vi.fn()} />)
    const kevBadges = screen.getAllByText('⚠ KEV')
    expect(kevBadges).toHaveLength(1)  // only CVE-2021-44228 has kev:true
  })

  it('action buttons call onSend with correct text', () => {
    const onSend = vi.fn()
    render(<ScanCard scanData={base} onSend={onSend} />)
    fireEvent.click(screen.getByText('Narrate'))
    expect(onSend).toHaveBeenCalledWith('Narrate the findings from scan 42')
    fireEvent.click(screen.getByText('Explain worst'))
    expect(onSend).toHaveBeenCalledWith('Explain the worst vulnerability from scan 42')
    fireEvent.click(screen.getByText('Rescan'))
    expect(onSend).toHaveBeenCalledWith('Scan 192.168.1.1 again')
  })
})
