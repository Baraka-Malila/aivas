// frontend/src/lib/severity.test.js
import { describe, it, expect } from 'vitest'
import { sevClasses, gradeColor, gradeBadgeClass } from './severity'

describe('sevClasses', () => {
  it('returns red classes for CRITICAL', () => {
    const cls = sevClasses('CRITICAL')
    expect(cls).toContain('bg-red-50')
    expect(cls).toContain('text-red-800')
  })
  it('returns amber classes for HIGH', () => {
    const cls = sevClasses('HIGH')
    expect(cls).toContain('bg-amber-50')
  })
  it('returns green classes for LOW', () => {
    const cls = sevClasses('LOW')
    expect(cls).toContain('bg-green-50')
  })
  it('falls back to LOW for unknown severity', () => {
    expect(sevClasses('UNKNOWN')).toContain('bg-green-50')
  })
})

describe('gradeColor', () => {
  it('returns dark green for A', () => {
    expect(gradeColor('A')).toBe('#2a6e2a')
  })
  it('returns red for F', () => {
    expect(gradeColor('F')).toBe('#8a0000')
  })
})

describe('gradeBadgeClass', () => {
  it('returns green for A', () => {
    expect(gradeBadgeClass('A')).toContain('green')
  })
  it('returns red for F', () => {
    expect(gradeBadgeClass('F')).toContain('red')
  })
})
