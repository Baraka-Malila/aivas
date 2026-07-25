// frontend/src/lib/mdToHtml.test.js
import { describe, it, expect } from 'vitest'
import { mdToHtml } from './mdToHtml'

describe('mdToHtml', () => {
  it('wraps plain text in a paragraph', () => {
    expect(mdToHtml('hello world')).toContain('<p')
    expect(mdToHtml('hello world')).toContain('hello world')
  })
  it('converts **bold** to <strong>', () => {
    expect(mdToHtml('**CVE-2021-1234** is critical')).toContain('<strong>CVE-2021-1234</strong>')
  })
  it('converts bullet lists', () => {
    const html = mdToHtml('- item one\n- item two')
    expect(html).toContain('<ul')
    expect(html).toContain('<li>')
    expect(html).toContain('item one')
  })
  it('escapes HTML entities', () => {
    expect(mdToHtml('<script>alert(1)</script>')).toContain('&lt;script&gt;')
  })
  it('returns empty string for empty input', () => {
    expect(mdToHtml('')).toBe('')
  })
})
