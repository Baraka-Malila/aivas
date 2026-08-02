/**
 * AIVAS E2E pipeline tests — full frontend + backend, headless Chromium.
 * Server must be running at http://localhost:8765 with the built frontend.
 *
 * Scenarios:
 *  1.  Single welcome message on load (StrictMode double-mount regression)
 *  2.  Exactly one POST /api/sessions per page load
 *  3.  Exactly one /ws/chat WebSocket opened per session
 *  4.  Chat input is enabled once WS is open
 *  5.  User message appears immediately after send
 *  6.  AI response or error appears (no blank screen, no crash)
 *  7.  No scan-progress card without a scan being triggered
 *  8.  Settings modal opens, saves provider to localStorage
 *  9.  New conversation resets to single welcome message
 * 10.  Page survives reload cleanly
 */

import { test, expect } from '@playwright/test'

// ---------------------------------------------------------------------------
// 1. Single welcome message — StrictMode double-mount regression
// ---------------------------------------------------------------------------
test('shows exactly one welcome message on load', async ({ page }) => {
  await page.goto('/')
  await page.waitForSelector('[data-testid="ai-message"]', { timeout: 10_000 })

  // Brief pause to catch a second message from double-mount
  await page.waitForTimeout(500)

  const count = await page.locator('[data-testid="ai-message"]').count()
  expect(count).toBe(1)

  const text = await page.locator('[data-testid="ai-message"]').first().textContent()
  expect(text.trim().length).toBeGreaterThan(10)
})

// ---------------------------------------------------------------------------
// 2. Exactly one session created per page load
// ---------------------------------------------------------------------------
test('creates exactly one session per page load', async ({ page }) => {
  const sessionPosts = []
  page.on('request', req => {
    if (req.url().includes('/api/sessions') && req.method() === 'POST') {
      sessionPosts.push(req.url())
    }
  })

  await page.goto('/')
  await page.waitForSelector('[data-testid="ai-message"]', { timeout: 10_000 })
  await page.waitForTimeout(600)

  expect(sessionPosts.length).toBe(1)
})

// ---------------------------------------------------------------------------
// 3. Exactly one chat WebSocket opened per session
// ---------------------------------------------------------------------------
test('opens exactly one chat WebSocket per session', async ({ page }) => {
  const chatSockets = []
  page.on('websocket', ws => {
    if (ws.url().includes('/ws/chat/')) chatSockets.push(ws.url())
  })

  await page.goto('/')
  await page.waitForSelector('[data-testid="ai-message"]', { timeout: 10_000 })
  await page.waitForTimeout(600)

  expect(chatSockets.length).toBe(1)
})

// ---------------------------------------------------------------------------
// 4. Chat input enabled once WebSocket opens
// ---------------------------------------------------------------------------
test('chat input is enabled after WebSocket opens', async ({ page }) => {
  await page.goto('/')
  const input = page.locator('[data-testid="chat-input"]')
  await expect(input).toBeEnabled({ timeout: 10_000 })
})

// ---------------------------------------------------------------------------
// 5. User message appears immediately in chat
// ---------------------------------------------------------------------------
test('user message appears immediately after send', async ({ page }) => {
  await page.goto('/')
  await page.waitForSelector('[data-testid="chat-input"]', { timeout: 10_000 })
  await page.locator('[data-testid="chat-input"]').waitFor({ state: 'visible' })
  await expect(page.locator('[data-testid="chat-input"]')).toBeEnabled()

  await page.locator('[data-testid="chat-input"]').fill('hello there')
  await page.keyboard.press('Enter')

  await expect(page.locator('[data-testid="user-message"]').first()).toBeVisible({ timeout: 5_000 })
  const text = await page.locator('[data-testid="user-message"]').first().textContent()
  expect(text).toContain('hello there')
})

// ---------------------------------------------------------------------------
// 6. AI response: app recovers — no crash, input re-enables
//    (Works with or without Groq key — error path is also valid)
// ---------------------------------------------------------------------------
test('app recovers after sending message (with or without Groq key)', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('[data-testid="chat-input"]')).toBeEnabled({ timeout: 10_000 })

  await page.locator('[data-testid="chat-input"]').fill('what can you do')
  await page.keyboard.press('Enter')

  // Wait for either: a second AI message (success) or input re-enabled (error handled)
  await Promise.race([
    page.waitForFunction(
      () => document.querySelectorAll('[data-testid="ai-message"]').length >= 2,
      { timeout: 20_000 }
    ),
    page.waitForFunction(
      () => {
        const input = document.querySelector('[data-testid="chat-input"]')
        return input && !input.disabled
      },
      { timeout: 20_000 }
    ),
  ])

  // No crash — page is still responsive
  await expect(page.locator('[data-testid="chat-input"]')).toBeVisible()
  await expect(page.locator('[data-testid="user-message"]').first()).toBeVisible()
})

// ---------------------------------------------------------------------------
// 7. No scan-progress card without a scan being triggered
// ---------------------------------------------------------------------------
test('no scan-progress card appears without a scan trigger', async ({ page }) => {
  await page.goto('/')
  await page.waitForSelector('[data-testid="ai-message"]', { timeout: 10_000 })

  const count = await page.locator('[data-testid="scan-progress"]').count()
  expect(count).toBe(0)
})

// ---------------------------------------------------------------------------
// 8. Settings modal opens, persists provider to localStorage
// ---------------------------------------------------------------------------
test('settings modal opens and saves provider to localStorage', async ({ page }) => {
  await page.goto('/')
  await page.waitForSelector('[data-testid="ai-message"]', { timeout: 10_000 })

  // Click settings gear icon (aria-label="Settings")
  await page.locator('button[aria-label="Settings"]').click()

  // Modal must appear
  const modal = page.locator('[data-testid="settings-modal"]')
  await expect(modal).toBeVisible({ timeout: 5_000 })

  // Change provider dropdown to claude
  const select = modal.locator('select').first()
  await select.selectOption('claude')

  // Save
  await modal.locator('button:has-text("Save")').click()

  // Modal closes
  await expect(modal).not.toBeVisible({ timeout: 5_000 })

  // localStorage reflects the choice
  const stored = await page.evaluate(() => localStorage.getItem('aivas_provider'))
  expect(stored).toBe('claude')
})

// ---------------------------------------------------------------------------
// 9. New conversation resets to a single welcome message
// ---------------------------------------------------------------------------
test('new conversation button resets chat to one welcome message', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('[data-testid="chat-input"]')).toBeEnabled({ timeout: 10_000 })

  // Send a message so there's visible history
  await page.locator('[data-testid="chat-input"]').fill('a test message')
  await page.keyboard.press('Enter')
  await expect(page.locator('[data-testid="user-message"]').first()).toBeVisible({ timeout: 5_000 })

  // Open history drawer (aria-label="Conversation history")
  await page.locator('button[aria-label="Conversation history"]').click()
  await page.waitForSelector('[data-testid="session-drawer"]', { timeout: 5_000 })

  // Click New Conversation
  await page.locator('[data-testid="session-drawer"] button:has-text("New")').click()

  // Chat resets: 1 AI message, 0 user messages
  await expect(page.locator('[data-testid="user-message"]')).toHaveCount(0, { timeout: 5_000 })
  await expect(page.locator('[data-testid="ai-message"]')).toHaveCount(1, { timeout: 5_000 })
})

// ---------------------------------------------------------------------------
// 10. Page survives reload cleanly
// ---------------------------------------------------------------------------
test('page loads cleanly after reload', async ({ page }) => {
  await page.goto('/')
  await page.waitForSelector('[data-testid="ai-message"]', { timeout: 10_000 })

  await page.reload()
  await page.waitForSelector('[data-testid="ai-message"]', { timeout: 10_000 })

  const count = await page.locator('[data-testid="ai-message"]').count()
  expect(count).toBe(1)

  await expect(page.locator('[data-testid="chat-input"]')).toBeEnabled({ timeout: 10_000 })
})
