# AIVAS Web UI — Design Spec

## Overview

A desktop-first, AI-led web interface for AIVAS. The web UI is a companion to the TUI — same FastAPI backend, different surface. Target user: SME owner or non-technical staff who needs to understand their network risk without knowing what a CVE is.

Design direction: **Minimal Intelligence** — AI chat is the primary interface. No forms, no nav menu, no data tables. The AI greets first, the user responds naturally, results appear as rich inline cards.

---

## Goals

- Non-technical users can scan their network and understand results without training
- Everything accessible through natural language (English or Swahili)
- No feature duplication with TUI — web UI is for read/understand, TUI is for power use
- Single deployable command: `aivas serve` starts the FastAPI server + serves the frontend

---

## Layout

### Desktop (primary target)
Full viewport height. Three zones stacked vertically:

1. **Header bar** — fixed, thin (48px). AIVAS logo left, two icon buttons right (History, Settings).
2. **Chat area** — fills remaining height, scrollable. Content centered, `max-width: 800px`, auto horizontal margins.
3. **Input bar** — fixed at bottom, full width. Input field centered matching chat column width.

No sidebar. No secondary panels. One column.

### Mobile
Same structure, no changes needed — single column naturally adapts. Cards reflow, input stays pinned to bottom.

---

## Header

- **Logo**: `✦ AIVAS` in `#4a9eff`, same star glyph as TUI
- **Subtitle**: `"Network Security"` in muted text beside it
- **Controls** (right): two 32px icon buttons
  - `🕐` — opens History drawer
  - `⚙` — opens Settings modal
- Background: `#0d0d0d`, bottom border `#1a1a1a`

---

## Chat Area

### Message types

**AI message**: No background bubble. Label `✦ AIVAS` in `#4a9eff` above text. Body text `#c8c8c8`, font-size 14px, line-height 1.7.

**User message**: Right-aligned. Bubble with `background: #0d1929`, `border: 1px solid #1a2d45`, border-radius `14px 14px 4px 14px`. Text `#90bde0`.

**Status/progress line**: AI message variant. Animated spinner glyph (`⠋⠙⠹…`) cycling, followed by current step text. Updates in place (same message node, text swaps via JS).

**Scan result card**: Appears as a child of an AI message. See Card section below.

### Opening state

On page load, the frontend calls `GET /api/history?limit=1`. If a result exists, the user is returning; otherwise first visit. The AI sends the opening message automatically (no user action needed):

- **First visit**: `"Hello. I'm AIVAS, your network security assistant. Give me an IP address or network range and I'll scan it for you. Type /help to see what I can do."`
- **Returning user**: `"Welcome back. Your last scan of [IP] was [N] days ago — Grade [X], [N] critical vulnerabilities. Want me to rescan, or would you like a summary?"` (data from history response)

---

## Scan Result Card

Displayed inline inside the chat, below the AI's text line "Scan complete. Here's what I found:".

### Structure (top to bottom)

```
┌─────────────────────────────────────────┐
│  192.168.100.253              Grade: F  │  ← header: IP + grade
│  6 open services · 30 findings          │
├─────────────────────────────────────────┤
│  14 CRITICAL   16 HIGH   0 MEDIUM       │  ← severity pills
├─────────────────────────────────────────┤
│  ● CVE-2021-44228  Apache Log4j RCE  10.0 │
│  ● CVE-2022-0778   OpenSSL DoS       9.8  │
│  ● CVE-2023-1945   OpenSSH pre-auth  7.5  │
│  ↓ Show all 30 findings                 │  ← expand toggle
├─────────────────────────────────────────┤
│  [Narrate findings]  [Explain worst]  [Rescan] │  ← action buttons
└─────────────────────────────────────────┘
```

### Card details

- **Grade badge**: Large (28px, bold), color-coded: A=`#66bb6a`, B=`#aed581`, C=`#fdd835`, D=`#ff7043`, F=`#ef5350`
- **Severity pills**: colored label chips. Critical=`#ef5350` on `#1a0505`, High=`#ff7043` on `#1a0e05`, Medium=`#fdd835` on `#1a1505`
- **CVE rows**: severity dot, CVE ID in monospace, description, CVSS score right-aligned. Top 5 shown by default.
- **Show all toggle**: Expands to full list inline (no page navigation)
- **Action buttons**: "Narrate findings" (primary, blue tint), "Explain worst CVE" (secondary), "Rescan" (secondary). Clicking any POSTs to `POST /api/chat` with the equivalent natural language message and appends it as a user bubble — they are shortcuts, not separate flows.

---

## Color Palette

| Token | Value | Usage |
|---|---|---|
| `bg` | `#0a0a0a` | Page background |
| `surface` | `#111111` | Cards, modals |
| `surface-raised` | `#161616` | Inputs, buttons |
| `border` | `#1e1e1e` | All borders |
| `border-subtle` | `#141414` | Row dividers |
| `text` | `#e0e0e0` | Primary text |
| `text-muted` | `#666666` | Labels, hints |
| `accent` | `#4a9eff` | AIVAS brand, links, primary actions |
| `critical` | `#ef5350` | Grade F, CRITICAL severity |
| `high` | `#ff7043` | HIGH severity |
| `medium` | `#fdd835` | MEDIUM severity |
| `low` | `#66bb6a` | LOW severity, Grade A |

---

## Typography

- **UI / body**: `system-ui, -apple-system, sans-serif` — no custom font load, fast render
- **CVE IDs, IPs, CVSS scores, code**: `'Fira Code', 'SF Mono', 'Courier New', monospace` — maintains technical identity consistent with TUI
- **Font sizes**: 14px body, 12px card metadata, 11px CVE rows, 10px labels/pills

---

## History Drawer

Slides in from the right when History icon is clicked. Width: 320px on desktop, full-width on mobile.

Contents:
- Title: `"Scan History"`
- List of past scans: each row shows IP, grade badge, date, CVE count
- Clicking a row sends `"summarize scan [ID]"` to the AI chat and closes the drawer

No separate history page — history is accessed through the drawer and discussed in the chat.

---

## Settings Modal

Centered modal overlay. Two settings:

1. **API Key** — text input, masked. Save button. Shows "Connected" / "Not configured" status.
2. **Language** — three-way toggle: Auto-detect / English / Swahili. Default: Auto-detect.

---

## Scan Progress (Real-time)

When a scan runs, the AI message updates in place using a WebSocket connection:

```
⠸ Running port discovery on 192.168.100.253…   (step 1)
⠸ Detecting services on 6 open ports…           (step 2)
⠸ Correlating CVEs for apache, openssh…         (step 3)
⠸ Scoring and grading results…                  (step 4)
```

Each step replaces the previous spinner text. When done, the spinner message is replaced with "Scan complete." and the result card is appended.

---

## Backend Integration

`aivas serve` starts:
- FastAPI on `localhost:8000` (configurable)
- Serves `frontend/index.html` at `/`
- REST endpoints:
  - `GET /api/history?limit=N` — list past scans
  - `GET /api/scan/{id}` — get findings for a scan
  - `POST /api/chat` — send message to AI agent; returns `{response: str, scan_id: int | null}`. If `scan_id` is set, the AI decided to run a scan — frontend immediately opens the WebSocket for that scan_id.
- WebSocket `ws://localhost:8000/ws/scan/{scan_id}` — real-time scan progress events (emits step text, then a final `{type: "done", findings: [...]}` event that triggers card render)

Frontend is a single `index.html` with embedded CSS and vanilla JS — no build step, no framework, no npm. Served directly from FastAPI's `StaticFiles`.

---

## File Structure

```
aivas/
  frontend/
    index.html          ← entire frontend (HTML + CSS + JS, no build)
  aivas/
    server/
      main.py           ← FastAPI app, routes, WebSocket
      scan_ws.py        ← WebSocket scan progress handler
      chat_api.py       ← /api/chat → wraps existing agent.py
    cli.py              ← adds `aivas serve` entry point
```

---

## Out of Scope (this spec)

- Mobile-specific layout changes (single column works as-is)
- Report HTML export (separate future spec)
- Network auto-discovery (separate future spec)
- LLM mid-narrations during scan steps (separate future spec)
- Multi-user / authentication
- Deployment beyond `localhost`
