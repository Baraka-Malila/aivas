# AIVAS Frontend Overhaul — Design Spec

> **Status:** Approved for implementation

---

## 1. Goal

Replace the current single-file `index.html` frontend with a production-quality React application that surfaces every capability of the AIVAS backend — scan phases, HTTP prober misconfigurations, multi-host network scans, CVE findings, AI assessment, and PDF reports — in a UI that non-technical SME staff can operate without training.

---

## 2. Tech Stack

| Layer | Choice | Reason |
|---|---|---|
| Framework | React 18 + Vite | Fast dev server, standard toolchain |
| Styling | Tailwind CSS v3 | Utility-first, consistent spacing |
| Components | shadcn/ui | Accessible primitives, copies into repo |
| Icons | lucide-react | Matches shadcn aesthetic |
| HTTP | native `fetch` + browser `WebSocket` | No extra deps |
| Build | Vite → `dist/` static bundle | Served by existing FastAPI `StaticFiles` |

No Redux, no React Router, no extra state libraries. Single-page, no URL routing needed.

---

## 3. Color System

```
Background (main):    #f8fafc   (slate-50)
Surface (panels):     #ffffff   (white)
Sidebar:              #0f172a   (slate-900)
Sidebar text:         #cbd5e1   (slate-300)
Sidebar active:       #1e293b   (slate-800) + left border #3b82f6 (blue-500)
Border:               #e2e8f0   (slate-200)
Text primary:         #0f172a   (slate-900)
Text muted:           #64748b   (slate-500)
Accent (terminal):    #22c55e   (green-500) — monospace elements only

Severity badges (inline only, no background painting):
  CRITICAL: text #991b1b  bg #fef2f2
  HIGH:     text #92400e  bg #fffbeb
  MEDIUM:   text #78350f  bg #fefce8
  LOW:      text #166534  bg #f0fdf4
```

---

## 4. Layout

```
┌──────────────────────────────────────────────────────┐
│ Sidebar (220px, fixed)  │  Main area (flex-1)        │
│  AIVAS wordmark         │  ┌─────────────────────┐   │
│  ─────────────          │  │ Scan bar (sticky top)│   │
│  [New Scan]             │  └─────────────────────┘   │
│                         │  ┌─────────────────────┐   │
│  Recent Scans           │  │ Content area        │   │
│   · 192.168.1.1   F     │  │ (scrollable)        │   │
│   · 10.0.0.0/24  B      │  └─────────────────────┘   │
│   · scanme.nmap…  A     │                             │
│  ─────────────          │                             │
│  [Settings]             │                             │
└──────────────────────────────────────────────────────┘
```

- Sidebar is always visible; no hamburger on desktop; collapses to icon-only below 768px
- Scan bar is a sticky horizontal strip: target input + [Scan] + [Quick Scan] + Advanced Options toggle
- Content area fills remaining height; scrollable

---

## 5. Scan Bar

```
[ Target: 192.168.1.0/24 ________________________ ]  [ Quick Scan ]  [ Scan ]  [ ▾ Options ]
```

- Target input: `type="text"`, `autocomplete="off"`, `spellcheck="false"` — no browser autofill
- **[Quick Scan]**: Level 1 — top 100 ports, banner grab only, no NSE vuln scripts
- **[Scan]**: Level 2 — top 1000 ports, NSE vuln scripts + HTTP prober (default, recommended)
- **[▾ Options]**: expands Advanced Options panel below scan bar (see §6)
- Both buttons disabled + show spinner while scan is running; re-enable on completion or error

---

## 6. Advanced Options Panel (collapsed by default)

```
[ UDP scan (requires root) ○ ]    [ NSE script depth: Standard ▾ ]
```

- **UDP toggle**: adds `-sU` flag; shows warning "Requires root — may be slow" if enabled
- **NSE depth dropdown**: Standard (default) | Extended (adds `http-shellshock`, `smb-vuln-ms17-010`, `ftp-*-backdoor`)
- No SSH credentials option — SSH package inventory is CLI-only (v2 roadmap)
- Settings gear → opens Settings modal (theme toggle placeholder, API key field for LLM)

---

## 7. Content Area States

### 7a. Idle (no scan running, no scan selected)

```
┌──────────────────────────────────────────┐
│  AIVAS                                   │
│  AI-Assisted Vulnerability Assessment    │
│                                          │
│  Enter a target above to begin scanning  │
│  e.g. 192.168.1.1  or  10.0.0.0/24      │
└──────────────────────────────────────────┘
```

Centered, no borders, muted text.

### 7b. Scan Running — Live Progress Feed

Full-width scrollable log. Each line fades in with 80ms stagger per line. Lines appear as a monospace terminal feed:

```
[phase header] PHASE: HOST DISCOVERY
[line]           Pinging 192.168.1.0/24 …
[line]         ▸ 7 live hosts found
[line]           · 192.168.1.1
[line]           · 192.168.1.5
[phase header] PHASE: PORT SCANNING
[line]           Scanning 192.168.1.1 …
[line]           80/tcp   OPEN → Apache httpd 2.4.49
[line]           443/tcp  OPEN → Apache httpd 2.4.49
[phase header] PHASE: HTTP PROBE
[line]           192.168.1.1:80 — Missing CSP header
[line]           192.168.1.1:80 — /.git/HEAD exposed (200)
[phase header] PHASE: CVE LOOKUP
[line]           Apache httpd 2.4.49 (port 80) …
[line]         → 3 CVE(s) — worst: CVE-2021-41773 (CRITICAL 9.8)
```

- Phase headers: uppercase, slate-500, small letter-spacing, `border-b border-slate-200`
- Lines: `font-mono text-sm text-slate-700`
- CVE found lines: severity badge inline (colored per §3)
- Auto-scrolls to bottom as lines arrive
- 50ms delay between CVE lookup events emitted by backend (already designed)

### 7c. Scan Complete — Tabbed Results

```
[ Findings (12) ]  [ Assessment ]  [ Report ]
─────────────────────────────────────────────
... tab content ...

▾ View scan log
  [collapsed terminal log from §7b]
```

The scan log collapses under a "View scan log" toggle below the tab content. It is never cleared — users can expand to review the full step sequence.

**Findings tab:**

Two sections:

*Section 1 — CVE Findings*
Sortable table: # | Severity | CVE ID | CVSS | Host | Service | Description (truncated 100 chars)

*Section 2 — Misconfigurations* (only if HTTP prober found issues)
Table: Host:Port | Check | Finding | Severity (INFO/MEDIUM/HIGH)

Example misconfig rows:
- `192.168.1.1:80` | Missing header | `Content-Security-Policy` not set | MEDIUM
- `192.168.1.1:80` | Exposed path | `/.git/HEAD` returns 200 | HIGH
- `192.168.1.1:80` | Dangerous method | `TRACE` allowed | MEDIUM

**Assessment tab:**

Risk grade (large, color-coded letter) + score + one-paragraph executive summary.
[Generate AI Assessment] button → calls `/api/narrate/{scan_id}`, streams markdown into panel.
AI output renders as formatted markdown (bold, paragraphs, lists).
Loading state: pulsing dots + "AIVAS is analyzing…"

**Report tab:**

Two buttons: [View HTML Report] (opens `/api/report/{scan_id}` in new tab) + [Download PDF] (triggers `/api/report/{scan_id}/pdf` download).
Small print note: "Report is suitable for submission to IT managers and compliance officers."

---

## 8. Sidebar History

Each history entry:
```
192.168.1.1          [F]
2026-06-30  3 CVEs
```

Grade badge colors match §3 severity colors (A→green, B→green, C→yellow, D→orange, F→red).

Clicking a history entry loads the scan's findings into content area (§7c tab view) without re-scanning.

Deleting a history entry: hover reveals trash icon; click → confirmation toast ("Deleted scan #12. Undo?") with 5-second undo.

---

## 9. Scan Phase Events (backend additions required)

The backend (`scan_worker.py`) must emit explicit phase-header events so the frontend can render section dividers:

```python
{"type": "progress", "phase": "phase_header", "text": "HOST DISCOVERY"}
{"type": "progress", "phase": "phase_header", "text": "PORT SCANNING"}
{"type": "progress", "phase": "phase_header", "text": "HTTP PROBE"}
{"type": "progress", "phase": "phase_header", "text": "CVE LOOKUP"}
{"type": "progress", "phase": "phase_header", "text": "SCORING"}
```

The frontend renders these with the phase header style; all other progress lines render as normal log lines.

---

## 10. HTTP Prober Integration (backend addition required)

`scan_worker.py` currently does not call `aivas.prober.probe_http_service()`. It must be wired in after port scanning, before CVE lookup:

```
for each discovered HTTP/HTTPS service (port 80, 443, 8080, 8443, etc.):
    emit phase_header "HTTP PROBE"
    call probe_http_service(host, port, scheme)
    for each misconfiguration finding:
        emit progress event describing it
        accumulate in misconfigs list
save misconfigs alongside findings in done event
```

The `done` event gains a new field: `"misconfigs": [{"host":…, "port":…, "check":…, "detail":…, "severity":…}]`

---

## 11. CVE Lookup Pacing (backend addition)

Add `await asyncio.sleep(0.05)` after each `correlate()` call inside `_cve_events()`. This ensures individual CVE lookup lines are visible on the frontend rather than arriving as a burst.

---

## 12. Device Type Inference (backend addition)

After parsing nmap XML, infer device type from port fingerprint and add to service metadata:

```
Router:    ports 23, 80, 443, 8080 (no 22/21/3389)
Printer:   port 9100, 515, 631
Windows:   port 3389, 139, 445
Linux srv: port 22, no 3389
Android:   port 5555 (ADB)
Camera:    port 554 (RTSP), 37777
```

Emit as part of host_scan line: `── Scanning 192.168.1.1 (Router) ──`
Include `"device_type"` in the `done` event's services list.

---

## 13. File Structure

```
aivas/frontend/
  index.html                  ← Vite entry point
  package.json
  vite.config.js
  tailwind.config.js
  postcss.config.js
  src/
    main.jsx
    App.jsx                   ← layout shell, WebSocket state
    components/
      Sidebar.jsx             ← nav + history list
      ScanBar.jsx             ← target input + buttons + advanced options
      ProgressFeed.jsx        ← live terminal log (§7b)
      ResultsTabs.jsx         ← Findings / Assessment / Report tabs (§7c)
      FindingsTable.jsx       ← CVE table
      MisconfigTable.jsx      ← HTTP prober misconfig table
      AssessmentPanel.jsx     ← grade + AI narration
      ReportPanel.jsx         ← HTML/PDF download buttons
      ScanLog.jsx             ← collapsible archived log
    hooks/
      useWebSocket.js         ← WebSocket connection + event routing
      useHistory.js           ← fetch /api/history, delete scan
    lib/
      mdToHtml.js             ← markdown → HTML (bold, lists, paragraphs)
      severity.js             ← severity → color class mapping
```

---

## 14. What is NOT in scope for this implementation

- Authentication / login
- SSH credential entry or package inventory in web UI (CLI-only, v2 roadmap)
- URL routing or multi-page navigation
- Dark mode (Settings placeholder only)
- Mobile-optimized layout (responsive basics only — min-width 768px target)

---

## 15. Backend Changes Summary

| File | Change |
|---|---|
| `aivas/server/scan_worker.py` | Add phase_header events; wire HTTP prober; add 50ms CVE pacing; add device type inference; include `misconfigs` in done event |
| `aivas/server/api.py` | Pass misconfigs through WebSocket done message (already in done dict from worker) |
| No changes needed | `history.py`, `report_gen.py`, `report_helpers.py`, `report_pdf.py` |

---

*Spec written 2026-06-30. Approved by Baraka Malila.*
