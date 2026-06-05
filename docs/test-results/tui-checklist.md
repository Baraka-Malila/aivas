# AIVAS TUI — Manual Test Checklist

**Instructions:** Write `PASS`, `FAIL`, or a short note in the Result column. Leave blank if not tested yet.

**Version under test:** v0.1.0
**Tester:**
**Date:**

---

## Before Testing — Required Steps

1. Ensure nmap is installed: `which nmap`
2. Ensure the CVE database is populated: `aivas search apache` should return results
3. Launch the TUI: `aivas` (PATH must include `~/.local/bin`)
4. If PATH is not set: `export PATH="$HOME/.local/bin:$PATH" && aivas`

---

## Setup and Launch

| # | Test | Result | Notes |
|---|------|--------|-------|
| L1 | Run `aivas` with no arguments — TUI launches | | |
| L2 | AIVAS ASCII banner renders correctly in the output pane | | |
| L3 | Input bar is visible at the bottom with placeholder hint text | | |
| L4 | Header shows "AIVAS" title and clock | | |
| L5 | Footer shows Ctrl+C and Ctrl+L keybind hints | | |
| L6 | Run `aivas scan --help` (CLI mode) — help text prints and exits | | |
| L7 | Run `aivas doctor` (CLI mode) — doctor output prints and exits | | |

---

## Input Bar

| # | Test | Result | Notes |
|---|------|--------|-------|
| I1 | Click the input bar — cursor appears, ready to type | | |
| I2 | Type a command — characters appear in the input | | |
| I3 | Press Enter with empty input — nothing happens, no error | | |
| I4 | Press Ctrl+L — output pane clears | | |
| I5 | Press Ctrl+C — TUI exits cleanly | | |
| I6 | Type a long command (>80 chars) — input bar scrolls horizontally | | |
| I7 | After command executes, input clears and cursor returns to input | | |

---

## /help

| # | Test | Result | Notes |
|---|------|--------|-------|
| H1 | `/help` — lists all available commands | | |
| H2 | `/help scan` — shows usage and description for /scan | | |
| H3 | `/help doctor` — shows usage for /doctor | | |
| H4 | `/HELP` (uppercase) — works the same as `/help` | | |
| H5 | `/help unknowncmd` — does not crash | | |

---

## /doctor

| # | Test | Result | Notes |
|---|------|--------|-------|
| DR1 | `/doctor` — panel renders with check marks | | |
| DR2 | nmap entry shows version string (e.g. "Nmap 7.94") | | |
| DR3 | Database entry shows CVE count (e.g. "240,831 CVEs") | | |
| DR4 | API key entry shows "not set" when no key configured | | |
| DR5 | API key entry shows "configured" after `/config set api_key ...` | | |
| DR6 | Permissions entry shows correct root/user status | | |

---

## /config

| # | Test | Result | Notes |
|---|------|--------|-------|
| CF1 | `/config show` — lists all settings with current values | | |
| CF2 | `/config set provider ollama` — confirms "provider = ollama" | | |
| CF3 | `/config show` after CF2 — shows updated provider | | |
| CF4 | `/config set api_key sk-test123` — confirms, key stored | | |
| CF5 | `/config show` after CF4 — api_key shown as *** | | |
| CF6 | `/config set badkey value` — shows error, does not crash | | |
| CF7 | Exit TUI and relaunch — config values from CF2/CF4 persist | | |

---

## /scan

| # | Test | Result | Notes |
|---|------|--------|-------|
| SC1 | `/scan` with no target — shows usage error | | |
| SC2 | `/scan 192.168.100.253` — scan runs, CVE table appears | | |
| SC3 | During scan — spinner or "Scanning..." message visible | | |
| SC4 | `/scan 192.168.100.253` — UI remains responsive during scan (can type in input) | | |
| SC5 | `/scan 192.168.100.253 --level 1` — completes faster than level 2 | | |
| SC6 | `/scan 192.168.100.253 --level 3` — runs without crash | | |
| SC7 | `/scan 192.168.100.253 --udp` — runs (may warn about root if not root) | | |
| SC8 | `/scan 999.999.999.999` — invalid IP, scan error shown, no crash | | |
| SC9 | `/scan hostname-that-does-not-exist` — scan error shown, no crash | | |
| SC10 | KEV-flagged CVEs show [KEV] tag in the output table | | |
| SC11 | Risk score and grade appear below the CVE table | | |
| SC12 | Config findings table appears if HTTP service is detected | | |

---

## /quick and /deep

| # | Test | Result | Notes |
|---|------|--------|-------|
| QD1 | `/quick 192.168.100.253` — runs level 1 scan | | |
| QD2 | `/quick` with no target — shows usage error | | |
| QD3 | `/deep 192.168.100.253` — runs with UDP | | |
| QD4 | `/deep` with no target — shows usage error | | |

---

## /history

| # | Test | Result | Notes |
|---|------|--------|-------|
| HS1 | `/history list` with no saved scans — shows "no scans saved" message | | |
| HS2 | Run `aivas scan 192.168.100.253 --save` (CLI mode), then `/history list` — scan appears | | |
| HS3 | `/history show 1` — findings from scan #1 render in output pane | | |
| HS4 | `/history show 9999` — "not found" message, no crash | | |
| HS5 | `/history show abc` — "usage" error, no crash | | |
| HS6 | `/history` with no subcommand — shows usage or defaults to list | | |

---

## /kev

| # | Test | Result | Notes |
|---|------|--------|-------|
| KV1 | `/kev` — "Downloading CISA KEV feed" message appears | | |
| KV2 | `/kev` — completes with count of CVEs marked | | |
| KV3 | `/kev` with no internet — shows error message, no crash | | |
| KV4 | `/kev` a second time — completes without duplicate errors | | |

---

## /clear and /exit

| # | Test | Result | Notes |
|---|------|--------|-------|
| CL1 | `/clear` — output pane empties | | |
| CL2 | `/clear` — input remains focused after clearing | | |
| CL3 | `/exit` — TUI closes cleanly | | |

---

## Free Text and AI Routing

| # | Test | Result | Notes |
|---|------|--------|-------|
| AI1 | Type plain text with no API key — shows "No API key configured" message | | |
| AI2 | Message includes suggestion to use `/scan` or `/doctor` | | |
| AI3 | With API key set: type "scan the ASUS machine for web vulnerabilities" — AI parses intent and runs scan | | |
| AI4 | With API key set: partial/ambiguous query — either scans or asks for clarification | | |
| AI5 | With API key set: AI call fails (bad key) — error shown, no crash | | |

---

## Output Panel Behavior

| # | Test | Result | Notes |
|---|------|--------|-------|
| OP1 | Long CVE table (20+ rows) — output pane scrolls | | |
| OP2 | Run two scans in sequence — both results visible in output (not overwritten) | | |
| OP3 | `/clear` between scans — second scan result is the only visible content | | |
| OP4 | Output from `/doctor` followed by `/scan` — both visible, clearly separated | | |
| OP5 | Very long description text wraps within the table column | | |
| OP6 | Colors render correctly (CRITICAL red, HIGH yellow, [KEV] magenta) | | |
| OP7 | Output is scrollable with mouse wheel (if terminal supports it) | | |
| OP8 | Output is scrollable with keyboard (Page Up / Page Down) | | |

---

## Unknown and Invalid Commands

| # | Test | Result | Notes |
|---|------|--------|-------|
| UK1 | `/randomcommand` — "Unknown command" message shown | | |
| UK2 | `/` alone (no command name) — no crash | | |
| UK3 | `/scan` with extra unknown flags — handles gracefully | | |
| UK4 | Very long input (500+ chars) — no crash | | |
| UK5 | Input with special characters (`<>&;|`) — no shell injection, no crash | | |

---

## CLI Compatibility (aivas subcommands still work)

| # | Test | Result | Notes |
|---|------|--------|-------|
| CL1 | `aivas scan 192.168.100.253` — runs scan from terminal, no TUI | | |
| CL2 | `aivas doctor` — health check output, no TUI | | |
| CL3 | `aivas config show` — prints config, no TUI | | |
| CL4 | `aivas history list` — prints history table, no TUI | | |
| CL5 | `aivas --help` — shows all commands | | |
| CL6 | `aivas update-kev` — syncs KEV feed from terminal | | |

---

## Terminal Compatibility

| # | Terminal | Test | Result | Notes |
|---|----------|------|--------|-------|
| TC1 | GNOME Terminal | TUI launches, renders correctly | | |
| TC2 | Zsh default terminal (ASUS TUF) | TUI launches, renders correctly | | |
| TC3 | tmux pane | TUI renders without corruption | | |
| TC4 | SSH session | TUI renders (may vary by client) | | |
| TC5 | Small terminal window (80x24) | Layout does not break | | |
| TC6 | Wide terminal (220+ cols) | Layout does not stretch unusably | | |

---

## Deferred Items

| # | Item | Notes |
|---|------|-------|
| DEF-01 | First-run setup wizard (api key prompt, nmap check on first launch) | Sprint 2i |
| DEF-02 | Tab/arrow key autocomplete for slash commands | Polish pass |
| DEF-03 | Markdown rendering of narration output inside TUI | After narration integration |
| DEF-04 | /scan --save option in TUI (prompt to save after scan) | Sprint 2i |
| DEF-05 | Textual Web mode (browser GUI) | Post-diploma |
| DEF-06 | Mouse click on CVE row to expand full description | Polish pass |
| DEF-07 | Level 2 active CVE verification probes | Post-diploma |
| DEF-08 | Swahili narration rendering in output pane | After narration integration |
| DEF-09 | pip install aivas from PyPI (public package publish) | After v1.0.0 tag |

---

_Checklist version: 2026-06-05 rev 1_
