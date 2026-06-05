# AIVAS — Project Status, Architecture & Roadmap
**Date:** 2026-06-05  
**Authors:** Baraka Malila, Michael Megewa  
**Supervisor:** Namsembwa Mzava  
**Institution:** MUST — Diploma in Computer Engineering

---

## What AIVAS Is

**AI-Assisted Network Vulnerability Assessment System** — a Python CLI tool that:
1. Scans a target with nmap (`-sV`, NSE scripts)
2. Correlates discovered services against a local SQLite CVE database (sourced from NIST NVD)
3. Scores, ranks, and presents findings in a rich terminal table
4. Optionally generates bilingual (English/Swahili) AI risk narrations
5. Optionally exports an HTML/PDF report and persists findings to scan history

Design principles: **offline-first, low-resource, modular, bilingual, accessible to non-expert operators**.

---

## Sprint History

### Sprint 1 — Foundation
- CLI skeleton (`aivas scan`, Click)
- SQLite schema (`cves`, `cpe_matches` tables)
- NVD JSON bulk ingest (`nvd_ingest.py`) from NVD JSON data feeds
- Basic nmap orchestrator
- XML parser for nmap `-oX` output
- CVSS-based risk scorer

### Sprint 2a — Correlator + Output
- `correlator.py`: maps nmap `product`/`version` fields → CVE lookups
- `PRODUCT_CPE_MAP`: static product → CPE vendor:product mapping
- `formatting.py`: Rich terminal tables with CVE ID, CVSS, severity, confidence
- Risk grade display (A–F)

### Sprint 2b — Narration
- `narrator/providers.py`: Groq and Ollama LLM providers
- `narrator/narrator.py`: generates English + Swahili risk narrations per finding
- `--narrate` flag wires narration into scan output
- `--lang en|sw|both` flag for language selection

### Sprint 2c — Reports & History
- `reporter.py`: HTML/PDF export via WeasyPrint
- `history.py`: scan persistence to SQLite (`scans`, `scan_findings` tables)
- `aivas history list/show` commands
- `aivas report --scan <id>` to regenerate HTML from stored findings
- `--save` flag to persist any scan
- `--report <path>` flag to export

### Sprint 2d — Scan Depth & Discovery
- `--level 1|2|3` flag: level 1 = quick `-sV`, level 2 = + vuln NSE scripts, level 3 = SSH package probe
- `--udp` flag: adds `-sU` for IoT/mobile discovery
- `scanner/nse.py`: NSE script selection per level
- `scanner/probe.py`: auto-probe services with no banner (HTTP header, SSL CN, raw banner)
- `scanner/ssh_probe.py`: SSH into host, run `dpkg -l`/`rpm -qa`, correlate installed packages
- `scanner/orchestrator.py`: root fallback for OS detection (`-O` silently removed if not root)
- `parser.py`: accept `open|filtered` nmap state (required for UDP)

### Sprint 2e — NVD Sync + Natural Language
- `database/nvd_sync.py`: replaced raw HTTP pagination with `nvdlib.searchCVE()` — handles pagination, rate limiting, incremental sync by date window
- `aivas update-db --api-key` command
- `narrator/intent.py`: LLM extracts scan intent from natural language query (target IP, level, focus)
- `aivas ask "scan the router for web vulnerabilities"` command
- OS-aware CVE filtering: Linux findings suppressed for Windows-targeting CVEs and vice versa

### Sprint 2e — Critical Bug Fixes (post-live-testing)
These bugs were found by running AIVAS against 4 real devices on a LAN:

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| OS detection never activated | `scan_cmd.py` never passed `os_detect=True` | Added `os_detect=True` to `run_scan()` call |
| Version filter false positives | `cpe_query.py` ignored version field in CPE criteria strings | Added `_cpe_version()` extraction + exact match logic |
| Non-PEP-440 version crash | "8.9p1" fails `Version()` | Added `_parse_version()` normaliser (8.9p1 → 8.9.1) |
| UDP ports silently dropped | Parser filtered `state != "open"` | Accept `open\|filtered` state |
| Vacuous test assertion | `assert mock.called or "Error" in output` | Fixed to proper mock of `run_scan` |

---

## Live Test Results (2026-06-05)

Four real devices on LAN 192.168.100.0/24:

| Device | IP | Result |
|--------|----|--------|
| Kali Linux (attacker) | 192.168.100.3 | SSH 8.9p1 → CVE matches; OpenSSH findings |
| Samsung S21 | 192.168.100.252 | 0 open ports (Android firewall) — correct |
| ASUS TUF (Apache 2.4.52) | 192.168.100.253 | Apache CVEs found: 30+ findings, grade F |
| R2D2-Coms (IoT gateway) | 192.168.100.254 | CoAP/DHCP/SNMP found via UDP; no CVE matches (firmware unknown) |

**Key finding:** AIVAS CVE matches align with nmap-vulners on all critical CVEs for Apache 2.4.52 (CVE-2021-41773, CVE-2022-22720, etc.).

**Gap found:** nikto ran against .253 and found 4 misconfigurations AIVAS missed entirely:
- ETag header leaks inode/file path (info disclosure)
- Missing `X-Frame-Options` header (clickjacking)
- `/server-status` endpoint exposed (traffic/connection monitoring)
- POST and OPTIONS methods enabled (unnecessary attack surface)

These are **configuration findings** — not CVE-based — which is why AIVAS missed them. This is the Level 1 gap.

---

## Comparison vs Similar Tools

| Tool | Approach | Offline? | Active Probing? | Bilingual? | Notes |
|------|----------|----------|-----------------|------------|-------|
| **AIVAS** | nmap + local CVE DB + LLM | Yes | No (Level 1 planned) | Yes | Our tool |
| nmap-vulners | nmap NSE + cloud Vulners API | No | No | No | Matches AIVAS on critical CVEs |
| vulscan | nmap NSE + local CSVs | Yes | No | No | CSV databases years outdated |
| OpenVAS | Full vuln scanner + active | No | Yes | No | Heavy (needs 3+ services, 4GB+) |
| Nessus | Commercial, cloud-connected | No | Yes | No | Enterprise, not free |
| nikto | HTTP config checks only | Yes | Config only | No | No CVE correlation |
| Nuclei | Template-based active CVE probes | Partial | Yes | No | Go binary, thousands of templates |

**AIVAS advantages over comparable free tools:**
1. Offline CVE database (NVD local) — works without internet after initial sync
2. Bilingual output (English + Swahili) — unique to African deployment context
3. Scan history persistence — longitudinal tracking
4. Natural language interface (`aivas ask`)
5. Low resource footprint — runs on a single laptop
6. Modular — each component replaceable independently

**Current gaps vs OpenVAS/Nessus:**
1. No active config probing (Level 1) — **Sprint 2g will close this**
2. No CVE-specific active verification (Level 2) — post-diploma roadmap
3. No credentialed Windows scans
4. No authenticated web app scanning

---

## Architecture Philosophy: Plug-and-Play

AIVAS is intentionally architected so any component can be swapped or extended without touching the others.

```
┌─────────────────────────────────────────────────────────┐
│  CLI Layer (commands/)                                  │
│  scan_cmd.py  ask_cmd.py  history_cmds.py  report_cmd  │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│  Orchestration (correlator.py, scorer.py)               │
└───────┬──────────────┬──────────────────────┬───────────┘
        │              │                      │
┌───────▼──────┐ ┌─────▼──────┐ ┌────────────▼──────────┐
│  Scanner     │ │  Database  │ │  Narrator              │
│  nmap + NSE  │ │  SQLite    │ │  Groq / Ollama         │
│  ssh_probe   │ │  NVD sync  │ │  EN + SW               │
│  HTTP probe  │ │  CPE query │ └────────────────────────┘
└──────────────┘ └────────────┘
        │
┌───────▼──────────────────────────────────────────────┐
│  Prober (Sprint 2g — new layer)                      │
│  prober/headers.py   prober/endpoints.py             │
│  prober/methods.py   prober/cve_probes/ (Level 2)    │
└──────────────────────────────────────────────────────┘
```

Each layer communicates through simple Python dicts (`service`, `finding`) — no ORM, no class hierarchies. New scanners, databases, or narrators slot in by matching the same dict shape.

---

## Level 1 vs Level 2 Probing (Key Concept)

### Level 1 — Configuration Probing (Sprint 2g)
**What:** Inspect server behaviour without exploiting anything. No attack, just observation.  
**How:** HTTP requests to known endpoints, check response headers, look for exposed admin pages.  
**Who can run it:** Any user — no root, no special permission.  
**Examples:**
- Is `X-Frame-Options` missing? → clickjacking risk
- Is `/server-status` accessible? → Apache mod_status leaks traffic data
- Does the server disclose its version in `Server:` header? → info disclosure
- Is `/.git/` accessible? → source code exposure

### Level 2 — CVE-Specific Active Verification (Post-diploma roadmap)
**What:** Attempt CVE-specific proof-of-concept to confirm exploitability.  
**How:** Structured probe per CVE (path traversal attempt, header injection test, etc.).  
**Who can run it:** Security professionals with authorization. Not casual users.  
**Examples:**
- CVE-2021-41773: try `GET /cgi-bin/.%2e/.%2e/bin/sh` — does the server respond with shell output?
- CVE-2014-6271 (ShellShock): send `() { :;};` in User-Agent, check response
- CVE-2016-6210 (OpenSSH timing): measure login timing for valid vs invalid usernames

**The architectural bridge:** Level 1 and Level 2 use the same probe function signature:
```python
def probe(host: str, port: int, **ctx) -> list[dict]:
    # returns list of Finding dicts
    # {type, title, severity, description, recommendation}
```
Level 2 adds `cve_id` to the Finding dict and a CVE registry that maps CVE IDs to probe functions.

---

## Nuclei — Reference Only (Not Integrated)

Nuclei (projectdiscovery) is a Go-based vulnerability scanner with thousands of community YAML templates. We do NOT run it as part of AIVAS because:
- It's a separate Go binary (not Python, non-trivial install)
- Its templates make real exploit-like requests — Level 2 territory

**What we DO use from nuclei:**
Its template structure is the design pattern for our Level 2 probe registry:
```yaml
# nuclei template pattern we mirror in Python:
id: CVE-2021-41773
info:
  severity: critical
http:
  - method: GET
    path: /cgi-bin/.%2e/.%2e/bin/sh
    matchers:
      - type: word
        words: ["/bin/sh", "root:"]
```
Equivalent Python probe:
```python
# aivas/prober/cve_probes/cve_2021_41773.py
def probe(host, port, **ctx) -> list[dict]:
    resp = requests.get(f"http://{host}:{port}/cgi-bin/.%2e/.%2e/bin/sh", ...)
    if any(w in resp.text for w in ["/bin/sh", "root:"]):
        return [{"type": "cve", "cve_id": "CVE-2021-41773", "confirmed": True, ...}]
    return []
```

---

## Immediate Roadmap

### Sprint 2f — KEV Integration (CISA Known Exploited Vulnerabilities)
**Why:** Not all CRITICAL CVEs are equal. KEV marks the ~1000 CVEs actively being exploited in the wild right now. Flagging these for operators changes the action priority entirely.  
**What:** Download KEV JSON feed (free, from CISA), add `kev` boolean to `cves` table, mark in output.  
**Effort:** ~2 hours, ~50 lines of code.  
**Deliverable:** `[KEV]` tag appears next to findings that are actively exploited.

### Sprint 2g — Level 1 Active Configuration Probing
**Why:** nikto found 4 misconfigs on .253 that AIVAS missed. Configuration weaknesses are common, easy to detect, require no root.  
**What:**  
- `aivas/prober/headers.py`: check `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, server version disclosure in `Server:` header, ETag inode leak  
- `aivas/prober/endpoints.py`: probe `/server-status`, `/server-info`, `/.git/`, `/wp-admin/`, `/.env`, `/phpmyadmin/`  
- `aivas/prober/methods.py`: check which HTTP methods are enabled (`OPTIONS` request)  
- Results feed into the same findings table with `type: "misconfiguration"`  
- Integrated into the `scan` pipeline as a post-nmap step for HTTP services  
**Effort:** ~4 hours, ~150 lines of code across 3 files.

### Sprint 2h — Usability (When Manual Testing Begins)
- `aivas doctor`: check nmap, python version, DB exists, API key set
- Config file `~/.aivas/config.yml`: store api_key, default provider, default lang
- Sudo warning when `--udp` used without root
- Installation script for SME deployment
- README update with real examples

---

## Long-Term Vision (Post-Diploma)

AIVAS is designed as a **scalable foundation** for a full pentesting framework:

```
Phase 1 (current): Passive CVE correlation + config probing
Phase 2:          Active CVE verification (Level 2 probes)
Phase 3:          Multi-scanner support (masscan, Rustscan alongside nmap)
Phase 4:          Web app scanning module (SQL injection, XSS detection)
Phase 5:          Full framework — comparable to OpenVAS but lightweight + offline + bilingual
```

The plug-and-play architecture means each phase adds a new module without rewriting existing ones.

**Open source plan:** Release on GitHub under MIT license once manual testing is complete. Target community: security researchers and SME IT staff in East Africa where internet connectivity and enterprise tool budgets are constraints.

---

## Test Coverage

**164 tests** as of Sprint 2e (2026-06-05), all passing.  
Coverage spans: parser, correlator, cpe_query, nvd_ingest, nvd_sync, narrator, providers, intent, scoring, formatting, history, scanner orchestrator, probe, ssh_probe, NSE selection, CLI commands.

---

## File Size Compliance

All Python source files are under the 200-line limit per CLAUDE.md rules:

| File | Lines |
|------|-------|
| scan_cmd.py | 166 |
| cpe_query.py | 148 |
| narrator.py | ~120 |
| correlator.py | ~100 |
| All others | < 100 |
