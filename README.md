# AIVAS — AI-Assisted Network Vulnerability Assessment System

**The only free, plain-language, Swahili-capable network vulnerability scanner built for African SMEs.**

AIVAS combines Nmap service discovery, a full offline NIST NVD CVE database, targeted active verification, and AI-powered risk narration — giving non-expert users the security visibility of enterprise tools like Nessus and OpenVAS, without the cost or complexity.

---

## What AIVAS Does

```
$ aivas scan 192.168.1.0/24

[AIVAS] Scanning 192.168.1.0/24...
[AIVAS] Discovered 12 hosts, 47 open services

[CRITICAL] 192.168.1.10 — Apache httpd 2.4.49 (port 80)
  CVE-2021-41773 | CVSS 9.8 | Path Traversal / RCE
  EN: Your web server has a critical known exploit. Attackers can access any
      file on the server without authentication. Update Apache to 2.4.51+.
  SW: Seva yako ya wavuti ina udhaifu mkubwa unaojulikana. Sasisha Apache
      hadi toleo la 2.4.51 au zaidi mara moja.

[HIGH] 192.168.1.5 — OpenSSH 7.4 (port 22)
  CVE-2018-15473 | CVSS 5.3 | User Enumeration
  EN: Your SSH server leaks valid usernames. Combined with weak passwords,
      this enables targeted brute-force attacks. Update to OpenSSH 7.8+.

Network Risk Score: 62/100 — HIGH
Report saved: reports/scan_2026-06-04_192.168.1.0.pdf
```

---

## Key Features

- **Full NVD CVE database** — 200,000+ CVEs stored locally in SQLite, synced from NIST
- **Active verification** — Nmap NSE scripts verify critical CVEs (Heartbleed, EternalBlue, etc.), not just version guessing
- **AI narration** — Groq (default) or Ollama (offline) explains every finding in plain language
- **Bilingual output** — English and Swahili, side by side
- **Remediation guidance** — actionable fix instructions per CVE, AI-generated
- **Network risk score** — aggregate CVSS scores into a 0–100 grade
- **Scan history** — track security posture over time, alert when new CVEs affect your network
- **PDF/HTML reports** — professional output for management
- **Optional credentialed scanning** — SSH into hosts for exact package version accuracy

---

## Quickstart

```bash
# Install
pip install aivas

# First-time: download CVE database (~600MB)
aivas update-db

# Scan your network
aivas scan 192.168.1.0/24

# Scan with SSH credentials for higher accuracy
aivas scan 192.168.1.0/24 --credentials admin@192.168.1.10

# Export PDF report
aivas scan 192.168.1.0/24 --output pdf

# Use local LLM (offline mode)
aivas scan 192.168.1.0/24 --provider ollama
```

---

## Architecture

```
aivas/
  cli.py          — entry point, argument parsing (Click)
  scanner.py      — Nmap orchestration, NSE script selection
  parser.py       — Nmap XML output → structured service data
  database.py     — SQLite CVE store, NVD sync, CPE matching
  correlator.py   — service version → CVE lookup + CVSS scoring
  narrator.py     — LLM prompting (Groq/Ollama), EN+SW generation
  reporter.py     — rich terminal output + PDF/HTML export
  history.py      — scan result persistence, diff, alerting
```

Each module has one responsibility and stays under 200 lines. Interfaces are stable — adding new scan types, LLM providers, or output formats does not require changing existing modules.

---

## Comparison

| | AIVAS | OpenVAS | Nessus |
|---|---|---|---|
| Cost | Free | Free (complex setup) | ~$3,000/yr |
| Install | `pip install` | Docker + hours | Complex |
| Plain language output | Yes (LLM) | No | No |
| Swahili | Yes | No | No |
| Remediation guidance | AI-generated | Basic | Some |
| Active verification | NSE scripts | 90,000+ NASL plugins | Extensive |
| Resource usage | Lightweight | Heavy | Heavy |

---

## Academic Context

Final year project — Diploma in Computer Engineering  
Mbeya University of Science and Technology (MUST), Tanzania  
Students: Baraka Winchislaus Malila & Michael Chacha Megewa  
Supervisor: Namsembwa Mzava | 2025/2026

---

## Roadmap

- **v1.0** — Core: CVE DB, Nmap + NSE scanning, LLM narration, PDF reports, scan history
- **v2.0** — Web dashboard GUI
- **v3.0** — IDS/IDPS integration, real-time alerting
