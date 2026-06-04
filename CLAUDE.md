# CLAUDE.md — AIVAS Implementation Repo

## Project
AIVAS: AI-Assisted Network Vulnerability Assessment System
Python CLI — Nmap + NVD SQLite + Groq/Ollama LLM → bilingual vulnerability reports

## Code Rules
- **No file exceeds 200 lines.** If a module grows past this, split it.
- One file = one responsibility. Name it after what it does.
- No comments explaining what code does. Only add a comment if the WHY is non-obvious.
- No features beyond what is in the current spec. No speculative abstractions.

## Git Rules
- All commits: `git config user.name "Baraka Malila"` + `git config user.email "bmalila87@gmail.com"` (already set)
- Never use `--author` flag or co-author attribution
- Branch naming: `feature/<name>`, `fix/<name>`, `docs/<name>`
- User pushes to GitHub themselves after reviewing local commits

## Module Map
```
aivas/cli.py        — Click entry point, routes subcommands
aivas/scanner.py    — Nmap orchestration, NSE script flags
aivas/parser.py     — Nmap XML → Python dicts
aivas/database.py   — SQLite schema, NVD sync, CPE queries
aivas/correlator.py — service → CVE match + CVSS scoring
aivas/narrator.py   — Groq/Ollama prompts, EN+SW generation
aivas/reporter.py   — rich terminal, PDF/HTML via Jinja2
aivas/history.py    — scan persistence, diff, new-CVE alerts
```

## References (study before touching each module)
- `scanner.py` → study `../final year project/references/AutoRecon/autorecon/main.py`
- `correlator.py` → study `../final year project/references/vulscan/vulscan.nse`
- `database.py` → study `../final year project/references/nvdlib/nvdlib/`
- `narrator.py` → Groq Python SDK docs, Ollama Python SDK docs
- `reporter.py` → study `../final year project/references/collection-claude-code-source-code` for UI patterns
- NSE scripts → study `../final year project/references/nmap-vulners/vulners.nse`

## LLM Providers
- Default: Groq (`GROQ_API_KEY` env var). Free tier, fastest inference, any machine with internet.
- Optional: Ollama (`--provider ollama`). Fully offline, needs ~4GB RAM + model downloaded.
- Flag: `aivas scan <target> --provider [groq|ollama]`

## Scan Levels
- **Level 1 (default):** `nmap -sV` + targeted NSE scripts (ssl-heartbleed, smb-vuln-ms17-010, ftp-anon, http-shellshock, mysql-empty-password)
- **Level 2 (--deep):** Full NSE vuln category scan
- **Level 3 (--credentials user@host):** SSH credentialed package version check

## Known Limitations (document in reports)
- Version-based correlation may produce false positives when patches are backported
- Banner hiding causes false negatives — credentialed scan resolves this
- Does not monitor live traffic (not an IDS)
- Does not scan source code (not a SAST tool)
