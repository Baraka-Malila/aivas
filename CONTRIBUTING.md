# Contributing to AIVAS

AIVAS is an open-source project and contributions are welcome. This document covers how to set up a development environment, coding standards, how to report issues, and how to submit changes.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Running Tests](#running-tests)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Scope and Roadmap](#scope-and-roadmap)

---

## Getting Started

AIVAS requires Python 3.10 or later and nmap.

```bash
# Clone the repository
git clone https://github.com/Baraka-Malila/aivas.git
cd aivas

# Install in editable mode (requires pip >= 23)
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"

# Verify the installation
aivas --help
```

If the `aivas` command is not found after install, add `~/.local/bin` to your PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Development Setup

### Dependencies

```bash
python3 -m pip install -e ".[dev]"
```

The `[dev]` group installs pytest, ruff (linter), and pytest-cov.

### Database

AIVAS uses a local SQLite CVE database. To populate it for development:

```bash
# From the NVD JSON data feeds (if you have them locally)
aivas update-db --source /path/to/nvd-json-data-feeds/

# Or from the NVD API (requires a free API key for higher rate limits)
aivas update-db --api-key YOUR_NIST_KEY
```

For most development work, a small subset of CVEs is sufficient. The test suite uses in-memory SQLite databases and does not require a populated local DB.

---

## Project Structure

```
aivas/
  cli.py              Entry point, Click group, top-level commands
  config.py           Config file (~/.aivas/config.yml) read/write
  correlator.py       Maps nmap services to CVE candidates
  formatting.py       Rich table builders (cve_table, misconfig_table)
  parser.py           Nmap XML parser
  scorer.py           CVSS-based risk score and grade
  reporter.py         HTML/PDF report generator
  history.py          Scan persistence (SQLite)

  commands/           One file per CLI subcommand
  database/           CVE DB schema, ingest, CPE query, KEV sync
  narrator/           LLM providers, intent parsing, narration
  prober/             Level 1 config probes (headers, endpoints, methods)
  scanner/            Nmap orchestration, NSE scripts, SSH probe
  tui/                Textual TUI app and slash command handlers
```

**File size limit:** No Python source file may exceed 200 lines. If a file approaches this limit, split it by responsibility.

---

## Coding Standards

### Style

AIVAS uses [ruff](https://docs.astral.sh/ruff/) for linting. Run it before committing:

```bash
ruff check aivas/ tests/
ruff format aivas/ tests/
```

The ruff configuration is in `pyproject.toml`. The main rules: no unused imports, no bare `except`, consistent quote style.

### General rules

- One module, one responsibility. A file that does two things should be two files.
- No file exceeds 200 lines of code.
- Default to no comments. Only add one when the WHY is non-obvious.
- Do not add features beyond what a task requires.
- Error handling only at system boundaries (user input, external APIs, subprocesses). Do not guard against internal invariants that cannot fail.
- All new behaviour must be covered by tests before the PR is merged.

### Data shape

Services and findings flow through the codebase as plain dicts. The shapes are:

```python
# Service (output of parser.py)
{
    "host": str, "port": int, "protocol": str,
    "service": str, "product": str, "version": str,
    "nse_results": dict, "os_family": str,
}

# CVE finding (output of correlator.py / cpe_query.py)
{
    "cve_id": str, "cvss_score": float, "cvss_severity": str,
    "description": str, "confidence": str, "kev": int, ...
}

# Misconfiguration finding (output of prober/)
{
    "type": "misconfiguration", "title": str,
    "severity": str, "description": str, "recommendation": str,
}
```

New probe modules must return a `list[dict]` conforming to the misconfiguration shape. New scanner modules must return a `list[dict]` conforming to the service shape.

---

## Running Tests

```bash
# Run the full test suite
python3 -m pytest

# Run a specific file
python3 -m pytest tests/test_cpe_query.py -v

# Run with coverage report
python3 -m pytest --cov=aivas --cov-report=term-missing
```

The test suite uses in-memory SQLite databases and mocked HTTP/subprocess calls. No network access or nmap installation is required to run tests.

All PRs must pass the full test suite. The CI pipeline runs on every push and pull request.

---

## Submitting Changes

### Branch naming

```
feat/short-description       New feature
fix/short-description        Bug fix
docs/short-description       Documentation only
refactor/short-description   Refactoring with no behaviour change
test/short-description       Tests only
```

### Commit messages

Use the imperative mood and be specific:

```
feat: add HSTS header check to prober/headers.py
fix: version filter false positive for OpenSSL wildcard CPEs
docs: add Level 2 probe architecture to roadmap
```

Reference the relevant area of the codebase in the message. Do not write "fix bug" or "update code".

### Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes with tests.
3. Run `ruff check` and `python3 -m pytest` — both must pass.
4. Open a pull request against `main`. Use the PR template.
5. Describe what changed, why, and how to test it.
6. A maintainer will review within a reasonable time. Address feedback by adding new commits, not force-pushing.

### What gets accepted

- Bug fixes with a test that reproduces the bug.
- New probe checks (headers, endpoints, CVE-specific) that follow the existing signature.
- New product entries in `PRODUCT_CPE_MAP` with a reference to the CPE string in NVD.
- Language improvements to narration prompts.
- Performance improvements to CPE query logic.
- Documentation improvements.

### What will not be accepted

- Changes that increase a file beyond 200 lines without splitting it.
- New dependencies added without discussion in an issue first.
- Features not aligned with the project roadmap.
- Code without tests.

---

## Reporting Issues

Use GitHub Issues. Select the appropriate template:

- **Bug report** — something is broken or behaving incorrectly.
- **Feature request** — an idea for a new capability.

For security vulnerabilities, do not open a public issue. See [SECURITY.md](SECURITY.md).

Before opening an issue:
- Run `aivas doctor` and include the output.
- Include the exact command you ran and the full error output.
- Include your OS, Python version (`python3 --version`), and nmap version (`nmap --version`).

---

## Scope and Roadmap

AIVAS is a network vulnerability assessment tool for Linux. The project roadmap is documented in:

```
docs/superpowers/specs/2026-06-05-aivas-roadmap-and-status.md
```

Key near-term items: KEV integration, Level 1 config probing, usability improvements. Level 2 active CVE verification probes are on the roadmap but not yet in scope for the current release.

If you want to work on something on the roadmap, open an issue first to discuss approach before starting. This avoids duplicate work and ensures the implementation fits the architecture.

---

_AIVAS is a final year project at MUST (Mbeya University of Science and Technology), Diploma in Computer Engineering, 2025/2026. It is being developed as open-source software with the intent to grow beyond the academic context._
