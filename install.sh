#!/usr/bin/env bash
# AIVAS installer — works on Kali, Ubuntu, Debian, and similar systems.
# Usage:
#   bash install.sh          # installs into ~/.local (no root needed)
#   bash install.sh --system # installs system-wide (needs sudo)
set -euo pipefail

PYPI_PKG="aivas"
MIN_PYTHON="3.10"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[aivas]${NC} $*"; }
success() { echo -e "${GREEN}[aivas]${NC} $*"; }
warn()    { echo -e "${YELLOW}[aivas]${NC} $*"; }
die()     { echo -e "${RED}[aivas] ERROR:${NC} $*" >&2; exit 1; }

# ── Python check ────────────────────────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
            PYTHON="$cmd"; break
        fi
    fi
done
[[ -n "$PYTHON" ]] || die "Python $MIN_PYTHON+ not found. Install with: sudo apt install python3"

info "Using $PYTHON ($($PYTHON --version))"

# ── nmap check ──────────────────────────────────────────────────────────────
if ! command -v nmap &>/dev/null; then
    warn "nmap not found — installing..."
    sudo apt-get install -y nmap || die "Could not install nmap. Run: sudo apt install nmap"
fi

# ── Install AIVAS ────────────────────────────────────────────────────────────
SYSTEM_FLAG=""
[[ "${1:-}" == "--system" ]] && SYSTEM_FLAG="--break-system-packages"

info "Installing AIVAS from PyPI..."
if [[ -n "$SYSTEM_FLAG" ]]; then
    $PYTHON -m pip install --upgrade $SYSTEM_FLAG "$PYPI_PKG"
else
    # Try pipx first (cleanest), fall back to user pip
    if command -v pipx &>/dev/null; then
        info "Using pipx for isolated install..."
        pipx install "$PYPI_PKG" --force
        success "Installed via pipx. Run: aivas"
        exit 0
    fi

    # Kali / Ubuntu 23+: try user install; if blocked, suggest pipx or venv
    if $PYTHON -m pip install --user --upgrade "$PYPI_PKG" 2>&1 | grep -q "externally-managed"; then
        warn "System Python is externally managed (PEP 668)."
        info "Installing pipx then retrying..."
        sudo apt-get install -y pipx 2>/dev/null || $PYTHON -m pip install --user pipx $SYSTEM_FLAG
        pipx install "$PYPI_PKG" --force
        success "Installed via pipx. Run: aivas"
        exit 0
    fi
fi

# ── PATH reminder ────────────────────────────────────────────────────────────
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    warn "Add ~/.local/bin to PATH — add this to ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

success "AIVAS installed successfully!"
echo ""
echo "  Quick start:"
echo "    aivas --help          # list commands"
echo "    aivas serve --open    # open web UI in browser"
echo "    aivas                 # launch terminal UI"
echo ""
echo "  First run — set your AI provider key:"
echo "    aivas config set api_key YOUR_GROQ_KEY"
echo "    # or: aivas config set provider mistral"
echo "    #     aivas config set mistral_api_key YOUR_KEY"
