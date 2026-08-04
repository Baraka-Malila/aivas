#!/usr/bin/env bash
# Upload signed AIVAS source package to Launchpad PPA.
# Usage: ./scripts/upload-ppa.sh [noble|jammy]  (default: noble)
set -euo pipefail

DISTRO="${1:-noble}"
PKG="aivas"
VERSION="0.1.1"
DEB_REV="1"
FULL_VERSION="${VERSION}-${DEB_REV}~${DISTRO}1"
BUILD_DIR="/tmp/aivas-launchpad-build"
CHANGES_FILE="${BUILD_DIR}/${PKG}_${FULL_VERSION}_source.changes"

DPUT_CFG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/dput.cf"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[upload]${NC} $*"; }
success() { echo -e "${GREEN}[upload]${NC} $*"; }
die()     { echo -e "${RED}[upload] ERROR:${NC} $*" >&2; exit 1; }

# ── pre-flight ───────────────────────────────────────────────────────────────
command -v dput    &>/dev/null || die "dput not found. Run: sudo apt install dput"
command -v debsign &>/dev/null || die "debsign not found. Run: sudo apt install devscripts"

[[ -f "${CHANGES_FILE}" ]] \
    || die ".changes file not found: ${CHANGES_FILE}\n  Run: ./scripts/build-source-package.sh ${DISTRO} first"

GPG_KEY="bmalila87@gmail.com"
gpg --list-secret-keys "${GPG_KEY}" &>/dev/null \
    || die "GPG key for ${GPG_KEY} not found."

# ── sign ─────────────────────────────────────────────────────────────────────
info "Signing ${CHANGES_FILE}..."
debsign -k"${GPG_KEY}" "${CHANGES_FILE}"

# ── upload ───────────────────────────────────────────────────────────────────
info "Uploading to ppa:malila-arch/aivas (${DISTRO})..."
dput --config="${DPUT_CFG}" malila-arch-aivas "${CHANGES_FILE}"

success "Uploaded! Check build status at:"
echo "  https://launchpad.net/~malila-arch/+archive/ubuntu/aivas/+builds"
echo ""
echo "  Once built, users install with:"
echo "    sudo add-apt-repository ppa:malila-arch/aivas"
echo "    sudo apt update && sudo apt install aivas"
