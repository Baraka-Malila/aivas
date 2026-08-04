#!/usr/bin/env bash
# Build a signed Launchpad source package for AIVAS.
# Usage: ./scripts/build-source-package.sh [noble|jammy]  (default: noble)
set -euo pipefail

DISTRO="${1:-noble}"
PKG="aivas"
VERSION="0.1.0"
DEB_REV="1"
FULL_VERSION="${VERSION}-${DEB_REV}~${DISTRO}1"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="/tmp/aivas-launchpad-build"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[build]${NC} $*"; }
success() { echo -e "${GREEN}[build]${NC} $*"; }
die()     { echo -e "${RED}[build] ERROR:${NC} $*" >&2; exit 1; }

# ── pre-flight ───────────────────────────────────────────────────────────────
command -v debuild &>/dev/null || die "debuild not found. Run: sudo apt install devscripts debhelper"
command -v gpg    &>/dev/null || die "gpg not found."
[[ -f "${REPO_ROOT}/debian/prebuilt/aivas-${VERSION}-py3-none-any.whl" ]] \
    || die "Pre-built wheel missing: debian/prebuilt/aivas-${VERSION}-py3-none-any.whl\n  Run: python3 -m build && cp dist/*.whl debian/prebuilt/"

GPG_KEY="bmalila87@gmail.com"
gpg --list-secret-keys "${GPG_KEY}" &>/dev/null \
    || die "GPG key for ${GPG_KEY} not found. Import it first."

# ── prepare clean build tree ─────────────────────────────────────────────────
info "Preparing build tree for ${DISTRO}..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

# Copy repo (exclude git, build artefacts, dist, node_modules)
rsync -a --exclude='.git' --exclude='dist' --exclude='build' \
    --exclude='*.egg-info' --exclude='node_modules' --exclude='__pycache__' \
    --exclude='.venv' --exclude='aivas.db' \
    "${REPO_ROOT}/" "${BUILD_DIR}/${PKG}-${VERSION}/"

# Rewrite changelog distro name
sed -i "s/) noble;/) ${DISTRO};/" "${BUILD_DIR}/${PKG}-${VERSION}/debian/changelog"
sed -i "s/~noble1/~${DISTRO}1/g"  "${BUILD_DIR}/${PKG}-${VERSION}/debian/changelog"
sed -i "s/-1~noble/-1~${DISTRO}/g" "${BUILD_DIR}/${PKG}-${VERSION}/debian/changelog"

# ── create orig tarball ───────────────────────────────────────────────────────
info "Creating orig tarball..."
cd "${BUILD_DIR}"
tar --exclude="${PKG}-${VERSION}/debian" \
    -czf "${PKG}_${VERSION}.orig.tar.gz" "${PKG}-${VERSION}/"

# ── build signed source package ───────────────────────────────────────────────
info "Running debuild -S -sa ..."
cd "${BUILD_DIR}/${PKG}-${VERSION}"
debuild -S -sa \
    -k"${GPG_KEY}" \
    2>&1

success "Source package built in ${BUILD_DIR}/"
ls -lh "${BUILD_DIR}"/*.dsc "${BUILD_DIR}"/*.changes 2>/dev/null

info "Next: run ./scripts/upload-ppa.sh ${DISTRO}"
