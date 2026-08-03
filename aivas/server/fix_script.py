"""Generate a downloadable distro-aware bash fix script from scan findings."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from aivas.history import get_scan_findings, get_scan_meta

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

_CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# (search term in description/product, apt package, rpm package, apk package)
_PKG_MAP: list[tuple[str, str, str, str]] = [
    ("openssl",      "openssl",             "openssl",            "openssl"),
    ("libssl",       "openssl",             "openssl",            "openssl"),
    ("openssh",      "openssh-server",      "openssh-server",     "openssh"),
    ("nginx",        "nginx",               "nginx",              "nginx"),
    ("apache",       "apache2",             "httpd",              "apache2"),
    ("php",          "php",                 "php",                "php"),
    ("mysql",        "mysql-server",        "mysql-server",       "mysql"),
    ("mariadb",      "mariadb-server",      "mariadb-server",     "mariadb"),
    ("postgresql",   "postgresql",          "postgresql-server",  "postgresql"),
    ("samba",        "samba",               "samba",              "samba"),
    ("linux kernel", "linux-image-generic", "kernel",             "linux-lts"),
    ("curl",         "curl",                "curl",               "curl"),
    ("libcurl",      "libcurl4",            "libcurl",            "curl"),
    ("python",       "python3",             "python3",            "python3"),
    ("bind",         "bind9",               "bind",               "bind"),
    ("sudo",         "sudo",                "sudo",               "sudo"),
    ("glibc",        "libc6",               "glibc",              "musl"),
    ("expat",        "libexpat1",           "expat",              "expat"),
    ("zlib",         "zlib1g",              "zlib",               "zlib"),
    ("vim",          "vim",                 "vim",                "vim"),
    ("bash",         "bash",                "bash",               "bash"),
    ("wget",         "wget",                "wget",               "wget"),
    ("git",          "git",                 "git",                "git"),
    ("sqlite",       "sqlite3",             "sqlite",             "sqlite"),
    ("log4j",        "liblog4j2-java",      "log4j",              ""),
    ("jackson",      "jackson",             "jackson-databind",   ""),
    ("spring",       "libspring-java",      "spring-framework",   ""),
    ("redis",        "redis-server",        "redis",              "redis"),
    ("docker",       "docker.io",           "docker-ce",          "docker"),
]


def _infer_packages(findings: list[dict]) -> tuple[list[str], list[str], list[str]]:
    """Return (apt_pkgs, rpm_pkgs, apk_pkgs) inferred from CVE descriptions."""
    seen_apt: set[str] = set()
    seen_rpm: set[str] = set()
    seen_apk: set[str] = set()
    apt_pkgs: list[str] = []
    rpm_pkgs: list[str] = []
    apk_pkgs: list[str] = []
    for f in findings:
        # Match against description text + installed product name
        search_text = (
            (f.get("description") or "").lower() + " " +
            (f.get("installed_version") or "").lower()
        )
        for term, apt_p, rpm_p, apk_p in _PKG_MAP:
            if term in search_text:
                if apt_p and apt_p not in seen_apt:
                    seen_apt.add(apt_p)
                    apt_pkgs.append(apt_p)
                if rpm_p and rpm_p not in seen_rpm:
                    seen_rpm.add(rpm_p)
                    rpm_pkgs.append(rpm_p)
                if apk_p and apk_p not in seen_apk:
                    seen_apk.add(apk_p)
                    apk_pkgs.append(apk_p)
    return apt_pkgs, rpm_pkgs, apk_pkgs


def generate_fix_script(conn: sqlite3.Connection, scan_id: int) -> str | None:
    meta = get_scan_meta(conn, scan_id)
    if not meta:
        return None

    findings = get_scan_findings(conn, scan_id)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEV_ORDER.index(f.get("cvss_severity") or "LOW")
        if (f.get("cvss_severity") or "LOW") in _SEV_ORDER else 99,
    )

    kev_findings = [f for f in sorted_findings if f.get("kev")]
    non_kev = [f for f in sorted_findings if not f.get("kev")]

    # Build CVE comment block — KEV entries get CISA URL
    cve_lines_parts = []
    for f in kev_findings:
        cve_lines_parts.append(
            f"#   {f['cve_id']:<16} {(f.get('cvss_severity') or 'UNKNOWN'):<8}  "
            f"[KEV] {_CISA_KEV_URL}?search={f['cve_id']}"
        )
    for f in non_kev:
        cve_lines_parts.append(
            f"#   {f['cve_id']:<16} {(f.get('cvss_severity') or 'UNKNOWN'):<8}  "
            f"{(f.get('description') or '')[:60]}"
        )
    cve_lines = "\n".join(cve_lines_parts)

    apt_pkgs, rpm_pkgs, apk_pkgs = _infer_packages(findings)
    apt_str = " ".join(apt_pkgs)
    rpm_str = " ".join(rpm_pkgs)
    apk_str = " ".join(apk_pkgs)

    apt_cmd = f"apt-get install --only-upgrade -y {apt_str}" if apt_str else "apt-get dist-upgrade -y"
    rpm_cmd = f"dnf update -y {rpm_str}" if rpm_str else "dnf update -y"
    yum_cmd = f"yum update -y {rpm_str}" if rpm_str else "yum update -y"
    zypper_cmd = f"zypper update -y {apt_str or rpm_str}" if (apt_str or rpm_str) else "zypper update -y"
    apk_cmd = f"apk upgrade {apk_str}" if apk_str else "apk upgrade"
    pacman_cmd = "pacman -Su --noconfirm"

    kev_warn = ""
    if kev_findings:
        ids = " ".join(f['cve_id'] for f in kev_findings[:5])
        extra = f" (+ {len(kev_findings)-5} more)" if len(kev_findings) > 5 else ""
        kev_warn = (
            f"\n# ⚠  WARNING: {len(kev_findings)} actively-exploited CVE(s) in CISA KEV catalog."
            f"\n#    {ids}{extra}"
            f"\n#    Full catalog: {_CISA_KEV_URL}"
            "\n#    Apply this fix IMMEDIATELY — these are confirmed in-the-wild attacks.\n"
        )

    # Manual fallback block for unknown distros
    manual_lines = []
    if apt_pkgs:
        manual_lines.append(f"#    Debian/Ubuntu:  sudo apt-get install --only-upgrade -y {apt_str}")
    if rpm_pkgs:
        manual_lines.append(f"#    RHEL/CentOS:    sudo dnf update -y {rpm_str}")
    if apk_pkgs:
        manual_lines.append(f"#    Alpine:         sudo apk upgrade {apk_str}")
    if not manual_lines:
        manual_lines.append("#    Run your distribution's package manager to apply all pending security updates.")
    manual_block = "\n".join(manual_lines)

    target = meta.get("target", "unknown")
    grade = (meta.get("grade") or "").replace("Grade ", "")

    return f"""#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
#  AIVAS — Automated Remediation Script
#  Scan #{scan_id}  |  Target: {target}  |  Grade: {grade}
#  Generated: {now}
# ══════════════════════════════════════════════════════════════════════════
#
#  CVEs addressed ({len(findings)} total):
{cve_lines}
#{kev_warn}
#  REVIEW BEFORE RUNNING:
#  - Test in a non-production environment first.
#  - Reboot may be required for kernel-level patches.
# ══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── 0. Privilege check ────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        echo "[AIVAS] Running as non-root — using sudo for package commands."
    else
        echo "ERROR: Root privileges required. Run as root or install sudo." >&2
        exit 1
    fi
else
    SUDO=""
fi

# ── 1. Detect OS ──────────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID="${{ID:-unknown}}"
else
    DISTRO_ID="unknown"
fi

case "$DISTRO_ID" in
    ubuntu|debian|linuxmint|raspbian|pop)
        PKG_MGR="apt" ;;
    rhel|centos|rocky|almalinux|fedora|amzn)
        command -v dnf >/dev/null 2>&1 && PKG_MGR="dnf" || PKG_MGR="yum" ;;
    opensuse*|sles)
        PKG_MGR="zypper" ;;
    arch|manjaro|endeavouros)
        PKG_MGR="pacman" ;;
    alpine)
        PKG_MGR="apk" ;;
    *)
        echo "[AIVAS] Unrecognised distribution: $DISTRO_ID" >&2
        echo "        Apply patches manually using the commands below:" >&2
        echo "{manual_block}" >&2
        exit 1 ;;
esac

echo "[AIVAS] Distribution: $DISTRO_ID  |  Package manager: $PKG_MGR"

# ── 2. Refresh package lists ──────────────────────────────────────────────
case "$PKG_MGR" in
    apt)
        $SUDO apt-get update -y ;;
    dnf)
        $SUDO dnf check-update --refresh || true ;;
    yum)
        $SUDO yum check-update || true ;;
    zypper)
        $SUDO zypper refresh ;;
    pacman)
        $SUDO pacman -Sy --noconfirm ;;
    apk)
        $SUDO apk update ;;
esac

# ── 3. Apply targeted upgrades ────────────────────────────────────────────
case "$PKG_MGR" in
    apt)
        $SUDO {apt_cmd} ;;
    dnf)
        $SUDO {rpm_cmd} ;;
    yum)
        $SUDO {yum_cmd} ;;
    zypper)
        $SUDO {zypper_cmd} ;;
    pacman)
        $SUDO {pacman_cmd} ;;
    apk)
        $SUDO {apk_cmd} ;;
esac

echo "[AIVAS] Patching complete for scan #{scan_id}."
echo "        Verify that affected services are still running correctly."
"""
