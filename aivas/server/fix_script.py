"""Generate a downloadable distro-aware bash fix script from scan findings."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from aivas.history import get_scan_findings, get_scan_meta

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# (search term in description, apt package, rpm package)
_PKG_MAP: list[tuple[str, str, str]] = [
    ("openssl",     "openssl",            "openssl"),
    ("libssl",      "openssl",            "openssl"),
    ("openssh",     "openssh-server",     "openssh-server"),
    ("nginx",       "nginx",              "nginx"),
    ("apache",      "apache2",            "httpd"),
    ("php",         "php",                "php"),
    ("mysql",       "mysql-server",       "mysql-server"),
    ("postgresql",  "postgresql",         "postgresql-server"),
    ("samba",       "samba",              "samba"),
    ("linux kernel","linux-image-generic","kernel"),
    ("curl",        "curl",               "curl"),
    ("libcurl",     "libcurl4",           "libcurl"),
    ("python",      "python3",            "python3"),
    ("bind",        "bind9",              "bind"),
    ("sudo",        "sudo",               "sudo"),
    ("glibc",       "libc6",              "glibc"),
    ("expat",       "libexpat1",          "expat"),
    ("zlib",        "zlib1g",             "zlib"),
    ("vim",         "vim",                "vim"),
    ("bash",        "bash",               "bash"),
    ("wget",        "wget",               "wget"),
    ("git",         "git",                "git"),
    ("sqlite",      "sqlite3",            "sqlite"),
    ("log4j",       "liblog4j2-java",     "log4j"),
    ("jackson",     "jackson",            "jackson-databind"),
    ("spring",      "libspring-java",     "spring-framework"),
]


def _infer_packages(findings: list[dict]) -> tuple[list[str], list[str]]:
    """Return (apt_pkgs, rpm_pkgs) inferred from CVE descriptions."""
    seen_apt: set[str] = set()
    seen_rpm: set[str] = set()
    apt_pkgs: list[str] = []
    rpm_pkgs: list[str] = []
    for f in findings:
        desc = (f.get("description") or "").lower()
        for term, apt_p, rpm_p in _PKG_MAP:
            if term in desc:
                if apt_p not in seen_apt:
                    seen_apt.add(apt_p)
                    apt_pkgs.append(apt_p)
                if rpm_p not in seen_rpm:
                    seen_rpm.add(rpm_p)
                    rpm_pkgs.append(rpm_p)
    return apt_pkgs, rpm_pkgs


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

    cve_lines = "\n".join(
        f"#   {f['cve_id']:<16} {(f.get('cvss_severity') or 'UNKNOWN'):<8}  "
        f"{(f.get('description') or '')[:60]}"
        for f in sorted_findings
    )

    apt_pkgs, rpm_pkgs = _infer_packages(findings)
    apt_str = " ".join(apt_pkgs) if apt_pkgs else ""
    rpm_str = " ".join(rpm_pkgs) if rpm_pkgs else ""

    apt_cmd = (
        f"apt-get install --only-upgrade -y {apt_str}"
        if apt_str else
        "apt-get dist-upgrade -y"
    )
    rpm_cmd = (
        f"dnf update -y {rpm_str}"
        if rpm_str else
        "dnf update -y"
    )
    yum_cmd = (
        f"yum update -y {rpm_str}"
        if rpm_str else
        "yum update -y"
    )
    zypper_cmd = (
        f"zypper update -y {apt_str or rpm_str}"
        if (apt_str or rpm_str) else
        "zypper update -y"
    )

    kev_warn = ""
    kev_count = sum(1 for f in findings if f.get("kev"))
    if kev_count:
        kev_warn = (
            f"\n# ⚠  WARNING: {kev_count} actively-exploited CVE(s) (CISA KEV catalog)."
            "\n#    Apply this fix IMMEDIATELY — these are confirmed in-the-wild attacks.\n"
        )

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
#  - This script requires root or sudo privileges.
#  - Reboot may be required for kernel-level patches.
# ══════════════════════════════════════════════════════════════════════════

set -euo pipefail

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
    *)
        echo "ERROR: Unrecognised distribution: $DISTRO_ID" >&2
        echo "Apply patches manually. See the AIVAS report for CVE details." >&2
        exit 1 ;;
esac

echo "[AIVAS] Distribution: $DISTRO_ID  |  Package manager: $PKG_MGR"

# ── 2. Refresh package lists ──────────────────────────────────────────────
case "$PKG_MGR" in
    apt)
        apt-get update -y ;;
    dnf)
        dnf check-update --refresh || true ;;
    yum)
        yum check-update || true ;;
    zypper)
        zypper refresh ;;
    pacman)
        pacman -Sy --noconfirm ;;
esac

# ── 3. Apply targeted upgrades ────────────────────────────────────────────
case "$PKG_MGR" in
    apt)
        {apt_cmd} ;;
    dnf)
        {rpm_cmd} ;;
    yum)
        {yum_cmd} ;;
    zypper)
        {zypper_cmd} ;;
    pacman)
        pacman -Su --noconfirm ;;
esac

echo "[AIVAS] Patching complete for scan #{scan_id}."
echo "        Verify that affected services are still running correctly."
"""
