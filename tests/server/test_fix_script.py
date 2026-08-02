import sqlite3
import pytest
from aivas.database.schema import create_schema
from aivas.server.fix_script import generate_fix_script, _infer_packages


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def _insert_scan(conn, target="192.168.1.1"):
    cur = conn.execute(
        "INSERT INTO scans (target, started_at, finished_at, host_count, finding_count, risk_score, grade)"
        " VALUES (?, datetime('now'), datetime('now'), 1, 2, 80, 'Grade F')",
        (target,),
    )
    conn.commit()
    return cur.lastrowid


def _insert_finding(conn, scan_id, cve_id, severity="HIGH", description="", kev=0):
    conn.execute(
        "INSERT INTO cves (cve_id, description, cvss_score, cvss_severity, kev) VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(cve_id) DO NOTHING",
        (cve_id, description, 7.5, severity, kev),
    )
    conn.execute(
        "INSERT INTO findings (scan_id, host, cve_id, cvss_score, cvss_severity)"
        " VALUES (?, '192.168.1.1', ?, ?, ?)",
        (scan_id, cve_id, 7.5, severity),
    )
    conn.commit()


def test_returns_none_for_missing_scan(conn):
    assert generate_fix_script(conn, 9999) is None


def test_script_has_shebang(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2022-0001")
    script = generate_fix_script(conn, scan_id)
    assert script.startswith("#!/usr/bin/env bash")


def test_script_contains_scan_id(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2022-0001")
    script = generate_fix_script(conn, scan_id)
    assert f"#{scan_id}" in script


def test_script_contains_target(conn):
    scan_id = _insert_scan(conn, target="10.0.0.5")
    _insert_finding(conn, scan_id, "CVE-2022-0001")
    script = generate_fix_script(conn, scan_id)
    assert "10.0.0.5" in script


def test_script_lists_cve(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2021-44228", "CRITICAL", "Apache Log4j RCE")
    script = generate_fix_script(conn, scan_id)
    assert "CVE-2021-44228" in script


def test_script_has_kev_warning_when_kev_present(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2021-44228", "CRITICAL", "Log4j", kev=1)
    script = generate_fix_script(conn, scan_id)
    assert "KEV" in script or "actively-exploited" in script


def test_script_no_kev_warning_when_none(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2022-0001", "HIGH", "Some OpenSSL issue", kev=0)
    script = generate_fix_script(conn, scan_id)
    assert "actively-exploited" not in script


def test_script_has_distro_detection(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2022-0001")
    script = generate_fix_script(conn, scan_id)
    assert "os-release" in script
    assert "apt" in script
    assert "dnf" in script


def test_infer_packages_openssl(conn):
    findings = [{"description": "OpenSSL memory corruption vulnerability"}]
    apt_pkgs, rpm_pkgs = _infer_packages(findings)
    assert "openssl" in apt_pkgs
    assert "openssl" in rpm_pkgs


def test_infer_packages_nginx(conn):
    findings = [{"description": "nginx HTTP/2 header handling flaw"}]
    apt_pkgs, rpm_pkgs = _infer_packages(findings)
    assert "nginx" in apt_pkgs


def test_infer_packages_deduplicates(conn):
    findings = [
        {"description": "OpenSSL flaw 1"},
        {"description": "OpenSSL flaw 2"},
    ]
    apt_pkgs, _ = _infer_packages(findings)
    assert apt_pkgs.count("openssl") == 1


def test_infer_packages_unknown_returns_empty(conn):
    findings = [{"description": "Some obscure application bug"}]
    apt_pkgs, rpm_pkgs = _infer_packages(findings)
    assert apt_pkgs == []
    assert rpm_pkgs == []


def test_script_uses_specific_package_when_known(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2022-0778", "HIGH", "OpenSSL infinite loop")
    script = generate_fix_script(conn, scan_id)
    assert "openssl" in script


def test_script_falls_back_to_dist_upgrade_when_no_packages(conn):
    scan_id = _insert_scan(conn)
    _insert_finding(conn, scan_id, "CVE-2099-9999", "LOW", "Hypothetical unknown app")
    script = generate_fix_script(conn, scan_id)
    assert "dist-upgrade" in script or "update" in script
