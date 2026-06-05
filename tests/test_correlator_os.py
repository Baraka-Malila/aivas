import sqlite3
import pytest
from aivas.correlator import correlate
from aivas.database.schema import create_schema


@pytest.fixture
def db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    # CVE whose description mentions Linux — should be filtered for Windows hosts
    conn.execute(
        """INSERT INTO cves (cve_id, cvss_score, cvss_severity, description)
           VALUES ('CVE-2021-1234', 9.8, 'CRITICAL', 'Linux kernel vulnerability in nginx')"""
    )
    conn.execute(
        """INSERT INTO cpe_matches (cve_id, cpe_criteria, vulnerable)
           VALUES ('CVE-2021-1234', 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', 1)"""
    )
    conn.commit()
    return conn


def test_correlate_filters_linux_cve_for_windows_host(db):
    services = [{
        "host": "192.168.1.1", "port": 80, "protocol": "tcp",
        "service": "http", "product": "nginx", "version": "",
        "nse_results": {}, "os_family": "Windows",
    }]
    findings = correlate(db, services, os_hint="Windows")
    assert not any(f["cve_id"] == "CVE-2021-1234" for f in findings)


def test_correlate_no_os_hint_returns_all(db):
    services = [{
        "host": "192.168.1.1", "port": 80, "protocol": "tcp",
        "service": "http", "product": "nginx", "version": "",
        "nse_results": {}, "os_family": "",
    }]
    findings = correlate(db, services)
    assert any(f["cve_id"] == "CVE-2021-1234" for f in findings)
