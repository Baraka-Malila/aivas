import sqlite3

import pytest

from aivas.database.schema import create_schema
from aivas.server.report_helpers import executive_summary
from aivas.history import list_scans


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_executive_summary_no_kev_no_warning():
    findings = [
        {"cve_id": "CVE-1", "cvss_severity": "HIGH", "kev": False},
    ]
    text = executive_summary("B", 80, "1.1.1.1", findings)
    assert "known exploited" not in text.lower()


def test_executive_summary_kev_prepends_warning():
    findings = [
        {"cve_id": "CVE-1", "cvss_severity": "CRITICAL", "kev": True},
    ]
    text = executive_summary("C", 75, "1.1.1.1", findings)
    # Order matters — KEV sentence must come first
    assert text.lower().index("known exploited") < text.lower().index("risk score")


def test_executive_summary_kev_uses_plural_for_multiple():
    findings = [
        {"cve_id": "CVE-1", "cvss_severity": "CRITICAL", "kev": True},
        {"cve_id": "CVE-2", "cvss_severity": "HIGH", "kev": True},
    ]
    text = executive_summary("C", 70, "1.1.1.1", findings)
    assert "2 actively-exploited" in text or "2 known-exploited" in text


def test_list_scans_returns_kev_count(conn):
    # Insert a scan + findings, one KEV
    conn.execute(
        "INSERT INTO scans(id, target, started_at) VALUES (1, 'host', '2026-06-30')"
    )
    # Insert two CVEs (one KEV) and findings linking them
    conn.execute("INSERT INTO cves(cve_id, description, kev) VALUES('CVE-A','x',1)")
    conn.execute("INSERT INTO cves(cve_id, description, kev) VALUES('CVE-B','y',0)")
    conn.execute(
        "INSERT INTO findings(scan_id, host, cve_id) VALUES (1,'host','CVE-A')"
    )
    conn.execute(
        "INSERT INTO findings(scan_id, host, cve_id) VALUES (1,'host','CVE-B')"
    )
    conn.commit()
    scans = list_scans(conn, limit=5)
    assert scans[0]["kev_count"] == 1


def test_list_scans_kev_count_zero_when_no_kev(conn):
    conn.execute(
        "INSERT INTO scans(id, target, started_at) VALUES (1, 'host', '2026-06-30')"
    )
    conn.execute("INSERT INTO cves(cve_id, description, kev) VALUES('CVE-B','y',0)")
    conn.execute(
        "INSERT INTO findings(scan_id, host, cve_id) VALUES (1,'host','CVE-B')"
    )
    conn.commit()
    assert list_scans(conn, limit=5)[0]["kev_count"] == 0
