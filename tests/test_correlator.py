import pytest
from aivas.correlator import correlate
from aivas.database import insert_cve, parse_cve_data


@pytest.fixture
def db_with_cves(db, sample_cve_data, sample_cve_range_data):
    insert_cve(db, parse_cve_data(sample_cve_data))
    insert_cve(db, parse_cve_data(sample_cve_range_data))
    return db


def test_correlate_returns_list(db_with_cves):
    services = [{"host": "192.168.1.1", "port": 80, "protocol": "tcp",
                 "service": "http", "product": "Apache httpd", "version": "2.4.49",
                 "nse_results": {}}]
    findings = correlate(db_with_cves, services)
    assert isinstance(findings, list)


def test_version_match_gives_probable(db_with_cves):
    services = [{"host": "192.168.1.1", "port": 80, "protocol": "tcp",
                 "service": "http", "product": "Apache httpd", "version": "2.4.49",
                 "nse_results": {}}]
    findings = correlate(db_with_cves, services)
    cve_ids = [f["cve_id"] for f in findings]
    assert "CVE-2021-41773" in cve_ids
    apache_finding = next(f for f in findings if f["cve_id"] == "CVE-2021-41773")
    assert apache_finding["confidence"] == "probable"


def test_nse_hit_gives_confirmed(db_with_cves):
    # Insert Shellshock CVE so the correlator can retrieve it
    db_with_cves.execute(
        """INSERT OR IGNORE INTO cves (cve_id, cvss_score, cvss_severity, description)
           VALUES ('CVE-2014-6271', 9.8, 'CRITICAL', 'Shellshock bash vulnerability')"""
    )
    db_with_cves.commit()
    services = [{"host": "192.168.1.1", "port": 80, "protocol": "tcp",
                 "service": "http", "product": "Apache httpd", "version": "2.4.49",
                 "nse_results": {"http-shellshock": "VULNERABLE: Shellshock"}}]
    findings = correlate(db_with_cves, services)
    confirmed = [f for f in findings if f["confidence"] == "confirmed"]
    assert any(f["cve_id"] == "CVE-2014-6271" for f in confirmed)


def test_findings_sorted_by_cvss_desc(db_with_cves):
    services = [
        {"host": "192.168.1.1", "port": 80, "protocol": "tcp",
         "service": "http", "product": "Apache httpd", "version": "2.4.49",
         "nse_results": {}},
        {"host": "192.168.1.1", "port": 22, "protocol": "tcp",
         "service": "ssh", "product": "OpenSSH", "version": "7.4",
         "nse_results": {}},
    ]
    findings = correlate(db_with_cves, services)
    scores = [f.get("cvss_score") or 0 for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_no_duplicate_cve_ids(db_with_cves):
    services = [
        {"host": "192.168.1.1", "port": 80, "protocol": "tcp",
         "service": "http", "product": "Apache httpd", "version": "2.4.49",
         "nse_results": {}},
        {"host": "192.168.1.1", "port": 8080, "protocol": "tcp",
         "service": "http", "product": "Apache httpd", "version": "2.4.49",
         "nse_results": {}},
    ]
    findings = correlate(db_with_cves, services)
    cve_ids = [f["cve_id"] for f in findings]
    assert len(cve_ids) == len(set(cve_ids))


def test_unknown_service_returns_empty(db_with_cves):
    services = [{"host": "192.168.1.1", "port": 9999, "protocol": "tcp",
                 "service": "unknown", "product": "SomeObscureDaemon", "version": "1.0",
                 "nse_results": {}}]
    findings = correlate(db_with_cves, services)
    assert findings == []
