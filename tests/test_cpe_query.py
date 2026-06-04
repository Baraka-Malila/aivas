import pytest
from aivas.database.nvd_ingest import parse_cve_data, insert_cve
from aivas.database.cpe_query import normalize_product, find_cves


# ── normalize_product ────────────────────────────────────────────────

def test_normalize_apache():
    assert normalize_product("Apache httpd") == "apache:http_server"


def test_normalize_nginx():
    assert normalize_product("nginx") == "nginx:nginx"


def test_normalize_openssh():
    assert normalize_product("OpenSSH") == "openbsd:openssh"
    assert normalize_product("OpenSSH for Windows") == "openbsd:openssh"


def test_normalize_mysql():
    assert normalize_product("MySQL") == "mysql:mysql"


def test_normalize_case_insensitive():
    assert normalize_product("APACHE HTTPD") == "apache:http_server"


def test_normalize_unknown_returns_none():
    assert normalize_product("SomeObscureProduct 99") is None


# ── find_cves: exact version match ───────────────────────────────────

def test_find_cves_exact_version_match(db, sample_cve_data):
    insert_cve(db, parse_cve_data(sample_cve_data))

    results = find_cves(db, "Apache httpd", "2.4.49")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2021-41773"
    assert results[0]["confidence"] == "probable"
    assert results[0]["cvss_score"] == 9.8


def test_find_cves_no_match_patched_version(db, sample_cve_data):
    insert_cve(db, parse_cve_data(sample_cve_data))

    results = find_cves(db, "Apache httpd", "2.4.51")
    assert results == []


def test_find_cves_no_match_older_version(db, sample_cve_data):
    insert_cve(db, parse_cve_data(sample_cve_data))

    results = find_cves(db, "Apache httpd", "2.4.48")
    assert results == []


# ── find_cves: version range (not exact) ─────────────────────────────

def test_find_cves_version_in_range(db, sample_cve_range_data):
    insert_cve(db, parse_cve_data(sample_cve_range_data))

    results = find_cves(db, "OpenSSH", "7.4")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2018-15473"


def test_find_cves_version_at_range_boundary(db, sample_cve_range_data):
    insert_cve(db, parse_cve_data(sample_cve_range_data))

    results = find_cves(db, "OpenSSH", "7.7")
    assert len(results) == 1  # versionEndIncluding=7.7, so 7.7 is affected


def test_find_cves_version_above_range(db, sample_cve_range_data):
    insert_cve(db, parse_cve_data(sample_cve_range_data))

    results = find_cves(db, "OpenSSH", "7.8")
    assert results == []


# ── find_cves: no version info ────────────────────────────────────────

def test_find_cves_no_version_returns_possible(db, sample_cve_data):
    insert_cve(db, parse_cve_data(sample_cve_data))

    results = find_cves(db, "Apache httpd", None)
    assert len(results) >= 1
    assert all(r["confidence"] == "possible" for r in results)


# ── find_cves: unknown product ────────────────────────────────────────

def test_find_cves_unknown_product_returns_empty(db):
    results = find_cves(db, "SomeUnknownProduct", "1.0.0")
    assert results == []


# ── find_cves: sorted by CVSS score ──────────────────────────────────

def test_find_cves_sorted_by_cvss_descending(db, sample_cve_data, sample_cve_range_data):
    # Insert two CVEs for the same product with different CVSS scores
    low_cve = {
        "id": "CVE-2021-00001",
        "descriptions": [{"lang": "en", "value": "Low severity apache issue."}],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "baseScore": 3.1,
                    "baseSeverity": "LOW",
                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    "attackVector": "NETWORK",
                }
            }]
        },
        "weaknesses": [],
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.4.49",
                    "versionEndIncluding": "2.4.49",
                }]
            }]
        }]
    }
    insert_cve(db, parse_cve_data(sample_cve_data))
    insert_cve(db, parse_cve_data(low_cve))

    results = find_cves(db, "Apache httpd", "2.4.49")
    assert results[0]["cvss_score"] >= results[-1]["cvss_score"]
