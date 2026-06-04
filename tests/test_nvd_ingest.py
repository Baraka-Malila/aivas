import json
import pytest
from pathlib import Path
from aivas.database.nvd_ingest import parse_cve_data, insert_cve, ingest_feeds


def test_parse_extracts_cve_id(sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    assert record["cve_id"] == "CVE-2021-41773"


def test_parse_extracts_english_description(sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    assert "path traversal" in record["description"].lower()


def test_parse_extracts_cvss_v31(sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    assert record["cvss_score"] == 9.8
    assert record["cvss_severity"] == "CRITICAL"
    assert record["attack_vector"] == "NETWORK"
    assert record["cvss_vector"].startswith("CVSS:3.1")


def test_parse_extracts_cwe(sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    assert record["cwe_id"] == "CWE-22"


def test_parse_extracts_cpe_matches(sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    assert len(record["cpe_matches"]) == 1
    cpe = record["cpe_matches"][0]
    assert "apache:http_server" in cpe["cpe_criteria"]
    assert cpe["version_start_incl"] == "2.4.49"
    assert cpe["version_end_incl"] == "2.4.49"
    assert cpe["vulnerable"] == 1


def test_parse_returns_none_for_missing_id():
    assert parse_cve_data({}) is None


def test_insert_cve_saves_to_db(db, sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    insert_cve(db, record)
    row = db.execute("SELECT * FROM cves WHERE cve_id = ?", ("CVE-2021-41773",)).fetchone()
    assert row is not None
    assert row["cvss_score"] == 9.8


def test_insert_cve_saves_cpe_matches(db, sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    insert_cve(db, record)
    rows = db.execute(
        "SELECT * FROM cpe_matches WHERE cve_id = ?", ("CVE-2021-41773",)
    ).fetchall()
    assert len(rows) == 1
    assert "apache:http_server" in rows[0]["cpe_criteria"]


def test_insert_cve_is_idempotent(db, sample_cve_data):
    record = parse_cve_data(sample_cve_data)
    insert_cve(db, record)
    insert_cve(db, record)  # second call must not raise or duplicate
    count = db.execute("SELECT COUNT(*) FROM cves WHERE cve_id = ?", ("CVE-2021-41773",)).fetchone()[0]
    assert count == 1


def test_ingest_feeds_processes_json_files(db, tmp_path, sample_cve_data):
    # Build a minimal nvd-json-data-feeds directory structure
    year_dir = tmp_path / "CVE-2021" / "CVE-2021-41xxx"
    year_dir.mkdir(parents=True)
    (year_dir / "CVE-2021-41773.json").write_text(json.dumps(sample_cve_data))

    count = ingest_feeds(db, tmp_path)
    assert count == 1
    row = db.execute("SELECT cve_id FROM cves WHERE cve_id = 'CVE-2021-41773'").fetchone()
    assert row is not None


def test_ingest_feeds_skips_malformed_files(db, tmp_path):
    year_dir = tmp_path / "CVE-2021" / "CVE-2021-00xxx"
    year_dir.mkdir(parents=True)
    (year_dir / "CVE-2021-00001.json").write_text("not valid json {{{")

    count = ingest_feeds(db, tmp_path)
    assert count == 0  # skipped gracefully


def test_parse_falls_back_to_cvss_v30():
    data = {
        "id": "CVE-2019-99999",
        "descriptions": [{"lang": "en", "value": "A test CVE."}],
        "metrics": {
            "cvssMetricV30": [{
                "type": "Primary",
                "cvssData": {
                    "baseScore": 7.5,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "attackVector": "NETWORK",
                }
            }]
        },
        "weaknesses": [],
        "configurations": []
    }
    record = parse_cve_data(data)
    assert record["cvss_score"] == 7.5
    assert record["cvss_severity"] == "HIGH"
