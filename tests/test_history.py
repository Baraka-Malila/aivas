import pytest
from aivas.history import save_scan, list_scans, diff_scans

FINDINGS_A = [
    {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
     "confidence": "probable", "host": "192.168.1.10",
     "narration_en": "Critical risk.", "narration_sw": "Hatari kubwa."},
    {"cve_id": "CVE-2018-15473", "cvss_score": 5.3, "cvss_severity": "MEDIUM",
     "confidence": "probable", "host": "192.168.1.10"},
]

FINDINGS_B = [
    {"cve_id": "CVE-2018-15473", "cvss_score": 5.3, "cvss_severity": "MEDIUM",
     "confidence": "probable", "host": "192.168.1.10"},
    {"cve_id": "CVE-2017-0144", "cvss_score": 8.1, "cvss_severity": "HIGH",
     "confidence": "confirmed", "host": "192.168.1.10"},
]


def test_save_scan_returns_int(db):
    scan_id = save_scan(db, "192.168.1.0/24", FINDINGS_A)
    assert isinstance(scan_id, int) and scan_id > 0


def test_save_scan_inserts_findings_rows(db):
    scan_id = save_scan(db, "192.168.1.0/24", FINDINGS_A)
    count = db.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    assert count == 2


def test_save_scan_grade_critical(db):
    scan_id = save_scan(db, "target", FINDINGS_A)
    row = db.execute(
        "SELECT grade, risk_score FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    assert row["grade"] == "Grade B"
    assert row["risk_score"] > 0


def test_save_scan_empty_findings_grade_pass(db):
    scan_id = save_scan(db, "target", [])
    row = db.execute(
        "SELECT grade, finding_count FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    assert row["grade"] == "Grade A"
    assert row["finding_count"] == 0


def test_list_scans_newest_first(db):
    save_scan(db, "192.168.1.0/24", FINDINGS_A)
    save_scan(db, "10.0.0.0/8", [])
    scans = list_scans(db)
    assert scans[0]["target"] == "10.0.0.0/8"


def test_diff_scans_new_fixed_common(db):
    id1 = save_scan(db, "target", FINDINGS_A)
    id2 = save_scan(db, "target", FINDINGS_B)
    result = diff_scans(db, id1, id2)
    assert result["new"] == ["CVE-2017-0144"]
    assert result["fixed"] == ["CVE-2021-41773"]
    assert result["common"] == ["CVE-2018-15473"]


def test_save_scan_stores_fix_fields(db):
    findings = [{
        "cve_id": "CVE-2021-41773", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
        "confidence": "probable", "host": "192.168.1.10",
        "narration_en": "Critical.", "narration_sw": "Hatari.",
        "fix_en": "Patch Apache.", "fix_sw": "Rekebisha Apache.",
    }]
    scan_id = save_scan(db, "target", findings)
    row = db.execute(
        "SELECT en_fix, sw_fix FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    assert row["en_fix"] == "Patch Apache."
    assert row["sw_fix"] == "Rekebisha Apache."


def test_get_scan_findings_returns_findings(db):
    from aivas.history import get_scan_findings
    findings = [
        {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
         "confidence": "probable", "host": "192.168.1.10",
         "narration_en": "Critical risk.", "narration_sw": "Hatari.",
         "fix_en": "Patch it.", "fix_sw": "Rekebisha."},
    ]
    scan_id = save_scan(db, "target", findings)
    result = get_scan_findings(db, scan_id)
    assert len(result) == 1
    assert result[0]["cve_id"] == "CVE-2021-41773"
    assert result[0]["cvss_score"] == 9.8
    assert result[0]["narration_en"] == "Critical risk."
    assert result[0]["fix_en"] == "Patch it."


def test_get_scan_findings_empty_scan(db):
    from aivas.history import get_scan_findings
    scan_id = save_scan(db, "target", [])
    result = get_scan_findings(db, scan_id)
    assert result == []
