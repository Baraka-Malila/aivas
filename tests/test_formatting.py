from rich.table import Table
from aivas.formatting import cve_table, SEVERITY_COLORS


def test_severity_colors_keys():
    assert set(SEVERITY_COLORS.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_cve_table_returns_rich_table():
    rows = [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
             "cvss_severity": "CRITICAL", "confidence": "probable",
             "description": "Path traversal in Apache"}]
    t = cve_table("Test Title", rows)
    assert isinstance(t, Table)


def test_cve_table_title():
    t = cve_table("My Title", [])
    assert t.title == "My Title"


def test_cve_table_has_five_columns():
    t = cve_table("X", [])
    assert len(t.columns) == 5


def test_cve_table_description_truncated():
    long_desc = "A" * 300
    rows = [{"cve_id": "CVE-0000-0001", "cvss_score": 5.0,
             "cvss_severity": "MEDIUM", "confidence": "possible",
             "description": long_desc}]
    t = cve_table("T", rows, desc_max=60)
    cell = t.columns[4]._cells[0]
    assert len(cell) <= 120


def test_cve_table_none_score_shows_na():
    rows = [{"cve_id": "CVE-1999-0001", "cvss_score": None,
             "cvss_severity": None, "confidence": "possible",
             "description": "test"}]
    t = cve_table("T", rows)
    score_cell = t.columns[1]._cells[0]
    assert score_cell == "N/A"
