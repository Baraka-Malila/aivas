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


from io import StringIO
from rich.console import Console
from aivas.formatting import print_narrations, print_score


def _cap(fn, *args):
    buf = StringIO()
    c = Console(file=buf, highlight=False, markup=False)
    fn(*args, console=c)
    return buf.getvalue()


def test_print_narrations_outputs_cve_and_narration():
    findings = [
        {
            "cve_id": "CVE-2021-41773",
            "cvss_score": 9.8,
            "narration_en": "Critical path traversal.",
            "narration_sw": "Njia ya hatari.",
            "fix_en": "Update Apache.",
            "fix_sw": "Sasisha Apache.",
        }
    ]
    out = _cap(print_narrations, findings)
    assert "CVE-2021-41773" in out
    assert "Critical path traversal." in out
    assert "Njia ya hatari." in out
    assert "Update Apache." in out


def test_print_score_shows_score_and_grade():
    findings = [{"cvss_severity": "CRITICAL", "confidence": "confirmed"}]
    out = _cap(print_score, findings)
    assert "/100" in out
    assert "Grade" in out


def test_print_score_empty_is_100():
    out = _cap(print_score, [])
    assert "100" in out
    assert "Grade A" in out


def test_print_narrations_lang_en_only():
    findings = [{"cve_id": "CVE-X", "cvss_score": 5.0,
                 "narration_en": "English risk.", "narration_sw": "Hatari."}]
    out = _cap(print_narrations, findings, "en")
    assert "English risk." in out
    assert "Hatari." not in out


def test_print_narrations_lang_sw_only():
    findings = [{"cve_id": "CVE-X", "cvss_score": 5.0,
                 "narration_en": "English risk.", "narration_sw": "Hatari."}]
    out = _cap(print_narrations, findings, "sw")
    assert "Hatari." in out
    assert "English risk." not in out


def test_print_narrations_lang_both_shows_all():
    findings = [{"cve_id": "CVE-X", "cvss_score": 5.0,
                 "narration_en": "English risk.", "narration_sw": "Hatari."}]
    out = _cap(print_narrations, findings, "both")
    assert "English risk." in out
    assert "Hatari." in out
