from pathlib import Path
import pytest
from aivas.reporter import generate_report

SAMPLE_FINDINGS = [
    {
        "cve_id": "CVE-2021-41773",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "confidence": "probable",
        "description": "Path traversal in Apache 2.4.49.",
        "host": "192.168.1.10",
    },
    {
        "cve_id": "CVE-2018-15473",
        "cvss_score": 5.3,
        "cvss_severity": "MEDIUM",
        "confidence": "probable",
        "description": "OpenSSH user enumeration.",
        "host": "192.168.1.10",
        "narration_en": "Low-severity info leak.",
        "narration_sw": "Uvujaji wa taarifa.",
    },
]


def test_generate_report_creates_html_file(tmp_path):
    out = tmp_path / "report.html"
    generate_report(SAMPLE_FINDINGS, out)
    assert out.exists()
    assert out.stat().st_size > 0


def test_html_report_contains_cve_ids(tmp_path):
    out = tmp_path / "report.html"
    generate_report(SAMPLE_FINDINGS, out)
    content = out.read_text()
    assert "CVE-2021-41773" in content
    assert "CVE-2018-15473" in content


def test_html_report_contains_narrations(tmp_path):
    out = tmp_path / "report.html"
    generate_report(SAMPLE_FINDINGS, out)
    content = out.read_text()
    assert "Low-severity info leak." in content
    assert "Uvujaji wa taarifa." in content


def test_html_report_contains_custom_title(tmp_path):
    out = tmp_path / "report.html"
    generate_report(SAMPLE_FINDINGS, out, meta={"title": "My Custom Report"})
    content = out.read_text()
    assert "My Custom Report" in content


def test_generate_report_accepts_string_path(tmp_path):
    out = str(tmp_path / "report.html")
    generate_report(SAMPLE_FINDINGS, out)
    assert Path(out).exists()


def test_generate_report_empty_findings(tmp_path):
    out = tmp_path / "empty.html"
    generate_report([], out)
    assert out.exists()
    content = out.read_text()
    assert "No vulnerabilities" in content or "0" in content
