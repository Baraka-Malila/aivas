from unittest.mock import patch
from click.testing import CliRunner
from aivas.cli import cli


def test_report_cmd_generates_report(tmp_path):
    report_out = tmp_path / "out.html"
    fake_findings = [
        {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
         "confidence": "probable", "host": "10.0.0.1",
         "narration_en": "Risk.", "narration_sw": "Hatari.",
         "fix_en": "Patch.", "fix_sw": "Rekebisha.", "description": ""},
    ]
    with patch("aivas.commands.report_cmd.get_scan_findings", return_value=fake_findings), \
         patch("aivas.commands.report_cmd.list_scans",
               return_value=[{"id": 1, "target": "10.0.0.1", "started_at": "2026-01-01",
                               "report_path": None, "grade": "Grade B", "risk_score": 83}]):
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--scan", "1", "--output", str(report_out)])
    assert result.exit_code == 0
    assert report_out.exists()


def test_report_cmd_scan_not_found(tmp_path):
    report_out = tmp_path / "out.html"
    with patch("aivas.commands.report_cmd.list_scans", return_value=[]):
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--scan", "999", "--output", str(report_out)])
    assert result.exit_code != 0


def test_report_cmd_requires_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["report", "--scan", "1"])
    assert result.exit_code != 0
