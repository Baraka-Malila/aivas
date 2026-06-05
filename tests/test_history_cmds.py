from unittest.mock import patch
from click.testing import CliRunner
from aivas.cli import cli
from aivas.history import save_scan


def test_history_empty(db):
    runner = CliRunner()
    result = runner.invoke(cli, ["history"], obj={"conn": db})
    assert result.exit_code == 0
    assert "No scans" in result.output


def test_history_shows_saved_scan(db):
    findings = [{"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                 "cvss_severity": "CRITICAL", "confidence": "probable",
                 "host": "10.0.0.1"}]
    save_scan(db, "10.0.0.0/24", findings)
    runner = CliRunner()
    result = runner.invoke(cli, ["history"], obj={"conn": db})
    assert result.exit_code == 0
    assert "10.0.0.0/24" in result.output
    assert "Grade" in result.output


def test_diff_shows_new_and_fixed(db):
    findings_a = [{"cve_id": "CVE-A", "cvss_score": 9.0, "cvss_severity": "CRITICAL",
                   "confidence": "probable", "host": "10.0.0.1"}]
    findings_b = [{"cve_id": "CVE-B", "cvss_score": 7.5, "cvss_severity": "HIGH",
                   "confidence": "probable", "host": "10.0.0.1"}]
    id1 = save_scan(db, "target", findings_a)
    id2 = save_scan(db, "target", findings_b)
    runner = CliRunner()
    result = runner.invoke(cli, ["diff", str(id1), str(id2)], obj={"conn": db})
    assert result.exit_code == 0
    assert "CVE-B" in result.output
    assert "CVE-A" in result.output


def test_scan_save_flag_persists_to_db(tmp_path):
    MINIMAL_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(MINIMAL_XML)

    fake_finding = {"cve_id": "CVE-2021-41773", "cvss_score": 9.8,
                    "cvss_severity": "CRITICAL", "description": "test",
                    "confidence": "probable", "host": "192.168.1.10"}

    db_path = tmp_path / "test.db"
    with patch("aivas.commands.scan_cmd.correlate", return_value=[fake_finding]):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["--db", str(db_path), "scan", "--import", str(xml_file), "--save"],
        )
    assert result.exit_code == 0
    assert "Scan saved as #" in result.output
