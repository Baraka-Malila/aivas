from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from aivas.cli import cli


MINIMAL_NMAP_XML = """<?xml version="1.0"?>
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


def test_scan_import_no_findings(tmp_path):
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(MINIMAL_NMAP_XML)
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--import", str(xml_file)])
    assert result.exit_code == 0


def test_scan_import_missing_file():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--import", "/nonexistent/file.xml"])
    assert result.exit_code != 0


def test_scan_requires_target_or_import():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])
    assert result.exit_code != 0


def test_scan_live_raises_without_nmap():
    with patch("aivas.scanner.orchestrator.shutil.which", return_value=None):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "192.168.1.0/24"])
        assert result.exit_code != 0
        assert "nmap" in result.output.lower()


def test_scan_import_shows_findings(tmp_path):
    from aivas.database import insert_cve, get_db, create_schema
    from aivas.database.nvd_ingest import parse_cve_data
    db_path = tmp_path / "test.db"
    # Use --db flag to point CLI at our temp DB
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    # Insert Apache 2.4.49 CVE
    sample = {
        "id": "CVE-2021-41773",
        "published": "2021-10-05T09:15:00.000",
        "lastModified": "2021-10-08T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "NETWORK"}}]},
        "weaknesses": [],
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.49",
            "versionEndIncluding": "2.4.49",
        }]}]}]
    }
    parsed = parse_cve_data(sample)
    parsed["cpe_matches"] = parsed.pop("cpe_matches", [])
    insert_cve(conn, parsed)
    conn.commit()
    conn.close()

    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(MINIMAL_NMAP_XML)
    runner = CliRunner()
    result = runner.invoke(cli, ["--db", str(db_path), "scan", "--import", str(xml_file)])
    assert result.exit_code == 0
    assert "CVE-2021-41773" in result.output
