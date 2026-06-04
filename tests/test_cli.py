import sqlite3
import pytest
from click.testing import CliRunner
from aivas.cli import cli
from aivas.database.schema import create_schema
from aivas.database.nvd_ingest import parse_cve_data, insert_cve


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def populated_db(tmp_path, sample_cve_data, sample_cve_range_data):
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    create_schema(conn)
    insert_cve(conn, parse_cve_data(sample_cve_data))
    insert_cve(conn, parse_cve_data(sample_cve_range_data))
    conn.close()
    return db_path


def test_search_finds_apache_cve(runner, populated_db):
    result = runner.invoke(cli, [
        "--db", str(populated_db),
        "search", "Apache httpd", "--version", "2.4.49"
    ])
    assert result.exit_code == 0
    assert "CVE-2021-41773" in result.output
    assert "9.8" in result.output


def test_search_no_results_message(runner, populated_db):
    result = runner.invoke(cli, [
        "--db", str(populated_db),
        "search", "Apache httpd", "--version", "2.4.99"
    ])
    assert result.exit_code == 0
    assert "No CVEs found" in result.output


def test_search_unknown_product(runner, populated_db):
    result = runner.invoke(cli, [
        "--db", str(populated_db),
        "search", "ObscureProduct123"
    ])
    assert result.exit_code == 0
    assert "No CVEs found" in result.output or "not recognized" in result.output.lower()


def test_search_without_version_shows_possible(runner, populated_db):
    result = runner.invoke(cli, [
        "--db", str(populated_db),
        "search", "Apache httpd"
    ])
    assert result.exit_code == 0
    assert "CVE-2021-41773" in result.output
    assert "possible" in result.output.lower()


def test_update_db_bulk_from_feeds(runner, tmp_path, sample_cve_data):
    import json
    db_path = tmp_path / "test.db"
    feeds_dir = tmp_path / "feeds"
    year_dir = feeds_dir / "CVE-2021" / "CVE-2021-41xxx"
    year_dir.mkdir(parents=True)
    (year_dir / "CVE-2021-41773.json").write_text(json.dumps(sample_cve_data))

    result = runner.invoke(cli, [
        "--db", str(db_path),
        "update-db", "--source", str(feeds_dir)
    ])
    assert result.exit_code == 0
    assert "1" in result.output  # "Ingested 1 CVEs" or similar
