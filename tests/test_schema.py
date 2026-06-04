import sqlite3
from aivas.database.schema import create_schema, get_db


def test_create_schema_makes_all_tables(db):
    tables = {
        r["name"]
        for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"cves", "cpe_matches", "scans", "findings", "sync_meta"}.issubset(tables)


def test_create_schema_is_idempotent(db):
    create_schema(db)  # second call must not raise
    tables = {
        r["name"]
        for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "cves" in tables


def test_cves_table_columns(db):
    cols = {
        r["name"]
        for r in db.execute("PRAGMA table_info(cves)").fetchall()
    }
    expected = {
        "cve_id", "description", "published", "last_modified",
        "vuln_status", "cvss_score", "cvss_severity", "cvss_vector",
        "attack_vector", "cwe_id",
    }
    assert expected.issubset(cols)


def test_cpe_matches_table_columns(db):
    cols = {
        r["name"]
        for r in db.execute("PRAGMA table_info(cpe_matches)").fetchall()
    }
    expected = {
        "id", "cve_id", "cpe_criteria", "version_start_incl",
        "version_start_excl", "version_end_incl", "version_end_excl", "vulnerable",
    }
    assert expected.issubset(cols)


def test_get_db_creates_file(tmp_path):
    db_path = tmp_path / "mytest.db"
    conn = get_db(db_path)
    assert db_path.exists()
    conn.close()
