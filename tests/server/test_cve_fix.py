import sqlite3

import pytest

from aivas.database.schema import create_schema
from aivas.server.report_helpers import cve_fix


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_cve_fix_prefers_stored_fix_en(conn):
    f = {"cve_id": "CVE-1", "description": "Path traversal",
         "fix_en": "Custom stored advice."}
    assert cve_fix(f, conn=conn, lang="en") == "Custom stored advice."


def test_cve_fix_prefers_stored_fix_sw(conn):
    f = {"cve_id": "CVE-1", "description": "Path traversal",
         "fix_sw": "Hatua iliyohifadhiwa."}
    assert cve_fix(f, conn=conn, lang="sw") == "Hatua iliyohifadhiwa."


def test_cve_fix_falls_back_to_cache_when_no_stored(conn):
    from aivas.server.cve_advice import put_advice
    put_advice(conn, "CVE-2", "Cached EN", "Cached SW", "m")
    f = {"cve_id": "CVE-2", "description": "Path traversal"}
    assert cve_fix(f, conn=conn, lang="en") == "Cached EN"
    assert cve_fix(f, conn=conn, lang="sw") == "Cached SW"


def test_cve_fix_falls_back_to_legacy_when_no_cache(conn):
    f = {"cve_id": "CVE-3", "description": "buffer overflow"}
    result = cve_fix(f, conn=conn, lang="en")
    assert "ASLR" in result or "vendor patch" in result.lower()


def test_cve_fix_works_without_conn(conn):
    f = {"cve_id": "CVE-4", "description": "remote code execution"}
    result = cve_fix(f, conn=None, lang="en")
    assert "vendor patch" in result.lower() or "patch" in result.lower()


def test_cve_fix_default_lang_is_en(conn):
    f = {"cve_id": "CVE-5", "description": "sql injection",
         "fix_en": "EN stored", "fix_sw": "SW stored"}
    assert cve_fix(f, conn=conn) == "EN stored"
