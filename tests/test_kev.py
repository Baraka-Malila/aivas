import json
import sqlite3
from unittest.mock import patch, MagicMock

import pytest

from aivas.database.schema import create_schema
from aivas.database.kev import fetch_kev, mark_kev, sync_kev, get_kev_status


SAMPLE_KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-41773"},
        {"cveID": "CVE-2021-42013"},
        {"cveID": "CVE-2014-9999"},  # not in DB
    ]
}


@pytest.fixture()
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    create_schema(c)
    c.execute(
        "INSERT INTO cves (cve_id, description, cvss_score) VALUES (?,?,?)",
        ("CVE-2021-41773", "Path traversal", 9.8),
    )
    c.execute(
        "INSERT INTO cves (cve_id, description, cvss_score) VALUES (?,?,?)",
        ("CVE-2021-42013", "Path traversal followup", 9.8),
    )
    c.commit()
    return c


def _mock_urlopen(url, timeout=None):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(SAMPLE_KEV).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def test_fetch_kev_returns_cve_ids():
    with patch("aivas.database.kev.urllib.request.urlopen", side_effect=_mock_urlopen):
        ids = fetch_kev("http://fake/kev.json")
    assert "CVE-2021-41773" in ids
    assert "CVE-2021-42013" in ids
    assert len(ids) == 3


def test_mark_kev_updates_known_cves(conn):
    marked = mark_kev(conn, ["CVE-2021-41773", "CVE-2021-42013", "CVE-2014-9999"])
    assert marked == 2  # only the 2 that exist in DB
    rows = conn.execute("SELECT cve_id FROM cves WHERE kev = 1").fetchall()
    ids = {r["cve_id"] for r in rows}
    assert ids == {"CVE-2021-41773", "CVE-2021-42013"}


def test_sync_kev_marks_and_stores_timestamp(conn):
    with patch("aivas.database.kev.urllib.request.urlopen", side_effect=_mock_urlopen):
        count = sync_kev(conn, url="http://fake/kev.json")
    assert count == 2
    status = get_kev_status(conn)
    assert status["count"] == 2
    assert status["last_updated"] is not None


def test_get_kev_status_empty(conn):
    status = get_kev_status(conn)
    assert status["count"] == 0
    assert status["last_updated"] is None


def test_sync_kev_idempotent(conn):
    with patch("aivas.database.kev.urllib.request.urlopen", side_effect=_mock_urlopen):
        sync_kev(conn, url="http://fake/kev.json")
        count2 = sync_kev(conn, url="http://fake/kev.json")
    assert count2 == 2
    status = get_kev_status(conn)
    assert status["count"] == 2
