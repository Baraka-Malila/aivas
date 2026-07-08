import asyncio
import sqlite3
from unittest.mock import patch, MagicMock

import pytest

from aivas.database.schema import create_schema
from aivas.server.cve_advice import (
    get_advice, put_advice, generate_advice, warm_cache,
)


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


def test_get_advice_returns_none_when_missing(conn):
    assert get_advice(conn, "CVE-X") is None


def test_put_then_get_roundtrip(conn):
    put_advice(conn, "CVE-1", "en text", "sw text", "test-model")
    row = get_advice(conn, "CVE-1")
    assert row["advice_en"] == "en text"
    assert row["advice_sw"] == "sw text"
    assert row["model"] == "test-model"


def test_put_advice_upserts_existing(conn):
    put_advice(conn, "CVE-1", "old", "old", "m1")
    put_advice(conn, "CVE-1", "new", "new", "m2")
    row = get_advice(conn, "CVE-1")
    assert row["advice_en"] == "new"
    assert row["model"] == "m2"


def test_generate_advice_parses_two_paragraph_response():
    fake_provider = MagicMock()
    fake_provider.generate.return_value = (
        "Update Apache to 2.4.50 or later. Block port externally.\n\n"
        "Sasisha Apache hadi 2.4.50. Zuia port nje."
    )
    cve_row = {
        "cve_id": "CVE-2021-41773",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "description": "Path traversal in Apache 2.4.49",
    }
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        en, sw = asyncio.run(generate_advice("CVE-2021-41773", cve_row, "key"))
    assert "Apache" in en
    assert "Sasisha" in sw or "Apache" in sw


def test_generate_advice_handles_single_paragraph_response():
    fake_provider = MagicMock()
    fake_provider.generate.return_value = "Only English here."
    cve_row = {
        "cve_id": "CVE-X", "cvss_score": 5, "cvss_severity": "MEDIUM",
        "description": "Something",
    }
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        en, sw = asyncio.run(generate_advice("CVE-X", cve_row, "key"))
    assert en == "Only English here."
    assert sw == ""


def test_warm_cache_skips_existing(conn):
    put_advice(conn, "CVE-A", "en", "sw", "cached-model")
    fake_provider = MagicMock()
    fake_provider.generate.return_value = "new en\n\nnew sw"
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-A','x')")
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-B','y')")
    conn.commit()
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        asyncio.run(warm_cache(conn, ["CVE-A", "CVE-B"], "key"))
    # CVE-A still has cached values
    assert get_advice(conn, "CVE-A")["advice_en"] == "en"
    # CVE-B got generated
    assert get_advice(conn, "CVE-B")["advice_en"] == "new en"


def test_warm_cache_silently_skips_unknown_cves(conn):
    fake_provider = MagicMock()
    fake_provider.generate.return_value = "x\n\ny"
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        # CVE-MISSING has no row in cves table — must not crash
        asyncio.run(warm_cache(conn, ["CVE-MISSING"], "key"))
    assert get_advice(conn, "CVE-MISSING") is None


def test_warm_cache_handles_provider_errors(conn):
    fake_provider = MagicMock()
    fake_provider.generate.side_effect = RuntimeError("Groq down")
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-Z','x')")
    conn.commit()
    with patch("aivas.server.cve_advice.GroqProvider", return_value=fake_provider):
        # must not raise
        asyncio.run(warm_cache(conn, ["CVE-Z"], "key"))
    assert get_advice(conn, "CVE-Z") is None


def test_warm_cache_no_api_key_is_noop(conn):
    conn.execute("INSERT INTO cves(cve_id, description) VALUES('CVE-Y','x')")
    conn.commit()
    asyncio.run(warm_cache(conn, ["CVE-Y"], ""))
    assert get_advice(conn, "CVE-Y") is None
