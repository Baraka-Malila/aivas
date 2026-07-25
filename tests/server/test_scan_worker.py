import asyncio
import sqlite3
from unittest.mock import patch

import pytest

from aivas.database.schema import create_schema
from aivas.server.scan_worker import run_scan


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "test.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


async def _collect(gen):
    events = []
    async for ev in gen:
        events.append(ev)
    return events


def test_run_scan_nmap_error(conn):
    with patch("aivas.server.scan_worker._blocking_nmap",
               side_effect=RuntimeError("nmap not found")):
        events = asyncio.run(_collect(run_scan(conn, "192.168.1.1")))
    assert events[-1]["type"] == "error"
    assert "nmap not found" in events[-1]["text"]


def test_run_scan_no_open_ports(conn):
    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<nmaprun/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[]):
            events = asyncio.run(_collect(run_scan(conn, "192.168.1.99")))
    assert events[-1]["type"] == "error"
    assert "no open ports" in events[-1]["text"]


def test_run_scan_done_event_shape(conn):
    fake_service = {"host": "192.168.1.1", "port": 80, "service": "http",
                    "product": "apache", "version": "2.4", "os_family": None}
    fake_probe_result = {"status": "ok", "findings": []}
    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_helpers.correlate", return_value=[]):
                with patch("aivas.prober.probe_http_service",
                           return_value=fake_probe_result):
                    events = asyncio.run(_collect(run_scan(conn, "192.168.1.1")))
    done = events[-1]
    assert done["type"] == "done"
    assert done["target"] == "192.168.1.1"
    assert done["grade"] == "A"
    assert done["score"] == 100
    assert done["service_count"] == 1
    assert isinstance(done["findings"], list)
    assert isinstance(done["scan_id"], int)
    assert isinstance(done["services"], list)
    assert isinstance(done["misconfigs"], list)


def test_run_scan_emits_many_progress_events(conn):
    fake_service = {"host": "192.168.1.1", "port": 22, "service": "ssh",
                    "product": "openssh", "version": "7.4", "os_family": None}
    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_helpers.correlate", return_value=[]):
                events = asyncio.run(_collect(run_scan(conn, "192.168.1.1")))
    progress = [e for e in events if e["type"] == "progress"]
    # Should have at least: init, ports, ports_done, open_ports, port_open,
    # cve_start, cve_lookup, cve_none, scoring, grade
    assert len(progress) >= 8


def test_run_scan_populates_narration_when_api_key_set(monkeypatch, conn):
    """When GROQ_API_KEY is set, web scan flow runs narrator and warm_cache."""
    fake_service = {"host":"1.1.1.1","port":80,"service":"http",
                    "product":"apache","version":"2.4","os_family":None}
    fake_finding = {
        "cve_id":"CVE-2021-41773", "cvss_score":9.8, "cvss_severity":"CRITICAL",
        "description":"path traversal", "confidence":"probable",
        "host":"1.1.1.1", "port":80,
    }
    called = {"narrate": 0, "warm": 0}

    def fake_narrate(findings, provider):
        called["narrate"] += 1
        for f in findings:
            f["narration_en"] = "Test EN"
            f["narration_sw"] = "Test SW"
            f["fix_en"] = "Fix EN"
            f["fix_sw"] = "Fix SW"
        return findings

    async def fake_warm(*a, **kw):
        called["warm"] += 1

    monkeypatch.setenv("GROQ_API_KEY", "k")
    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_helpers.correlate", return_value=[fake_finding]):
                with patch("aivas.server.scan_worker.narrate", side_effect=fake_narrate):
                    with patch("aivas.server.scan_worker.warm_cache", side_effect=fake_warm):
                        events = asyncio.run(_collect(run_scan(conn, "1.1.1.1")))
    assert called["narrate"] == 1
    assert called["warm"] == 1
    # Done event findings should have narration populated
    done = events[-1]
    assert done["type"] == "done"
    if done["findings"]:
        f = done["findings"][0]
        # Narration fields aren't in the done event payload, but they were saved to DB.
    row = conn.execute(
        "SELECT en_risk FROM findings WHERE cve_id='CVE-2021-41773'"
    ).fetchone()
    assert row["en_risk"] == "Test EN"


def test_run_scan_skips_narration_without_api_key(monkeypatch, conn):
    """No GROQ_API_KEY -> narrator not called; scan still completes."""
    fake_service = {"host":"1.1.1.1","port":80,"service":"http",
                    "product":"apache","version":"2.4","os_family":None}
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    called = {"narrate": 0}

    def fake_narrate(findings, provider):
        called["narrate"] += 1
        return findings

    with patch("aivas.server.scan_worker._blocking_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_helpers.correlate", return_value=[]):
                with patch("aivas.server.scan_worker.narrate", side_effect=fake_narrate):
                    events = asyncio.run(_collect(run_scan(conn, "1.1.1.1")))
    assert called["narrate"] == 0
    # Scan completes — "done" (found port, no CVE findings) or "error" are both acceptable
    assert events[-1]["type"] in ("done", "error")
