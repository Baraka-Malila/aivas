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
    with patch("aivas.server.scan_worker._run_nmap",
               side_effect=RuntimeError("nmap not found")):
        events = asyncio.run(_collect(run_scan(conn, "192.168.1.1")))
    assert events[-1]["type"] == "error"
    assert "nmap not found" in events[-1]["text"]


def test_run_scan_no_open_ports(conn):
    with patch("aivas.server.scan_worker._run_nmap", return_value="<nmaprun/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[]):
            events = asyncio.run(_collect(run_scan(conn, "192.168.1.99")))
    assert events[-1]["type"] == "error"
    assert "no open ports" in events[-1]["text"]


def test_run_scan_done_event_shape(conn):
    fake_service = {"host": "192.168.1.1", "port": 80, "service": "http",
                    "product": "apache", "version": "2.4", "os_family": None}
    with patch("aivas.server.scan_worker._run_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_worker.correlate", return_value=[]):
                events = asyncio.run(_collect(run_scan(conn, "192.168.1.1")))
    done = events[-1]
    assert done["type"] == "done"
    assert done["target"] == "192.168.1.1"
    assert done["grade"] == "A"
    assert done["score"] == 100
    assert done["service_count"] == 1
    assert isinstance(done["findings"], list)
    assert isinstance(done["scan_id"], int)


def test_run_scan_emits_progress_events(conn):
    fake_service = {"host": "192.168.1.1", "port": 22, "service": "ssh",
                    "product": "openssh", "version": "7.4", "os_family": None}
    with patch("aivas.server.scan_worker._run_nmap", return_value="<xml/>"):
        with patch("aivas.server.scan_worker.parse_nmap_xml", return_value=[fake_service]):
            with patch("aivas.server.scan_worker.correlate", return_value=[]):
                events = asyncio.run(_collect(run_scan(conn, "192.168.1.1")))
    progress = [e for e in events if e["type"] == "progress"]
    assert len(progress) >= 2
