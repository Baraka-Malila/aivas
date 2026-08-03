"""Test that run_scan accepts creds and includes credential services in done event."""
import asyncio
import sqlite3
from unittest.mock import patch

import pytest

from aivas.database.schema import create_schema
from aivas.server.scan_worker import run_scan


FAKE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

CREDENTIAL_SERVICES = [
    {"host": "192.168.1.5", "port": 0, "protocol": "tcp",
     "service": "package", "product": "nginx", "version": "1.18.0",
     "nse_results": {}, "os_family": "Linux"},
]


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "test.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    yield db
    db.close()


async def _run_to_done(conn, target, creds=None):
    events = []
    async for ev in run_scan(conn, target, level=2, creds=creds):
        events.append(ev)
    return events


def test_run_scan_without_creds_skips_phase2(conn):
    with patch("aivas.server.scan_worker._async_nmap") as mock_nmap, \
         patch("aivas.server.scan_helpers.correlate", return_value=[]), \
         patch("aivas.prober.probe_http_service",
               return_value={"status": "unreachable", "findings": []}):
        mock_nmap.return_value = FAKE_NMAP_XML
        events = asyncio.run(_run_to_done(conn, "192.168.1.5"))

    done = next(e for e in events if e.get("type") == "done")
    assert done["credential_scan"] is False


def test_run_scan_with_creds_triggers_phase2(conn):
    creds = {"method": "ssh", "username": "ubuntu", "password": "pass", "port": 22}

    async def _fake_cred_events(host, creds, timeout=90):
        yield {"type": "progress", "phase": "credential_probe", "text": "  Connecting…"}
        yield {"__credential_services": CREDENTIAL_SERVICES}

    with patch("aivas.server.scan_worker._async_nmap") as mock_nmap, \
         patch("aivas.server.scan_helpers.correlate", return_value=[]), \
         patch("aivas.prober.probe_http_service",
               return_value={"status": "unreachable", "findings": []}), \
         patch("aivas.server.scan_worker.credential_scan_events",
               side_effect=_fake_cred_events):
        mock_nmap.return_value = FAKE_NMAP_XML
        events = asyncio.run(_run_to_done(conn, "192.168.1.5", creds=creds))

    done = next(e for e in events if e.get("type") == "done")
    assert done["credential_scan"] is True
