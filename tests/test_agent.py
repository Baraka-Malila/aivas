"""Tests for agent.py tool executor."""
import asyncio
import json
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aivas.database.schema import create_schema


@pytest.fixture
def conn(tmp_path):
    db = sqlite3.connect(str(tmp_path / "t.db"), check_same_thread=False)
    db.row_factory = sqlite3.Row
    create_schema(db)
    return db


NMAP_XML_WITH_MAC = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme Corp"/>
    <hostnames><hostname name="device.local" type="PTR"/></hostnames>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.6" addrtype="ipv4"/>
  </host>
</nmaprun>"""

NMAP_XML_NO_MAC = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
  </host>
</nmaprun>"""


def _mock_proc(stdout: bytes):
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout, b""))
    return proc


def test_discover_hosts_returns_up_devices(conn):
    """Only 'up' hosts are returned; down hosts are filtered out."""
    from aivas.tui.agent import _exec_tool

    with patch("asyncio.create_subprocess_exec", return_value=_mock_proc(NMAP_XML_WITH_MAC)):
        result_json, intent = asyncio.run(
            _exec_tool("discover_hosts", {"target": "192.168.1.0/24"}, conn)
        )

    result = json.loads(result_json)
    assert result["count"] == 1
    assert result["devices"][0]["ip"] == "192.168.1.5"
    assert result["devices"][0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert result["devices"][0]["vendor"] == "Acme Corp"
    assert result["devices"][0]["hostname"] == "device.local"
    assert intent is None


def test_discover_hosts_notes_missing_mac(conn):
    """When no device has a MAC, note field mentions cap_net_raw."""
    from aivas.tui.agent import _exec_tool

    with patch("asyncio.create_subprocess_exec", return_value=_mock_proc(NMAP_XML_NO_MAC)):
        result_json, _ = asyncio.run(
            _exec_tool("discover_hosts", {"target": "10.0.0.0/24"}, conn)
        )

    result = json.loads(result_json)
    assert result["count"] == 1
    assert "cap_net_raw" in result["note"]


def test_discover_hosts_requires_target(conn):
    """Missing target returns error JSON."""
    from aivas.tui.agent import _exec_tool

    result_json, intent = asyncio.run(
        _exec_tool("discover_hosts", {}, conn)
    )
    result = json.loads(result_json)
    assert "error" in result
    assert intent is None


def test_get_findings_returns_up_to_50(conn):
    """get_findings cap is 50 (was 15)."""
    from aivas.tui.agent import _exec_tool
    from aivas.history import save_scan

    findings = [
        {"cve_id": f"CVE-2021-{i:05d}", "cvss_score": 5.0,
         "cvss_severity": "MEDIUM", "confidence": "probable", "host": "1.2.3.4"}
        for i in range(60)
    ]
    save_scan(conn, "1.2.3.4", findings)

    result_json, _ = asyncio.run(_exec_tool("get_findings", {"scan_id": "1"}, conn))
    result = json.loads(result_json)
    assert len(result) == 50


def test_get_last_scan_returns_up_to_25(conn):
    """get_last_scan findings cap is 25 (was 10)."""
    from aivas.tui.agent import _exec_tool
    from aivas.history import save_scan

    findings = [
        {"cve_id": f"CVE-2021-{i:05d}", "cvss_score": 5.0,
         "cvss_severity": "MEDIUM", "confidence": "probable", "host": "1.2.3.4"}
        for i in range(30)
    ]
    save_scan(conn, "1.2.3.4", findings)

    result_json, _ = asyncio.run(_exec_tool("get_last_scan", {}, conn))
    result = json.loads(result_json)
    assert len(result["findings"]) == 25


def test_discover_hosts_schema_present():
    """discover_hosts schema exists in TOOLS list."""
    from aivas.tui.agent_prompts import TOOLS
    names = [t["function"]["name"] for t in TOOLS]
    assert "discover_hosts" in names


def test_system_prompt_has_routing_rule():
    """SYSTEM prompt contains ROUTING RULE for discover_hosts."""
    from aivas.tui.agent_prompts import SYSTEM
    assert "ROUTING RULE" in SYSTEM
    assert "discover_hosts" in SYSTEM


def test_system_prompt_has_honesty_rule():
    """SYSTEM prompt contains HONESTY RULE requiring get_findings before summaries."""
    from aivas.tui.agent_prompts import SYSTEM
    assert "HONESTY RULE" in SYSTEM
    assert "get_findings" in SYSTEM
