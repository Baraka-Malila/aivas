"""Tests for UDP device discovery via nmap NSE (mDNS/SSDP)."""
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from aivas.scanner.udp_discover import udp_device_info

_UPNP_XML = b"""<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="1900">
        <state state="open|filtered"/>
        <script id="upnp-info" output="friendlyName: Samsung TV&#10;  manufacturer: Samsung"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

_DNS_XML = b"""<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="5353">
        <state state="open|filtered"/>
        <script id="dns-service-discovery" output="_workstation._tcp&#10;  Name: Baraka-MacBook"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def _make_proc(returncode: int, stdout: bytes, stderr: bytes = b"") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.kill = MagicMock()
    proc.wait = AsyncMock()
    return proc


def test_upnp_friendly_name_extracted():
    proc = _make_proc(0, _UPNP_XML)
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = asyncio.run(udp_device_info(["192.168.1.10"]))
    assert result.get("192.168.1.10") == "Samsung TV"


def test_dns_service_name_extracted():
    proc = _make_proc(0, _DNS_XML)
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = asyncio.run(udp_device_info(["192.168.1.20"]))
    assert result.get("192.168.1.20") == "Baraka-MacBook"


def test_nmap_failure_returns_empty_dict():
    proc = _make_proc(1, b"", b"requires root")
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = asyncio.run(udp_device_info(["192.168.1.10"]))
    assert result == {}


def test_empty_hosts_returns_immediately():
    result = asyncio.run(udp_device_info([]))
    assert result == {}


def test_timeout_returns_empty_dict():
    async def hanging_communicate():
        await asyncio.sleep(999)
        return b"", b""

    proc = MagicMock()
    proc.communicate = hanging_communicate
    proc.kill = MagicMock()
    proc.wait = AsyncMock()

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = asyncio.run(udp_device_info(["192.168.1.1"], timeout=1))
    assert result == {}


def test_malformed_xml_returns_empty_dict():
    proc = _make_proc(0, b"not xml at all")
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = asyncio.run(udp_device_info(["192.168.1.1"]))
    assert result == {}
