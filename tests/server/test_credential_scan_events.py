"""Tests for credential_scan_events in scan_helpers."""
import asyncio
from unittest.mock import patch

import pytest

from aivas.server.scan_helpers import credential_scan_events
from aivas.scanner.probe_errors import CredentialError, ProbeError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError


SSH_CREDS = {"method": "ssh", "username": "ubuntu", "password": "pass", "port": 22, "key_path": None}
WINRM_CREDS = {"method": "winrm", "username": "Administrator", "password": "pass", "port": 5985, "key_path": None}

FAKE_SERVICES = [
    {"host": "192.168.1.5", "port": 0, "protocol": "tcp",
     "service": "package", "product": "nginx", "version": "1.18.0",
     "nse_results": {}, "os_family": "Linux"},
]


async def _collect(host, creds, timeout=30):
    events = []
    async for ev in credential_scan_events(host, creds, timeout=timeout):
        events.append(ev)
    return events


def test_ssh_success_yields_credential_services():
    async def _fake_probe(*a, **kw):
        return FAKE_SERVICES

    with patch("aivas.scanner.ssh_probe.probe_async", side_effect=_fake_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    sentinels = [e for e in events if "__credential_services" in e]
    assert len(sentinels) == 1
    assert sentinels[0]["__credential_services"] == FAKE_SERVICES


def test_winrm_success_yields_credential_services():
    async def _fake_probe(*a, **kw):
        return FAKE_SERVICES

    with patch("aivas.scanner.winrm_probe.probe_async", side_effect=_fake_probe):
        events = asyncio.run(_collect("10.0.0.5", WINRM_CREDS))

    sentinels = [e for e in events if "__credential_services" in e]
    assert len(sentinels) == 1


def test_credential_error_yields_error_sentinel():
    async def _bad_probe(*a, **kw):
        raise CredentialError("bad password")

    with patch("aivas.scanner.ssh_probe.probe_async", side_effect=_bad_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1
    assert "authentication" in errors[0]["__credential_error"].lower() or "bad password" in errors[0]["__credential_error"].lower()


def test_connection_error_yields_error_sentinel():
    async def _bad_probe(*a, **kw):
        raise ProbeConnectionError("port closed")

    with patch("aivas.scanner.ssh_probe.probe_async", side_effect=_bad_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1


def test_probe_error_yields_error_sentinel():
    async def _bad_probe(*a, **kw):
        raise ProbeError("timeout")

    with patch("aivas.scanner.ssh_probe.probe_async", side_effect=_bad_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1
