"""Tests for credential_scan_events in scan_helpers.

SSH tests connect to real localhost (aivas_test key).
WinRM tests mock _make_session — we don't have a Windows box in CI.
ProbeError test mocks ssh_probe to simulate an unusual mid-session failure.
"""
import asyncio
import getpass
import os
from unittest.mock import patch

import pytest

from aivas.server.scan_helpers import credential_scan_events
from aivas.scanner.probe_errors import CredentialError, ProbeError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError

_TEST_KEY = os.path.expanduser("~/.ssh/aivas_test")
_TEST_USER = getpass.getuser()
_HAS_KEY = os.path.exists(_TEST_KEY)


async def _collect(host, creds, timeout=30):
    events = []
    async for ev in credential_scan_events(host, creds, timeout=timeout):
        events.append(ev)
    return events


# ---------------------------------------------------------------------------
# SSH — real localhost connections
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_KEY, reason="~/.ssh/aivas_test not found")
def test_ssh_success_yields_credential_services():
    """Real SSH into localhost yields __credential_services sentinel with packages."""
    creds = {"method": "ssh", "username": _TEST_USER, "password": None,
             "port": 22, "key_path": _TEST_KEY}
    events = asyncio.run(_collect("127.0.0.1", creds))
    sentinels = [e for e in events if "__credential_services" in e]
    assert len(sentinels) == 1
    services = sentinels[0]["__credential_services"]
    assert len(services) > 0, "Expected real packages from localhost"
    assert any(s["product"] == "linux-kernel" for s in services)


@pytest.mark.skipif(not _HAS_KEY, reason="~/.ssh/aivas_test not found")
def test_credential_error_yields_error_sentinel():
    """Bad username → CredentialError → __credential_error sentinel."""
    creds = {"method": "ssh", "username": "no_such_user_aivas", "password": "bad",
             "port": 22, "key_path": None}
    events = asyncio.run(_collect("127.0.0.1", creds))
    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1
    assert errors[0]["__credential_error"]


@pytest.mark.skipif(not _HAS_KEY, reason="~/.ssh/aivas_test not found")
def test_connection_error_yields_error_sentinel():
    """Unreachable port → ProbeConnectionError → __credential_error sentinel."""
    creds = {"method": "ssh", "username": _TEST_USER, "password": None,
             "port": 19999, "key_path": _TEST_KEY}
    events = asyncio.run(_collect("127.0.0.1", creds))
    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1


def test_probe_error_yields_error_sentinel():
    """Mid-session ProbeError (e.g. command timeout) → __credential_error sentinel.

    This scenario can't be triggered naturally without killing an SSH session
    mid-flight, so we simulate it at the probe level.
    """
    async def _bad_probe(*a, **kw):
        raise ProbeError("command timeout")

    with patch("aivas.scanner.ssh_probe.probe_async", side_effect=_bad_probe):
        creds = {"method": "ssh", "username": _TEST_USER, "password": None,
                 "port": 22, "key_path": _TEST_KEY}
        events = asyncio.run(_collect("127.0.0.1", creds))

    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1
    assert "command timeout" in errors[0]["__credential_error"]


# ---------------------------------------------------------------------------
# WinRM — mocked (requires a real Windows machine)
# ---------------------------------------------------------------------------

def test_winrm_success_yields_credential_services():
    """WinRM probe success → __credential_services sentinel (mocked — needs Windows)."""
    fake_services = [
        {"host": "10.0.0.5", "port": 0, "protocol": "tcp",
         "service": "package", "product": "notepad++", "version": "8.6.2",
         "nse_results": {}, "os_family": "Windows"},
    ]

    async def _fake_probe(*a, **kw):
        return fake_services

    with patch("aivas.scanner.winrm_probe.probe_async", side_effect=_fake_probe):
        creds = {"method": "winrm", "username": "Administrator",
                 "password": "pass", "port": 5985, "key_path": None}
        events = asyncio.run(_collect("10.0.0.5", creds))

    sentinels = [e for e in events if "__credential_services" in e]
    assert len(sentinels) == 1
    assert sentinels[0]["__credential_services"] == fake_services
