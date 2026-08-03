"""Tests for Windows WinRM probe module."""
import asyncio
import json
from unittest.mock import patch, MagicMock

import pytest

from aivas.scanner import winrm_probe
from aivas.scanner.probe_errors import CredentialError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
from aivas.scanner.probe_errors import ProbeError


def _make_ps_result(stdout_data=None, status_code: int = 0):
    """Build a mock pywinrm run_ps() result."""
    m = MagicMock()
    m.status_code = status_code
    if stdout_data is None:
        m.std_out = b""
    else:
        m.std_out = json.dumps(stdout_data).encode()
    m.std_err = b""
    return m


def _make_session(results: list):
    """Build a mock winrm.Session that returns results in order."""
    session = MagicMock()
    session.run_ps.side_effect = results
    return session


def test_parse_registry_apps_returns_service_dicts():
    """Apps from registry query become service dicts."""
    apps = [
        {"DisplayName": "Python 3.11.4", "DisplayVersion": "3.11.4150.1013", "Publisher": "PSF"},
        {"DisplayName": "Git", "DisplayVersion": "2.43.0", "Publisher": "The Git Dev"},
    ]
    result = winrm_probe._parse_registry_apps(apps, "10.0.0.5")
    products = [r["product"] for r in result]
    assert "Python 3.11.4" in products
    assert "Git" in products
    versions = {r["product"]: r["version"] for r in result}
    assert versions["Git"] == "2.43.0"
    assert result[0]["os_family"] == "Windows"
    assert result[0]["service"] == "package"


def test_parse_patches_returns_service_dicts():
    """KB patches become service dicts."""
    patches = [{"HotFixID": "KB5034441"}, {"HotFixID": "KB5035853"}]
    result = winrm_probe._parse_patches(patches, "10.0.0.5")
    ids = [r["product"] for r in result]
    assert "KB5034441" in ids
    assert result[0]["service"] == "patch"


def test_probe_async_success():
    """Full probe_async returns combined packages + patches."""
    apps = [{"DisplayName": "OpenSSL 3.0.2", "DisplayVersion": "3.0.2", "Publisher": "OpenSSL"}]
    patches = [{"HotFixID": "KB5034441"}]
    os_info = [{"Caption": "Windows 11 Pro", "Version": "10.0.22631", "BuildNumber": "22631"}]
    mock_session = _make_session([
        _make_ps_result(apps),
        _make_ps_result(patches),
        _make_ps_result(os_info),
    ])
    with patch("aivas.scanner.winrm_probe._make_session", return_value=mock_session):
        result = asyncio.run(winrm_probe.probe_async("10.0.0.5", "Administrator", "pass"))
    products = [r["product"] for r in result]
    assert "OpenSSL 3.0.2" in products
    assert "KB5034441" in products


def test_probe_async_raises_credential_error():
    """WinRM auth failure → CredentialError."""
    import winrm as _winrm
    with patch("aivas.scanner.winrm_probe._make_session") as mock_factory:
        mock_factory.side_effect = _winrm.exceptions.InvalidCredentialsError("401")
        with pytest.raises(CredentialError):
            asyncio.run(winrm_probe.probe_async("10.0.0.5", "Administrator", "wrong"))


def test_probe_async_raises_connection_error():
    """WinRM unreachable → ConnectionError."""
    import requests.exceptions
    with patch("aivas.scanner.winrm_probe._make_session") as mock_factory:
        mock_factory.side_effect = requests.exceptions.ConnectionError("refused")
        with pytest.raises(ProbeConnectionError):
            asyncio.run(winrm_probe.probe_async("10.0.0.99", "Administrator", "pass"))


def test_probe_async_raises_probe_error_when_winrm_missing():
    """If pywinrm is not installed, ProbeError is raised with install hint."""
    import sys
    with patch.dict(sys.modules, {"winrm": None}):
        with pytest.raises(ProbeError, match="pip install pywinrm"):
            asyncio.run(winrm_probe.probe_async("10.0.0.5", "Administrator", "pass"))
