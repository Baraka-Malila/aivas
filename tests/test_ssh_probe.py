import asyncio
import paramiko
from unittest.mock import patch, MagicMock
import pytest
from aivas.scanner.ssh_probe import probe, _parse_dpkg, _parse_rpm
from aivas.scanner import ssh_probe
from aivas.scanner.probe_errors import CredentialError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
from aivas.scanner.probe_errors import ProbeError


def test_parse_dpkg_returns_service_dicts():
    dpkg_output = (
        "ii  openssh-server  1:8.9p1-3  amd64  secure shell server\n"
        "ii  apache2         2.4.52-1   amd64  Apache HTTP server\n"
    )
    result = _parse_dpkg(dpkg_output, "192.168.1.1")
    names = [r["product"] for r in result]
    assert "openssh-server" in names
    assert "apache2" in names
    versions = {r["product"]: r["version"] for r in result}
    assert versions["apache2"] == "2.4.52"


def test_parse_rpm_returns_service_dicts():
    rpm_output = (
        "openssh-server-8.7p1-1.fc36.x86_64\n"
        "httpd-2.4.51-7.el9.x86_64\n"
    )
    result = _parse_rpm(rpm_output, "192.168.1.1")
    names = [r["product"] for r in result]
    assert "openssh-server" in names
    assert "httpd" in names


def test_probe_raises_on_auth_failure():
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient") as MockClient:
        MockClient.return_value.connect.side_effect = paramiko.AuthenticationException
        with pytest.raises(CredentialError):
            probe("192.168.1.1", "user", password="wrong")


def test_probe_uses_dpkg_on_debian():
    mock_client = MagicMock()
    mock_client.exec_command.side_effect = [
        (None, _mock_stdout("ID=ubuntu\n"), None),
        (None, _mock_stdout("ii  nginx  1.18.0  amd64  web server\n"), None),
        (None, _mock_stdout("5.15.0-91-generic\n"), None),
        (None, _mock_stdout("nginx.service enabled\n"), None),
    ]
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        result = probe("192.168.1.1", "user")
    assert any(r["product"] == "nginx" for r in result)


def test_probe_uses_rpm_on_redhat():
    mock_client = MagicMock()
    mock_client.exec_command.side_effect = [
        (None, _mock_stdout("rhel\n"), None),
        (None, _mock_stdout("nginx-1.20.1-1.el9.x86_64\n"), None),
        (None, _mock_stdout("5.14.0-362.el9.x86_64\n"), None),
        (None, _mock_stdout("nginx.service enabled\n"), None),
    ]
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        result = probe("192.168.1.1", "user")
    assert any(r["product"] == "nginx" for r in result)


def _mock_stdout(text: str):
    m = MagicMock()
    m.read.return_value = text.encode()
    return m


def test_credential_error_is_exception():
    e = CredentialError("bad password")
    assert isinstance(e, Exception)
    assert str(e) == "bad password"


def test_connection_error_is_exception():
    e = ProbeConnectionError("port closed")
    assert isinstance(e, Exception)


def test_probe_error_is_exception():
    e = ProbeError("timeout")
    assert isinstance(e, Exception)


def test_probe_async_debian_returns_packages():
    """probe_async with Debian OS returns packages + kernel entry."""
    mock_client = MagicMock()
    mock_client.exec_command.side_effect = [
        (None, _mock_stdout("ID=ubuntu\n"), None),
        (None, _mock_stdout("ii  nginx  1.18.0-0ubuntu1  amd64  web server\n"), None),
        (None, _mock_stdout("5.15.0-91-generic\n"), None),
        (None, _mock_stdout("nginx.service enabled\nssh.service enabled\n"), None),
    ]
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        result = asyncio.run(
            ssh_probe.probe_async("192.168.1.5", "ubuntu", password="pass")
        )
    products = [r["product"] for r in result]
    assert "nginx" in products
    assert "linux-kernel" in products


def test_probe_async_raises_credential_error_on_auth_fail():
    mock_client = MagicMock()
    mock_client.connect.side_effect = paramiko.AuthenticationException("bad creds")
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        with pytest.raises(CredentialError):
            asyncio.run(ssh_probe.probe_async("192.168.1.5", "user", password="wrong"))


def test_probe_async_raises_connection_error_on_refused():
    import socket as _socket
    mock_client = MagicMock()
    mock_client.connect.side_effect = _socket.error("Connection refused")
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        with pytest.raises(ProbeConnectionError):
            asyncio.run(ssh_probe.probe_async("192.168.1.99", "user", password="x"))
