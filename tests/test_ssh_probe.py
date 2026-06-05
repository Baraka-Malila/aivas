from unittest.mock import patch, MagicMock
import pytest
from aivas.scanner.ssh_probe import probe, _parse_dpkg, _parse_rpm


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
    import paramiko
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient") as MockClient:
        MockClient.return_value.connect.side_effect = paramiko.AuthenticationException
        with pytest.raises(RuntimeError, match="SSH authentication failed"):
            probe("192.168.1.1", "user", password="wrong")


def test_probe_uses_dpkg_on_debian():
    mock_client = MagicMock()
    mock_client.exec_command.side_effect = [
        (None, _mock_stdout("debian"), None),
        (None, _mock_stdout("ii  nginx  1.18.0  amd64  web server\n"), None),
    ]
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        result = probe("192.168.1.1", "user")
    assert any(r["product"] == "nginx" for r in result)


def test_probe_uses_rpm_on_redhat():
    mock_client = MagicMock()
    mock_client.exec_command.side_effect = [
        (None, _mock_stdout("rhel"), None),
        (None, _mock_stdout("nginx-1.20.1-1.el9.x86_64\n"), None),
    ]
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        result = probe("192.168.1.1", "user")
    assert any(r["product"] == "nginx" for r in result)


def _mock_stdout(text: str):
    m = MagicMock()
    m.read.return_value = text.encode()
    return m
