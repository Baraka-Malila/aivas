"""SSH probe tests.

Parser functions (pure string → dict) are unit-tested directly.
probe_async() is integration-tested against localhost over a real SSH connection
using the dedicated aivas_test key created at ~/.ssh/aivas_test.
"""
import asyncio
import getpass
import os
from unittest.mock import MagicMock, patch

import pytest

from aivas.scanner.ssh_probe import probe, _parse_dpkg, _parse_rpm, _get_ssh_hardening
from aivas.scanner import ssh_probe
from aivas.scanner.probe_errors import CredentialError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
from aivas.scanner.probe_errors import ProbeError

_TEST_KEY = os.path.expanduser("~/.ssh/aivas_test")
_TEST_USER = getpass.getuser()

# ---------------------------------------------------------------------------
# Parser unit tests — pure functions, no network
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Real SSH integration tests — connect to localhost with a key
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not os.path.exists(_TEST_KEY),
    reason="~/.ssh/aivas_test key not present — run: ssh-keygen -t ed25519 -f ~/.ssh/aivas_test -N '' && cat ~/.ssh/aivas_test.pub >> ~/.ssh/authorized_keys",
)
class TestSSHProbeReal:
    """Live SSH into localhost using the aivas_test key."""

    def test_probe_async_returns_packages_and_kernel(self):
        """probe_async actually SSHes into localhost and returns real packages."""
        services = asyncio.run(
            ssh_probe.probe_async(
                host="127.0.0.1",
                username=_TEST_USER,
                password=None,
                key_path=_TEST_KEY,
                port=22,
            )
        )
        assert len(services) > 0, "Expected at least one service/package from localhost"
        products = [s["product"] for s in services]
        assert "linux-kernel" in products, f"Expected linux-kernel in {products[:10]}"
        assert any(s["service"] == "package" for s in services), "Expected at least one package"

    def test_probe_async_kernel_has_real_version(self):
        """Kernel version from localhost matches uname -r."""
        import subprocess
        expected = subprocess.check_output(["uname", "-r"]).decode().strip()
        services = asyncio.run(
            ssh_probe.probe_async(
                host="127.0.0.1",
                username=_TEST_USER,
                password=None,
                key_path=_TEST_KEY,
                port=22,
            )
        )
        kernel = next((s for s in services if s["product"] == "linux-kernel"), None)
        assert kernel is not None
        assert kernel["version"] == expected, f"Expected kernel {expected}, got {kernel['version']}"

    def test_probe_async_bad_username_raises_credential_error(self):
        """Non-existent username → CredentialError, not a generic crash."""
        with pytest.raises(CredentialError):
            asyncio.run(
                ssh_probe.probe_async(
                    host="127.0.0.1",
                    username="this_user_does_not_exist_aivas",
                    password="wrong",
                    key_path=None,
                    port=22,
                )
            )

    def test_probe_async_bad_port_raises_connection_error(self):
        """Unreachable port → ProbeConnectionError."""
        with pytest.raises(ProbeConnectionError):
            asyncio.run(
                ssh_probe.probe_async(
                    host="127.0.0.1",
                    username=_TEST_USER,
                    password=None,
                    key_path=_TEST_KEY,
                    port=19999,  # nothing listening here
                )
            )


# ---------------------------------------------------------------------------
# SSH hardening parser unit tests — mock _run, no real SSH needed
# ---------------------------------------------------------------------------

def _make_client(config_text: str):
    """Return a mock SSHClient whose _run will return config_text."""
    client = MagicMock()
    return client, config_text


def test_hardening_root_login_flagged():
    _sshd = "PermitRootLogin yes\nPasswordAuthentication no\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    titles = [r["title"] for r in results]
    assert any("Root login" in t for t in titles)


def test_hardening_empty_passwords_flagged():
    _sshd = "PermitEmptyPasswords yes\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert any(r["severity"] == "CRITICAL" for r in results)


def test_hardening_password_auth_flagged():
    _sshd = "PasswordAuthentication yes\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert any("password authentication" in r["title"].lower() for r in results)


def test_hardening_protocol1_flagged():
    _sshd = "Protocol 1\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert any("protocol" in r["title"].lower() for r in results)
    assert any(r["severity"] == "HIGH" for r in results)


def test_hardening_max_auth_tries_flagged():
    _sshd = "MaxAuthTries 10\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert any("MaxAuthTries" in r["description"] for r in results)


def test_hardening_secure_config_returns_empty():
    _sshd = (
        "PermitRootLogin no\n"
        "PasswordAuthentication no\n"
        "PermitEmptyPasswords no\n"
        "X11Forwarding no\n"
        "MaxAuthTries 3\n"
        "UsePAM yes\n"
    )
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert results == []


def test_hardening_empty_config_returns_empty():
    with patch("aivas.scanner.ssh_probe._run", return_value=""):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert results == []


def test_hardening_comments_ignored():
    _sshd = "# PermitRootLogin yes\nPermitRootLogin no\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert results == []


def test_hardening_result_shape():
    _sshd = "PermitRootLogin yes\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "192.168.0.5")
    assert len(results) == 1
    r = results[0]
    assert r["host"] == "192.168.0.5"
    assert r["type"] == "ssh_hardening"
    assert "title" in r
    assert "severity" in r
    assert "description" in r
    assert "recommendation" in r


def test_hardening_x11_flagged():
    _sshd = "X11Forwarding yes\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert any("X11" in r["title"] for r in results)
    assert any(r["severity"] == "LOW" for r in results)


def test_hardening_use_pam_disabled_flagged():
    _sshd = "UsePAM no\n"
    with patch("aivas.scanner.ssh_probe._run", return_value=_sshd):
        results = _get_ssh_hardening(MagicMock(), "10.0.0.1")
    assert any("PAM" in r["title"] for r in results)
