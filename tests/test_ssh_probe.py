"""SSH probe tests.

Parser functions (pure string → dict) are unit-tested directly.
probe_async() is integration-tested against localhost over a real SSH connection
using the dedicated aivas_test key created at ~/.ssh/aivas_test.
"""
import asyncio
import getpass
import os

import pytest

from aivas.scanner.ssh_probe import probe, _parse_dpkg, _parse_rpm
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
