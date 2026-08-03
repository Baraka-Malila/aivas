# Credentialed Remote Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable AIVAS to SSH into Linux machines and WinRM into Windows machines to enumerate installed packages, kernel versions, and running services, then correlate them against the CVE database — the same technique Nessus calls "credentialed scanning."

**Architecture:** nmap runs first (Phase 1, existing) for open ports and services; then optional Phase 2 uses SSH/WinRM credentials to enumerate installed software from inside the machine. Phase 2 results merge with Phase 1 before CVE correlation. The scan then runs normally — findings appear in the same ScanCard. Credentials flow from frontend settings or chat → POST /api/scan → WebSocket → scan_worker.

**Tech Stack:** Python/paramiko (SSH, already in pyproject.toml), pywinrm (new, Windows WinRM), FastAPI, React.

## Global Constraints

- No file exceeds 200 lines of code — split if approaching limit
- All service dicts use the shape: `{"host": str, "port": int, "protocol": str, "service": str, "product": str, "version": str, "nse_results": dict, "os_family": str}`
- New exception types live in `aivas/scanner/probe_errors.py` — never import from each other between probe modules
- pywinrm is an optional dependency — import lazily inside `probe_async()` so AIVAS works without it
- Credentials are never persisted server-side; passed per-request only
- `_pending` in `aivas/server/main.py` stores `tuple` (variable length) — always unpack by index, not destructuring with fixed count
- Tests mock paramiko and winrm — never make real network connections in tests
- Frontend stores saved targets in localStorage key `aivas_remote_targets` as JSON array
- Commit after every task with `git add <specific files> && git commit -m "feat: ..."`

---

### Task 1: `scanner/probe_errors.py` + extend `scanner/ssh_probe.py`

**Files:**
- Create: `aivas/scanner/probe_errors.py`
- Modify: `aivas/scanner/ssh_probe.py`
- Modify: `tests/test_ssh_probe.py`

**Interfaces:**
- Produces: `CredentialError`, `ConnectionError`, `ProbeError` (importable from `aivas.scanner.probe_errors`)
- Produces: `ssh_probe.probe_async(host, username, password, key_path, port, timeout) -> list[dict]`
- Later tasks import `probe_async` and all three exception types

---

- [ ] **Step 1: Write failing tests for probe_errors and the new ssh_probe functions**

Add to `tests/test_ssh_probe.py` (append after existing tests):

```python
import asyncio
import paramiko
from unittest.mock import patch, MagicMock, AsyncMock
from aivas.scanner.probe_errors import CredentialError, ConnectionError as ProbeConnectionError, ProbeError


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
    # exec_command calls: os-release, dpkg -l, uname -r, systemctl
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
    import socket
    mock_client = MagicMock()
    mock_client.connect.side_effect = socket.error("Connection refused")
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient", return_value=mock_client):
        with pytest.raises(ProbeConnectionError):
            asyncio.run(ssh_probe.probe_async("192.168.1.99", "user", password="x"))
```

Also add `import asyncio` and `from aivas.scanner import ssh_probe` to the imports at the top of `tests/test_ssh_probe.py`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/cyberpunk/aivas
pytest tests/test_ssh_probe.py::test_credential_error_is_exception -v
```
Expected: `FAILED` — `ModuleNotFoundError: No module named 'aivas.scanner.probe_errors'`

- [ ] **Step 3: Create `aivas/scanner/probe_errors.py`**

```python
"""Shared exception types for remote probe modules (SSH, WinRM)."""


class CredentialError(Exception):
    """Authentication failed — wrong username, password, or key rejected."""


class ConnectionError(Exception):
    """Cannot reach the target host on the given port."""


class ProbeError(Exception):
    """Any other probe failure: command error, timeout, missing dependency."""
```

- [ ] **Step 4: Rewrite `aivas/scanner/ssh_probe.py`**

Replace the entire file with:

```python
"""SSH-based remote package enumeration for Linux targets."""
from __future__ import annotations

import asyncio
import socket

import paramiko

from aivas.scanner.probe_errors import CredentialError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
from aivas.scanner.probe_errors import ProbeError


async def probe_async(
    host: str,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    timeout: int = 90,
) -> list[dict]:
    """Connect via SSH and enumerate packages, kernel, and services.

    Returns list of service dicts in the same shape as nmap parser output.
    Raises CredentialError, ConnectionError, or ProbeError on failure.
    """
    return await asyncio.to_thread(
        _probe_sync, host, username, password, key_path, port, timeout
    )


def _probe_sync(
    host: str,
    username: str,
    password: str | None,
    key_path: str | None,
    port: int,
    timeout: int,
) -> list[dict]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs: dict = {
            "hostname": host, "port": port, "username": username,
            "timeout": min(timeout, 30),
        }
        if key_path:
            kwargs["key_filename"] = key_path
        elif password:
            kwargs["password"] = password
        client.connect(**kwargs)
    except paramiko.AuthenticationException as exc:
        raise CredentialError(
            f"SSH authentication failed for {username}@{host}:{port}"
        ) from exc
    except (socket.error, OSError) as exc:
        raise ProbeConnectionError(
            f"Cannot reach {host} on port {port} — is SSH running?"
        ) from exc
    except Exception as exc:
        raise ProbeError(f"SSH connection error: {exc}") from exc

    try:
        os_family = _detect_os(client, host)
        services: list[dict] = []
        services.extend(_get_packages(client, host, os_family))
        services.extend(_get_kernel(client, host))
        services.extend(_get_services(client, host))
        return services
    except (CredentialError, ProbeConnectionError, ProbeError):
        raise
    except Exception as exc:
        raise ProbeError(f"SSH enumeration error on {host}: {exc}") from exc
    finally:
        client.close()


def _run(client: paramiko.SSHClient, cmd: str, timeout: int = 30) -> str:
    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode(errors="replace")


def _detect_os(client: paramiko.SSHClient, host: str) -> str:
    out = _run(client, "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null")
    lower = out.lower()
    if "debian" in lower or "ubuntu" in lower:
        return "debian"
    return "rhel"


def _get_packages(client: paramiko.SSHClient, host: str, os_family: str) -> list[dict]:
    if os_family == "debian":
        return _parse_dpkg(_run(client, "dpkg -l 2>/dev/null"), host)
    return _parse_rpm(_run(client, "rpm -qa 2>/dev/null"), host)


def _get_kernel(client: paramiko.SSHClient, host: str) -> list[dict]:
    version = _run(client, "uname -r 2>/dev/null").strip()
    if not version:
        return []
    return [{
        "host": host, "port": 0, "protocol": "tcp",
        "service": "kernel", "product": "linux-kernel",
        "version": version, "nse_results": {}, "os_family": "Linux",
    }]


def _get_services(client: paramiko.SSHClient, host: str) -> list[dict]:
    out = _run(
        client,
        "systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null"
        " || service --status-all 2>/dev/null | grep '+' || true",
    )
    results = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0].removesuffix(".service")
        if not name or name in ("UNIT", "Legacy"):
            continue
        results.append({
            "host": host, "port": 0, "protocol": "tcp",
            "service": "service", "product": name,
            "version": "", "nse_results": {}, "os_family": "Linux",
        })
    return results


def _parse_dpkg(output: str, host: str) -> list[dict]:
    services = []
    for line in output.splitlines():
        if not line.startswith("ii"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[1].split(":")[0]
        version = parts[2].lstrip("1:").split("-")[0].split("+")[0]
        services.append({
            "host": host, "port": 0, "protocol": "tcp",
            "service": "package", "product": name,
            "version": version, "nse_results": {}, "os_family": "Linux",
        })
    return services


def _parse_rpm(output: str, host: str) -> list[dict]:
    services = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.rsplit("-", 2)
        if len(parts) < 3:
            continue
        name = parts[0]
        version = parts[1].split(":")[0]
        services.append({
            "host": host, "port": 0, "protocol": "tcp",
            "service": "package", "product": name,
            "version": version, "nse_results": {}, "os_family": "Linux",
        })
    return services


# Synchronous wrapper kept for CLI backward compatibility (scan_cmd.py)
def probe(
    host: str,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
) -> list[dict]:
    return _probe_sync(host, username, password, key_path, port, timeout=90)
```

- [ ] **Step 5: Run the new tests**

```bash
cd /home/cyberpunk/aivas
pytest tests/test_ssh_probe.py -v
```
Expected: all pass. The existing `test_probe_raises_on_auth_failure` must still pass — verify it does (it catches `RuntimeError`; update it to catch `CredentialError` if it fails).

If `test_probe_raises_on_auth_failure` fails because it checks for `RuntimeError`, update that test to match the new exception type:
```python
def test_probe_raises_on_auth_failure():
    from aivas.scanner.probe_errors import CredentialError
    with patch("aivas.scanner.ssh_probe.paramiko.SSHClient") as MockClient:
        MockClient.return_value.connect.side_effect = paramiko.AuthenticationException
        with pytest.raises(CredentialError):
            probe("192.168.1.1", "user", password="wrong")
```

- [ ] **Step 6: Run full test suite to check for regressions**

```bash
cd /home/cyberpunk/aivas
pytest tests/ -x -q 2>&1 | tail -20
```
Expected: all existing tests pass.

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/scanner/probe_errors.py aivas/scanner/ssh_probe.py tests/test_ssh_probe.py
git commit -m "feat: probe_errors module + extend ssh_probe with async, kernel, services"
```

---

### Task 2: `scanner/winrm_probe.py` + `pyproject.toml` + tests

**Files:**
- Create: `aivas/scanner/winrm_probe.py`
- Modify: `pyproject.toml`
- Create: `tests/test_winrm_probe.py`

**Interfaces:**
- Consumes: `CredentialError`, `ConnectionError`, `ProbeError` from `aivas.scanner.probe_errors`
- Produces: `winrm_probe.probe_async(host, username, password, port, use_ssl, timeout) -> list[dict]`

---

- [ ] **Step 1: Write failing tests**

Create `tests/test_winrm_probe.py`:

```python
"""Tests for Windows WinRM probe module."""
import asyncio
import json
from unittest.mock import patch, MagicMock

import pytest

from aivas.scanner import winrm_probe
from aivas.scanner.probe_errors import CredentialError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
from aivas.scanner.probe_errors import ProbeError


def _make_ps_result(stdout_data: list[dict] | dict | None = None, status_code: int = 0):
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/cyberpunk/aivas
pytest tests/test_winrm_probe.py -v 2>&1 | head -20
```
Expected: `FAILED` — `ModuleNotFoundError: No module named 'aivas.scanner.winrm_probe'`

- [ ] **Step 3: Add pywinrm to `pyproject.toml`**

In `pyproject.toml`, find the `dependencies` list and add `"pywinrm>=0.4.3"` after `"paramiko>=3.0"`:

```toml
    "paramiko>=3.0",
    "pywinrm>=0.4.3",
```

Then install it:
```bash
cd /home/cyberpunk/aivas
pip install pywinrm>=0.4.3 -q
```

- [ ] **Step 4: Create `aivas/scanner/winrm_probe.py`**

```python
"""WinRM-based remote package enumeration for Windows targets."""
from __future__ import annotations

import asyncio
import json

from aivas.scanner.probe_errors import CredentialError
from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
from aivas.scanner.probe_errors import ProbeError

# Registry-based software query — faster than Win32_Product and no side effects
_PS_APPS = r"""
$paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = $paths | ForEach-Object {
    Get-ItemProperty $_ -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher
}
$apps | ConvertTo-Json -Compress
"""

_PS_PATCHES = r"""
Get-WmiObject -Class Win32_QuickFixEngineering |
  Select-Object HotFixID |
  ConvertTo-Json -Compress
"""

_PS_OS = r"""
Get-WmiObject -Class Win32_OperatingSystem |
  Select-Object Caption, Version, BuildNumber |
  ConvertTo-Json -Compress
"""


def _make_session(host: str, username: str, password: str, port: int, use_ssl: bool):
    """Create a pywinrm Session. Separated for easy mocking in tests."""
    try:
        import winrm
    except ImportError:
        raise ProbeError(
            "pywinrm not installed on AIVAS machine. Run: pip install pywinrm"
        )
    scheme = "https" if use_ssl else "http"
    return winrm.Session(
        f"{scheme}://{host}:{port}/wsman",
        auth=(username, password),
        transport="ntlm",
        server_cert_validation="ignore",
    )


async def probe_async(
    host: str,
    username: str,
    password: str,
    port: int = 5985,
    use_ssl: bool = False,
    timeout: int = 90,
) -> list[dict]:
    """Connect via WinRM and enumerate installed software and patches.

    Returns list of service dicts matching the nmap parser output shape.
    Raises CredentialError, ConnectionError, or ProbeError on failure.
    """
    return await asyncio.to_thread(
        _probe_sync, host, username, password, port, use_ssl, timeout
    )


def _probe_sync(
    host: str, username: str, password: str,
    port: int, use_ssl: bool, timeout: int,
) -> list[dict]:
    try:
        import winrm.exceptions
        import requests.exceptions
    except ImportError:
        raise ProbeError(
            "pywinrm not installed on AIVAS machine. Run: pip install pywinrm"
        )

    try:
        session = _make_session(host, username, password, port, use_ssl)
    except ProbeError:
        raise
    except Exception as exc:
        _classify_error(exc, host, port)

    services: list[dict] = []
    try:
        services.extend(_query_apps(session, host))
        services.extend(_query_patches(session, host))
        services.extend(_query_os(session, host))
    except (CredentialError, ProbeConnectionError, ProbeError):
        raise
    except Exception as exc:
        raise ProbeError(f"WinRM enumeration error on {host}: {exc}") from exc
    return services


def _classify_error(exc: Exception, host: str, port: int) -> None:
    """Convert pywinrm/requests exceptions into probe_errors types."""
    try:
        import winrm.exceptions
        import requests.exceptions
        if isinstance(exc, winrm.exceptions.InvalidCredentialsError):
            raise CredentialError(
                f"WinRM authentication failed for {host}:{port}"
            ) from exc
        if isinstance(exc, requests.exceptions.ConnectionError):
            raise ProbeConnectionError(
                f"WinRM not available on {host}. On that machine, run as Administrator: winrm quickconfig"
            ) from exc
    except (CredentialError, ProbeConnectionError):
        raise
    except Exception:
        pass
    raise ProbeError(f"WinRM connection error: {exc}") from exc


def _run_ps(session, script: str) -> list[dict]:
    """Run a PowerShell script and parse JSON output. Returns [] on empty."""
    result = session.run_ps(script)
    if not result.std_out:
        return []
    raw = result.std_out.decode(errors="replace").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def _query_apps(session, host: str) -> list[dict]:
    rows = _run_ps(session, _PS_APPS)
    return _parse_registry_apps(rows, host)


def _query_patches(session, host: str) -> list[dict]:
    rows = _run_ps(session, _PS_PATCHES)
    return _parse_patches(rows, host)


def _query_os(session, host: str) -> list[dict]:
    rows = _run_ps(session, _PS_OS)
    if not rows:
        return []
    os_row = rows[0]
    version = os_row.get("Version") or os_row.get("BuildNumber") or ""
    caption = os_row.get("Caption") or "Windows"
    return [{
        "host": host, "port": 0, "protocol": "tcp",
        "service": "os", "product": caption,
        "version": version, "nse_results": {}, "os_family": "Windows",
    }]


def _parse_registry_apps(rows: list[dict], host: str) -> list[dict]:
    services = []
    for row in rows:
        name = (row.get("DisplayName") or "").strip()
        version = (row.get("DisplayVersion") or "").strip()
        if not name:
            continue
        services.append({
            "host": host, "port": 0, "protocol": "tcp",
            "service": "package", "product": name,
            "version": version, "nse_results": {}, "os_family": "Windows",
        })
    return services


def _parse_patches(rows: list[dict], host: str) -> list[dict]:
    services = []
    for row in rows:
        kb_id = (row.get("HotFixID") or "").strip()
        if not kb_id:
            continue
        services.append({
            "host": host, "port": 0, "protocol": "tcp",
            "service": "patch", "product": kb_id,
            "version": "", "nse_results": {}, "os_family": "Windows",
        })
    return services
```

- [ ] **Step 5: Run winrm tests**

```bash
cd /home/cyberpunk/aivas
pytest tests/test_winrm_probe.py -v
```
Expected: all 6 tests pass.

- [ ] **Step 6: Run full suite for regressions**

```bash
pytest tests/ -x -q 2>&1 | tail -10
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/scanner/winrm_probe.py pyproject.toml tests/test_winrm_probe.py
git commit -m "feat: winrm_probe — Windows credentialed scanning via pywinrm"
```

---

### Task 3: `server/scan_helpers.py` — `credential_scan_events()`

**Files:**
- Modify: `aivas/server/scan_helpers.py` (append one function, ~50 lines)
- Create: `tests/server/test_credential_scan_events.py`

**Interfaces:**
- Consumes: `ssh_probe.probe_async`, `winrm_probe.probe_async`, all three exception types
- Produces: `credential_scan_events(host, creds, timeout) -> AsyncGenerator[dict, None]`
  - `creds` shape: `{"method": "ssh"|"winrm", "username": str, "password": str, "key_path": str|None, "port": int}`
  - Yields progress `_ev(...)` dicts, then final sentinel `{"__credential_services": list[dict]}` or `{"__credential_error": str}`

---

- [ ] **Step 1: Check tests/server/ exists**

```bash
ls /home/cyberpunk/aivas/tests/server/ 2>/dev/null || mkdir -p /home/cyberpunk/aivas/tests/server && touch /home/cyberpunk/aivas/tests/server/__init__.py
```

- [ ] **Step 2: Write failing test**

Create `tests/server/test_credential_scan_events.py`:

```python
"""Tests for credential_scan_events in scan_helpers."""
import asyncio
from unittest.mock import patch, AsyncMock

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

    with patch("aivas.server.scan_helpers.ssh_probe.probe_async", side_effect=_fake_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    sentinels = [e for e in events if "__credential_services" in e]
    assert len(sentinels) == 1
    assert sentinels[0]["__credential_services"] == FAKE_SERVICES


def test_winrm_success_yields_credential_services():
    async def _fake_probe(*a, **kw):
        return FAKE_SERVICES

    with patch("aivas.server.scan_helpers.winrm_probe.probe_async", side_effect=_fake_probe):
        events = asyncio.run(_collect("10.0.0.5", WINRM_CREDS))

    sentinels = [e for e in events if "__credential_services" in e]
    assert len(sentinels) == 1


def test_credential_error_yields_error_sentinel():
    async def _bad_probe(*a, **kw):
        raise CredentialError("bad password")

    with patch("aivas.server.scan_helpers.ssh_probe.probe_async", side_effect=_bad_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1
    assert "authentication" in errors[0]["__credential_error"].lower()


def test_connection_error_yields_error_sentinel():
    async def _bad_probe(*a, **kw):
        raise ProbeConnectionError("port closed")

    with patch("aivas.server.scan_helpers.ssh_probe.probe_async", side_effect=_bad_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1


def test_probe_error_yields_error_sentinel():
    async def _bad_probe(*a, **kw):
        raise ProbeError("timeout")

    with patch("aivas.server.scan_helpers.ssh_probe.probe_async", side_effect=_bad_probe):
        events = asyncio.run(_collect("192.168.1.5", SSH_CREDS))

    errors = [e for e in events if "__credential_error" in e]
    assert len(errors) == 1
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd /home/cyberpunk/aivas
pytest tests/server/test_credential_scan_events.py -v 2>&1 | head -15
```
Expected: `FAILED` — `ImportError: cannot import name 'credential_scan_events'`

- [ ] **Step 4: Add `credential_scan_events` to `aivas/server/scan_helpers.py`**

Append after the last line of `scan_helpers.py` (after the closing of `scan_host`):

```python


async def credential_scan_events(
    host: str,
    creds: dict,
    timeout: int = 90,
) -> AsyncGenerator[dict, None]:
    """Run SSH or WinRM probe on host; yield progress events then sentinel.

    creds keys: method ("ssh"|"winrm"), username, password, port, key_path (SSH only).
    Final event is {"__credential_services": [...]} on success,
    or {"__credential_error": "<human message>"} on failure.
    """
    from aivas.scanner import ssh_probe, winrm_probe
    from aivas.scanner.probe_errors import CredentialError
    from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
    from aivas.scanner.probe_errors import ProbeError

    method = creds.get("method", "ssh")
    port = creds.get("port") or (22 if method == "ssh" else 5985)
    label = f"{host}:{port} ({method.upper()})"

    yield _ev("credential_probe", f"  Connecting to {label}…")
    try:
        if method == "ssh":
            services = await ssh_probe.probe_async(
                host=host,
                username=creds["username"],
                password=creds.get("password"),
                key_path=creds.get("key_path"),
                port=port,
                timeout=timeout,
            )
        else:
            services = await winrm_probe.probe_async(
                host=host,
                username=creds["username"],
                password=creds.get("password", ""),
                port=port,
                timeout=timeout,
            )
        yield _ev(
            "credential_done",
            f"  {label} — {len(services)} software item(s) enumerated",
        )
        yield {"__credential_services": services}
    except CredentialError as exc:
        yield {"__credential_error": str(exc)}
    except ProbeConnectionError as exc:
        yield {"__credential_error": str(exc)}
    except ProbeError as exc:
        yield {"__credential_error": str(exc)}
    except Exception as exc:
        yield {"__credential_error": f"Credential scan failed: {exc}"}
```

- [ ] **Step 5: Run credential_scan_events tests**

```bash
cd /home/cyberpunk/aivas
pytest tests/server/test_credential_scan_events.py -v
```
Expected: all 5 tests pass.

- [ ] **Step 6: Run full suite**

```bash
pytest tests/ -x -q 2>&1 | tail -10
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/scan_helpers.py tests/server/test_credential_scan_events.py tests/server/__init__.py
git commit -m "feat: credential_scan_events — SSH/WinRM probe integrated into scan helper pipeline"
```

---

### Task 4: `server/scan_worker.py` — Phase 2 credential scan integration

**Files:**
- Modify: `aivas/server/scan_worker.py` (add `creds` param to `run_scan`, Phase 2 block after HTTP probe)

**Interfaces:**
- Consumes: `credential_scan_events` from `aivas.server.scan_helpers`
- Produces: `run_scan(conn, target, level=2, creds=None)` — signature change; all existing callers still work because `creds` defaults to `None`

---

- [ ] **Step 1: Write failing test**

Create `tests/server/test_scan_worker_creds.py`:

```python
"""Test that run_scan accepts creds and includes credential services in done event."""
import asyncio
import sqlite3
from unittest.mock import patch, AsyncMock, MagicMock

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


async def _run_to_done(conn, target, creds=None):
    events = []
    async for ev in run_scan(conn, target, level=2, creds=creds):
        events.append(ev)
    return events


def _make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, started_at TEXT,"
        " grade TEXT, score INTEGER, finding_count INTEGER,"
        " critical_count INTEGER, kev_count INTEGER)"
    )
    conn.execute(
        "CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_id INTEGER,"
        " cve_id TEXT, cvss_score REAL, cvss_severity TEXT, description TEXT,"
        " confidence TEXT, host TEXT)"
    )
    conn.execute("CREATE TABLE cves (cve_id TEXT PRIMARY KEY, kev INTEGER)")
    conn.commit()
    return conn


def test_run_scan_without_creds_skips_phase2():
    conn = _make_conn()

    async def _fake_nmap(*a, **kw):
        return FAKE_NMAP_XML

    with patch("aivas.server.scan_worker._async_nmap", side_effect=_fake_nmap), \
         patch("aivas.server.scan_helpers.correlate", return_value=[]), \
         patch("aivas.server.scan_helpers.probe_http_service",
               return_value={"status": "unreachable", "findings": []}):
        events = asyncio.run(_run_to_done(conn, "192.168.1.5"))

    done = next(e for e in events if e.get("type") == "done")
    assert done["credential_scan"] is False


def test_run_scan_with_creds_triggers_phase2():
    conn = _make_conn()
    creds = {"method": "ssh", "username": "ubuntu", "password": "pass", "port": 22}

    async def _fake_nmap(*a, **kw):
        return FAKE_NMAP_XML

    async def _fake_cred_events(host, creds, timeout=90):
        yield {"type": "progress", "phase": "credential_probe", "text": "  Connecting…"}
        yield {"__credential_services": CREDENTIAL_SERVICES}

    with patch("aivas.server.scan_worker._async_nmap", side_effect=_fake_nmap), \
         patch("aivas.server.scan_helpers.correlate", return_value=[]), \
         patch("aivas.server.scan_helpers.probe_http_service",
               return_value={"status": "unreachable", "findings": []}), \
         patch("aivas.server.scan_worker.credential_scan_events",
               side_effect=_fake_cred_events):
        events = asyncio.run(_run_to_done(conn, "192.168.1.5", creds=creds))

    done = next(e for e in events if e.get("type") == "done")
    assert done["credential_scan"] is True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/cyberpunk/aivas
pytest tests/server/test_scan_worker_creds.py -v 2>&1 | head -15
```
Expected: `FAILED` — `run_scan() got unexpected keyword argument 'creds'`

- [ ] **Step 3: Modify `aivas/server/scan_worker.py`**

**Change 1** — update import at top of file (line 18–21):
```python
from aivas.server.scan_helpers import (
    _ev, _svc_label,
    cve_events, http_probe_events, scan_host,
    credential_scan_events,
)
```

**Change 2** — update `run_scan` signature (line 91):
```python
async def run_scan(
    conn: sqlite3.Connection, target: str, level: int = 2, creds: dict | None = None
) -> AsyncGenerator[dict, None]:
```

**Change 3** — inside `run_scan`, in the single-host branch, after the HTTP probe block (after line 191 `yield _emit(ev)`) and before the CVE lookup block, add Phase 2:

```python
        # Phase 2: credentialed scan (optional)
        credential_services: list[dict] = []
        if creds:
            yield _emit(_ev("phase_header", "CREDENTIAL SCAN"))
            async for ev in credential_scan_events(target, creds):
                if "__credential_services" in ev:
                    credential_services = ev["__credential_services"]
                    yield _emit(_ev(
                        "credential_result",
                        f"  Enumerated {len(credential_services)} software item(s) via {creds.get('method','?').upper()}",
                    ))
                elif "__credential_error" in ev:
                    yield _emit(_ev("credential_error", f"  ⚠ {ev['__credential_error']}"))
                    yield _emit(_ev("credential_fallback", "  Continuing with nmap results only"))
                else:
                    yield _emit(ev)
        all_services.extend(credential_services)
```

Place this block between the HTTP probe section (ending around line 191) and the CVE lookup section (`yield _emit(_ev("phase_header", "CVE LOOKUP"))`).

Also update `services` → `services + credential_services` in the CVE lookup call:
```python
        yield _emit(_ev("phase_header", "CVE LOOKUP"))
        async for ev in cve_events(conn, services + credential_services, "  "):
```

**Change 4** — update the done event (near the end) to include `credential_scan`:
```python
    yield {
        "type": "done",
        ...
        "misconfigs": all_misconfigs,
        "credential_scan": creds is not None and bool(credential_services if not is_net else True),
    }
```

Find the existing `"misconfigs": all_misconfigs,` line and add `"credential_scan": creds is not None,` after it.

- [ ] **Step 4: Run Phase 2 tests**

```bash
cd /home/cyberpunk/aivas
pytest tests/server/test_scan_worker_creds.py -v
```
Expected: both tests pass.

- [ ] **Step 5: Run full suite**

```bash
pytest tests/ -x -q 2>&1 | tail -10
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/scan_worker.py tests/server/test_scan_worker_creds.py
git commit -m "feat: scan_worker Phase 2 — credentialed scan integrated after HTTP probe"
```

---

### Task 5: `server/main.py` + `server/ws_chat.py` — API wiring

**Files:**
- Modify: `aivas/server/main.py`
- Modify: `aivas/server/ws_chat.py`

**Interfaces:**
- `ScanRequest` gains optional `creds: dict | None = None`
- `_pending` stores `(target, level, creds)` tuples
- New endpoint: `POST /api/probe/test` → `{"ok": bool, "error": str | None}`
- `scan_ws` passes `creds` to `run_scan()`

---

- [ ] **Step 1: Modify `aivas/server/main.py`**

**Change 1** — update `_pending` type annotation (line 29):
```python
_pending: dict[str, tuple] = {}
```

**Change 2** — update `ScanRequest` (find current definition around line 133):
```python
class ScanRequest(BaseModel):
    target: str
    level: int = 2
    creds: dict | None = None
```

**Change 3** — update `start_scan` endpoint to store creds (around line 193–197):
```python
@app.post("/api/scan")
async def start_scan(body: ScanRequest):
    scan_key = str(uuid.uuid4())
    _pending[scan_key] = (body.target, body.level, body.creds)
    return {"scan_key": scan_key}
```

**Change 4** — update `scan_ws` to unpack creds and pass to `run_scan` (around line 200–211):
```python
@app.websocket("/ws/scan/{scan_key}")
async def scan_ws(websocket: WebSocket, scan_key: str):
    await websocket.accept()
    entry = _pending.pop(scan_key, None)
    if not entry:
        await websocket.send_json({"type": "error", "text": "Unknown scan key."})
        await websocket.close()
        return
    target = entry[0]
    level = entry[1]
    creds = entry[2] if len(entry) > 2 else None
    _log.info("Scan started: %s (level %d, creds=%s)", target, level, bool(creds))
    from aivas.server.scan_worker import run_scan
    scan_gen = run_scan(_conn, target, level, creds=creds)
    # ... rest of handler unchanged
```

**Change 5** — add `POST /api/probe/test` endpoint. Add this after the `start_scan` endpoint:

```python
class ProbeTestRequest(BaseModel):
    method: str          # "ssh" or "winrm"
    host: str
    username: str
    password: str = ""
    port: int = 22
    key_path: str | None = None


@app.post("/api/probe/test")
async def probe_test(body: ProbeTestRequest):
    """Test SSH or WinRM credentials without running a scan."""
    from aivas.scanner.probe_errors import CredentialError, ProbeError
    from aivas.scanner.probe_errors import ConnectionError as ProbeConnectionError
    try:
        if body.method == "ssh":
            from aivas.scanner.ssh_probe import probe_async
            await probe_async(
                host=body.host, username=body.username,
                password=body.password or None, key_path=body.key_path,
                port=body.port, timeout=10,
            )
        else:
            from aivas.scanner.winrm_probe import probe_async
            await probe_async(
                host=body.host, username=body.username,
                password=body.password, port=body.port, timeout=10,
            )
        return {"ok": True}
    except (CredentialError, ProbeConnectionError, ProbeError) as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "error": f"Test failed: {exc}"}
```

- [ ] **Step 2: Modify `aivas/server/ws_chat.py`**

Find line 83 (currently `_main._pending[scan_key] = (event["target"], event["level"])`):
```python
_main._pending[scan_key] = (event["target"], event["level"], event.get("creds"))
```

- [ ] **Step 3: Manual smoke test**

Start the server and test the probe/test endpoint:
```bash
cd /home/cyberpunk/aivas
uvicorn aivas.server.main:app --port 8765 &
sleep 2
curl -s -X POST http://localhost:8765/api/probe/test \
  -H "Content-Type: application/json" \
  -d '{"method":"ssh","host":"127.0.0.1","username":"nobody","password":"x","port":22}'
# Expected: {"ok":false,"error":"..."}
kill %1
```

- [ ] **Step 4: Run full suite**

```bash
cd /home/cyberpunk/aivas
pytest tests/ -x -q 2>&1 | tail -10
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/server/main.py aivas/server/ws_chat.py
git commit -m "feat: API wiring — ScanRequest creds field, probe/test endpoint, ws_chat creds passthrough"
```

---

### Task 6: Agent tool `remote_scan` (TUI + web chat)

**Files:**
- Modify: `aivas/tui/agent_prompts.py`
- Modify: `aivas/tui/agent.py`
- Modify: `aivas/server/chat_stream.py`

**Interfaces:**
- Consumes: scan_intent now supports 3-tuple `(target, level, creds)`
- Produces: `remote_scan` tool callable from chat in both TUI and web

---

- [ ] **Step 1: Add `remote_scan` tool to `aivas/tui/agent_prompts.py`**

Append to the `TOOLS` list (before the closing `]`):

```python
    {"type": "function", "function": {
        "name": "remote_scan",
        "description": (
            "Scan a host using SSH (Linux) or WinRM (Windows) credentials to enumerate "
            "installed packages and services from inside the machine. "
            "Use when the user says 'scan via SSH', 'scan as ubuntu', 'credentialed scan', "
            "provides a username/password, or says 'scan my Windows machine'. "
            "For Linux/Mac: method=ssh. For Windows: method=winrm."
        ),
        "parameters": {
            "type": "object",
            "required": ["target", "method", "username"],
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname"},
                "method": {"type": "string", "enum": ["ssh", "winrm"],
                           "description": "ssh for Linux/Mac, winrm for Windows"},
                "username": {"type": "string", "description": "Login username"},
                "password": {"type": "string", "description": "Login password"},
                "port": {"type": "integer",
                         "description": "SSH port (default 22) or WinRM port (default 5985)"},
                "key_path": {"type": "string",
                             "description": "Path to SSH private key file (optional)"},
            },
        },
    }},
```

Also update the `SYSTEM` prompt — in the "Tools available:" section, add after `query_shodan` line:
```python
- remote_scan: scan a remote host using SSH credentials (Linux) or WinRM (Windows) to enumerate installed packages and services from inside the machine. More accurate than a port scan — finds vulnerabilities in software not listening on any port.
```

- [ ] **Step 2: Add `remote_scan` case to `aivas/tui/agent.py`**

In `_exec_tool`, add this case after the `scan_host` case (after line ~60):

```python
    if name == "remote_scan":
        target = _as_str(args.get("target"))
        method = _as_str(args.get("method")) or "ssh"
        username = _as_str(args.get("username"))
        password = _as_str(args.get("password"))
        port = _as_int(args.get("port")) or (22 if method == "ssh" else 5985)
        key_path = _as_str(args.get("key_path"))
        if not target:
            return json.dumps({"error": "target is required for remote_scan"}), None
        if not username:
            return json.dumps({"error": "username is required for remote_scan"}), None
        creds = {
            "method": method, "username": username,
            "password": password, "port": port, "key_path": key_path,
        }
        return json.dumps({
            "status": "running_in_background",
            "instruction": (
                "Credentialed scan is running. Results will appear in the scan card. "
                "Do NOT predict or describe findings."
            ),
        }), (target, 2, creds)
```

- [ ] **Step 3: Update scan_triggered event in `aivas/server/chat_stream.py`**

Find the line (around line 246):
```python
if scan_intent:
    yield {"type": "scan_triggered", "target": scan_intent[0], "level": scan_intent[1]}
```

Replace with:
```python
if scan_intent:
    creds_payload = scan_intent[2] if len(scan_intent) > 2 else None
    yield {
        "type": "scan_triggered",
        "target": scan_intent[0],
        "level": scan_intent[1],
        **({"creds": creds_payload} if creds_payload else {}),
    }
```

Also update `_PHASE_A_SYSTEM` in `chat_stream.py` — add a new routing rule at the end of the string:

```python
    "(6) User provides SSH credentials, says 'scan as <username>', 'scan via SSH', "
    "or 'scan my Windows machine with WinRM' → call remote_scan with target, "
    "method (ssh or winrm), username, and password if provided.\n"
```

- [ ] **Step 4: Update TOOLS import in `chat_stream.py`**

`chat_stream.py` imports `_TOOLS` from `aivas.tui.agent_prompts`. The `remote_scan` tool is now in TOOLS automatically — no change needed to the import.

- [ ] **Step 5: Manual test in TUI**

```bash
cd /home/cyberpunk/aivas
python -m aivas.cli chat
# Type: scan 192.168.1.X via SSH as ubuntu
# Expected: agent calls remote_scan tool, scan starts
```

- [ ] **Step 6: Run full suite**

```bash
cd /home/cyberpunk/aivas
pytest tests/ -x -q 2>&1 | tail -10
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add aivas/tui/agent_prompts.py aivas/tui/agent.py aivas/server/chat_stream.py
git commit -m "feat: remote_scan agent tool — credentialed scans triggerable via chat"
```

---

### Task 7: Frontend — SettingsModal Remote Targets + useScan creds passthrough

**Files:**
- Modify: `frontend/src/components/SettingsModal.jsx`
- Modify: `frontend/src/hooks/useScan.js`
- Modify: `frontend/src/App.jsx`

**Interfaces:**
- `useScan.start(scanKey, creds)` — creds now optional second arg
- App.jsx `handleSend` triggers scans via chat (creds come from agent), SettingsModal "Scan Now" button passes creds directly
- SettingsModal stores targets in `localStorage.aivas_remote_targets` as `JSON.stringify([{host, method, username, password, port}])`

---

- [ ] **Step 1: Update `frontend/src/hooks/useScan.js`**

`useScan` currently opens a WebSocket directly to `/ws/scan/${scanKey}`. The scanKey is created server-side when the scan is registered via POST. For SettingsModal "Scan Now", we need to POST the scan with creds first, then open the WebSocket.

The `start(scanKey)` function already works for chat-triggered scans (ws_chat.py creates the scan registration including creds). For direct "Scan Now" button scans from SettingsModal, App.jsx will POST `/api/scan` with creds and get a scanKey, then call `start(scanKey)`. No change to useScan is needed.

- [ ] **Step 2: Add `handleDirectScan` to `frontend/src/App.jsx`**

In `App.jsx`, add a new callback after `handleAnalysis`:

```javascript
const handleDirectScan = useCallback(async (target, creds) => {
  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, level: 2, creds }),
    })
    const { scan_key } = await resp.json()
    scanPendingRef.current = true
    const slotId = uid()
    scanningIdRef.current = slotId
    dispatch({ type: 'APPEND', msg: { id: slotId, type: 'scan-progress', log: ['Initializing credentialed scan…'] } })
    startScan(scan_key)
  } catch (err) {
    dispatch({ type: 'APPEND', msg: { id: uid(), type: 'ai', text: `Failed to start scan: ${err.message}` } })
  }
}, [startScan])
```

Pass it to SettingsModal:
```jsx
<SettingsModal
  open={settingsOpen}
  onClose={() => setSettingsOpen(false)}
  onScan={handleDirectScan}
/>
```

- [ ] **Step 3: Add Remote Targets section to `frontend/src/components/SettingsModal.jsx`**

Add state at the top of the component (after existing `useState` declarations):

```javascript
const [remoteTargets, setRemoteTargets] = useState([])
const [newTarget, setNewTarget] = useState({ host: '', method: 'ssh', username: '', password: '', port: 22 })
const [testResult, setTestResult]  = useState(null)   // null | {ok, error}
const [testing, setTesting]        = useState(false)
```

Load saved targets in the `useEffect` that loads settings:
```javascript
setRemoteTargets(JSON.parse(localStorage.getItem('aivas_remote_targets') || '[]'))
```

Add helper functions inside the component (before `return`):

```javascript
const saveTarget = () => {
  if (!newTarget.host || !newTarget.username) return
  const updated = [...remoteTargets, { ...newTarget }]
  setRemoteTargets(updated)
  localStorage.setItem('aivas_remote_targets', JSON.stringify(updated))
  setNewTarget({ host: '', method: 'ssh', username: '', password: '', port: 22 })
  setTestResult(null)
}

const deleteTarget = (i) => {
  const updated = remoteTargets.filter((_, idx) => idx !== i)
  setRemoteTargets(updated)
  localStorage.setItem('aivas_remote_targets', JSON.stringify(updated))
}

const testConnection = async () => {
  setTesting(true)
  setTestResult(null)
  try {
    const resp = await fetch('/api/probe/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...newTarget }),
    })
    setTestResult(await resp.json())
  } catch (e) {
    setTestResult({ ok: false, error: 'Network error' })
  }
  setTesting(false)
}
```

Add the Remote Targets section JSX inside the modal, after the Language section and before the Save button:

```jsx
{/* Remote Targets */}
<div className="mb-4">
  <label style={{ color: '#666' }} className="text-xs block mb-2">Remote Targets (SSH / WinRM)</label>

  {/* Saved targets list */}
  {remoteTargets.map((t, i) => (
    <div key={i} style={{ background: '#161616', border: '1px solid #1e1e1e', borderRadius: 4 }}
         className="flex items-center gap-2 px-3 py-2 mb-1.5 text-xs">
      <span style={{ color: '#4a9eff', fontFamily: 'monospace' }}>{t.method.toUpperCase()}</span>
      <span style={{ color: '#e0e0e0' }}>{t.username}@{t.host}:{t.port}</span>
      <div className="ml-auto flex gap-2">
        <button
          onClick={() => { onScan(t.host, { method: t.method, username: t.username, password: t.password, port: t.port }); onClose() }}
          style={{ color: '#4a9eff' }} className="hover:opacity-80 transition-opacity">
          Scan
        </button>
        <button onClick={() => deleteTarget(i)} style={{ color: '#555' }} className="hover:text-red-400 transition-colors">✕</button>
      </div>
    </div>
  ))}

  {/* New target form */}
  <div style={{ border: '1px solid #1e1e1e', borderRadius: 4 }} className="p-2.5 mt-2">
    <div className="flex gap-2 mb-2">
      <select
        value={newTarget.method}
        onChange={e => setNewTarget(t => ({ ...t, method: e.target.value, port: e.target.value === 'ssh' ? 22 : 5985 }))}
        style={{ ...inputStyle, width: 80 }}
        className="rounded px-2 py-1.5 text-xs outline-none"
      >
        <option value="ssh">SSH</option>
        <option value="winrm">WinRM</option>
      </select>
      <input
        type="text"
        placeholder="host or IP"
        value={newTarget.host}
        onChange={e => setNewTarget(t => ({ ...t, host: e.target.value }))}
        style={{ ...inputStyle, flex: 1 }}
        className="rounded px-2 py-1.5 text-xs outline-none"
      />
      <input
        type="number"
        placeholder="port"
        value={newTarget.port}
        onChange={e => setNewTarget(t => ({ ...t, port: Number(e.target.value) }))}
        style={{ ...inputStyle, width: 60 }}
        className="rounded px-2 py-1.5 text-xs outline-none"
      />
    </div>
    <div className="flex gap-2 mb-2">
      <input
        type="text"
        placeholder="username"
        value={newTarget.username}
        onChange={e => setNewTarget(t => ({ ...t, username: e.target.value }))}
        style={{ ...inputStyle, flex: 1 }}
        className="rounded px-2 py-1.5 text-xs outline-none"
      />
      <input
        type="password"
        placeholder="password"
        value={newTarget.password}
        onChange={e => setNewTarget(t => ({ ...t, password: e.target.value }))}
        style={{ ...inputStyle, flex: 1 }}
        className="rounded px-2 py-1.5 text-xs outline-none"
      />
    </div>
    <div className="flex gap-2 items-center">
      <button
        onClick={testConnection}
        disabled={testing || !newTarget.host || !newTarget.username}
        style={{ background: '#161616', border: '1px solid #1e1e1e', color: testing ? '#555' : '#e0e0e0' }}
        className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity disabled:cursor-not-allowed"
      >
        {testing ? 'Testing…' : 'Test Connection'}
      </button>
      <button
        onClick={saveTarget}
        disabled={!newTarget.host || !newTarget.username}
        style={{ background: '#161616', border: '1px solid #4a9eff', color: '#4a9eff' }}
        className="text-xs px-3 py-1.5 rounded hover:opacity-80 transition-opacity disabled:cursor-not-allowed"
      >
        Save Target
      </button>
      {testResult && (
        <span style={{ color: testResult.ok ? '#66bb6a' : '#ef5350' }} className="text-xs">
          {testResult.ok ? '✓ Connected' : `✗ ${testResult.error}`}
        </span>
      )}
    </div>
  </div>
</div>
```

Update the prop signature to accept `onScan`:
```javascript
export default function SettingsModal({ open, onClose, onScan }) {
```

- [ ] **Step 4: Build frontend**

```bash
cd /home/cyberpunk/aivas/frontend
npm run build 2>&1 | tail -20
```
Expected: build succeeds with no errors.

- [ ] **Step 5: Run frontend tests**

```bash
cd /home/cyberpunk/aivas/frontend
npm test -- --run 2>&1 | tail -20
```
Expected: all tests pass (SettingsModal tests still pass since the modal's core fields are unchanged).

- [ ] **Step 6: Manual end-to-end test**

Start the server:
```bash
cd /home/cyberpunk/aivas
uvicorn aivas.server.main:app --reload --port 8000
```

In the browser:
1. Open Settings → Remote Targets section is visible
2. Enter host=`<your Linux device IP>`, method=SSH, username=`ubuntu`, password=`yourpass`
3. Click "Test Connection" → should show ✓ or a real error
4. Click "Save Target" → target appears in the saved list
5. Click "Scan" → scan-progress card appears, then scan-card with results including packages enumerated via SSH

- [ ] **Step 7: Commit**

```bash
cd /home/cyberpunk/aivas
git add frontend/src/components/SettingsModal.jsx frontend/src/App.jsx
git commit -m "feat: SettingsModal remote targets — save SSH/WinRM credentials, test connection, scan from settings"
```

---

## Self-Review

**Spec coverage:**
- ✅ `scanner/probe_errors.py` — Task 1
- ✅ `scanner/ssh_probe.py` extended with async, kernel, services — Task 1
- ✅ `scanner/winrm_probe.py` with registry app query, patches, OS — Task 2
- ✅ `pyproject.toml` pywinrm dependency — Task 2
- ✅ `credential_scan_events()` in scan_helpers — Task 3
- ✅ `run_scan(creds=)` Phase 2 integration — Task 4
- ✅ `done` event `credential_scan` field — Task 4
- ✅ `ScanRequest.creds`, `_pending` tuple, scan_ws unpack — Task 5
- ✅ `POST /api/probe/test` endpoint — Task 5
- ✅ `ws_chat.py` creds in pending — Task 5
- ✅ `remote_scan` tool in TOOLS and SYSTEM — Task 6
- ✅ `_exec_tool` remote_scan case with 3-tuple scan_intent — Task 6
- ✅ `chat_stream.py` scan_triggered with creds, Phase A routing rule — Task 6
- ✅ SettingsModal Remote Targets section — Task 7
- ✅ Test Connection button via `/api/probe/test` — Task 7
- ✅ handleDirectScan in App.jsx for settings-triggered scans — Task 7
- ✅ Error messages per failure type defined in probe modules — Tasks 1 & 2

**Placeholder scan:** No TBD, TODO, or vague steps found. All code blocks are complete.

**Type consistency:**
- `creds` dict shape `{method, username, password, port, key_path}` is consistent across scan_helpers, scan_worker, main.py, agent.py, and SettingsModal.
- `scan_intent` 3-tuple `(target, level, creds)` is consistent between agent.py and chat_stream.py.
- `__credential_services` sentinel key is consistent between scan_helpers and scan_worker.
- Service dict shape is identical across ssh_probe, winrm_probe, and existing correlator expectations.
