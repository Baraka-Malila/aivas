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
