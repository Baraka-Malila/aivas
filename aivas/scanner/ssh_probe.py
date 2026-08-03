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
