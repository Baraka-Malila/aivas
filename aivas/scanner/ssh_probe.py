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
    services, _ = await asyncio.to_thread(
        _probe_sync, host, username, password, key_path, port, timeout
    )
    return services


async def probe_full_async(
    host: str,
    username: str,
    password: str | None = None,
    key_path: str | None = None,
    port: int = 22,
    timeout: int = 90,
) -> tuple[list[dict], list[dict]]:
    """Like probe_async but also returns SSH hardening misconfigurations.

    Returns (services, hardening_misconfigs).
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
) -> tuple[list[dict], list[dict]]:
    """Return (services, hardening_misconfigs)."""
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
        hardening = _get_ssh_hardening(client, host)
        return services, hardening
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


_SSHD_CHECKS: list[tuple[str, str, str, str, str]] = [
    # (config_key, bad_value_pattern, severity, title, recommendation)
    ("PermitRootLogin",      r"^yes$",           "HIGH",   "Root login permitted over SSH",
     "Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd"),
    ("PasswordAuthentication", r"^yes$",         "MEDIUM", "SSH password authentication enabled",
     "Set PasswordAuthentication no in /etc/ssh/sshd_config to require key-based auth only"),
    ("PermitEmptyPasswords", r"^yes$",           "CRITICAL", "SSH allows empty passwords",
     "Set PermitEmptyPasswords no in /etc/ssh/sshd_config immediately"),
    ("X11Forwarding",        r"^yes$",           "LOW",    "SSH X11 forwarding enabled",
     "Set X11Forwarding no in /etc/ssh/sshd_config unless X11 forwarding is actively needed"),
    ("Protocol",             r"^1",              "HIGH",   "SSH protocol version 1 permitted",
     "Remove Protocol 1 from /etc/ssh/sshd_config — SSHv1 is cryptographically broken"),
    ("MaxAuthTries",         r"^([5-9]|[1-9]\d)", "LOW",  "SSH MaxAuthTries too high",
     "Set MaxAuthTries 3 in /etc/ssh/sshd_config to limit brute-force attempts"),
    ("UsePAM",               r"^no$",            "LOW",   "UsePAM disabled",
     "Set UsePAM yes in /etc/ssh/sshd_config to enable account/session management policies"),
]


def _get_ssh_hardening(client: paramiko.SSHClient, host: str) -> list[dict]:
    """Read sshd_config and return misconfiguration dicts for insecure settings."""
    import re as _re
    raw = _run(client,
               "cat /etc/ssh/sshd_config 2>/dev/null "
               "|| cat /etc/openssh/sshd_config 2>/dev/null || true")
    if not raw.strip():
        return []

    # Parse key→value (last occurrence wins, matching OpenSSH precedence)
    config: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1].strip()

    misconfigs: list[dict] = []
    for key, bad_pattern, severity, title, recommendation in _SSHD_CHECKS:
        value = config.get(key.lower())
        if value is None:
            continue
        if _re.match(bad_pattern, value, _re.IGNORECASE):
            misconfigs.append({
                "host": host,
                "type": "ssh_hardening",
                "title": title,
                "severity": severity,
                "description": (
                    f"sshd_config: {key} = {value}. "
                    f"{title} increases the risk of unauthorized access."
                ),
                "recommendation": recommendation,
            })
    return misconfigs


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
