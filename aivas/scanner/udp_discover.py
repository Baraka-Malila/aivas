"""Async UDP device discovery using nmap NSE scripts for mDNS and SSDP.

Runs a short nmap UDP scan against ports 5353 (mDNS) and 1900 (SSDP) on
a list of IPs and extracts device friendly names from NSE output.

Never raises — returns an empty dict on any failure so callers can proceed
without device names.
"""
from __future__ import annotations

import asyncio
import re
import shutil

from aivas.parser import parse_nmap_xml

_FRIENDLY_NAME_RE = re.compile(r"friendlyName[:\s]+(.+)", re.IGNORECASE)
_DNS_NAME_RE = re.compile(r"\bName[:\s]+(.+)", re.IGNORECASE)


async def udp_device_info(hosts: list[str], timeout: int = 25) -> dict[str, str]:
    """Return {ip: friendly_name} for hosts that respond to mDNS/SSDP probes.

    Runs nmap -sU on ports 5353,1900 with dns-service-discovery and upnp-info
    NSE scripts. Requires root for UDP scanning; returns {} silently if not root
    or if nmap is unavailable.
    """
    if not hosts:
        return {}

    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [
        nmap_bin, "-sU", "-p", "5353,1900",
        "--script", "dns-service-discovery,upnp-info",
        "--host-timeout", "20s",
        "-oX", "-",
    ] + hosts

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return {}
    except Exception:
        return {}

    if proc.returncode != 0:
        return {}

    try:
        services = parse_nmap_xml(stdout.decode())
    except Exception:
        return {}

    result: dict[str, str] = {}
    for svc in services:
        ip = svc.get("host", "")
        if not ip or ip in result:
            continue
        nse = svc.get("nse_results") or {}

        upnp = nse.get("upnp-info", "")
        m = _FRIENDLY_NAME_RE.search(upnp)
        if m:
            result[ip] = m.group(1).strip()
            continue

        dns = nse.get("dns-service-discovery", "")
        m = _DNS_NAME_RE.search(dns)
        if m:
            result[ip] = m.group(1).strip()

    return result
