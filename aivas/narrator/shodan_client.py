"""Shodan free-tier IP intelligence lookup."""
from __future__ import annotations
import ipaddress
import requests

_BASE = "https://api.shodan.io/shodan/host"

_PRIVATE_MSG = (
    "Shodan does not index private/internal IP addresses (RFC 1918). "
    "This address is only reachable inside your local network — Shodan has no data for it. "
    "Try a public-facing IP or hostname instead."
)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def query_shodan(ip: str, api_key: str) -> dict:
    """Return threat intelligence for ip from Shodan free-tier API.

    Returns a dict with ip, ports, hostnames, country, org, vulns, tags.
    On error or missing key, returns {"ip": ip, "error": "..."}.
    """
    if not api_key:
        return {"ip": ip, "error": "Shodan key not configured."}
    if _is_private(ip):
        return {"ip": ip, "error": _PRIVATE_MSG}
    try:
        resp = requests.get(
            f"{_BASE}/{ip}",
            params={"key": api_key},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "ip": data.get("ip_str", ip),
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "country": data.get("country_name", ""),
            "org": data.get("org", ""),
            "vulns": list(data.get("vulns", {}).keys()),
            "tags": data.get("tags", []),
        }
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}
