"""Tool-event helpers for the streaming chat agent."""
from __future__ import annotations
import json

_SILENT_TOOLS: set[str] = {"scan_host"}


def _tool_summary(name: str, result_json: str) -> str:
    """Return a short human-readable summary of a tool result."""
    try:
        data = json.loads(result_json)
    except (json.JSONDecodeError, ValueError):
        return "done"

    if name == "get_local_info":
        if isinstance(data, dict):
            ip = data.get("ip") or data.get("primary_ip") or data.get("local_ip", "")
            hostname = data.get("hostname", "")
            if ip:
                return f"{hostname} · {ip}" if hostname else ip
        return "done"

    if name == "get_findings":
        count = len(data) if isinstance(data, list) else 0
        return f"{count} finding{'s' if count != 1 else ''} returned"

    if name == "get_last_scan":
        count = len(data.get("findings", [])) if isinstance(data, dict) else 0
        return f"{count} finding{'s' if count != 1 else ''} returned"

    if name == "discover_hosts":
        if isinstance(data, dict):
            count = data.get("count", 0)
            note = data.get("note", "")
            if count == 0 and note:
                return note[:80]
            return f"{count} device{'s' if count != 1 else ''} found"
        return "done"

    if name == "get_history":
        count = len(data) if isinstance(data, list) else 0
        return f"{count} scan{'s' if count != 1 else ''} in history"

    if name == "query_shodan":
        if isinstance(data, dict):
            if data.get("error"):
                return data["error"][:120]
            ports = data.get("ports", [])
            org = data.get("org", "")
            country = data.get("country", "")
            return f"{len(ports)} port(s) · {org or country or 'unknown org'}"
        return "done"

    if name == "list_saved_targets":
        if isinstance(data, dict):
            targets = data.get("targets", [])
            if not targets:
                return "no saved targets"
            return f"{len(targets)} saved target{'s' if len(targets) != 1 else ''}"
        return "done"

    return "done"
