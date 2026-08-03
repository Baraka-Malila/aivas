"""AIVAS AI agent: Groq tool-calling loop for free-text dispatch."""
from __future__ import annotations

import asyncio
import json
import re as _re
import sqlite3
from typing import TYPE_CHECKING

from .agent_prompts import SYSTEM as _SYSTEM, TOOLS as _TOOLS

_XML_CALL_RE = _re.compile(r'<function(?:=\w[^>]*)?>.*?</function>', _re.DOTALL)

if TYPE_CHECKING:
    from .app import AIVASApp

_MAX_STEPS = 5


def _as_int(v, default: int | None = None) -> int | None:
    if v is None:
        return default
    s = str(v).strip()
    if not s:
        return default
    try:
        return int(s)
    except ValueError:
        return default


def _as_str(v, default: str = "") -> str:
    if v is None:
        return default
    return str(v).strip()



async def _exec_tool(
    name: str, args: dict, conn: sqlite3.Connection, shodan_key: str | None = None
) -> tuple[str, tuple | None]:
    """Execute a tool call. Returns (result_json, scan_intent) or (error_json, None)."""
    from aivas.history import list_scans, get_scan_findings

    if name == "scan_host":
        target = _as_str(args.get("target"))
        level = _as_int(args.get("level"), default=2) or 2
        if not target:
            return json.dumps({"error": "No target specified."}), None
        return json.dumps({
            "status": "running_in_background",
            "instruction": (
                "The scan is running in a separate process. "
                "Results are NOT available yet — do NOT describe or predict findings. "
                "Tell the user the scan has started and results will appear in the scan card below."
            ),
        }), (target, level)

    if name == "list_saved_targets":
        rows = conn.execute(
            "SELECT id, label, host, method, username, password, port, key_path "
            "FROM remote_targets ORDER BY id DESC"
        ).fetchall()
        targets = [dict(r) for r in rows]
        if not targets:
            return json.dumps({"targets": [], "note": "No saved targets found. User can add them in Settings."}), None
        return json.dumps({"targets": targets}), None

    if name == "remote_scan":
        target = _as_str(args.get("target"))
        method = _as_str(args.get("method")) or "ssh"
        username = _as_str(args.get("username"))
        password = _as_str(args.get("password"))
        port = _as_int(args.get("port")) or (22 if method == "ssh" else 5985)
        key_path = _as_str(args.get("key_path")) or None
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

    if name == "get_history":
        limit = _as_int(args.get("limit"), default=5) or 5
        scans = list_scans(conn, limit=limit)
        return json.dumps(scans), None

    if name == "get_last_scan":
        scans = list_scans(conn, limit=1)
        if not scans:
            return json.dumps({"error": "No scans in history yet."}), None
        findings = get_scan_findings(conn, scans[0]["id"])
        return json.dumps({"scan": scans[0], "findings": findings[:25]}), None

    if name == "get_findings":
        scan_id = _as_int(args.get("scan_id"))
        if scan_id is None:
            return json.dumps({"error": "scan_id must be an integer."}), None
        findings = get_scan_findings(conn, scan_id)
        return json.dumps(findings[:50]), None

    if name == "explain_cve":
        cve_id = _as_str(args.get("cve_id"))
        if not cve_id:
            return json.dumps({"error": "cve_id is required."}), None
        row = conn.execute(
            "SELECT cve_id, cvss_score, cvss_severity, description FROM cves WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        if not row:
            return json.dumps({"error": f"{cve_id} not found in local database."}), None
        return json.dumps(dict(row)), None

    if name == "query_shodan":
        ip = _as_str(args.get("ip"))
        if not ip:
            return json.dumps({"error": "ip is required."}), None
        from aivas.narrator.shodan_client import query_shodan
        result = query_shodan(ip, shodan_key or "")
        return json.dumps(result), None

    if name == "get_local_info":
        import socket
        import subprocess as _sp
        info: dict = {}
        try:
            info["hostname"] = socket.gethostname()
        except Exception:
            info["hostname"] = "unknown"
        # Primary outbound IP — UDP connect trick, sends no packet
        for _dest in ("8.8.8.8", "192.168.1.1", "10.0.0.1"):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _s:
                    _s.connect((_dest, 80))
                    _ip = _s.getsockname()[0]
                    if not _ip.startswith("127."):
                        info["primary_ip"] = _ip
                        break
            except Exception:
                continue
        # Full interface list from ip addr; also derive network CIDR
        try:
            import ipaddress as _ipa
            _r = _sp.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True, text=True, timeout=3,
            )
            if _r.returncode == 0:
                info["interfaces"] = [
                    ln.strip() for ln in _r.stdout.splitlines()
                    if ln.strip().startswith("inet ") and "127.0.0.1" not in ln
                ]
                # Derive "network" = CIDR range for the primary IP
                primary = info.get("primary_ip", "")
                for iface_line in info.get("interfaces", []):
                    parts = iface_line.split()
                    if len(parts) >= 2 and primary and primary in parts[1]:
                        try:
                            info["network"] = str(_ipa.ip_interface(parts[1]).network)
                            break
                        except ValueError:
                            pass
        except Exception:
            pass
        # Fallback: /24 from primary_ip if no prefix found
        if "network" not in info and info.get("primary_ip"):
            octets = info["primary_ip"].rsplit(".", 1)
            if len(octets) == 2:
                info["network"] = f"{octets[0]}.0/24"
        return json.dumps(info), None

    if name == "discover_hosts":
        import shutil
        import xml.etree.ElementTree as ET
        target = _as_str(args.get("target"))
        if not target:
            return json.dumps({"error": "target (CIDR or IP range) is required."}), None

        nmap_bin = shutil.which("nmap") or "nmap"
        cmd = [nmap_bin, "-sn", "-oX", "-", target]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        except Exception as exc:
            return json.dumps({"error": f"Host discovery failed: {exc}"}), None

        devices = []
        try:
            root = ET.fromstring(stdout.decode())
            for host in root.findall("host"):
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue
                dev: dict = {}
                for addr in host.findall("address"):
                    atype = addr.get("addrtype", "")
                    if atype == "ipv4":
                        dev["ip"] = addr.get("addr")
                    elif atype == "mac":
                        dev["mac"] = addr.get("addr")
                        vendor = addr.get("vendor")
                        if vendor:
                            dev["vendor"] = vendor
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname[@type='PTR']")
                    if hn is None:
                        hn = hostnames.find("hostname")
                    if hn is not None:
                        dev["hostname"] = hn.get("name")
                if dev.get("ip"):
                    devices.append(dev)
        except Exception as exc:
            return json.dumps({"error": f"Could not parse discovery output: {exc}"}), None

        note = ""
        if devices and not any(d.get("mac") for d in devices):
            note = "MAC addresses not available — nmap may need cap_net_raw capability (see /doctor)."

        return json.dumps({"devices": devices, "count": len(devices), "note": note}), None

    return json.dumps({"error": f"Unknown tool: {name}"}), None


async def run_agent(
    app: "AIVASApp", text: str, api_key: str,
    context: str = "", history: list[dict] | None = None,
    shodan_key: str | None = None,
) -> tuple[str, tuple | None, list[dict]]:
    """Run Groq tool-calling loop with optional prior history.

    Returns:
        (final_text, scan_intent | None, assistant_turns)
        - final_text: the assistant's last natural-language reply
        - scan_intent: (target, level) if any scan_host tool call was made, else None
        - assistant_turns: the new messages produced this call, ready to persist:
            [{"role":"assistant","content":..., "tool_calls":[...]?},
             {"role":"tool","tool_call_id":..., "content":...}, ...]
    """
    from groq import Groq

    system = "\n\n".join(filter(None, [_SYSTEM, context or ""]))
    client = Groq(api_key=api_key)
    messages: list[dict] = [{"role": "system", "content": system}]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": text})
    scan_intent: tuple | None = None
    turns_to_persist: list[dict] = []

    def _call(msgs: list[dict], tools) -> object:
        kwargs: dict = {
            "model": "llama-3.3-70b-versatile",
            "messages": msgs,
            "max_tokens": 1000,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        return client.chat.completions.create(**kwargs)

    for _step in range(_MAX_STEPS):
        try:
            resp = await asyncio.to_thread(_call, messages, _TOOLS)
        except Exception as exc:
            s = str(exc)
            if "400" in s or "tool" in s.lower():
                # Retry without tools
                orig = [
                    {"role": "system", "content": system},
                    {"role": "user", "content": text},
                ]
                resp = await asyncio.to_thread(_call, orig, None)
                content = _XML_CALL_RE.sub("", resp.choices[0].message.content or "").strip()
                turns_to_persist.append({"role": "assistant", "content": content})
                return content, scan_intent, turns_to_persist
            raise
        msg = resp.choices[0].message

        if not msg.tool_calls:
            content = _XML_CALL_RE.sub("", msg.content or "").strip()
            turns_to_persist.append({"role": "assistant", "content": content})
            return content, scan_intent, turns_to_persist

        # Build assistant turn with tool_calls
        tool_calls_payload = [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in msg.tool_calls
        ]
        assistant_turn = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": tool_calls_payload,
        }
        messages.append(assistant_turn)
        turns_to_persist.append(assistant_turn)

        # Execute each tool, record both the in-flight message and the persisted turn
        for tc in msg.tool_calls:
            raw = tc.function.arguments or "{}"
            try:
                args = json.loads(raw) or {}
            except (json.JSONDecodeError, TypeError):
                args = {}
            result, si = await _exec_tool(tc.function.name, args, app.conn, shodan_key=shodan_key)
            if si:
                scan_intent = si
            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)

    final = await asyncio.to_thread(_call, messages, None)
    content = _XML_CALL_RE.sub("", final.choices[0].message.content or "").strip()
    turns_to_persist.append({"role": "assistant", "content": content})
    return content, scan_intent, turns_to_persist
