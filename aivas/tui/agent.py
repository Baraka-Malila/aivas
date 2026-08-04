"""AIVAS AI agent: Groq/Mistral tool-calling loop for free-text dispatch."""
from __future__ import annotations

import asyncio
import json
import re as _re
import sqlite3
from typing import TYPE_CHECKING

import httpx

from .agent_prompts import SYSTEM as _SYSTEM, TOOLS as _TOOLS, PHASE_A_SYSTEM as _PHASE_A_SYSTEM

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


def _mistral_call(messages: list[dict], tools: list | None, api_key: str) -> dict:
    """Blocking Mistral chat/completions call."""
    body: dict = {
        "model": "mistral-small-latest",
        "messages": messages,
        "max_tokens": 1000,
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    resp = httpx.post(
        "https://api.mistral.ai/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=body,
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()


def _mistral_msg(raw: dict):
    """Extract normalised message from Mistral response dict."""
    choice = raw["choices"][0]["message"]
    content = choice.get("content") or ""
    tool_calls_raw = choice.get("tool_calls") or []

    class _Fn:
        __slots__ = ("name", "arguments")
        def __init__(self, n, a): self.name = n; self.arguments = a

    class _TC:
        __slots__ = ("id", "function")
        def __init__(self, i, f): self.id = i; self.function = f

    class _Msg:
        __slots__ = ("content", "tool_calls")
        def __init__(self, c, tc): self.content = c; self.tool_calls = tc

    tcs = [_TC(t["id"], _Fn(t["function"]["name"], t["function"].get("arguments", "{}")))
           for t in tool_calls_raw]
    return _Msg(content, tcs or None)


async def run_agent(
    app: "AIVASApp", text: str, api_key: str,
    provider: str = "groq",
    context: str = "", history: list[dict] | None = None,
    shodan_key: str | None = None,
) -> tuple[str, tuple | None, list[dict]]:
    """Run tool-calling loop (Groq or Mistral) with optional prior history.

    Returns:
        (final_text, scan_intent | None, assistant_turns)
    """
    system = "\n\n".join(filter(None, [_SYSTEM, context or ""]))
    messages: list[dict] = [{"role": "system", "content": system}]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": text})
    scan_intent: tuple | None = None
    # Only persist clean user/assistant pairs — no tool_call/tool_result plumbing.
    # Tool call IDs are provider-specific (Groq vs Mistral); storing them breaks
    # history when the user switches providers mid-session.
    turns_to_persist: list[dict] = [{"role": "user", "content": text}]

    use_mistral = (provider == "mistral")

    if not use_mistral:
        from groq import Groq
        client = Groq(api_key=api_key)

        def _groq_call(msgs: list[dict], tools) -> object:
            kwargs: dict = {"model": "llama-3.3-70b-versatile", "messages": msgs, "max_tokens": 1000}
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            return client.chat.completions.create(**kwargs)

    # Phase A base: short routing prompt + optional context.
    # messages[1:] carries history + user message, so we swap the system
    # prompt only for tool-routing calls (Phase A) and keep full _SYSTEM
    # for the final narrative call (Phase B).
    phase_a_base = _PHASE_A_SYSTEM + (f"\n\n{context}" if context else "")

    for _step in range(_MAX_STEPS):
        # Phase A: use short routing prompt for tool-selection calls.
        phase_a_msgs = [{"role": "system", "content": phase_a_base}] + messages[1:]
        try:
            if use_mistral:
                raw = await asyncio.to_thread(_mistral_call, phase_a_msgs, _TOOLS, api_key)
                msg = _mistral_msg(raw)
            else:
                resp = await asyncio.to_thread(_groq_call, phase_a_msgs, _TOOLS)
                msg = resp.choices[0].message
        except Exception as exc:
            s = str(exc)
            if not use_mistral and ("400" in s or "tool" in s.lower()):
                # Retry Groq without tools using full system for a clean text answer
                orig = [{"role": "system", "content": system}, {"role": "user", "content": text}]
                resp = await asyncio.to_thread(_groq_call, orig, None)
                content = _XML_CALL_RE.sub("", resp.choices[0].message.content or "").strip()
                turns_to_persist.append({"role": "assistant", "content": content})
                return content, scan_intent, turns_to_persist
            raise

        if not msg.tool_calls:
            # Phase B: no tool chosen — use full SYSTEM for the narrative response.
            try:
                if use_mistral:
                    raw_b = await asyncio.to_thread(_mistral_call, messages, None, api_key)
                    content = _XML_CALL_RE.sub("", (_mistral_msg(raw_b).content or "")).strip()
                else:
                    resp_b = await asyncio.to_thread(_groq_call, messages, None)
                    content = _XML_CALL_RE.sub("", resp_b.choices[0].message.content or "").strip()
            except Exception:
                content = _XML_CALL_RE.sub("", msg.content or "").strip()
            turns_to_persist.append({"role": "assistant", "content": content})
            return content, scan_intent, turns_to_persist

        tool_calls_payload = [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in msg.tool_calls
        ]
        assistant_turn = {"role": "assistant", "content": msg.content or "", "tool_calls": tool_calls_payload}
        messages.append(assistant_turn)
        # tool_call/tool_result turns are NOT added to turns_to_persist:
        # their IDs are provider-specific and corrupt history on provider switch.

        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}") or {}
            except (json.JSONDecodeError, TypeError):
                args = {}
            result, si = await _exec_tool(tc.function.name, args, app.conn, shodan_key=shodan_key)
            if si:
                scan_intent = si
            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            # (not added to turns_to_persist — see comment above)

    # Exhausted steps — one final call without tools
    try:
        if use_mistral:
            raw = await asyncio.to_thread(_mistral_call, messages, None, api_key)
            content = _XML_CALL_RE.sub("", (_mistral_msg(raw).content or "")).strip()
        else:
            final = await asyncio.to_thread(_groq_call, messages, None)
            content = _XML_CALL_RE.sub("", final.choices[0].message.content or "").strip()
    except Exception:
        content = ""
    turns_to_persist.append({"role": "assistant", "content": content})
    return content, scan_intent, turns_to_persist
