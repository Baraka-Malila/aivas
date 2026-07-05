"""AIVAS AI agent: Groq tool-calling loop for free-text dispatch."""
from __future__ import annotations

import asyncio
import json
import re as _re
import sqlite3
from typing import TYPE_CHECKING

from .agent_prompts import SYSTEM as _SYSTEM, TOOLS as _TOOLS

_XML_CALL_RE = _re.compile(r'<function=\w[^>]*>.*?</function>', _re.DOTALL)

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



def _exec_tool(name: str, args: dict, conn: sqlite3.Connection) -> tuple[str, tuple | None]:
    """Execute a tool call. Returns (result_json, scan_intent) or (error_json, None)."""
    from aivas.history import list_scans, get_scan_findings

    if name == "scan_host":
        target = _as_str(args.get("target"))
        level = _as_int(args.get("level"), default=2) or 2
        if not target:
            return json.dumps({"error": "No target specified."}), None
        msg = f"Scan initiated for {target} (level {level}). Results will appear below."
        return json.dumps({"status": "initiated", "message": msg}), (target, level)

    if name == "get_history":
        limit = _as_int(args.get("limit"), default=5) or 5
        scans = list_scans(conn, limit=limit)
        return json.dumps(scans), None

    if name == "get_last_scan":
        scans = list_scans(conn, limit=1)
        if not scans:
            return json.dumps({"error": "No scans in history yet."}), None
        findings = get_scan_findings(conn, scans[0]["id"])
        return json.dumps({"scan": scans[0], "findings": findings[:10]}), None

    if name == "get_findings":
        scan_id = _as_int(args.get("scan_id"))
        if scan_id is None:
            return json.dumps({"error": "scan_id must be an integer."}), None
        findings = get_scan_findings(conn, scan_id)
        return json.dumps(findings[:15]), None

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

    return json.dumps({"error": f"Unknown tool: {name}"}), None


async def run_agent(
    app: "AIVASApp", text: str, api_key: str,
    context: str = "", history: list[dict] | None = None,
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
            result, si = _exec_tool(tc.function.name, args, app.conn)
            if si:
                scan_intent = si
            tool_msg = {"role": "tool", "tool_call_id": tc.id, "content": result}
            messages.append(tool_msg)
            turns_to_persist.append(tool_msg)

    final = await asyncio.to_thread(_call, messages, None)
    content = _XML_CALL_RE.sub("", final.choices[0].message.content or "").strip()
    turns_to_persist.append({"role": "assistant", "content": content})
    return content, scan_intent, turns_to_persist
