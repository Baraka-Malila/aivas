"""AIVAS AI agent: Groq tool-calling loop for free-text dispatch."""
from __future__ import annotations

import asyncio
import json
import re as _re
import sqlite3
from typing import TYPE_CHECKING

_XML_CALL_RE = _re.compile(r'<function=\w[^>]*>.*?</function>', _re.DOTALL)

if TYPE_CHECKING:
    from .app import AIVASApp

_SYSTEM = """\
You are AIVAS, a network security analyst for small and medium businesses in Tanzania.

Rules:
- When asked to narrate, summarize, or explain findings: call get_findings FIRST to retrieve actual CVE data, then produce a full assessment.
- Structure every narration in exactly this order:
  1. EXECUTIVE SUMMARY — 2-3 sentences: what was scanned, total finding count, overall risk level.
  2. SEVERITY BREAKDOWN — count per level (CRITICAL / HIGH / MEDIUM / LOW) and what that means in plain language.
  3. TOP FINDINGS — list the 3-5 most dangerous CVEs with ID, CVSS score, and one sentence on what an attacker can do with each.
  4. REMEDIATION — concrete steps: name the specific software/service and version to update, any config changes needed.
- Never fabricate CVE details — only use data returned by the tools.
- When asked to scan: call scan_host. After initiating, confirm the scan has started.
- Be direct. No filler phrases. No generic "update software" advice — name the exact products.\
"""

_TOOLS = [
    {"type": "function", "function": {
        "name": "scan_host",
        "description": "Scan a host for open ports and vulnerabilities",
        "parameters": {"type": "object", "required": ["target"], "properties": {
            "target": {"type": "string", "description": "IP address, hostname, or CIDR"},
            "level": {"type": "string", "description": "Scan depth: 1=quick 2=full 3=deep"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_history",
        "description": "List recent scans from scan history",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "string", "description": "Number of scans to return"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_last_scan",
        "description": "Get CVE findings from the most recent scan",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_findings",
        "description": "Get CVE findings for a specific scan ID",
        "parameters": {"type": "object", "required": ["scan_id"], "properties": {
            "scan_id": {"type": "string", "description": "Scan ID from get_history"},
        }},
    }},
    {"type": "function", "function": {
        "name": "explain_cve",
        "description": "Look up a CVE in the local vulnerability database",
        "parameters": {"type": "object", "required": ["cve_id"], "properties": {
            "cve_id": {"type": "string", "description": "CVE ID e.g. CVE-2021-44228"},
        }},
    }},
]

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

_SWAHILI_HINTS = frozenset({
    "unaweza", "naweza", "ninaweza", "tafadhali", "asante", "ndiyo", "hapana",
    "angalia", "angalia", "angalau", "kompyuta", "mashine", "mtandao", "seva",
    "katika", "wangu", "mianya", "udhaifu", "usalama", "skani", "angalia",
    "kuangalia", "hii", "hizi", "yangu", "yako", "hapa",
})


def _detect_lang(text: str) -> str:
    words = set(text.lower().split())
    return "sw" if len(words & _SWAHILI_HINTS) >= 2 else "en"


def _lang_instruction(lang: str) -> str:
    if lang == "sw":
        return ("LAZIMA ujibu kwa Kiswahili PEKE YAKE. "
                "Usitumie Kiingereza hata kidogo. Jibu lako lote liwe kwa Kiswahili.")
    return "Respond ONLY in English. Do not mix in any Swahili."


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
    app: "AIVASApp", text: str, api_key: str, context: str = ""
) -> tuple[str, tuple | None]:
    """Run Groq tool-calling loop. Returns (response_text, scan_intent|None)."""
    from groq import Groq

    lang = _detect_lang(text)
    system = "\n\n".join(filter(None, [_SYSTEM, _lang_instruction(lang), context or ""]))
    client = Groq(api_key=api_key)
    orig_messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
    ]
    messages: list[dict] = list(orig_messages)
    scan_intent: tuple | None = None

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
                resp = await asyncio.to_thread(_call, orig_messages, None)
                content = _XML_CALL_RE.sub("", resp.choices[0].message.content or "").strip()
                return content, scan_intent
            raise
        msg = resp.choices[0].message

        if not msg.tool_calls:
            content = _XML_CALL_RE.sub("", msg.content or "").strip()
            return content, scan_intent

        messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ],
        })

        for tc in msg.tool_calls:
            raw = tc.function.arguments or "{}"
            try:
                args = json.loads(raw) or {}
            except (json.JSONDecodeError, TypeError):
                args = {}
            result, si = _exec_tool(tc.function.name, args, app.conn)
            if si:
                scan_intent = si
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

    final = await asyncio.to_thread(_call, messages, None)
    content = _XML_CALL_RE.sub("", final.choices[0].message.content or "").strip()
    return content, scan_intent
